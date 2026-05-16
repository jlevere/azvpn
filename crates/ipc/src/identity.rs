//! Per-connection caller identity for IPC authorization.
//!
//! The kernel knows who's on the other end of every local IPC
//! channel — we just have to ask. Two flavors that mirror the
//! kernel's native primitive for each platform:
//!
//! - **Windows**: `ImpersonateNamedPipeClient` → `OpenThreadToken` →
//!   `GetTokenInformation` extracts the client's primary SID, group
//!   membership in `BUILTIN\Administrators`, elevation state, and
//!   session ID. UAC's "split token" model means an admin user
//!   running non-elevated has the Administrators SID marked
//!   deny-only on its *primary* token; the canonical check looks up
//!   the *linked* (elevated) token via `TokenLinkedToken` and tries
//!   the membership check there. Tailscale's
//!   `/tmp/tailscale/ipn/ipnauth/ipnauth_windows.go:78–101` is the
//!   reference; this is a Rust port of the same pattern.
//!
//! - **Unix**: `SO_PEERCRED` (Linux) / `LOCAL_PEERCRED` (macOS)
//!   returns uid/gid/pid. Not yet wired through — tracked as the
//!   second half of `G.1` in `PLAN.md`. The cross-platform
//!   [`ClientIdentity`] enum carries the Unix variant for forward
//!   compatibility.
//!
//! The fetched [`ClientIdentity`] is stashed on the per-connection
//! tarpc server clone (`AzvpndServer::with_identity`); RPC handlers
//! consult it via `AzvpndServer::require_admin` to gate mutating
//! operations (`up`, `down`).

/// Caller identity captured at IPC accept time. Cheap to clone
/// (small Strings + Copy ints).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientIdentity {
    /// Windows named-pipe peer, identified via the impersonation
    /// API. Always populated on Windows; `None` connections are
    /// refused at accept time (cannot reason about authz without
    /// identity).
    #[cfg(target_os = "windows")]
    Windows(WindowsClientIdentity),

    /// Unix peer identified via `SO_PEERCRED` / `LOCAL_PEERCRED`.
    /// Reserved for the Linux/macOS half of G.1; today the Unix
    /// accept path logs peer creds but doesn't enforce authorization
    /// per-RPC.
    #[cfg(unix)]
    Unix(UnixClientIdentity),
}

impl ClientIdentity {
    /// `true` when the caller has effective admin authority — admin
    /// group member on Windows (after UAC linked-token resolution),
    /// uid==0 on Unix. Used by [`AzvpndServer::require_admin`].
    #[must_use]
    pub fn is_admin(&self) -> bool {
        match self {
            #[cfg(target_os = "windows")]
            Self::Windows(w) => w.is_admin,
            #[cfg(unix)]
            Self::Unix(u) => u.uid == 0,
        }
    }

    /// Short human-readable display for the audit log. Avoids
    /// platform-specific naming differences leaking into call sites.
    #[must_use]
    pub fn display(&self) -> String {
        match self {
            #[cfg(target_os = "windows")]
            Self::Windows(w) => match &w.user_name {
                Some(name) => format!("{} (sid={}, admin={})", name, w.sid, w.is_admin),
                None => format!("sid={} (admin={})", w.sid, w.is_admin),
            },
            #[cfg(unix)]
            Self::Unix(u) => format!("uid={} gid={} pid={}", u.uid, u.gid, u.pid),
        }
    }
}

/// Windows-side identity captured from the named-pipe client's
/// access token. All fields populated synchronously in
/// [`fetch_pipe_identity`].
#[cfg(target_os = "windows")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsClientIdentity {
    /// String-form SID (`"S-1-5-..."`). Stable identifier across
    /// reboots and logon sessions; useful for audit logging and
    /// future per-user policies.
    pub sid: String,
    /// `DOMAIN\Username` (or `MACHINE\username`) — best-effort
    /// lookup via `LookupAccountSidW`. `None` if the lookup fails
    /// (offline domain controller, deleted account, etc.); the SID
    /// itself is always present and sufficient for authz.
    pub user_name: Option<String>,
    /// `true` when the *effective* token is a member of
    /// `BUILTIN\Administrators`. For a UAC-limited primary token
    /// this means we followed the `TokenLinkedToken` chain and the
    /// linked elevated token was admin. The right field to check
    /// for "may this caller invoke admin RPCs?"
    pub is_admin: bool,
    /// `true` iff the *current* token has `TokenIsElevated=1`. False
    /// for an admin user running non-elevated even when
    /// [`is_admin`](Self::is_admin) is true via the linked-token
    /// path. Audit only — don't use for authz.
    pub is_elevated: bool,
    /// `true` iff the primary SID is exactly `S-1-5-18` (LocalSystem).
    /// Tells us when the caller is the SCM-spawned service itself —
    /// useful for separating "admin user via CLI" from
    /// "daemon-to-daemon" in audit logs.
    pub is_local_system: bool,
    /// Windows session ID. Session 0 is the service-isolation
    /// session; sessions 1+ are interactive user sessions (console
    /// and RDP). Helps distinguish a local-console caller from an
    /// RDP-connected admin in logs.
    pub session_id: u32,
}

/// Unix-side peer identity. Forward-declared; the Unix accept path
/// in `daemon::main::accept_loop` already reads peer creds but
/// doesn't yet populate this struct — landing alongside Track G.1's
/// Unix half.
#[cfg(unix)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnixClientIdentity {
    pub uid: u32,
    pub gid: u32,
    pub pid: u32,
}

/// Failure modes for the Windows identity fetch. Each maps to a
/// specific reason the kernel refused us a usable token — all are
/// treated as "refuse the connection" by the accept loop.
#[cfg(target_os = "windows")]
#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("ImpersonateNamedPipeClient failed: {0}")]
    Impersonate(std::io::Error),
    #[error("OpenThreadToken (post-impersonation) failed: {0}")]
    OpenThreadToken(std::io::Error),
    #[error("GetTokenInformation({class}) failed: {source}")]
    TokenInfo {
        class: &'static str,
        #[source]
        source: std::io::Error,
    },
    #[error("CheckTokenMembership failed: {0}")]
    CheckMembership(std::io::Error),
    #[error("ConvertSidToStringSidW failed: {0}")]
    SidToString(std::io::Error),
    #[error("CreateWellKnownSid(BUILTIN\\Administrators) failed: {0}")]
    WellKnownSid(std::io::Error),
}

/// Fetch the caller's identity from a connected named-pipe handle.
/// Synchronous — must NOT be called from inside an await point
/// because [`ImpersonateNamedPipeClient`] impersonates the current
/// OS thread and an await may resume on a different thread.
///
/// Call this after `NamedPipeServer::connect().await` returns and
/// before any further async work on the connection. The function
/// is internally self-contained: impersonate → query → revert,
/// all on the calling thread, with `RevertToSelf` guaranteed via
/// a drop-guard even on early return.
///
/// [`ImpersonateNamedPipeClient`]: https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient
#[cfg(target_os = "windows")]
#[allow(unsafe_code)]
pub fn fetch_pipe_identity(
    pipe: &tokio::net::windows::named_pipe::NamedPipeServer,
) -> Result<WindowsClientIdentity, IdentityError> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, LocalFree};
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows_sys::Win32::Security::{
        CheckTokenMembership, CreateWellKnownSid, GetTokenInformation, LookupAccountSidW,
        RevertToSelf, SECURITY_MAX_SID_SIZE, TOKEN_ELEVATION, TOKEN_ELEVATION_TYPE,
        TOKEN_LINKED_TOKEN, TOKEN_QUERY, TOKEN_USER, TokenElevation, TokenElevationType,
        TokenElevationTypeLimited, TokenLinkedToken, TokenSessionId, TokenUser,
        WinBuiltinAdministratorsSid,
    };
    use windows_sys::Win32::System::Pipes::ImpersonateNamedPipeClient;
    use windows_sys::Win32::System::Threading::{GetCurrentThread, OpenThreadToken};

    // `RevertToSelf` must run even on early return. The guard runs
    // it from Drop, so any `?` between impersonate and the natural
    // end of the function still un-impersonates the thread.
    struct RevertGuard;
    impl Drop for RevertGuard {
        fn drop(&mut self) {
            // SAFETY: `RevertToSelf` takes no parameters and undoes
            // a prior `ImpersonateNamedPipeClient` on the calling
            // thread. Idempotent if no impersonation is active.
            unsafe { RevertToSelf() };
        }
    }

    let pipe_handle = pipe.as_raw_handle() as HANDLE;
    // SAFETY: `pipe_handle` is a live named-pipe server handle we
    // own (it's the connected one we just accepted). The call
    // impersonates the client on the current thread; the
    // `RevertGuard` ensures we always revert.
    let ok = unsafe { ImpersonateNamedPipeClient(pipe_handle) };
    if ok == 0 {
        return Err(IdentityError::Impersonate(std::io::Error::last_os_error()));
    }
    let _revert = RevertGuard;

    // OpenThreadToken with OpenAsSelf=true: read the impersonation
    // token using *our* (process owner's) credentials, not the
    // impersonated client's. Required so the call works even when
    // the client doesn't grant us SE_TOKEN privileges.
    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: `GetCurrentThread` returns a pseudo-handle (-1) that
    // OpenThreadToken accepts; `&mut token` is a writable output.
    let ok = unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &raw mut token) };
    if ok == 0 {
        return Err(IdentityError::OpenThreadToken(
            std::io::Error::last_os_error(),
        ));
    }
    struct TokenHandle(HANDLE);
    impl Drop for TokenHandle {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: `self.0` is a kernel handle we own.
                unsafe { CloseHandle(self.0) };
            }
        }
    }
    let token = TokenHandle(token);

    let sid_string = sid_string_from_token(token.0)?;
    let user_name = lookup_account_name(token.0).ok();
    let session_id = query_token_u32(token.0, TokenSessionId, "TokenSessionId")?;

    let is_elevated = {
        let mut elevation: TOKEN_ELEVATION = unsafe { std::mem::zeroed() };
        let mut size = std::mem::size_of::<TOKEN_ELEVATION>() as u32;
        // SAFETY: `token.0` is a valid token handle; `elevation` is
        // a writable, properly-sized struct.
        let ok = unsafe {
            GetTokenInformation(
                token.0,
                TokenElevation,
                (&raw mut elevation).cast(),
                size,
                &raw mut size,
            )
        };
        if ok == 0 {
            return Err(IdentityError::TokenInfo {
                class: "TokenElevation",
                source: std::io::Error::last_os_error(),
            });
        }
        elevation.TokenIsElevated != 0
    };

    let is_local_system = sid_string == "S-1-5-18";

    // Admin check: try the current token first. If it says
    // "not admin" AND the token is the UAC-limited half of a
    // split, retry against the linked (elevated) token. This
    // mirrors what Tailscale's `IsAdministrator` does — without
    // the linked-token retry, an admin user running non-elevated
    // appears as a regular user.
    let mut admin_sid_buf = [0u8; SECURITY_MAX_SID_SIZE as usize];
    let mut admin_sid_size: u32 = SECURITY_MAX_SID_SIZE;
    let ok = unsafe {
        CreateWellKnownSid(
            WinBuiltinAdministratorsSid,
            std::ptr::null_mut(),
            admin_sid_buf.as_mut_ptr().cast(),
            &raw mut admin_sid_size,
        )
    };
    if ok == 0 {
        return Err(IdentityError::WellKnownSid(std::io::Error::last_os_error()));
    }
    let admin_sid_ptr = admin_sid_buf.as_mut_ptr().cast();

    let mut is_admin = check_membership(token.0, admin_sid_ptr)?;
    if !is_admin {
        let elev_type = query_token_u32(token.0, TokenElevationType, "TokenElevationType")?;
        if elev_type as i32 == TokenElevationTypeLimited {
            // Look up the linked elevated token and re-check.
            let mut linked: TOKEN_LINKED_TOKEN = unsafe { std::mem::zeroed() };
            let mut size = std::mem::size_of::<TOKEN_LINKED_TOKEN>() as u32;
            let ok = unsafe {
                GetTokenInformation(
                    token.0,
                    TokenLinkedToken,
                    (&raw mut linked).cast(),
                    size,
                    &raw mut size,
                )
            };
            if ok != 0 {
                let linked_token = TokenHandle(linked.LinkedToken);
                is_admin = check_membership(linked_token.0, admin_sid_ptr)?;
            }
        }
    }

    Ok(WindowsClientIdentity {
        sid: sid_string,
        user_name,
        is_admin,
        is_elevated,
        is_local_system,
        session_id,
    })
}

/// Read `TokenUser` and convert the SID to its canonical string form.
/// Sole responsibility — keeps the unsafe Win32 plumbing out of the
/// main fetch function's body.
#[cfg(target_os = "windows")]
#[allow(unsafe_code)]
fn sid_string_from_token(token: windows_sys::Win32::Foundation::HANDLE) -> Result<String, IdentityError> {
    use widestring::U16CStr;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows_sys::Win32::Security::{GetTokenInformation, TOKEN_USER, TokenUser};

    // Two-call pattern: first size-only to get the required buffer
    // length, then again with the right-sized buffer.
    let mut size: u32 = 0;
    // SAFETY: NULL buffer + 0 size makes GetTokenInformation report
    // the required size in `size` and return ERROR_INSUFFICIENT_BUFFER.
    unsafe { GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &raw mut size) };
    if size == 0 {
        return Err(IdentityError::TokenInfo {
            class: "TokenUser (size probe)",
            source: std::io::Error::last_os_error(),
        });
    }
    let mut buf = vec![0u8; size as usize];
    // SAFETY: `buf` is a writable buffer of exactly `size` bytes.
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            buf.as_mut_ptr().cast(),
            size,
            &raw mut size,
        )
    };
    if ok == 0 {
        return Err(IdentityError::TokenInfo {
            class: "TokenUser",
            source: std::io::Error::last_os_error(),
        });
    }
    // SAFETY: TOKEN_USER lays out as { PSID Sid; DWORD Attributes; }
    // — we cast and read the SID pointer, which points into `buf`.
    let user = unsafe { &*(buf.as_ptr().cast::<TOKEN_USER>()) };
    let mut str_sid: *mut u16 = std::ptr::null_mut();
    // SAFETY: `user.User.Sid` is a valid SID inside our buffer.
    // `ConvertSidToStringSidW` allocates a UTF-16 string via
    // LocalAlloc; we LocalFree it after copying.
    let ok = unsafe { ConvertSidToStringSidW(user.User.Sid, &raw mut str_sid) };
    if ok == 0 {
        return Err(IdentityError::SidToString(std::io::Error::last_os_error()));
    }
    // SAFETY: `str_sid` now points to a NUL-terminated UTF-16
    // string. We borrow it just long enough to copy into a `String`
    // and then `LocalFree` it.
    let owned = unsafe { U16CStr::from_ptr_str(str_sid) }.to_string_lossy();
    // SAFETY: `str_sid` was allocated by ConvertSidToStringSidW
    // (which uses LocalAlloc); it's our responsibility to free.
    unsafe { LocalFree(str_sid.cast()) };
    Ok(owned)
}

/// Best-effort lookup of `DOMAIN\Username` for a token's user SID.
/// Used only for audit logging. `LookupAccountSidW` can be slow on
/// domain-joined hosts (LSA roundtrip), so callers tolerate failure
/// — the SID alone is the authoritative identifier.
#[cfg(target_os = "windows")]
#[allow(unsafe_code)]
fn lookup_account_name(
    token: windows_sys::Win32::Foundation::HANDLE,
) -> Result<String, IdentityError> {
    use widestring::U16Str;
    use windows_sys::Win32::Security::{
        GetTokenInformation, LookupAccountSidW, SID_NAME_USE, TOKEN_USER, TokenUser,
    };

    let mut size: u32 = 0;
    unsafe { GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &raw mut size) };
    if size == 0 {
        return Err(IdentityError::TokenInfo {
            class: "TokenUser (size probe, for name lookup)",
            source: std::io::Error::last_os_error(),
        });
    }
    let mut buf = vec![0u8; size as usize];
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            buf.as_mut_ptr().cast(),
            size,
            &raw mut size,
        )
    };
    if ok == 0 {
        return Err(IdentityError::TokenInfo {
            class: "TokenUser (for name lookup)",
            source: std::io::Error::last_os_error(),
        });
    }
    let user = unsafe { &*(buf.as_ptr().cast::<TOKEN_USER>()) };

    let mut name: [u16; 256] = [0; 256];
    let mut name_len: u32 = name.len() as u32;
    let mut domain: [u16; 256] = [0; 256];
    let mut domain_len: u32 = domain.len() as u32;
    let mut sid_use: SID_NAME_USE = 0;
    // SAFETY: All buffers are writable and the lengths are honest;
    // `user.User.Sid` is the SID we extracted moments ago.
    let ok = unsafe {
        LookupAccountSidW(
            std::ptr::null(),
            user.User.Sid,
            name.as_mut_ptr(),
            &raw mut name_len,
            domain.as_mut_ptr(),
            &raw mut domain_len,
            &raw mut sid_use,
        )
    };
    if ok == 0 {
        return Err(IdentityError::TokenInfo {
            class: "LookupAccountSidW",
            source: std::io::Error::last_os_error(),
        });
    }
    let domain_str = unsafe { U16Str::from_ptr(domain.as_ptr(), domain_len as usize) }
        .to_string_lossy();
    let name_str = unsafe { U16Str::from_ptr(name.as_ptr(), name_len as usize) }
        .to_string_lossy();
    if domain_str.is_empty() {
        Ok(name_str)
    } else {
        Ok(format!("{domain_str}\\{name_str}"))
    }
}

/// Read a `u32`-shaped token-information class (SessionId,
/// ElevationType). Small helper so the main fetch function doesn't
/// repeat the same six-line dance per field.
#[cfg(target_os = "windows")]
#[allow(unsafe_code)]
fn query_token_u32(
    token: windows_sys::Win32::Foundation::HANDLE,
    class: windows_sys::Win32::Security::TOKEN_INFORMATION_CLASS,
    class_name: &'static str,
) -> Result<u32, IdentityError> {
    use windows_sys::Win32::Security::GetTokenInformation;
    let mut value: u32 = 0;
    let mut size: u32 = 4;
    let ok = unsafe {
        GetTokenInformation(
            token,
            class,
            (&raw mut value).cast(),
            size,
            &raw mut size,
        )
    };
    if ok == 0 {
        return Err(IdentityError::TokenInfo {
            class: class_name,
            source: std::io::Error::last_os_error(),
        });
    }
    Ok(value)
}

/// `CheckTokenMembership` wrapper that maps the BOOL return into
/// our `IdentityError`. Used twice in [`fetch_pipe_identity`] —
/// once against the primary token, once against the linked
/// elevated token (UAC retry path).
#[cfg(target_os = "windows")]
#[allow(unsafe_code)]
fn check_membership(
    token: windows_sys::Win32::Foundation::HANDLE,
    sid: windows_sys::Win32::Security::PSID,
) -> Result<bool, IdentityError> {
    use windows_sys::Win32::Security::CheckTokenMembership;
    let mut is_member: i32 = 0;
    let ok = unsafe { CheckTokenMembership(token, sid, &raw mut is_member) };
    if ok == 0 {
        return Err(IdentityError::CheckMembership(
            std::io::Error::last_os_error(),
        ));
    }
    Ok(is_member != 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "windows")]
    fn windows_admin() -> ClientIdentity {
        ClientIdentity::Windows(WindowsClientIdentity {
            sid: "S-1-5-21-1-2-3-1000".to_owned(),
            user_name: Some("EXAMPLE\\alice".to_owned()),
            is_admin: true,
            is_elevated: true,
            is_local_system: false,
            session_id: 1,
        })
    }

    #[cfg(target_os = "windows")]
    fn windows_non_admin() -> ClientIdentity {
        ClientIdentity::Windows(WindowsClientIdentity {
            sid: "S-1-5-21-1-2-3-1001".to_owned(),
            user_name: None,
            is_admin: false,
            is_elevated: false,
            is_local_system: false,
            session_id: 1,
        })
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_admin_is_admin() {
        assert!(windows_admin().is_admin());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_non_admin_is_not_admin() {
        assert!(!windows_non_admin().is_admin());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_display_includes_username_when_present() {
        let s = windows_admin().display();
        assert!(s.contains("EXAMPLE\\alice"));
        assert!(s.contains("admin=true"));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_display_falls_back_to_sid_when_name_missing() {
        let s = windows_non_admin().display();
        assert!(s.starts_with("sid="));
        assert!(s.contains("admin=false"));
    }

    #[cfg(unix)]
    #[test]
    fn unix_root_is_admin() {
        let id = ClientIdentity::Unix(UnixClientIdentity {
            uid: 0,
            gid: 0,
            pid: 1234,
        });
        assert!(id.is_admin());
    }

    #[cfg(unix)]
    #[test]
    fn unix_non_root_is_not_admin() {
        let id = ClientIdentity::Unix(UnixClientIdentity {
            uid: 1000,
            gid: 1000,
            pid: 5678,
        });
        assert!(!id.is_admin());
    }
}
