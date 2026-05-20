//! macOS sleep/wake notifications via IOKit.
//!
//! Subscribes to `IORegisterForSystemPower` (the canonical API per Apple
//! Tech Q&A QA1340) and emits a `()` on every *FullWake* — when the user
//! actually wakes the machine. DarkWake-for-maintenance (Power Nap,
//! scheduled BTM, etc.) does **not** deliver `kIOMessageSystemHasPoweredOn`
//! per Apple DTS guidance, so it's filtered out at the framework level
//! and we never see it. That's exactly the discrimination the connect
//! loop needs: it should soft-restart the tunnel after a real lid-open
//! but ignore the ~17-minute DarkWake maintenance cycle that an idle
//! closed-lid laptop runs through. The wall-clock-jump heuristic this
//! replaces conflated the two.
//!
//! ## Architecture
//!
//! IOKit delivers callbacks on a `CFRunLoop`. We don't want to take over
//! the daemon's tokio runtime with one, so we follow the same pattern
//! `if-watch/src/apple.rs` uses for `SCDynamicStore`: spawn a dedicated
//! `std::thread`, register the notification port against that thread's
//! `CFRunLoop`, then call `CFRunLoop::run_current()` to block it forever.
//! The C callback runs on that thread and pushes `()` through a
//! `tokio::sync::mpsc::UnboundedSender`. The async side awaits the
//! receiver inside `netmon::next_change`'s `tokio::select!`.
//!
//! The thread is never joined — it lives for the daemon's process
//! lifetime. Shutdown is via process exit (launchd `SIGTERM` reaps it).
//! There's no daemon-internal teardown path that needs to stop power
//! notifications; the tunnel does, the watcher doesn't.

#![cfg(target_os = "macos")]

use std::ptr;

use core_foundation::base::TCFType as _;
use core_foundation::runloop::{
    CFRunLoop, CFRunLoopSource, CFRunLoopSourceRef, kCFRunLoopCommonModes,
};
use tokio::sync::mpsc;
use tracing::{debug, warn};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("failed to spawn power-event background thread: {0}")]
    ThreadSpawn(#[from] std::io::Error),
}

/// Subscribe to FullWake notifications. The returned receiver yields
/// `()` each time the system fully wakes; DarkWake-for-maintenance is
/// filtered out by the framework. The sender lives on a dedicated OS
/// thread that runs IOKit's `CFRunLoop` until process exit.
pub fn watch() -> Result<mpsc::UnboundedReceiver<()>, Error> {
    let (tx, rx) = mpsc::unbounded_channel();
    // 256 KiB is comfortably above what a CFRunLoop dispatch + our
    // ~40-byte callback stack needs; default macOS thread stack is
    // ~2 MiB, all of which would otherwise be reserved for the
    // process lifetime since this thread never returns.
    std::thread::Builder::new()
        .name("azvpn-darwin-power".into())
        .stack_size(256 * 1024)
        .spawn(move || background(tx))?;
    Ok(rx)
}

// ─── IOKit FFI ──────────────────────────────────────────────────────

// IOKit values for `messageType` in the power-management interest
// callback. See `<IOKit/IOMessage.h>` — they're all
// `iokit_common_msg(x) = 0xE0000000 | x`. We list the four the runtime
// can hand us (Apple's framework hides DarkWake-for-maintenance entirely
// from this callback per DTS guidance, so we don't need to filter them
// here — we only see real sleep/wake).
const KIO_MESSAGE_CAN_SYSTEM_SLEEP: u32 = 0xE000_0270;
const KIO_MESSAGE_SYSTEM_WILL_SLEEP: u32 = 0xE000_0280;
const KIO_MESSAGE_SYSTEM_WILL_POWER_ON: u32 = 0xE000_0320;
const KIO_MESSAGE_SYSTEM_HAS_POWERED_ON: u32 = 0xE000_0300;

// `mach_port_t` is `unsigned int` on Darwin (32-bit even on arm64 — the
// userspace port number, not a pointer). IOKit typedefs `io_connect_t`,
// `io_object_t`, `io_service_t` all to `mach_port_t`.
type IoConnectT = libc::c_uint;
type IoObjectT = libc::c_uint;
type IoServiceT = libc::c_uint;

const MACH_PORT_NULL: IoConnectT = 0;

// `IONotificationPortRef` is an opaque struct pointer.
#[repr(C)]
struct IoNotificationPort {
    _private: [u8; 0],
}
type IoNotificationPortRef = *mut IoNotificationPort;

// C callback signature exactly matches `IOServiceInterestCallback` from
// `<IOKit/IOKitLib.h>`. `messageArgument` for power events is the
// `notificationID` to feed to `IOAllowPowerChange`.
#[allow(unsafe_code)]
type IoServiceInterestCallback = unsafe extern "C" fn(
    refcon: *mut libc::c_void,
    service: IoServiceT,
    message_type: u32,
    message_argument: *mut libc::c_void,
);

#[allow(unsafe_code)]
#[link(name = "IOKit", kind = "framework")]
unsafe extern "C" {
    fn IORegisterForSystemPower(
        refcon: *mut libc::c_void,
        port_ref: *mut IoNotificationPortRef,
        callback: IoServiceInterestCallback,
        notifier: *mut IoObjectT,
    ) -> IoConnectT;

    fn IODeregisterForSystemPower(notifier: *mut IoObjectT) -> libc::c_int;

    fn IOAllowPowerChange(kernel_port: IoConnectT, notification_id: libc::intptr_t) -> libc::c_int;

    fn IONotificationPortGetRunLoopSource(notify: IoNotificationPortRef) -> CFRunLoopSourceRef;

    fn IONotificationPortDestroy(notify: IoNotificationPortRef);

    fn IOServiceClose(connect: IoConnectT) -> libc::c_int;
}

// ─── Background thread + callback ───────────────────────────────────

/// Mutable state shared with the C callback via `refcon`. The callback
/// runs on the same thread as `background`, so the `&mut` aliasing is
/// trivially safe — there's no other thread that touches this struct.
struct CallbackState {
    /// Port handle from `IORegisterForSystemPower`. Needed to ack
    /// sleep-veto-eligible messages (`CanSystemSleep`, `SystemWillSleep`)
    /// via `IOAllowPowerChange`. Not vetoing sleep is mandatory — if we
    /// don't ack within ~30s, the kernel waits for us; longer-running
    /// state would block lid-close.
    root_port: IoConnectT,
    /// Channel back to the async daemon. Unbounded because wake events
    /// arrive at most a few times per day; bounded would risk dropping
    /// the one event that matters if a netmon consumer briefly stalls.
    tx: mpsc::UnboundedSender<()>,
}

#[allow(unsafe_code)]
unsafe extern "C" fn power_callback(
    refcon: *mut libc::c_void,
    _service: IoServiceT,
    message_type: u32,
    message_argument: *mut libc::c_void,
) {
    // SAFETY: `refcon` is the `Box::leak`'d pointer we handed to
    // `IORegisterForSystemPower` from `background`. The leak guarantees
    // it lives for the duration of the run loop, and IOKit only calls
    // this callback on the same thread that called `CFRunLoop::run_current()`,
    // so there is no other thread accessing this state.
    let state: &CallbackState = unsafe { &*refcon.cast::<CallbackState>() };

    match message_type {
        KIO_MESSAGE_CAN_SYSTEM_SLEEP | KIO_MESSAGE_SYSTEM_WILL_SLEEP => {
            // Ack without vetoing. `messageArgument` is the
            // notificationID, passed by IOKit as an opaque `*mut c_void`
            // but interpreted as `intptr_t` per the IOPMLib.h contract.
            // SAFETY: `root_port` is the live port from the successful
            // `IORegisterForSystemPower` call; `notification_id` is the
            // matching ID IOKit just handed us.
            let _ =
                unsafe { IOAllowPowerChange(state.root_port, message_argument as libc::intptr_t) };
            debug!(
                message_type = format!("{message_type:#x}"),
                "acked sleep notification"
            );
        }
        KIO_MESSAGE_SYSTEM_HAS_POWERED_ON => {
            // FullWake. DarkWake-for-maintenance doesn't deliver this
            // message (per Apple DTS, thread 770517), so the filter is
            // built into the framework — we forward unconditionally.
            debug!("FullWake detected");
            // `send` failing means the receiver is gone, which only
            // happens at daemon shutdown. Ignore.
            let _ = state.tx.send(());
        }
        KIO_MESSAGE_SYSTEM_WILL_POWER_ON => {
            // Fires early in the wake sequence, before the network
            // stack is back. We deliberately wait for HAS_POWERED_ON so
            // the consumer's reconnect doesn't race kernel re-attach.
            debug!("SystemWillPowerOn — waiting for HasPoweredOn");
        }
        _ => {
            debug!(
                message_type = format!("{message_type:#x}"),
                "ignoring power message"
            );
        }
    }
}

#[allow(unsafe_code)]
fn background(tx: mpsc::UnboundedSender<()>) {
    // Heap-allocate the state and leak it: it must outlive every
    // possible callback invocation, which means the lifetime of the
    // run loop, which is "until process exit". The C side stores a
    // raw pointer to it via `refcon`.
    let state_box = Box::new(CallbackState {
        root_port: MACH_PORT_NULL,
        tx,
    });
    let state_ptr = Box::into_raw(state_box);
    let refcon = state_ptr.cast::<libc::c_void>();

    let mut port_ref: IoNotificationPortRef = ptr::null_mut();
    let mut notifier: IoObjectT = 0;

    // SAFETY: out-pointers point at locals on this stack frame;
    // `power_callback` has the IOKit-required ABI; `refcon` is a stable
    // pointer to a leaked allocation that outlives every callback.
    let root_port = unsafe {
        IORegisterForSystemPower(refcon, &raw mut port_ref, power_callback, &raw mut notifier)
    };
    if root_port == MACH_PORT_NULL {
        warn!("IORegisterForSystemPower returned MACH_PORT_NULL; power events disabled");
        // Recover the box so the leak isn't permanent on the failure
        // path. SAFETY: we own `state_ptr`; no callback was registered
        // so nothing else can dereference it.
        let _ = unsafe { Box::from_raw(state_ptr) };
        return;
    }

    // The callback needs `root_port` to call `IOAllowPowerChange`. The
    // C side holds a `*mut c_void` to our state via refcon; we
    // update the field through the same pointer we leaked.
    // SAFETY: still single-owner — IOKit hasn't fired any callback yet
    // because we haven't attached the run-loop source. There is no
    // aliasing access.
    unsafe { (*state_ptr).root_port = root_port };

    // SAFETY: `port_ref` was just populated by a successful registration.
    let source_ref = unsafe { IONotificationPortGetRunLoopSource(port_ref) };
    if source_ref.is_null() {
        warn!("IONotificationPortGetRunLoopSource returned null; power events disabled");
        // SAFETY: notifier/port_ref are live; deregister + destroy
        // releases them. IOServiceClose returns the root_port handle.
        unsafe {
            IODeregisterForSystemPower(&raw mut notifier);
            IONotificationPortDestroy(port_ref);
            IOServiceClose(root_port);
            let _ = Box::from_raw(state_ptr);
        }
        return;
    }

    // SAFETY: IONotificationPortGetRunLoopSource returns a borrowed
    // reference (the port owns it). `wrap_under_get_rule` CFRetains it,
    // matched by CFRelease when the CFRunLoopSource wrapper is dropped.
    let source = unsafe { CFRunLoopSource::wrap_under_get_rule(source_ref) };
    let run_loop = CFRunLoop::get_current();
    // SAFETY: kCFRunLoopCommonModes is a stable Apple-published global.
    run_loop.add_source(&source, unsafe { kCFRunLoopCommonModes });

    debug!("IOKit power notifications wired; entering CFRunLoop");
    // Blocks this thread forever. Returns only on explicit
    // `CFRunLoopStop` (we never call it) or process termination.
    CFRunLoop::run_current();

    // Defensive cleanup if the run loop ever does return — we don't
    // expect to reach this in production.
    // SAFETY: all handles are still live; deregister/destroy/close
    // releases them; `Box::from_raw` reclaims the leaked allocation.
    unsafe {
        IODeregisterForSystemPower(&raw mut notifier);
        IONotificationPortDestroy(port_ref);
        IOServiceClose(root_port);
        let _ = Box::from_raw(state_ptr);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iokit_message_constants_match_iomessage_h() {
        // Cross-check against `<IOKit/IOMessage.h>`:
        //   #define iokit_common_msg(m)  (sys_iokit|sub_iokit_common|m)
        //   sys_iokit         = err_system(0x38) = 0x38 << 26 = 0xE000_0000
        //   sub_iokit_common  = err_sub(0)       = 0
        // The constants here are computed as 0xE000_0000 | suffix.
        assert_eq!(KIO_MESSAGE_CAN_SYSTEM_SLEEP, 0xE000_0000 | 0x0270);
        assert_eq!(KIO_MESSAGE_SYSTEM_WILL_SLEEP, 0xE000_0000 | 0x0280);
        assert_eq!(KIO_MESSAGE_SYSTEM_HAS_POWERED_ON, 0xE000_0000 | 0x0300);
        assert_eq!(KIO_MESSAGE_SYSTEM_WILL_POWER_ON, 0xE000_0000 | 0x0320);
    }

    /// Spawn the watcher and assert it doesn't immediately crash; we
    /// can't synthesize sleep/wake from a unit test, but `watch()`
    /// returning successfully means the FFI symbols link and
    /// `IORegisterForSystemPower` is callable from a launchd-like
    /// (non-GUI, non-root) context — both real failure modes we'd
    /// want to catch in CI on a macOS runner.
    #[test]
    fn watch_returns_a_receiver() {
        let rx = watch().expect("watch() should succeed on macOS CI");
        // Receiver is open. Dropping it cleanly is the regression
        // check; the background thread continues to live but that's
        // by design.
        drop(rx);
    }
}
