//! `OAuth2` authorization-code + PKCE flow against Microsoft Entra ID
//! (RFC 8252 — OAuth for native apps). The interactive equivalent of
//! [`crate::DeviceCodeFlow`] — opens the system browser, lands the user
//! on AAD's sign-in page (with their existing browser session = SSO),
//! and receives the authorization code on a local HTTP listener.
//!
//! Wire parameters mirror what the official Microsoft Azure VPN
//! clients use against AAD (proven by reverse-engineering — see
//! `research/aad-flow-notes.md`):
//!
//! - Redirect URI: `http://localhost:2023` (Microsoft has this
//!   registered for the public-client app ID).
//! - `prompt=select_account` so the user can choose an account if
//!   they have several signed in.
//! - PKCE S256 (oauth2 crate's default).
//! - Scope: `{audience}/.default offline_access` (same as device-code).

use std::time::{Duration, SystemTime};

use oauth2::basic::{BasicClient, BasicTokenResponse};
use oauth2::{
    AuthorizationCode, ClientId, CsrfToken, EndpointNotSet, EndpointSet, PkceCodeChallenge,
    RedirectUrl, Scope,
};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;
use tracing::{info, instrument, warn};

use crate::{AadConfig, Error, Token, aad_authorize_url, aad_http_client, aad_token_url};

/// Loopback redirect Microsoft has registered against the well-known
/// Azure VPN public client. The Linux Azure VPN client hardcodes
/// `http://localhost:2023`; matching exactly avoids `AADSTS50011:
/// redirect_uri mismatch`.
const REDIRECT_URI: &str = "http://localhost:2023";
const LISTENER_BIND: &str = "127.0.0.1:2023";

/// How long we wait for the user to complete sign-in in their browser.
/// Generous; AAD's own code lifetime is 10 minutes, MFA can take a
/// while.
const CALLBACK_TIMEOUT: Duration = Duration::from_mins(10);

/// [`BasicClient`] specialised for the auth-code flow: auth + token
/// endpoints set, redirect URL set, device + introspection unset.
type AadAuthCodeClient = BasicClient<
    EndpointSet,    // auth_uri
    EndpointNotSet, // device_authorization_url
    EndpointNotSet, // introspection_url
    EndpointNotSet, // revocation_url
    EndpointSet,    // token_uri
>;

pub struct AuthCodeFlow {
    config: AadConfig,
    http: reqwest::Client,
    client: AadAuthCodeClient,
}

impl AuthCodeFlow {
    pub fn new(config: AadConfig) -> Result<Self, Error> {
        let token_url = aad_token_url(&config.tenant_id)?;
        let auth_url = aad_authorize_url(&config.tenant_id)?;
        let redirect = RedirectUrl::new(REDIRECT_URI.to_owned())
            .map_err(|e| Error::Other(format!("invalid redirect URL: {e}")))?;

        let client = BasicClient::new(ClientId::new(config.client_id().to_owned()))
            .set_auth_uri(auth_url)
            .set_token_uri(token_url)
            .set_redirect_uri(redirect);

        Ok(Self {
            config,
            http: aad_http_client()?,
            client,
        })
    }

    /// Run the full interactive flow: bind the loopback listener,
    /// open the browser, wait for the callback, exchange the code.
    ///
    /// Returns `Err(Error::LoopbackBindFailed)` when port 2023 is
    /// already in use — the only error the caller should treat as a
    /// signal to fall back to device-code. All other errors (AAD
    /// rejected the sign-in, user cancelled, code-exchange failure)
    /// bubble up unchanged so the user sees the actual cause.
    #[instrument(skip_all, fields(tenant = %self.config.tenant_id))]
    pub async fn run(&self) -> Result<Token, Error> {
        let listener = TcpListener::bind(LISTENER_BIND).await.map_err(|e| {
            warn!(error = %e, addr = LISTENER_BIND, "cannot bind loopback for OAuth callback");
            Error::LoopbackBindFailed
        })?;
        info!(listener = LISTENER_BIND, "loopback ready for OAuth callback");

        let scope = format!("{}/.default offline_access", self.config.audience);
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

        let mut authorize = self
            .client
            .authorize_url(CsrfToken::new_random)
            .add_scope(Scope::new(scope))
            .set_pkce_challenge(pkce_challenge)
            // Account picker — Microsoft's clients do this; without
            // it AAD silently re-uses whatever session the browser
            // already has, which is confusing when the user has
            // multiple work accounts.
            .add_extra_param("prompt", "select_account");

        if self.config.enable_groups {
            authorize = authorize.add_extra_param("claims", crate::GROUPS_CLAIMS_JSON);
        }
        let (auth_url, csrf_state) = authorize.url();

        info!(uri = auth_url.as_str(), "opening system browser for sign-in");
        if let Err(e) = open::that(auth_url.as_str()) {
            warn!(error = %e, "failed to launch browser; user can paste the URL manually");
        }

        let code = wait_for_callback(listener, csrf_state.secret()).await?;
        info!("received authorization code from loopback callback");

        let token_result: BasicTokenResponse = self
            .client
            .exchange_code(AuthorizationCode::new(code))
            .set_pkce_verifier(pkce_verifier)
            .request_async(&self.http)
            .await
            .map_err(|e| Error::TokenAcquisition(format!("code exchange failed: {e}")))?;

        let token = Token::from(&token_result);
        info!(
            expires_in = token
                .expires_at
                .duration_since(SystemTime::now())
                .map_or(0, |d| d.as_secs()),
            has_refresh = token.refresh_token.is_some(),
            "token acquired via auth-code flow"
        );
        Ok(token)
    }
}

/// Accept one HTTP connection on `listener`, parse the GET callback,
/// verify the state parameter matches what we sent, and return the
/// authorization code. Times out if the user never completes sign-in.
async fn wait_for_callback(listener: TcpListener, expected_state: &str) -> Result<String, Error> {
    let accept = tokio::time::timeout(CALLBACK_TIMEOUT, listener.accept())
        .await
        .map_err(|_| Error::TokenAcquisition("timed out waiting for browser callback".into()))?
        .map_err(|e| Error::TokenAcquisition(format!("accept on loopback: {e}")))?;
    let (mut stream, _addr) = accept;

    // Read until end-of-headers (`\r\n\r\n`). AAD's authorize callback
    // is a single GET with all params in the query string, but the
    // request can run several KB with extra response_mode / session_state
    // params — a one-shot read would risk truncation.
    let mut buf = Vec::with_capacity(4096);
    let mut chunk = [0u8; 1024];
    loop {
        let n = stream
            .read(&mut chunk)
            .await
            .map_err(|e| Error::TokenAcquisition(format!("read from loopback: {e}")))?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if buf.len() > 64 * 1024 {
            return Err(Error::TokenAcquisition("callback request too large".into()));
        }
    }
    let request = std::str::from_utf8(&buf)
        .map_err(|_| Error::TokenAcquisition("callback request was not UTF-8".into()))?;

    let (code, state) = parse_callback_query(request)?;
    if state != expected_state {
        return Err(Error::TokenAcquisition(
            "OAuth state mismatch — possible CSRF, refusing".into(),
        ));
    }

    let body = b"<!doctype html><html><body style=\"font-family:system-ui;padding:2em\">\
                 <h2>Signed in</h2><p>You can close this tab.</p></body></html>";
    let response = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: text/html; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.write_all(body).await;
    let _ = stream.shutdown().await;

    Ok(code)
}

/// Pull `code` + `state` out of the loopback callback request. AAD
/// can also send `?error=…&error_description=…` (user declined, AAD
/// rejected) — surfaced as `TokenAcquisition` with the AAD message.
fn parse_callback_query(request: &str) -> Result<(String, String), Error> {
    let first_line = request.lines().next().unwrap_or_default();
    let path = first_line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| Error::TokenAcquisition("malformed HTTP request from browser".into()))?;

    // Synthesize an absolute URL so `url::Url` can give us decoded
    // query pairs (handles `+`, `%XX`, and UTF-8 correctly).
    let parsed = url::Url::parse(&format!("http://localhost{path}"))
        .map_err(|e| Error::TokenAcquisition(format!("malformed callback URL: {e}")))?;

    let mut code = None;
    let mut state = None;
    let mut err = None;
    let mut err_desc = None;
    for (k, v) in parsed.query_pairs() {
        match k.as_ref() {
            "code" => code = Some(v.into_owned()),
            "state" => state = Some(v.into_owned()),
            "error" => err = Some(v.into_owned()),
            "error_description" => err_desc = Some(v.into_owned()),
            _ => {}
        }
    }

    if let Some(e) = err {
        let desc = err_desc.unwrap_or_default();
        return Err(Error::TokenAcquisition(format!(
            "AAD rejected sign-in: {e} ({desc})"
        )));
    }
    let code = code.ok_or_else(|| Error::TokenAcquisition("callback missing `code`".into()))?;
    let state = state.ok_or_else(|| Error::TokenAcquisition("callback missing `state`".into()))?;
    Ok((code, state))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_normal_callback() {
        let req = "GET /?code=ABC123&state=xyz HTTP/1.1\r\nHost: localhost\r\n\r\n";
        let (code, state) = parse_callback_query(req).unwrap();
        assert_eq!(code, "ABC123");
        assert_eq!(state, "xyz");
    }

    #[test]
    fn handles_url_encoded_values() {
        let req = "GET /?code=A%2BB%2FC&state=hello+world HTTP/1.1\r\n";
        let (code, state) = parse_callback_query(req).unwrap();
        assert_eq!(code, "A+B/C");
        assert_eq!(state, "hello world");
    }

    #[test]
    fn rejects_aad_error_callback() {
        let req = "GET /?error=access_denied&error_description=user+cancelled HTTP/1.1\r\n";
        let err = parse_callback_query(req).unwrap_err().to_string();
        assert!(err.contains("access_denied"));
        assert!(err.contains("user cancelled"));
    }

    #[test]
    fn rejects_missing_code() {
        let req = "GET /?state=xyz HTTP/1.1\r\n";
        let err = parse_callback_query(req).unwrap_err().to_string();
        assert!(err.contains("code"));
    }
}
