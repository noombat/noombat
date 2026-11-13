// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! HTTP request router for the sidecar REST API.
//!
//! All endpoints are served under `/admin/v1/`.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::Json;
use axum::extract::{Path as UrlPath, State};
use axum::http::StatusCode;
use axum::routing::{delete, get, post};
use axum::{Router, middleware};
use serde_json::json;
use tracing::{info, warn};

use crate::passwd_file;
use crate::password::generate_password;
use crate::{AppState, trigger_postfix_reload_debounced};

/// Validate that a Chatmail address extracted from a URL path is safe
/// to use as a filesystem path component.
///
/// A valid Chatmail address has the form `local@domain` and must not
/// contain path separators, traversal sequences, or null bytes.
fn validate_address(address: &str) -> Result<(), &'static str> {
    if address.is_empty() {
        return Err("address is empty");
    }
    if address.contains('/') || address.contains('\\') {
        return Err("address contains path separator");
    }
    if address.contains("..") {
        return Err("address contains traversal sequence");
    }
    if address.contains('\0') {
        return Err("address contains null byte");
    }
    // Reject whitespace and control characters. A newline or carriage
    // return in an address written to a Postfix map file (one entry per
    // line) would inject additional map entries.
    if address
        .bytes()
        .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
    {
        return Err("address contains whitespace or control character");
    }
    if address.starts_with('.') || address.starts_with('-') {
        return Err("address starts with disallowed character");
    }
    // A Chatmail address must contain exactly one '@'.
    if address.matches('@').count() != 1 {
        return Err("address must contain exactly one '@'");
    }
    Ok(())
}

/// Validate an address this relay is allowed to *create*.
///
/// Deliberately separate from [`validate_address`], which is shared by
/// the block, unblock, rotate, delete and exists handlers. Two of those
/// take a remote peer's address: `block_sender_pair` blocks the sender
/// named in a chat report, which is by definition somebody else's
/// domain. Folding the domain check into the shared validator would
/// answer 400 to every remote-sender block.
fn validate_local_address(address: &str, mail_domain: &str) -> Result<(), &'static str> {
    validate_address(address)?;
    if mail_domain.is_empty() {
        return Err("MAIL_DOMAIN is not configured");
    }
    // Dovecot lowercases the username before looking it up
    // (`auth_username_format` defaults to lowercase), so the account it
    // looks up is the lowercased form. Compare, and later write, in
    // that form, or a capitalised MAIL_DOMAIN would create an account no
    // login can ever reach.
    let Some((_, domain)) = address.rsplit_once('@') else {
        return Err("address must contain exactly one '@'");
    };
    if !domain.eq_ignore_ascii_case(mail_domain) {
        return Err("address is not on this relay's mail domain");
    }
    Ok(())
}

/// Construct a path within `base_dir` for the given address, verifying
/// that the result does not escape the base directory.
///
/// Returns `None` if the address fails validation or the resolved path
/// falls outside `base_dir`.
fn safe_child_path(base_dir: &str, address: &str) -> Option<PathBuf> {
    validate_address(address).ok()?;

    let base = Path::new(base_dir);
    let candidate = base.join(address);

    // Verify that the constructed path, after lexical resolution,
    // still begins with the base directory.  This catches edge cases
    // that string-level checks might miss (e.g. symlink tricks if
    // the directory exists).
    if let Ok(canonical_base) = base.canonicalize()
        && candidate.exists()
        && let Ok(canonical_candidate) = candidate.canonicalize()
        && !canonical_candidate.starts_with(&canonical_base)
    {
        warn!(
            address = %address,
            "resolved path escapes base directory"
        );
        return None;
    }
    Some(candidate)
    // If the candidate doesn't exist yet, the string-level checks
    // in validate_address are the defence. The address has already
    // been verified to contain no `/`, `\`, `..`, or null bytes.
}

/// Dispatch an incoming HTTP request.
/// A JSON reply: the status and the body every handler returns.
type Reply = (StatusCode, Json<serde_json::Value>);

fn reply(status: StatusCode, body: serde_json::Value) -> Reply {
    (status, Json(body))
}

fn invalid_address() -> Reply {
    reply(StatusCode::BAD_REQUEST, json!({"error": "invalid address"}))
}

/// The admin API.
///
/// Each address is a single path segment, so a value containing `/` no
/// longer reaches a handler at all: it matches no route and answers 404
/// where the hand-rolled prefix matching used to hand the whole
/// remainder to `validate_address`. That validator still runs, because
/// axum percent-decodes a segment before handing it over and `%2F`
/// would otherwise arrive as a separator after the routing decision.
pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route(
            "/admin/v1/accounts/{address}/rotate-password",
            post(rotate_password),
        )
        .route("/admin/v1/accounts/{address}/kick", post(kick))
        .route(
            "/admin/v1/accounts/{address}",
            delete(delete_account).put(create_account),
        )
        .route("/admin/v1/accounts/{address}/exists", get(account_exists))
        .route(
            "/admin/v1/access-maps/recipients/{address}/block",
            post(block_recipient).delete(unblock_recipient),
        )
        .route(
            "/admin/v1/access-maps/senders/{sender}/block-to/{recipient}",
            post(block_sender_pair).delete(unblock_sender_pair),
        )
        .fallback(not_found)
        .layer(middleware::from_fn_with_state(
            Arc::clone(&state),
            require_admin_secret,
        ))
        .with_state(state)
}

async fn not_found() -> Reply {
    reply(StatusCode::NOT_FOUND, json!({"error": "not found"}))
}

/// Reject anything without `Authorization: Bearer <secret>`.
///
/// Comparison uses HMAC-SHA256 digests to produce fixed-length
/// (32-byte) outputs before the constant-time comparison, eliminating
/// both timing and length oracle attacks.
///
/// Applied as a layer over every route including the fallback, so an
/// unauthenticated request cannot learn which paths exist.
async fn require_admin_secret(
    State(state): State<Arc<AppState>>,
    request: axum::extract::Request,
    next: middleware::Next,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::Sha256;
    use subtle::ConstantTimeEq;

    type HmacSha256 = Hmac<Sha256>;

    /// Fixed domain-separation tag (not secret).
    const HMAC_TAG: &[u8] = b"noombat-chatmail-admin-verify";

    let digest = |secret: &[u8]| {
        let mut mac =
            HmacSha256::new_from_slice(secret).expect("HMAC-SHA256 accepts any key length");
        mac.update(HMAC_TAG);
        mac.finalize().into_bytes()
    };

    let offered = request
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(|token| digest(token.as_bytes()));

    let expected = digest(state.config.admin_secret.as_bytes());

    match offered {
        Some(token) if bool::from(token.ct_eq(&expected)) => next.run(request).await,
        _ => reply(StatusCode::UNAUTHORIZED, json!({"error": "unauthorised"})).into_response(),
    }
}

// ..... ENDPOINT HANDLERS .....
//
// Each does a little blocking work: a file write, a `doveadm` or
// `postfix` invocation, a lock on the shared maps. The sole client is
// the co-located Noombat application server, issuing requests only on
// moderator-initiated actions (suspension, unsuspension, account
// deletion, per-pair sender blocks), so the rate is at most a few
// requests per hour and holding a worker for the duration costs
// nothing worth reclaiming.

/// `POST /admin/v1/accounts/{address}/rotate-password`
///
/// Replaces the account's line in the passwd-file with a new randomly
/// generated password. Returns the new password.
async fn rotate_password(
    State(state): State<Arc<AppState>>,
    UrlPath(address): UrlPath<String>,
) -> Reply {
    if validate_address(&address).is_err() {
        return invalid_address();
    }

    let new_password = generate_password();
    match state.passwd.replace(&address, new_password.as_bytes()) {
        Ok(()) => {}
        Err(passwd_file::Error::NotFound) => {
            return reply(StatusCode::NOT_FOUND, json!({"error": "account not found"}));
        }
        Err(passwd_file::Error::Unsafe) => return invalid_address(),
        Err(e) => {
            warn!(address = %address, error = %e, "the passwd-file could not be written");
            return reply(
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({"error": "password rotation failed"}),
            );
        }
    }
    info!(address = %address, "password rotated");

    reply(
        StatusCode::OK,
        json!({"address": address, "password": new_password}),
    )
}

/// `PUT /admin/v1/accounts/{address}`
///
/// Create a Chatmail account: the Maildir and a line in the passwd-file
/// for a freshly generated password, which is returned so the caller can
/// log in as the account it just made.
///
/// Creation happens here and nowhere else, behind the bearer secret the
/// `require_admin_secret` layer checks on every route in this router:
/// anything that created an account before authentication would create
/// it for an anonymous stranger.
///
/// The password is generated here rather than by the caller so that
/// exactly one side owns it. Two generators would silently disagree and
/// every subsequent login would fail.
async fn create_account(
    State(state): State<Arc<AppState>>,
    UrlPath(address): UrlPath<String>,
) -> Reply {
    if let Err(e) = validate_local_address(&address, &state.config.mail_domain) {
        warn!(address = ?address, error = %e, "account creation rejected");
        return invalid_address();
    }
    let address = address.to_lowercase();
    if !passwd_file::usable(&address) {
        warn!(address = ?address, "account creation rejected: not a usable passwd-file line");
        return invalid_address();
    }
    let Some(account_dir) = maildir_path(&state.config.vmail_home, &address) else {
        return invalid_address();
    };
    match state.passwd.contains(&address) {
        Ok(false) => {}
        Ok(true) => return reply(StatusCode::CONFLICT, json!({"error": "account exists"})),
        Err(e) => {
            warn!(address = %address, error = %e, "the passwd-file could not be read");
            return reply(
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({"error": "account creation failed"}),
            );
        }
    }

    // A failure below removes the directory only if this request made it:
    // one already there, with no line, may hold an account's mail.
    let created = !account_dir.exists();
    let discard = || {
        if created {
            let _ = std::fs::remove_dir_all(&account_dir);
        }
    };

    let maildir = account_dir.join("Maildir");
    for sub in ["cur", "new", "tmp"] {
        if let Err(e) = std::fs::create_dir_all(maildir.join(sub)) {
            warn!(address = %address, error = %e, "maildir could not be created");
            discard();
            return reply(
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({"error": "account creation failed"}),
            );
        }
    }

    // The sidecar runs as root; LMTP delivery runs as vmail (5000).
    // Without this the Maildir is unwritable by delivery, so creation
    // would report success and every message after it would fail.
    let mut owned = vec![account_dir.clone(), maildir.clone()];
    owned.extend(["cur", "new", "tmp"].map(|sub| maildir.join(sub)));
    for path in &owned {
        if let Err(e) = std::os::unix::fs::chown(
            path,
            Some(state.config.vmail_uid),
            Some(state.config.vmail_gid),
        ) {
            warn!(address = %address, path = ?path, error = %e, "ownership could not be set");
            discard();
            return reply(
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({"error": "account creation failed"}),
            );
        }
    }

    // Last, so a failure above leaves no login behind. `add` checks again
    // under its lock: of two concurrent requests for one address, one
    // gets the account and the other a conflict.
    let password = generate_password();
    match state.passwd.add(&address, password.as_bytes()) {
        Ok(()) => {}
        Err(passwd_file::Error::Exists) => {
            return reply(StatusCode::CONFLICT, json!({"error": "account exists"}));
        }
        Err(e) => {
            warn!(address = %address, error = %e, "the passwd-file could not be written");
            discard();
            return reply(
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({"error": "account creation failed"}),
            );
        }
    }

    info!(address = %address, "account created");
    reply(
        StatusCode::CREATED,
        json!({"address": address, "password": password}),
    )
}

/// `POST /admin/v1/accounts/{address}/kick`
///
/// Invokes `doveadm kick` to terminate all active IMAP sessions.
async fn kick(UrlPath(address): UrlPath<String>) -> Reply {
    if let Err(e) = validate_address(&address) {
        warn!(address = ?address, error = %e, "kick rejected: invalid address");
        return invalid_address();
    }
    // doveadm reads `*` and `?` in a user mask as wildcards, so one
    // request would kick every matching account.
    if address.contains(['*', '?']) {
        warn!(address = ?address, "kick rejected: wildcard");
        return invalid_address();
    }
    let status = std::process::Command::new("doveadm")
        .args(["kick", &address])
        .status();

    match status {
        Ok(s) if s.success() => {
            info!(address = %address, "IMAP sessions terminated");
            reply(StatusCode::OK, json!({"address": address, "kicked": true}))
        }
        Ok(s) => {
            warn!(address = %address, status = %s, "doveadm kick non-zero exit");
            // Non-zero exit may mean no active sessions, not an error.
            reply(
                StatusCode::OK,
                json!({
                    "address": address,
                    "kicked": true,
                    "note": "doveadm exited non-zero (may indicate no active sessions)"
                }),
            )
        }
        Err(e) => {
            warn!(address = %address, error = %e, "doveadm kick failed");
            reply(
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({"error": format!("doveadm kick failed: {e}")}),
            )
        }
    }
}

/// `DELETE /admin/v1/accounts/{address}`
///
/// Removes the account's passwd-file line and its entire maildir, and
/// blocks the address in the recipient access map so no further mail is
/// delivered to it.
///
/// The block is a delivery control and not a creation control:
/// `noombat_recipient_access` is read by Postfix's
/// `smtpd_recipient_restrictions`, which governs who may be delivered
/// *to*. What stops the address being recreated is that the only path
/// that creates one is the authenticated `PUT` above.
async fn delete_account(
    State(state): State<Arc<AppState>>,
    UrlPath(address): UrlPath<String>,
) -> Reply {
    let Some(account_dir) = maildir_path(&state.config.vmail_home, &address) else {
        return invalid_address();
    };

    // No address in these lines: they record an erasure. The line goes
    // first, so no login succeeds while the mail is being removed.
    if let Err(e) = state.passwd.remove(&address) {
        warn!(error = %e, "the passwd-file could not be written");
        return reply(
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({"error": "account deletion failed"}),
        );
    }
    if account_dir.exists() {
        if let Err(e) = std::fs::remove_dir_all(&account_dir) {
            warn!(error = %e, "account directory could not be removed");
            return reply(
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({"error": "account deletion failed"}),
            );
        }
        info!("account deleted (passwd-file line and maildir)");
    }

    // Block delivery to the address. This is a mail-flow control, not a
    // creation control: it is read by Postfix, and creation is the
    // sidecar's own authenticated endpoint.
    {
        let mut maps = state.maps.lock().unwrap_or_else(|e| e.into_inner());
        maps.blocked_recipients.insert(address.clone());
        if let Err(e) = maps.save(&state.config.access_maps_path) {
            warn!(error = %e, "failed to persist access maps");
        }
        maps.write_postfix_maps(&state.config);
    }
    trigger_postfix_reload_debounced(&state);

    reply(StatusCode::OK, json!({"address": address, "deleted": true}))
}

/// `POST /admin/v1/access-maps/recipients/{address}/block`
async fn block_recipient(
    State(state): State<Arc<AppState>>,
    UrlPath(address): UrlPath<String>,
) -> Reply {
    if let Err(e) = validate_address(&address) {
        warn!(address = ?address, error = %e, "block-recipient rejected: invalid address");
        return invalid_address();
    }
    {
        let mut maps = state.maps.lock().unwrap_or_else(|e| e.into_inner());
        maps.blocked_recipients.insert(address.clone());
        if let Err(e) = maps.save(&state.config.access_maps_path) {
            warn!(error = %e, "failed to persist access maps");
        }
        maps.write_postfix_maps(&state.config);
    }
    trigger_postfix_reload_debounced(&state);
    info!(address = %address, "recipient blocked");

    reply(StatusCode::OK, json!({"address": address, "blocked": true}))
}

/// `DELETE /admin/v1/access-maps/recipients/{address}/block`
async fn unblock_recipient(
    State(state): State<Arc<AppState>>,
    UrlPath(address): UrlPath<String>,
) -> Reply {
    if let Err(e) = validate_address(&address) {
        warn!(address = ?address, error = %e, "unblock-recipient rejected: invalid address");
        return invalid_address();
    }
    {
        let mut maps = state.maps.lock().unwrap_or_else(|e| e.into_inner());
        maps.blocked_recipients.remove(&address);
        if let Err(e) = maps.save(&state.config.access_maps_path) {
            warn!(error = %e, "failed to persist access maps");
        }
        maps.write_postfix_maps(&state.config);
    }
    trigger_postfix_reload_debounced(&state);
    info!(address = %address, "recipient unblocked");

    reply(
        StatusCode::OK,
        json!({"address": address, "unblocked": true}),
    )
}

/// `POST /admin/v1/access-maps/senders/{sender}/block-to/{recipient}`
async fn block_sender_pair(
    State(state): State<Arc<AppState>>,
    UrlPath((sender, recipient)): UrlPath<(String, String)>,
) -> Reply {
    if let Err(e) = validate_address(&sender).and_then(|()| validate_address(&recipient)) {
        warn!(
            sender = ?sender,
            recipient = ?recipient,
            error = %e,
            "block-sender-pair rejected: invalid address"
        );
        return invalid_address();
    }
    {
        let mut maps = state.maps.lock().unwrap_or_else(|e| e.into_inner());
        maps.sender_blocks
            .entry(sender.clone())
            .or_default()
            .insert(recipient.clone());
        if let Err(e) = maps.save(&state.config.access_maps_path) {
            warn!(error = %e, "failed to persist access maps");
        }
        maps.write_postfix_maps(&state.config);
    }
    trigger_postfix_reload_debounced(&state);
    info!(sender = %sender, recipient = %recipient, "sender pair blocked");

    reply(
        StatusCode::OK,
        json!({"sender": sender, "recipient": recipient, "blocked": true}),
    )
}

/// `DELETE /admin/v1/access-maps/senders/{sender}/block-to/{recipient}`
async fn unblock_sender_pair(
    State(state): State<Arc<AppState>>,
    UrlPath((sender, recipient)): UrlPath<(String, String)>,
) -> Reply {
    if let Err(e) = validate_address(&sender).and_then(|()| validate_address(&recipient)) {
        warn!(
            sender = ?sender,
            recipient = ?recipient,
            error = %e,
            "unblock-sender-pair rejected: invalid address"
        );
        return invalid_address();
    }
    {
        let mut maps = state.maps.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(set) = maps.sender_blocks.get_mut(&sender) {
            set.remove(&recipient);
            if set.is_empty() {
                maps.sender_blocks.remove(&sender);
            }
        }
        if let Err(e) = maps.save(&state.config.access_maps_path) {
            warn!(error = %e, "failed to persist access maps");
        }
        maps.write_postfix_maps(&state.config);
    }
    trigger_postfix_reload_debounced(&state);
    info!(sender = %sender, recipient = %recipient, "sender pair unblocked");

    reply(
        StatusCode::OK,
        json!({"sender": sender, "recipient": recipient, "unblocked": true}),
    )
}

/// `GET /admin/v1/accounts/{address}/exists`
async fn account_exists(
    State(state): State<Arc<AppState>>,
    UrlPath(address): UrlPath<String>,
) -> Reply {
    if validate_address(&address).is_err() {
        return invalid_address();
    }
    match state.passwd.contains(&address) {
        Ok(exists) => reply(
            StatusCode::OK,
            json!({"address": address, "exists": exists}),
        ),
        Err(e) => {
            warn!(address = %address, error = %e, "the passwd-file could not be read");
            reply(
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({"error": "account lookup failed"}),
            )
        }
    }
}

// ..... HELPERS .....

/// Derive the maildir path for a Chatmail address.
///
/// Returns `None` if the address fails validation or the resolved path
/// escapes `vmail_home`.
fn maildir_path(vmail_home: &str, address: &str) -> Option<PathBuf> {
    safe_child_path(vmail_home, address)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_address_accepts_valid() {
        assert!(validate_address("alice@chat.example.com").is_ok());
        assert!(validate_address("user123@chat.noombat.social").is_ok());
    }

    #[test]
    fn validate_address_rejects_traversal() {
        assert!(validate_address("../../etc/shadow").is_err());
        assert!(validate_address("alice@chat..example.com").is_err());
    }

    #[test]
    fn validate_address_rejects_path_separator() {
        assert!(validate_address("alice/../../etc/passwd").is_err());
        assert!(validate_address("alice\\bob").is_err());
    }

    #[test]
    fn validate_address_rejects_null_byte() {
        assert!(validate_address("alice\0@example.com").is_err());
    }

    #[test]
    fn validate_address_rejects_empty() {
        assert!(validate_address("").is_err());
    }

    #[test]
    fn validate_address_rejects_missing_at() {
        assert!(validate_address("alice").is_err());
    }

    #[test]
    fn validate_address_rejects_multiple_at() {
        assert!(validate_address("alice@chat@example.com").is_err());
    }

    #[test]
    fn validate_address_rejects_leading_dot() {
        assert!(validate_address(".hidden@example.com").is_err());
    }

    #[test]
    fn validate_address_rejects_whitespace() {
        assert!(validate_address("alice @example.com").is_err());
        assert!(validate_address("alice@example.com\n").is_err());
        assert!(validate_address("alice@example.com\r").is_err());
        assert!(validate_address("alice@example.com\t").is_err());
    }

    #[test]
    fn safe_child_path_rejects_traversal() {
        assert!(safe_child_path("/home/vmail", "../../etc/shadow").is_none());
    }

    #[test]
    fn safe_child_path_accepts_valid() {
        let p = safe_child_path("/home/vmail", "alice@chat.example.com");
        assert!(p.is_some());
        assert_eq!(
            p.unwrap(),
            PathBuf::from("/home/vmail/alice@chat.example.com")
        );
    }

    // ..... The authentication layer .....
    //
    // Reachable only through a socket before this rewrite, so none of it
    // was covered. `oneshot` drives the router directly.

    const SECRET: &str = "a-shared-secret";

    /// The uid and gid this process creates files with.
    ///
    /// `geteuid` would need `libc` and the crate forbids unsafe code, so
    /// ask the filesystem: create a file and read back who owns it.
    fn own_uid_gid(dir: &std::path::Path) -> (u32, u32) {
        use std::os::unix::fs::MetadataExt as _;
        let probe = dir.join(".ownership-probe");
        std::fs::write(&probe, b"").expect("a temporary directory is writable");
        let meta = std::fs::metadata(&probe).expect("the probe exists");
        let ids = (meta.uid(), meta.gid());
        std::fs::remove_file(&probe).expect("the probe is removable");
        ids
    }

    fn test_state(home: &std::path::Path) -> Arc<AppState> {
        let at = |name: &str| home.join(name).to_string_lossy().into_owned();
        let config = crate::config::Config {
            listen_host: "127.0.0.1".to_owned(),
            listen_port: 0,
            admin_secret: SECRET.to_owned(),
            vmail_home: home.to_string_lossy().into_owned(),
            access_maps_path: at("access-maps.json"),
            recipient_access_path: at("recipient_access"),
            sender_access_path: at("sender_access"),
            reload_debounce_secs: 2,
            allowlist_url: String::new(),
            allowlist_poll_interval_secs: 21_600,
            transport_maps_path: at("transport_maps"),
            sender_domains_path: at("sender_domains"),
            tls_cert_path: at("chatmail.pem"),
            tls_key_path: at("chatmail.key"),
            // Matches the `a@b.test` the validator tests already use.
            mail_domain: "b.test".to_owned(),
            // The running process, because a test is not root and cannot
            // chown to another uid. Production defaults to 5000. Taken
            // from a file this process just created rather than from
            // `geteuid`, because the crate forbids unsafe code.
            vmail_uid: own_uid_gid(home).0,
            vmail_gid: own_uid_gid(home).1,
        };
        let gid = config.vmail_gid;
        Arc::new(AppState {
            config,
            maps: std::sync::Mutex::new(crate::access_maps::AccessMaps::default()),
            passwd: crate::passwd_file::PasswdFile::new(home.join(".noombat-admin/passwd"), gid),
            last_reload: std::sync::Mutex::new(std::time::Instant::now()),
        })
    }

    async fn status_of(authorisation: Option<&str>, method: &str, path: &str) -> StatusCode {
        use tower::ServiceExt;

        let mut request = axum::http::Request::builder().method(method).uri(path);
        if let Some(value) = authorisation {
            request = request.header(axum::http::header::AUTHORIZATION, value);
        }
        let home = tempfile::tempdir().expect("a temporary directory");
        router(test_state(home.path()))
            .oneshot(request.body(axum::body::Body::empty()).expect("a request"))
            .await
            .expect("the router answers")
            .status()
    }

    #[tokio::test]
    async fn a_request_without_a_token_is_refused() {
        let status = status_of(None, "GET", "/admin/v1/accounts/a@b.test/exists").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn a_wrong_token_is_refused() {
        let status = status_of(
            Some("Bearer not-the-secret"),
            "GET",
            "/admin/v1/accounts/a@b.test/exists",
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn a_token_without_the_bearer_prefix_is_refused() {
        let status = status_of(Some(SECRET), "GET", "/admin/v1/accounts/a@b.test/exists").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn the_right_token_reaches_the_handler() {
        let status = status_of(
            Some(&format!("Bearer {SECRET}")),
            "GET",
            "/admin/v1/accounts/a@b.test/exists",
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    }

    // An unknown path must answer 401 without a token, not 404: the
    // layer sits over the fallback so an unauthenticated caller cannot
    // map which routes exist.
    #[tokio::test]
    async fn an_unknown_path_does_not_leak_its_absence() {
        assert_eq!(
            status_of(None, "GET", "/admin/v1/nothing-here").await,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            status_of(
                Some(&format!("Bearer {SECRET}")),
                "GET",
                "/admin/v1/nothing-here"
            )
            .await,
            StatusCode::NOT_FOUND
        );
    }

    // A separator in the address matched a route under the old prefix
    // matching and was caught by `validate_address`. Now it matches no
    // route at all, which is the stronger answer.
    #[tokio::test]
    async fn an_address_with_a_separator_matches_no_route() {
        let status = status_of(
            Some(&format!("Bearer {SECRET}")),
            "POST",
            "/admin/v1/accounts/a@b.test/../other/kick",
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    // Percent-encoded, so routing sees one segment and the decoded value
    // reaches the validator. This is the case the client's own
    // `check_segment` refuses before sending, and the reason it must:
    // the two ends have to agree about what a segment may contain.
    #[tokio::test]
    async fn a_percent_encoded_separator_is_refused_by_the_validator() {
        let status = status_of(
            Some(&format!("Bearer {SECRET}")),
            "POST",
            "/admin/v1/accounts/a%2Fb/kick",
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    // Refused before doveadm is spawned, so this needs no doveadm.
    #[tokio::test]
    async fn kick_refuses_a_wildcard_and_a_leading_dash() {
        for path in [
            "/admin/v1/accounts/*@b.test/kick",
            "/admin/v1/accounts/a%3F@b.test/kick",
            "/admin/v1/accounts/-a@b.test/kick",
        ] {
            let status = status_of(Some(&format!("Bearer {SECRET}")), "POST", path).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{path}");
        }
    }

    // ..... Account creation .....

    /// Drive one request against a router sharing `home`, returning the
    /// status and the parsed JSON body.
    ///
    /// `status_of` above builds a fresh tempdir per call, which is right
    /// for auth checks and wrong here: these assertions are about what is
    /// left on disk afterwards.
    async fn request_on(
        home: &std::path::Path,
        method: &str,
        path: &str,
    ) -> (StatusCode, serde_json::Value) {
        use tower::ServiceExt;

        let request = axum::http::Request::builder()
            .method(method)
            .uri(path)
            .header(
                axum::http::header::AUTHORIZATION,
                format!("Bearer {SECRET}"),
            )
            .body(axum::body::Body::empty())
            .expect("a request");
        let response = router(test_state(home))
            .oneshot(request)
            .await
            .expect("the router answers");
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .expect("a small body");
        let body = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        (status, body)
    }

    /// The passwd-file line for `address`, if it has one.
    fn passwd_line(home: &std::path::Path, address: &str) -> Option<String> {
        std::fs::read_to_string(home.join(".noombat-admin/passwd"))
            .ok()?
            .lines()
            .find(|l| l.split(':').next() == Some(address))
            .map(str::to_owned)
    }

    /// Whether `password` is the one the line was hashed from.
    fn opens(line: &str, password: &str) -> bool {
        use argon2::password_hash::PasswordVerifier as _;
        let Some((_, hash)) = line.split_once(":{ARGON2ID}") else {
            return false;
        };
        let Ok(parsed) = argon2::password_hash::phc::PasswordHash::new(hash) else {
            return false;
        };
        argon2::Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok()
    }

    #[tokio::test]
    async fn creating_an_account_writes_a_maildir_and_a_passwd_line() {
        let home = tempfile::tempdir().expect("a temporary directory");
        let (status, body) = request_on(home.path(), "PUT", "/admin/v1/accounts/a@b.test").await;

        assert_eq!(status, StatusCode::CREATED);
        let password = body["password"].as_str().expect("a password is returned");
        assert!(
            !password.is_empty(),
            "an empty password authenticates nobody"
        );

        let account = home.path().join("a@b.test");
        for sub in ["cur", "new", "tmp"] {
            assert!(
                account.join("Maildir").join(sub).is_dir(),
                "Maildir/{sub} was not created"
            );
        }
        let line = passwd_line(home.path(), "a@b.test").expect("a passwd-file line");
        assert!(
            opens(&line, password),
            "the line must hold the password the caller was given, or no login can succeed"
        );
        assert!(
            !account.join("password").exists(),
            "no password is stored in the clear"
        );
    }

    #[tokio::test]
    async fn the_passwd_file_is_readable_by_dovecot_s_group_only() {
        use std::os::unix::fs::MetadataExt as _;

        let home = tempfile::tempdir().expect("a temporary directory");
        request_on(home.path(), "PUT", "/admin/v1/accounts/a@b.test").await;

        let meta =
            std::fs::metadata(home.path().join(".noombat-admin/passwd")).expect("the passwd-file");
        assert_eq!(meta.mode() & 0o777, 0o640);
        assert_eq!(meta.gid(), test_state(home.path()).config.vmail_gid);
    }

    #[tokio::test]
    async fn creating_an_account_twice_is_refused() {
        let home = tempfile::tempdir().expect("a temporary directory");
        let (first, body) = request_on(home.path(), "PUT", "/admin/v1/accounts/a@b.test").await;
        assert_eq!(first, StatusCode::CREATED);
        let original = body["password"].as_str().expect("a password").to_owned();
        let line = passwd_line(home.path(), "a@b.test").expect("a passwd-file line");

        let (second, _) = request_on(home.path(), "PUT", "/admin/v1/accounts/a@b.test").await;
        assert_eq!(second, StatusCode::CONFLICT);
        assert_eq!(
            passwd_line(home.path(), "a@b.test").as_deref(),
            Some(line.as_str()),
            "a refused second create must not overwrite the live password"
        );
        assert!(opens(&line, &original));
    }

    #[tokio::test]
    async fn rotating_replaces_the_password() {
        let home = tempfile::tempdir().expect("a temporary directory");
        let (_, body) = request_on(home.path(), "PUT", "/admin/v1/accounts/a@b.test").await;
        let old = body["password"].as_str().expect("a password").to_owned();

        let (status, body) = request_on(
            home.path(),
            "POST",
            "/admin/v1/accounts/a@b.test/rotate-password",
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let new = body["password"].as_str().expect("a new password");
        let line = passwd_line(home.path(), "a@b.test").expect("a passwd-file line");
        assert!(opens(&line, new), "the new password must log in");
        assert!(!opens(&line, &old), "the old password must not");

        let (unknown, _) = request_on(
            home.path(),
            "POST",
            "/admin/v1/accounts/x@b.test/rotate-password",
        )
        .await;
        assert_eq!(unknown, StatusCode::NOT_FOUND);
        assert!(passwd_line(home.path(), "x@b.test").is_none());
    }

    #[tokio::test]
    async fn deleting_removes_the_line_and_the_mail() {
        let home = tempfile::tempdir().expect("a temporary directory");
        request_on(home.path(), "PUT", "/admin/v1/accounts/a@b.test").await;
        request_on(home.path(), "PUT", "/admin/v1/accounts/c@b.test").await;

        let (status, _) = request_on(home.path(), "DELETE", "/admin/v1/accounts/a@b.test").await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            passwd_line(home.path(), "a@b.test").is_none(),
            "a deleted account still logs in"
        );
        assert!(!home.path().join("a@b.test").exists());
        assert!(
            passwd_line(home.path(), "c@b.test").is_some(),
            "another account was removed"
        );
    }

    #[tokio::test]
    async fn existence_is_a_passwd_file_line() {
        let home = tempfile::tempdir().expect("a temporary directory");
        request_on(home.path(), "PUT", "/admin/v1/accounts/a@b.test").await;
        // A mailbox with no line is not an account: nothing can log in to it.
        std::fs::create_dir_all(home.path().join("x@b.test/Maildir")).expect("a stray maildir");

        let exists = |address: &'static str| {
            let home = home.path().to_owned();
            async move {
                let path = format!("/admin/v1/accounts/{address}/exists");
                request_on(&home, "GET", &path).await.1["exists"].clone()
            }
        };
        assert_eq!(exists("a@b.test").await, true);
        assert_eq!(exists("x@b.test").await, false);
        assert_eq!(exists("y@b.test").await, false);
    }

    #[tokio::test]
    async fn an_address_dovecot_would_not_read_back_is_refused() {
        let home = tempfile::tempdir().expect("a temporary directory");
        // A leading `#` makes the line a comment; `:` splits it.
        for address in ["%23a@b.test", "a:b@b.test"] {
            let path = format!("/admin/v1/accounts/{address}");
            let (status, _) = request_on(home.path(), "PUT", &path).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{address}");
            let rotate = format!("/admin/v1/accounts/{address}/rotate-password");
            let (status, _) = request_on(home.path(), "POST", &rotate).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{address}");
        }
        assert!(!home.path().join("#a@b.test").exists());
        assert!(!home.path().join("a:b@b.test").exists());
    }

    #[tokio::test]
    async fn a_failed_create_removes_only_what_it_made() {
        let home = tempfile::tempdir().expect("a temporary directory");
        // A directory where the passwd-file's temporary copy goes, so
        // every write fails after the maildir is made.
        std::fs::create_dir_all(home.path().join(".noombat-admin/passwd.tmp/x"))
            .expect("a blocker");
        // A mailbox with no line, holding mail.
        let stray = home.path().join("a@b.test/Maildir/cur");
        std::fs::create_dir_all(&stray).expect("a stray maildir");
        std::fs::write(stray.join("1.msg"), "mail").expect("a message");

        let (status, _) = request_on(home.path(), "PUT", "/admin/v1/accounts/a@b.test").await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(
            stray.join("1.msg").exists(),
            "a failed create deleted existing mail"
        );

        let (status, _) = request_on(home.path(), "PUT", "/admin/v1/accounts/c@b.test").await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(
            !home.path().join("c@b.test").exists(),
            "a failed create left the maildir it made"
        );
    }

    #[tokio::test]
    async fn an_address_on_another_domain_is_refused() {
        // The check that stops this endpoint provisioning mailboxes on a
        // domain the relay does not serve.
        let home = tempfile::tempdir().expect("a temporary directory");
        let (status, _) =
            request_on(home.path(), "PUT", "/admin/v1/accounts/a@elsewhere.test").await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(
            !home.path().join("a@elsewhere.test").exists(),
            "a refused address must leave nothing on disk"
        );
    }

    #[tokio::test]
    async fn the_domain_check_ignores_case() {
        // Dovecot lowercases the username before looking it up, so an
        // account written in mixed case is one no login can reach.
        let home = tempfile::tempdir().expect("a temporary directory");
        let (status, body) = request_on(home.path(), "PUT", "/admin/v1/accounts/a@B.TEST").await;

        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(
            body["address"], "a@b.test",
            "the address is stored lowercased"
        );
        assert!(passwd_line(home.path(), "a@b.test").is_some());
    }

    #[test]
    fn an_unconfigured_mail_domain_refuses_every_address() {
        // Empty rather than a panic at startup: this process starts where
        // the container health check cannot see it, so a panic here is an
        // invisible outage. Refusing one request is visible.
        assert!(validate_local_address("a@b.test", "").is_err());
    }

    #[test]
    fn the_shared_validator_still_accepts_a_remote_address() {
        // `block_sender_pair` blocks the sender named in a chat report,
        // which is somebody else's domain by definition. Folding the
        // domain check into `validate_address` would break it.
        assert!(validate_address("someone@remote.example").is_ok());
        assert!(validate_local_address("someone@remote.example", "b.test").is_err());
    }
}
