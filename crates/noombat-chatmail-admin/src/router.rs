// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! HTTP request router for the sidecar REST API.
//!
//! All endpoints are served under `/admin/v1/`.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde_json::json;
use tiny_http::{Header, Method, Request, Response, StatusCode};
use tracing::{info, warn};

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
pub fn handle_request(request: Request, state: &Arc<AppState>) {
    // Authenticate via shared secret.
    if !authenticate(&request, &state.config.admin_secret) {
        let _ = request.respond(json_response(
            StatusCode(401),
            &json!({"error": "unauthorised"}),
        ));
        return;
    }

    let method = request.method().clone();
    let url = request.url().to_owned();

    match route(&method, &url, request, state) {
        Ok(()) => {}
        Err(e) => {
            warn!(url = %url, error = %e, "handler error");
        }
    }
}

/// Verify the `Authorization: Bearer <secret>` header.
///
/// Comparison uses HMAC-SHA256 digests to produce fixed-length
/// (32-byte) outputs before the constant-time comparison, eliminating
/// both timing and length oracle attacks.
fn authenticate(request: &Request, expected: &str) -> bool {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    use subtle::ConstantTimeEq;

    type HmacSha256 = Hmac<Sha256>;

    /// Fixed domain-separation tag (not secret).
    const HMAC_TAG: &[u8] = b"noombat-chatmail-admin-verify";

    for header in request.headers() {
        if header.field.equiv("Authorization")
            && let Some(token) = header.value.as_str().strip_prefix("Bearer ")
        {
            let mut mac_a = HmacSha256::new_from_slice(token.as_bytes())
                .expect("HMAC-SHA256 accepts any key length");
            mac_a.update(HMAC_TAG);
            let digest_a = mac_a.finalize().into_bytes();

            let mut mac_b = HmacSha256::new_from_slice(expected.as_bytes())
                .expect("HMAC-SHA256 accepts any key length");
            mac_b.update(HMAC_TAG);
            let digest_b = mac_b.finalize().into_bytes();

            return digest_a.ct_eq(&digest_b).into();
        }
    }
    false
}

/// Match the URL path to a handler.
fn route(
    method: &Method,
    url: &str,
    request: Request,
    state: &Arc<AppState>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Strip query string if present.
    let path = url.split('?').next().unwrap_or(url);

    // POST /admin/v1/accounts/{address}/rotate-password
    if method == &Method::Post {
        if let Some(addr) = path
            .strip_prefix("/admin/v1/accounts/")
            .and_then(|rest| rest.strip_suffix("/rotate-password"))
        {
            return handle_rotate_password(request, state, addr);
        }
        // POST /admin/v1/accounts/{address}/kick
        if let Some(addr) = path
            .strip_prefix("/admin/v1/accounts/")
            .and_then(|rest| rest.strip_suffix("/kick"))
        {
            return handle_kick(request, state, addr);
        }
        // POST /admin/v1/access-maps/recipients/{address}/block
        if let Some(addr) = path
            .strip_prefix("/admin/v1/access-maps/recipients/")
            .and_then(|rest| rest.strip_suffix("/block"))
        {
            return handle_block_recipient(request, state, addr);
        }
        // POST /admin/v1/access-maps/senders/{sender}/block-to/{recipient}
        if let Some(rest) = path.strip_prefix("/admin/v1/access-maps/senders/")
            && let Some((sender, recipient)) = parse_sender_block_pair(rest)
        {
            return handle_block_sender_pair(request, state, &sender, &recipient);
        }
    }

    // DELETE /admin/v1/accounts/{address}
    if method == &Method::Delete {
        if let Some(addr) = path.strip_prefix("/admin/v1/accounts/")
            && !addr.contains('/')
            && !addr.is_empty()
        {
            return handle_delete_account(request, state, addr);
        }
        // DELETE /admin/v1/access-maps/recipients/{address}/block
        if let Some(addr) = path
            .strip_prefix("/admin/v1/access-maps/recipients/")
            .and_then(|rest| rest.strip_suffix("/block"))
        {
            return handle_unblock_recipient(request, state, addr);
        }
        // DELETE /admin/v1/access-maps/senders/{sender}/block-to/{recipient}
        if let Some(rest) = path.strip_prefix("/admin/v1/access-maps/senders/")
            && let Some((sender, recipient)) = parse_sender_block_pair(rest)
        {
            return handle_unblock_sender_pair(request, state, &sender, &recipient);
        }
    }

    // GET /admin/v1/accounts/{address}/exists
    if method == &Method::Get
        && let Some(addr) = path
            .strip_prefix("/admin/v1/accounts/")
            .and_then(|rest| rest.strip_suffix("/exists"))
    {
        return handle_account_exists(request, state, addr);
    }

    // Fallback: 404.
    request.respond(json_response(
        StatusCode(404),
        &json!({"error": "not found"}),
    ))?;
    Ok(())
}

/// Parse `{sender}/block-to/{recipient}` from a path suffix.
fn parse_sender_block_pair(rest: &str) -> Option<(String, String)> {
    let parts: Vec<&str> = rest.splitn(3, '/').collect();
    if parts.len() == 3 && parts[1] == "block-to" && !parts[0].is_empty() && !parts[2].is_empty() {
        Some((parts[0].to_owned(), parts[2].to_owned()))
    } else {
        None
    }
}

// ..... ENDPOINT HANDLERS .....

/// `POST /admin/v1/accounts/{address}/rotate-password`
///
/// Overwrites the user's password file with a new randomly generated
/// password. Returns the new password.
fn handle_rotate_password(
    request: Request,
    state: &Arc<AppState>,
    address: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let password_file = match password_file_path(&state.config.vmail_home, address) {
        Some(p) => p,
        None => {
            request.respond(json_response(
                StatusCode(400),
                &json!({"error": "invalid address"}),
            ))?;
            return Ok(());
        }
    };
    if !password_file.exists() {
        request.respond(json_response(
            StatusCode(404),
            &json!({"error": "account not found"}),
        ))?;
        return Ok(());
    }

    let new_password = generate_password();
    std::fs::write(&password_file, &new_password)?;
    info!(address = %address, "password rotated");

    request.respond(json_response(
        StatusCode(200),
        &json!({"address": address, "password": new_password}),
    ))?;
    Ok(())
}

/// `POST /admin/v1/accounts/{address}/kick`
///
/// Invokes `doveadm kick` to terminate all active IMAP sessions.
fn handle_kick(
    request: Request,
    state: &Arc<AppState>,
    address: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Err(e) = validate_address(address) {
        warn!(address = %address, error = %e, "kick rejected: invalid address");
        request.respond(json_response(
            StatusCode(400),
            &json!({"error": "invalid address"}),
        ))?;
        return Ok(());
    }
    let _ = state; // config not needed for this handler.
    let status = std::process::Command::new("doveadm")
        .args(["kick", address])
        .status();

    match status {
        Ok(s) if s.success() => {
            info!(address = %address, "IMAP sessions terminated");
            request.respond(json_response(
                StatusCode(200),
                &json!({"address": address, "kicked": true}),
            ))?;
        }
        Ok(s) => {
            warn!(address = %address, status = %s, "doveadm kick non-zero exit");
            // Non-zero exit may mean no active sessions, not an error.
            request.respond(json_response(
                StatusCode(200),
                &json!({"address": address, "kicked": true, "note": "doveadm exited non-zero (may indicate no active sessions)"}),
            ))?;
        }
        Err(e) => {
            warn!(address = %address, error = %e, "doveadm kick failed");
            request.respond(json_response(
                StatusCode(500),
                &json!({"error": format!("doveadm kick failed: {e}")}),
            ))?;
        }
    }
    Ok(())
}

/// `DELETE /admin/v1/accounts/{address}`
///
/// Removes the user's entire maildir and password file. Adds the
/// address to the recipient access map to prevent ghost account
/// creation.
fn handle_delete_account(
    request: Request,
    state: &Arc<AppState>,
    address: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let account_dir = match maildir_path(&state.config.vmail_home, address) {
        Some(p) => p,
        None => {
            request.respond(json_response(
                StatusCode(400),
                &json!({"error": "invalid address"}),
            ))?;
            return Ok(());
        }
    };

    if account_dir.exists() {
        // remove_dir_all deletes the entire account directory,
        // including the password file and all maildir contents.
        std::fs::remove_dir_all(&account_dir)?;
        info!(address = %address, "account directory deleted (maildir + password)");
    }

    // Block the recipient to prevent ghost account creation via
    // doveauth create-on-login.
    {
        let mut maps = state.maps.lock().unwrap_or_else(|e| e.into_inner());
        maps.blocked_recipients.insert(address.to_owned());
        if let Err(e) = maps.save(&state.config.access_maps_path) {
            warn!(error = %e, "failed to persist access maps");
        }
        maps.write_postfix_maps(&state.config);
    }
    trigger_postfix_reload_debounced(state);

    request.respond(json_response(
        StatusCode(200),
        &json!({"address": address, "deleted": true}),
    ))?;
    Ok(())
}

/// `POST /admin/v1/access-maps/recipients/{address}/block`
fn handle_block_recipient(
    request: Request,
    state: &Arc<AppState>,
    address: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Err(e) = validate_address(address) {
        warn!(address = %address, error = %e, "block-recipient rejected: invalid address");
        request.respond(json_response(
            StatusCode(400),
            &json!({"error": "invalid address"}),
        ))?;
        return Ok(());
    }
    {
        let mut maps = state.maps.lock().unwrap_or_else(|e| e.into_inner());
        maps.blocked_recipients.insert(address.to_owned());
        if let Err(e) = maps.save(&state.config.access_maps_path) {
            warn!(error = %e, "failed to persist access maps");
        }
        maps.write_postfix_maps(&state.config);
    }
    trigger_postfix_reload_debounced(state);
    info!(address = %address, "recipient blocked");

    request.respond(json_response(
        StatusCode(200),
        &json!({"address": address, "blocked": true}),
    ))?;
    Ok(())
}

/// `DELETE /admin/v1/access-maps/recipients/{address}/block`
fn handle_unblock_recipient(
    request: Request,
    state: &Arc<AppState>,
    address: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Err(e) = validate_address(address) {
        warn!(address = %address, error = %e, "unblock-recipient rejected: invalid address");
        request.respond(json_response(
            StatusCode(400),
            &json!({"error": "invalid address"}),
        ))?;
        return Ok(());
    }
    {
        let mut maps = state.maps.lock().unwrap_or_else(|e| e.into_inner());
        maps.blocked_recipients.remove(address);
        if let Err(e) = maps.save(&state.config.access_maps_path) {
            warn!(error = %e, "failed to persist access maps");
        }
        maps.write_postfix_maps(&state.config);
    }
    trigger_postfix_reload_debounced(state);
    info!(address = %address, "recipient unblocked");

    request.respond(json_response(
        StatusCode(200),
        &json!({"address": address, "unblocked": true}),
    ))?;
    Ok(())
}

/// `POST /admin/v1/access-maps/senders/{sender}/block-to/{recipient}`
fn handle_block_sender_pair(
    request: Request,
    state: &Arc<AppState>,
    sender: &str,
    recipient: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Err(e) = validate_address(sender).and_then(|()| validate_address(recipient)) {
        warn!(sender = %sender, recipient = %recipient, error = %e, "block-sender-pair rejected: invalid address");
        request.respond(json_response(
            StatusCode(400),
            &json!({"error": "invalid address"}),
        ))?;
        return Ok(());
    }
    {
        let mut maps = state.maps.lock().unwrap_or_else(|e| e.into_inner());
        maps.sender_blocks
            .entry(sender.to_owned())
            .or_default()
            .insert(recipient.to_owned());
        if let Err(e) = maps.save(&state.config.access_maps_path) {
            warn!(error = %e, "failed to persist access maps");
        }
        maps.write_postfix_maps(&state.config);
    }
    trigger_postfix_reload_debounced(state);
    info!(sender = %sender, recipient = %recipient, "sender pair blocked");

    request.respond(json_response(
        StatusCode(200),
        &json!({"sender": sender, "recipient": recipient, "blocked": true}),
    ))?;
    Ok(())
}

/// `DELETE /admin/v1/access-maps/senders/{sender}/block-to/{recipient}`
fn handle_unblock_sender_pair(
    request: Request,
    state: &Arc<AppState>,
    sender: &str,
    recipient: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Err(e) = validate_address(sender).and_then(|()| validate_address(recipient)) {
        warn!(sender = %sender, recipient = %recipient, error = %e, "unblock-sender-pair rejected: invalid address");
        request.respond(json_response(
            StatusCode(400),
            &json!({"error": "invalid address"}),
        ))?;
        return Ok(());
    }
    {
        let mut maps = state.maps.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(set) = maps.sender_blocks.get_mut(sender) {
            set.remove(recipient);
            if set.is_empty() {
                maps.sender_blocks.remove(sender);
            }
        }
        if let Err(e) = maps.save(&state.config.access_maps_path) {
            warn!(error = %e, "failed to persist access maps");
        }
        maps.write_postfix_maps(&state.config);
    }
    trigger_postfix_reload_debounced(state);
    info!(sender = %sender, recipient = %recipient, "sender pair unblocked");

    request.respond(json_response(
        StatusCode(200),
        &json!({"sender": sender, "recipient": recipient, "unblocked": true}),
    ))?;
    Ok(())
}

/// `GET /admin/v1/accounts/{address}/exists`
fn handle_account_exists(
    request: Request,
    state: &Arc<AppState>,
    address: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let exists = match password_file_path(&state.config.vmail_home, address) {
        Some(p) => p.exists(),
        None => {
            request.respond(json_response(
                StatusCode(400),
                &json!({"error": "invalid address"}),
            ))?;
            return Ok(());
        }
    };
    request.respond(json_response(
        StatusCode(200),
        &json!({"address": address, "exists": exists}),
    ))?;
    Ok(())
}

// ..... HELPERS .....

/// Derive the password file path for a Chatmail address.
///
/// Chatmail stores passwords at `{vmail_home}/{address}/password`.
/// Returns `None` if the address fails validation or the resolved path
/// escapes `vmail_home`.
fn password_file_path(vmail_home: &str, address: &str) -> Option<PathBuf> {
    safe_child_path(vmail_home, address).map(|p| p.join("password"))
}

/// Derive the maildir path for a Chatmail address.
///
/// Returns `None` if the address fails validation or the resolved path
/// escapes `vmail_home`.
fn maildir_path(vmail_home: &str, address: &str) -> Option<PathBuf> {
    safe_child_path(vmail_home, address)
}

/// Build a `tiny_http::Response` with a JSON body and `Content-Type`
/// header.
fn json_response(
    status: StatusCode,
    body: &serde_json::Value,
) -> Response<std::io::Cursor<Vec<u8>>> {
    let bytes = serde_json::to_vec(body).unwrap_or_default();
    let len = bytes.len();
    let header = Header::from_bytes("Content-Type", "application/json").unwrap();
    Response::new(
        status,
        vec![header],
        std::io::Cursor::new(bytes),
        Some(len),
        None,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_sender_pair_valid() {
        let (s, r) =
            parse_sender_block_pair("alice@chat.example.com/block-to/bob@chat.example.com")
                .unwrap();
        assert_eq!(s, "alice@chat.example.com");
        assert_eq!(r, "bob@chat.example.com");
    }

    #[test]
    fn parse_sender_pair_missing_recipient() {
        assert!(parse_sender_block_pair("alice@chat.example.com/block-to/").is_none());
    }

    #[test]
    fn parse_sender_pair_no_block_to() {
        assert!(parse_sender_block_pair("alice@chat.example.com/something/bob").is_none());
    }

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
}
