// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Autocrypt header extraction and injection for MIME messages.
//!
//! The `noombat-chat` proxy handles all MIME framing server-side
//! using `mailparse` (parsing) and `lettre` (construction). The
//! browser-side WASM module processes only parsed header data and
//! ciphertext, never raw MIME.

use noombat_core::error::{NoombatError, Result};

/// An extracted Autocrypt header from an incoming IMAP message.
#[derive(Debug, Clone)]
pub struct ExtractedAutocryptHeader {
    /// The raw `Autocrypt` header value (e.g.
    /// `addr=alice@example.com; prefer-encrypt=mutual; keydata=...`).
    pub header_value: String,
}

/// Extract the `Autocrypt` header from a raw MIME message.
///
/// Returns `None` if no `Autocrypt` header is present.
pub fn extract_autocrypt_header(raw_message: &[u8]) -> Result<Option<ExtractedAutocryptHeader>> {
    let parsed = mailparse::parse_mail(raw_message)
        .map_err(|e| NoombatError::Internal(format!("MIME parse error: {e}")))?;

    for header in &parsed.headers {
        if header.get_key().eq_ignore_ascii_case("autocrypt") {
            return Ok(Some(ExtractedAutocryptHeader {
                header_value: header.get_value(),
            }));
        }
    }

    Ok(None)
}

/// Extract the encrypted body from a raw MIME message.
///
/// For PGP/MIME messages, returns the raw encrypted payload (the
/// second part of the `multipart/encrypted` body). For inline PGP,
/// returns the body text.
pub fn extract_ciphertext_body(raw_message: &[u8]) -> Result<Vec<u8>> {
    let parsed = mailparse::parse_mail(raw_message)
        .map_err(|e| NoombatError::Internal(format!("MIME parse error: {e}")))?;

    // Check for PGP/MIME (multipart/encrypted).
    let content_type = parsed
        .headers
        .iter()
        .find(|h| h.get_key().eq_ignore_ascii_case("content-type"))
        .map(|h| h.get_value())
        .unwrap_or_default();

    if content_type.contains("multipart/encrypted") {
        // The encrypted payload is the second subpart.
        if parsed.subparts.len() >= 2 {
            return parsed.subparts[1]
                .get_body_raw()
                .map_err(|e| NoombatError::Internal(format!("body extraction failed: {e}")));
        }
    }

    // Fallback: return the raw body (inline PGP or plaintext).
    parsed
        .get_body_raw()
        .map_err(|e| NoombatError::Internal(format!("body extraction failed: {e}")))
}

/// Extract the sender address from the `From` header.
pub fn extract_from(raw_message: &[u8]) -> Result<Option<String>> {
    let parsed = mailparse::parse_mail(raw_message)
        .map_err(|e| NoombatError::Internal(format!("MIME parse error: {e}")))?;

    for header in &parsed.headers {
        if header.get_key().eq_ignore_ascii_case("from") {
            let value = header.get_value();
            // Extract the email address from the header value.
            // Handles both `Alice <alice@example.com>` and bare
            // `alice@example.com` forms.
            if let Some(start) = value.find('<')
                && let Some(end) = value.find('>')
            {
                return Ok(Some(value[start + 1..end].to_owned()));
            }
            // Bare address.
            return Ok(Some(value.trim().to_owned()));
        }
    }

    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_from_angle_brackets() {
        let msg = b"From: Alice <alice@example.com>\r\nSubject: Test\r\n\r\nHello";
        let from = extract_from(msg).unwrap().unwrap();
        assert_eq!(from, "alice@example.com");
    }

    #[test]
    fn extract_from_bare() {
        let msg = b"From: alice@example.com\r\nSubject: Test\r\n\r\nHello";
        let from = extract_from(msg).unwrap().unwrap();
        assert_eq!(from, "alice@example.com");
    }

    #[test]
    fn extract_autocrypt_present() {
        let msg = b"From: alice@example.com\r\nAutocrypt: addr=alice@example.com; keydata=AAAA\r\n\r\nBody";
        let header = extract_autocrypt_header(msg).unwrap().unwrap();
        assert!(header.header_value.contains("alice@example.com"));
    }

    #[test]
    fn extract_autocrypt_absent() {
        let msg = b"From: alice@example.com\r\nSubject: No autocrypt\r\n\r\nBody";
        assert!(extract_autocrypt_header(msg).unwrap().is_none());
    }
}
