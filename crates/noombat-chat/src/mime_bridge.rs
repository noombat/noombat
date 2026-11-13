// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Autocrypt header extraction and injection for MIME messages.
//!
//! The `noombat-chat` proxy handles all MIME framing server-side
//! using `mailparse` (parsing) and `lettre` (construction). The
//! browser-side crypto module processes only parsed header data
//! and ciphertext, never raw MIME.

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

/// Extract the encrypted body from a raw MIME message, as OpenPGP packets.
///
/// For PGP/MIME messages, the payload is the second part of the
/// `multipart/encrypted` body; otherwise the whole body. Armour, which
/// noombat's server and other clients send, is turned back into packets,
/// which is all the web client reads; anything else is returned as it is.
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

    // The encrypted payload is the second subpart; otherwise the body.
    let part = if content_type.contains("multipart/encrypted") && parsed.subparts.len() >= 2 {
        &parsed.subparts[1]
    } else {
        &parsed
    };
    let body = part
        .get_body_raw()
        .map_err(|e| NoombatError::Internal(format!("body extraction failed: {e}")))?;
    Ok(noombat_openpgp::dearmour(&body, true).unwrap_or(body))
}

/// Extract the sender address from the `From` header.
///
/// `None` unless there is exactly one `From` field and it names exactly
/// one mailbox, so a display name, a list or a group never stands in for
/// the sender. The relay filter reads `From` by the same rule.
pub fn extract_from(raw_message: &[u8]) -> Result<Option<String>> {
    let parsed = mailparse::parse_mail(raw_message)
        .map_err(|e| NoombatError::Internal(format!("MIME parse error: {e}")))?;
    // A space before the colon is not part of the name, as OpenDKIM reads it.
    let [header] = parsed
        .headers
        .iter()
        .filter(|h| h.get_key_ref().trim().eq_ignore_ascii_case("from"))
        .collect::<Vec<_>>()[..]
    else {
        return Ok(None);
    };
    // From the raw header, so an encoded word can only be a display name.
    let Some(mailbox) = mailparse::addrparse_header(header)
        .ok()
        .and_then(|list| list.extract_single_info())
    else {
        return Ok(None);
    };
    let addr = mailbox.addr.trim();
    let well_formed = addr
        .rsplit_once('@')
        .is_some_and(|(local, domain)| !local.is_empty() && !domain.is_empty())
        && !addr.contains(|c: char| c.is_whitespace() || c.is_control());
    Ok(well_formed.then(|| addr.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    // A real OpenPGP message, made with GnuPG 2.4.8 for a throwaway key.
    const PACKETS_B64: &str = concat!(
        "jA0ECQMKI4VJJnHskHr/0kgBbtNTv/pJtCeda2gQ4XL2Fk5nmaMT6qQx+QZDzL8L",
        "1pWIv2IsmD/bOt9aCnHMqm9B7dlr0XdABMIo65FzlAsoHA9kLMHdFIc="
    );

    fn pgp_mime(payload_headers: &str, payload: &str) -> Vec<u8> {
        format!(
            "From: <a@chat.example>\r\n\
             Content-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\"; \
             boundary=b\r\n\
             \r\n--b\r\nContent-Type: application/pgp-encrypted\r\n\r\nVersion: 1\r\n\
             --b\r\nContent-Type: application/octet-stream\r\n\
             {payload_headers}\r\n{payload}\r\n--b--\r\n"
        )
        .into_bytes()
    }

    fn packets() -> Vec<u8> {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD
            .decode(PACKETS_B64)
            .expect("a fixture")
    }

    #[test]
    fn an_armoured_payload_comes_out_as_packets() {
        let raw = pgp_mime("", &noombat_openpgp::armour(&packets()));
        assert_eq!(extract_ciphertext_body(&raw).unwrap(), packets());
    }

    #[test]
    fn armour_with_a_version_header_comes_out_as_packets() {
        // Other implementations still write one, and the relay lets it in.
        let armoured = noombat_openpgp::armour(&packets()).replacen(
            "-----BEGIN PGP MESSAGE-----\r\n",
            "-----BEGIN PGP MESSAGE-----\r\nVersion: GnuPG v2\r\n",
            1,
        );
        let raw = pgp_mime("", &armoured);
        assert_eq!(extract_ciphertext_body(&raw).unwrap(), packets());
    }

    #[test]
    fn a_base64_payload_comes_out_as_it_was_sent() {
        // Messages that arrived before the server armoured what it sends.
        let raw = pgp_mime("Content-Transfer-Encoding: base64\r\n", PACKETS_B64);
        assert_eq!(extract_ciphertext_body(&raw).unwrap(), packets());
    }

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

    fn from_of(value: &str) -> Option<String> {
        extract_from(format!("From: {value}\r\nSubject: t\r\n\r\nx").as_bytes()).unwrap()
    }

    #[test]
    fn a_display_name_is_never_the_sender() {
        let cases = [
            // A `>` in the name once sliced backwards and panicked.
            ("\"Bob :>\" <bob@peer.example>", "bob@peer.example"),
            (
                "\"<victim@dom.example>\" <attacker@atk.example>",
                "attacker@atk.example",
            ),
            (
                "=?utf-8?q?=3Cvictim=40dom=2Eexample=3E?= <attacker@atk.example>",
                "attacker@atk.example",
            ),
            ("\"Bob <3\" <bob@dom.example>", "bob@dom.example"),
            (
                "MAILER-DAEMON@peer.example (Mail Delivery System)",
                "MAILER-DAEMON@peer.example",
            ),
        ];
        for (value, sender) in cases {
            assert_eq!(from_of(value).as_deref(), Some(sender), "{value}");
        }
    }

    #[test]
    fn anything_but_one_mailbox_names_no_sender() {
        for value in [
            "",
            "garbage",
            "<victim@dom.example>, <attacker@atk.example>",
            "friends: victim@dom.example;",
            "<victim@>",
            "<@dom.example>",
            "victim@dom.example x@atk.example",
        ] {
            assert_eq!(from_of(value), None, "{value:?}");
        }
        for twice in [
            "From: <victim@dom.example>\r\nFrom: <attacker@atk.example>",
            "From : <victim@dom.example>\r\nFrom: <attacker@atk.example>",
        ] {
            let raw = format!("{twice}\r\n\r\nx");
            assert_eq!(extract_from(raw.as_bytes()).unwrap(), None, "{twice}");
        }
    }

    #[test]
    fn extract_autocrypt_present() {
        let msg = b"From: alice@example.com\r\n\
                    Autocrypt: addr=alice@example.com; keydata=AAAA\r\n\r\nBody";
        let header = extract_autocrypt_header(msg).unwrap().unwrap();
        assert!(header.header_value.contains("alice@example.com"));
    }

    #[test]
    fn extract_autocrypt_absent() {
        let msg = b"From: alice@example.com\r\nSubject: No autocrypt\r\n\r\nBody";
        assert!(extract_autocrypt_header(msg).unwrap().is_none());
    }
}
