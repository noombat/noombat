// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

#![forbid(unsafe_code)]
//! Whether a message is OpenPGP-encrypted and nothing else, and its
//! ASCII armour.
//!
//! The rule is the Chatmail relay's: session key packets, then one
//! encrypted data packet, with nothing before, between or after them. The
//! relay's filter applies it to the armour it carries, and the server to
//! the packets a member sends before armouring them, so the two cannot
//! disagree.

mod packets;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

const BEGIN: &str = "-----BEGIN PGP MESSAGE-----";
const END: &str = "-----END PGP MESSAGE-----";

/// Whether `packets`, unarmoured, are an encrypted OpenPGP message and
/// nothing else.
pub fn is_encrypted_packets(packets: &[u8]) -> bool {
    packets::is_encrypted(packets)
}

/// Whether `armour` holds an encrypted OpenPGP message and nothing else.
/// See [`dearmour`] for what the armour may carry.
pub fn is_encrypted_armour(armour: &[u8], version_header_allowed: bool) -> bool {
    dearmour(armour, version_header_allowed).is_some_and(|packets| is_encrypted_packets(&packets))
}

/// The packets inside armour, with either line ending; `None` if anything
/// in it is not the armour of one message.
///
/// A `Version:` header is accepted only when `version_header_allowed`, and
/// no other header ever: a header is plain text beside the ciphertext. The
/// checksum is optional, and where present must be the last line before
/// the end and must match the data, so no line of free text can pass as
/// one.
pub fn dearmour(armour: &[u8], version_header_allowed: bool) -> Option<Vec<u8>> {
    let text = std::str::from_utf8(armour).ok()?;
    let mut lines = text.lines().filter(|line| !line.is_empty()).peekable();
    if lines.next()? != BEGIN {
        return None;
    }
    if lines
        .peek()
        .is_some_and(|line| line.starts_with("Version: "))
    {
        if !version_header_allowed {
            return None;
        }
        lines.next();
    }
    let mut body: Vec<&str> = lines.collect();
    if body.pop()? != END {
        return None;
    }
    let checksum = body
        .last()
        .and_then(|line| line.strip_prefix('='))
        .map(str::to_owned);
    if checksum.is_some() {
        body.pop();
    }

    let mut packets = Vec::new();
    for line in body {
        STANDARD.decode_vec(line, &mut packets).ok()?;
    }
    if let Some(checksum) = checksum {
        let crc = crc24(&packets).to_be_bytes();
        if STANDARD.decode(checksum).ok()? != crc[1..] {
            return None;
        }
    }
    Some(packets)
}

/// `packets` in ASCII armour, with CRLF line endings, no header, and a
/// checksum: the form Chatmail relays read.
pub fn armour(packets: &[u8]) -> String {
    let encoded = STANDARD.encode(packets);
    let mut out = format!("{BEGIN}\r\n\r\n");
    let mut at = 0;
    while at < encoded.len() {
        let next = (at + 64).min(encoded.len());
        out.push_str(&encoded[at..next]);
        out.push_str("\r\n");
        at = next;
    }
    let crc = crc24(packets).to_be_bytes();
    out.push('=');
    out.push_str(&STANDARD.encode(&crc[1..]));
    out.push_str(&format!("\r\n{END}\r\n"));
    out
}

/// The armour checksum, RFC 9580 section 6.1.
fn crc24(data: &[u8]) -> u32 {
    let mut crc: u32 = 0x00B7_04CE;
    for &byte in data {
        crc ^= u32::from(byte) << 16;
        for _ in 0..8 {
            crc <<= 1;
            if crc & 0x0100_0000 != 0 {
                crc ^= 0x0186_4CFB;
            }
        }
    }
    crc & 0x00FF_FFFF
}

#[cfg(test)]
mod tests {
    use super::*;

    // Made with GnuPG 2.4.8 for a throwaway key: a public-key session key
    // (legacy header) then the encrypted data, and the same for a
    // passphrase.
    const PUBLIC_KEY_B64: &str = concat!(
        "hF4D5gR+wRuO+a0SAQdAHkKpTbvSw1fNE9zFhmx3xhSmjCnRKdVh6zebBJ1iYxEw",
        "31lS3a5e39Ng0/EhCl4klDieHsPRu7y8valn/aeFR6MqslAMEOOwKdA89j+gwGRE",
        "0k4BhvC57sRxfy3Rv6gOA1+1o1MSqh27Wn9VvTZ/A7y/UP+6zXBediljZse40vQN",
        "ulEjt8D59g1HCA8z0I+5L2WsvuRHPa1RLKTxdw1YeLs="
    );
    const PASSPHRASE_B64: &str = concat!(
        "jA0ECQMKI4VJJnHskHr/0kgBbtNTv/pJtCeda2gQ4XL2Fk5nmaMT6qQx+QZDzL8L",
        "1pWIv2IsmD/bOt9aCnHMqm9B7dlr0XdABMIo65FzlAsoHA9kLMHdFIc="
    );
    const ARMOURED: &str = "-----BEGIN PGP MESSAGE-----

hF4D5gR+wRuO+a0SAQdAkzTkDA6L+XZ47GvWXl0qDJJskcaDQ6iML7xon5M9UVEw
HbLADjGpItcxPP5bZ6DVMiHCE6ThuyA74SLmX2/0jmUn0MuYxbTgq9W/ucx9bhnO
0k4BXD3fX6pXDIXLbd33/VqHjKPDiJG+eclwQjojzTXbMEOYdzHhDWjcH+hBtYRN
z4kgkIr9mFRf1cyPyxaFkcBr7LOiGrzzkNxh5AutO3g=
=rS9G
-----END PGP MESSAGE-----
";

    fn binary(b64: &str) -> Vec<u8> {
        STANDARD.decode(b64).expect("a fixture")
    }

    #[test]
    fn real_encrypted_messages_pass() {
        assert!(is_encrypted_packets(&binary(PUBLIC_KEY_B64)));
        assert!(is_encrypted_packets(&binary(PASSPHRASE_B64)));
        assert!(is_encrypted_armour(ARMOURED.as_bytes(), false));
        let crlf = ARMOURED.replace('\n', "\r\n");
        assert!(is_encrypted_armour(crlf.as_bytes(), false));
        let unchecked = ARMOURED.replace("=rS9G\n", "");
        assert!(
            is_encrypted_armour(unchecked.as_bytes(), false),
            "the checksum is optional"
        );
    }

    #[test]
    fn raw_packets_are_not_armour() {
        assert!(!is_encrypted_armour(&binary(PUBLIC_KEY_B64), true));
    }

    #[test]
    fn a_version_header_passes_only_where_allowed() {
        let versioned = ARMOURED.replace(
            "-----BEGIN PGP MESSAGE-----\n",
            "-----BEGIN PGP MESSAGE-----\nVersion: GnuPG v2\n",
        );
        assert!(is_encrypted_armour(versioned.as_bytes(), true));
        assert!(!is_encrypted_armour(versioned.as_bytes(), false));
    }

    #[test]
    fn plain_text_in_or_beside_armour_fails() {
        assert!(!is_encrypted_armour(b"hello, this is plain text", true));
        let no_begin = ARMOURED.replace("-----BEGIN PGP MESSAGE-----", "meet me at noon");
        assert!(!is_encrypted_armour(no_begin.as_bytes(), true));
        let comment = ARMOURED.replace(
            "-----BEGIN PGP MESSAGE-----\n",
            "-----BEGIN PGP MESSAGE-----\nComment: meet me at noon\n",
        );
        assert!(!is_encrypted_armour(comment.as_bytes(), true));
        let after = format!("{ARMOURED}and a postscript in clear\n");
        assert!(!is_encrypted_armour(after.as_bytes(), true));
        let unterminated = ARMOURED.replace("-----END PGP MESSAGE-----\n", "");
        assert!(!is_encrypted_armour(unterminated.as_bytes(), true));
    }

    #[test]
    fn only_a_true_checksum_before_the_end_passes() {
        let wrong = ARMOURED.replace("=rS9G", "=rS9H");
        assert!(
            !is_encrypted_armour(wrong.as_bytes(), true),
            "a wrong checksum"
        );
        // Five characters that look like a checksum, among the data.
        let smuggled = ARMOURED.replace("\n0k4B", "\n=Meet\n0k4B");
        assert!(
            !is_encrypted_armour(smuggled.as_bytes(), true),
            "a line of text"
        );
        let twice = ARMOURED.replace("=rS9G\n", "=noon\n=rS9G\n");
        assert!(
            !is_encrypted_armour(twice.as_bytes(), true),
            "two checksum lines"
        );
    }

    #[test]
    fn armour_around_anything_but_ciphertext_fails() {
        // The armour lines are right; what they hold is base64 text.
        let fake = "-----BEGIN PGP MESSAGE-----\n\
                    aGVsbG8gd29ybGQgY2lwaGVydGV4dA==\n\
                    -----END PGP MESSAGE-----\n";
        assert!(!is_encrypted_armour(fake.as_bytes(), true));
    }

    #[test]
    fn armouring_round_trips_with_crlf_lines_and_a_checksum() {
        let packets = binary(PUBLIC_KEY_B64);
        let armoured = armour(&packets);
        assert!(armoured.starts_with("-----BEGIN PGP MESSAGE-----\r\n\r\n"));
        assert!(armoured.ends_with("\r\n-----END PGP MESSAGE-----\r\n"));
        assert!(!armoured.replace("\r\n", "").contains('\n'), "a bare LF");
        assert!(armoured.lines().all(|line| line.len() <= 64));
        assert!(
            armoured
                .lines()
                .any(|line| line.len() == 5 && line.starts_with('='))
        );
        assert_eq!(dearmour(armoured.as_bytes(), false), Some(packets));
    }

    #[test]
    fn armour_reads_back_the_way_chatmail_relays_read_it() {
        // Their reading: the BEGIN line ending in CRLF, the END line last,
        // leading blank lines skipped, everything from the last `=` dropped
        // as the checksum, and each remaining line decoded.
        let packets = binary(PASSPHRASE_B64);
        let armoured = armour(&packets);
        let rest = armoured
            .strip_prefix("-----BEGIN PGP MESSAGE-----\r\n")
            .expect("the BEGIN line, with CRLF");
        let rest = rest
            .trim_end_matches("\r\n")
            .strip_suffix("-----END PGP MESSAGE-----")
            .expect("the END line last");
        assert!(!rest.starts_with("Version: "));
        let rest = rest.trim_start_matches("\r\n");
        let (data, _) = rest.rsplit_once('=').expect("a checksum");
        let mut decoded = Vec::new();
        for line in data.split(['\r', '\n']) {
            STANDARD
                .decode_vec(line, &mut decoded)
                .expect("a base64 line");
        }
        assert_eq!(decoded, packets);
    }
}
