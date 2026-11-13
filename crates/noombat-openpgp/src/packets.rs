// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

//! Whether bytes are an encrypted OpenPGP message and nothing else: zero
//! or more session key packets, then one encrypted data packet that ends
//! the input (RFC 9580 section 10.3). Only the packet framing is read,
//! never a packet body.
//!
//! On purpose, to agree with Chatmail relays: tag 18 is the only encrypted
//! data, marker and padding packets and indeterminate legacy lengths are
//! refused, and partial body lengths are taken on any packet, with chunks
//! of any size.

/// Public-key encrypted session key, RFC 9580 section 5.1.
const PKESK: u8 = 1;
/// Symmetric-key encrypted session key, section 5.3.
const SKESK: u8 = 3;
/// Symmetrically encrypted and integrity protected data, section 5.13.
const SEIPD: u8 = 18;

/// Whether `message` is an Encrypted Message in the sense of section 10.3,
/// narrowed as the module documentation says.
pub(crate) fn is_encrypted(message: &[u8]) -> bool {
    let mut rest = message;
    loop {
        let Some((tag, after)) = next_packet(rest) else {
            return false;
        };
        match tag {
            PKESK | SKESK => rest = after,
            SEIPD => return after.is_empty(),
            _ => return false,
        }
    }
}

/// The tag of the packet at the start of `input`, and the input after that
/// packet; `None` if its header is malformed or it runs past the end.
/// Section 4.2: bit 7 of the first octet is always set, and bit 6 is set in
/// the OpenPGP format and clear in the legacy one.
fn next_packet(input: &[u8]) -> Option<(u8, &[u8])> {
    let (&first, rest) = input.split_first()?;
    if first & 0x80 == 0 {
        return None;
    }
    if first & 0x40 != 0 {
        return Some((first & 0x3F, skip_body(rest)?));
    }
    // Legacy format: the tag in bits 5 to 2 (section 4.2), the length type
    // in bits 1 and 0 (section 4.2.2). Type 3, indeterminate, is refused.
    let octets = match first & 0x03 {
        0 => 1,
        1 => 2,
        2 => 4,
        _ => return None,
    };
    let (len, rest) = read_be(rest, octets)?;
    Some(((first >> 2) & 0x0F, skip(rest, len)?))
}

/// `input` after an OpenPGP-format body and its length octets (section
/// 4.2.1), or `None` if either runs past the end.
fn skip_body(mut input: &[u8]) -> Option<&[u8]> {
    loop {
        let (&first, rest) = input.split_first()?;
        let (len, rest) = match first {
            0..=191 => (u32::from(first), rest),
            192..=223 => {
                let (&second, rest) = rest.split_first()?;
                let len = ((u32::from(first) - 192) << 8) + u32::from(second) + 192;
                (len, rest)
            }
            // A partial body length, section 4.2.1.4: skip the chunk, then
            // read the next length.
            224..=254 => {
                input = skip(rest, 1 << (first & 0x1F))?;
                continue;
            }
            255 => read_be(rest, 4)?,
        };
        return skip(rest, len);
    }
}

/// The big-endian number in the first `octets` octets of `input`, at most
/// four, and the input after them.
fn read_be(input: &[u8], octets: usize) -> Option<(u32, &[u8])> {
    let (number, rest) = input.split_at_checked(octets)?;
    let value = number
        .iter()
        .fold(0, |value, &octet| (value << 8) | u32::from(octet));
    Some((value, rest))
}

/// `input` after its first `len` octets, or `None` if it is shorter.
fn skip(input: &[u8], len: u32) -> Option<&[u8]> {
    input.get(usize::try_from(len).ok()?..)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A header octet, its length octets, then `body` octets of filler.
    fn packet(header: u8, length: &[u8], body: usize) -> Vec<u8> {
        let mut out = vec![header];
        out.extend_from_slice(length);
        out.resize(out.len() + body, 0xA5);
        out
    }

    /// An OpenPGP-format packet with a one-octet length.
    fn short(tag: u8, body: u8) -> Vec<u8> {
        packet(0xC0 | tag, &[body], body.into())
    }

    fn data() -> Vec<u8> {
        short(SEIPD, 40)
    }

    /// Whether a session key packet framed by `header` and `length`, then
    /// the encrypted data, passes with `body` octets in the session key
    /// and fails with one fewer or one more.
    fn frames_exactly(header: u8, length: &[u8], body: usize) -> bool {
        let message = |body| [packet(header, length, body), data()].concat();
        is_encrypted(&message(body))
            && !is_encrypted(&message(body - 1))
            && !is_encrypted(&message(body + 1))
    }

    #[test]
    fn an_esk_sequence_then_encrypted_data_passes() {
        let pkesk = short(PKESK, 12);
        let skesk = short(SKESK, 13);
        assert!(is_encrypted(&[pkesk.clone(), data()].concat()));
        assert!(is_encrypted(&[skesk.clone(), data()].concat()));
        assert!(is_encrypted(
            &[pkesk.clone(), skesk, pkesk, data()].concat()
        ));
    }

    #[test]
    fn a_lone_encrypted_data_packet_passes() {
        assert!(is_encrypted(&data()));
        assert!(is_encrypted(&[0xD2, 0x00]));
    }

    #[test]
    fn empty_input_fails() {
        assert!(!is_encrypted(&[]));
    }

    #[test]
    fn session_keys_alone_fail() {
        assert!(!is_encrypted(&short(PKESK, 12)));
        assert!(!is_encrypted(&short(SKESK, 13)));
        assert!(!is_encrypted(
            &[short(PKESK, 12), short(SKESK, 13)].concat()
        ));
    }

    #[test]
    fn anything_after_the_encrypted_data_fails() {
        let message = [short(PKESK, 12), data()].concat();
        assert!(!is_encrypted(&[message.clone(), vec![0x00]].concat()));
        assert!(!is_encrypted(&[message.clone(), data()].concat()));
        assert!(!is_encrypted(&[message, short(PKESK, 12)].concat()));
    }

    #[test]
    fn every_other_tag_fails_anywhere() {
        // Reserved 0, 19 and 20, signature, compressed, SED, marker, literal
        // and padding, then tags whose low five bits read 1 or 18, and 63.
        for tag in [0, 2, 8, 9, 10, 11, 19, 20, 21, 33, 50, 63] {
            let other = short(tag, 5);
            assert!(!is_encrypted(&other), "tag {tag} alone");
            assert!(
                !is_encrypted(&[other.clone(), data()].concat()),
                "tag {tag} first"
            );
            assert!(
                !is_encrypted(&[short(PKESK, 12), other].concat()),
                "tag {tag} last"
            );
        }
        // Legacy tags 9 and 11 differ from 1 and 3 only in the top tag bit.
        assert!(!is_encrypted(&[packet(0xA4, &[5], 5), data()].concat()));
        assert!(!is_encrypted(&[packet(0xAC, &[5], 5), data()].concat()));
    }

    #[test]
    fn a_header_with_bit_7_clear_fails() {
        assert!(!is_encrypted(&[0x40 | SEIPD, 0x00]));
        let session_key = packet(0x40 | PKESK, &[12], 12);
        assert!(!is_encrypted(&[session_key, data()].concat()));
    }

    #[test]
    fn of_all_inputs_up_to_two_octets_only_an_empty_tag_18_passes() {
        for first in 0..=u8::MAX {
            assert!(!is_encrypted(&[first]), "{first:#04x}");
            for second in 0..=u8::MAX {
                let input = [first, second];
                assert_eq!(
                    is_encrypted(&input),
                    input == [0xD2, 0x00],
                    "{first:#04x} {second:#04x}"
                );
            }
        }
    }

    #[test]
    fn openpgp_format_lengths_are_read() {
        assert!(frames_exactly(0xC1, &[1], 1));
        assert!(frames_exactly(0xC1, &[191], 191));
        assert!(frames_exactly(0xC1, &[0xC0, 0x00], 192));
        assert!(frames_exactly(0xC1, &[0xC5, 0xFB], 1723));
        assert!(frames_exactly(0xC1, &[0xDF, 0xFF], 8383));
        assert!(frames_exactly(0xC1, &[0xFF, 0x00, 0x00, 0x00, 0x05], 5));
        assert!(frames_exactly(
            0xC1,
            &[0xFF, 0x00, 0x01, 0x86, 0xA0],
            100_000
        ));
        assert!(frames_exactly(0xC3, &[0xC0, 0x00], 192));
        assert!(is_encrypted(&packet(0xD2, &[0xC0, 0x00], 192)));
        assert!(is_encrypted(&packet(
            0xD2,
            &[0xFF, 0x00, 0x00, 0x00, 0x00],
            0
        )));
    }

    #[test]
    fn legacy_lengths_are_read() {
        assert!(frames_exactly(0x84, &[12], 12));
        assert!(frames_exactly(0x8C, &[13], 13));
        assert!(frames_exactly(0x85, &[0x01, 0x2C], 300));
        assert!(frames_exactly(0x86, &[0x00, 0x01, 0x00, 0x2C], 65_580));
    }

    #[test]
    fn a_legacy_indeterminate_length_fails() {
        // Length type 3 in place of each type that would frame the octets.
        for length in [&[][..], &[12], &[0x00, 12], &[0x00, 0x00, 0x00, 12]] {
            let body = if length.is_empty() { 0 } else { 12 };
            let session_key = packet(0x87, length, body);
            assert!(!is_encrypted(&[session_key, data()].concat()));
        }
    }

    #[test]
    fn partial_lengths_chain_to_a_final_length() {
        // The example in section 4.2.3: 100000 octets in five chunks.
        let mut chunked = vec![0xD2];
        for (length, chunk) in [
            (&[0xEF][..], 32_768),
            (&[0xE1], 2),
            (&[0xE0], 1),
            (&[0xF0], 65_536),
            (&[0xC5, 0xDD], 1693),
        ] {
            chunked.extend_from_slice(length);
            chunked.resize(chunked.len() + chunk, 0xA5);
        }
        assert!(is_encrypted(&chunked));
        assert!(!is_encrypted(&chunked[..chunked.len() - 1]));
        // On a session key, a one-octet chunk then a zero final length.
        let session_key = vec![0xC1, 0xE0, 0xA5, 0x00];
        assert!(is_encrypted(&[session_key, data()].concat()));
        // A four-octet chunk, then a five-octet final length.
        let five = [0xD2, 0xE2, 1, 2, 3, 4, 0xFF, 0, 0, 0, 2, 5, 6];
        assert!(is_encrypted(&five));
    }

    #[test]
    fn a_partial_chunk_longer_than_the_input_fails() {
        assert!(!is_encrypted(&[0xD2, 0xE3, 1, 2, 3, 4]));
        assert!(!is_encrypted(&packet(0xD2, &[0xFE], 1 << 16)));
        // 254 is the largest partial length, not a five-octet one.
        assert!(!is_encrypted(&[0xD2, 0xFE, 0x00, 0x00, 0x00, 0x00]));
        // The chunk is whole, but no final length follows it.
        assert!(!is_encrypted(&[0xD2, 0xE2, 1, 2, 3, 4]));
    }

    #[test]
    fn truncated_headers_and_lengths_fail() {
        for truncated in [
            &[0xD2][..],
            &[0xD2, 0xC5],
            &[0xD2, 0xFF, 0x00, 0x00, 0x00],
            &[0x84],
            &[0x85, 0x00],
            &[0x86, 0x00, 0x00, 0x00],
        ] {
            assert!(!is_encrypted(truncated), "{truncated:02x?}");
        }
        let messages = [
            [packet(0x85, &[0x01, 0x2C], 300), data()].concat(),
            [short(SKESK, 13), packet(0xD2, &[0xC5, 0xFB], 1723)].concat(),
            packet(0xD2, &[0xE1, 1, 2, 0xFF, 0x00, 0x00, 0x01, 0x00], 256),
        ];
        for message in messages {
            assert!(is_encrypted(&message));
            for end in 0..message.len() {
                assert!(!is_encrypted(&message[..end]), "cut at {end}");
            }
        }
    }

    #[test]
    fn huge_lengths_fail_without_overflow() {
        let max = [0xFF; 4];
        assert!(!is_encrypted(&[&[0xD2, 0xFF][..], &max, &[0; 64]].concat()));
        assert!(!is_encrypted(&[&[0xC1, 0xFF][..], &max, &data()].concat()));
        assert!(!is_encrypted(&[&[0x86][..], &max, &data()].concat()));
        assert!(!is_encrypted(&[0xD2, 0xFE, 0xFE, 0xFE]));
    }
}
