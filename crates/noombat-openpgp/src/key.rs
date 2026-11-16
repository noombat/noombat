// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

//! Whether bytes are one OpenPGP public key for a chat address, read from
//! the packet framing and the key packets' fields (RFC 9580 sections 4,
//! 5.5 and 10.1). Signatures are not verified here: the client verifies
//! them before it encrypts to the key.

use std::fmt;

use crate::packets::read_be;

/// The most bytes a published key may take.
pub const MAX_PUBLIC_KEY_LEN: usize = 8192;

/// The longest User ID OpenPGP.js reads, in UTF-16 code units
/// (`maxUserIDLength`); it refuses the whole key over a longer one. Counted
/// here in octets, which UTF-8 text never has fewer of.
const MAX_USER_ID_LEN: usize = 5120;

const SIGNATURE: u8 = 2;
const SECRET_KEY: u8 = 5;
const PUBLIC_KEY: u8 = 6;
const SECRET_SUBKEY: u8 = 7;
const USER_ID: u8 = 13;
const PUBLIC_SUBKEY: u8 = 14;

/// Why a key was refused, worded for the member who sent it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyRefusal {
    TooLarge,
    Malformed,
    NotAPublicKey,
    SecretKey,
    UnsupportedVersion,
    UnknownAlgorithm(u8),
    PrimaryCannotSign(u8),
    UnexpectedPacket(u8),
    NoUserId,
    UserIdTooLong,
    OtherAddress,
    NoEncryptionSubkey,
}

impl fmt::Display for KeyRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge => write!(f, "the key is larger than {MAX_PUBLIC_KEY_LEN} bytes"),
            Self::Malformed => f.write_str("the key is not well-formed OpenPGP"),
            Self::NotAPublicKey => f.write_str("the key does not start with a public key"),
            Self::SecretKey => f.write_str("the key holds secret key material"),
            Self::UnsupportedVersion => f.write_str("only version 4 keys are accepted"),
            Self::UnknownAlgorithm(algorithm) => {
                write!(
                    f,
                    "the key uses public-key algorithm {algorithm}, which is not known"
                )
            }
            Self::PrimaryCannotSign(algorithm) => write!(
                f,
                "the primary key uses public-key algorithm {algorithm}, which cannot sign"
            ),
            Self::UnexpectedPacket(tag) => write!(
                f,
                "the key holds a packet of type {tag}, where only user IDs, signatures and \
                 subkeys may follow the key"
            ),
            Self::NoUserId => f.write_str("the key has no user ID"),
            Self::UserIdTooLong => write!(
                f,
                "a user ID on the key is longer than {MAX_USER_ID_LEN} bytes"
            ),
            Self::OtherAddress => f.write_str("a user ID on the key names another address"),
            Self::NoEncryptionSubkey => f.write_str("the key has no encryption subkey"),
        }
    }
}

impl std::error::Error for KeyRefusal {}

/// Whether `key` is one version 4 public key whose primary can sign, with
/// an encryption subkey, no secret key material, and at least one User ID,
/// every one of which names `address`, all in at most
/// [`MAX_PUBLIC_KEY_LEN`] bytes of packets with definite lengths.
///
/// Only User IDs, signatures and subkeys may follow the key. The Marker
/// and Padding packets RFC 9580 lets a key carry, and User Attribute
/// packets, are refused on purpose: no client this serves writes them.
pub fn check_public_key(key: &[u8], address: &str) -> Result<(), KeyRefusal> {
    if key.len() > MAX_PUBLIC_KEY_LEN {
        return Err(KeyRefusal::TooLarge);
    }
    let (tag, body, mut rest) = next_packet(key).ok_or(if key.is_empty() {
        KeyRefusal::NotAPublicKey
    } else {
        KeyRefusal::Malformed
    })?;
    match tag {
        PUBLIC_KEY => {
            let algorithm = version_4_key(body)?;
            if !can_sign(algorithm) {
                return Err(KeyRefusal::PrimaryCannotSign(algorithm));
            }
        }
        SECRET_KEY => return Err(KeyRefusal::SecretKey),
        _ => return Err(KeyRefusal::NotAPublicKey),
    }

    let mut user_ids = 0;
    let mut encryption_subkey = false;
    while !rest.is_empty() {
        let (tag, body, after) = next_packet(rest).ok_or(KeyRefusal::Malformed)?;
        rest = after;
        match tag {
            SIGNATURE => {}
            USER_ID => {
                if body.len() > MAX_USER_ID_LEN {
                    return Err(KeyRefusal::UserIdTooLong);
                }
                if !names(body, address) {
                    return Err(KeyRefusal::OtherAddress);
                }
                user_ids += 1;
            }
            PUBLIC_SUBKEY => encryption_subkey |= can_encrypt(version_4_key(body)?),
            SECRET_KEY | SECRET_SUBKEY => return Err(KeyRefusal::SecretKey),
            other => return Err(KeyRefusal::UnexpectedPacket(other)),
        }
    }
    if user_ids == 0 {
        return Err(KeyRefusal::NoUserId);
    }
    if !encryption_subkey {
        return Err(KeyRefusal::NoEncryptionSubkey);
    }
    Ok(())
}

/// The public-key algorithm of a key or subkey packet's body, which must
/// be version 4: the version, a four-octet creation time, the algorithm,
/// then exactly that algorithm's public fields (section 5.5.2). A secret
/// key packet relabelled as public carries its secret fields after those,
/// so nothing may follow them.
fn version_4_key(body: &[u8]) -> Result<u8, KeyRefusal> {
    let (algorithm, fields) = match body {
        [4, _, _, _, _, algorithm, fields @ ..] => (*algorithm, fields),
        [4, ..] | [] => return Err(KeyRefusal::Malformed),
        _ => return Err(KeyRefusal::UnsupportedVersion),
    };
    if public_fields_len(algorithm, fields)? != fields.len() {
        return Err(KeyRefusal::Malformed);
    }
    Ok(algorithm)
}

/// One of the shapes a key's public fields take (section 5.5.5).
#[derive(Clone, Copy)]
enum Field {
    /// A multiprecision integer: a two-octet bit count, then that many
    /// bits in whole octets (section 3.2).
    Mpi,
    /// A one-octet size, then that many octets: a curve OID or ECDH's KDF
    /// parameters. Sizes 0 and 255 are reserved.
    Sized,
    Fixed(usize),
}

/// The length of `algorithm`'s public fields at the start of `fields`.
fn public_fields_len(algorithm: u8, fields: &[u8]) -> Result<usize, KeyRefusal> {
    use Field::{Fixed, Mpi, Sized};
    let shape: &[Field] = match algorithm {
        // RSA: n and e.
        1..=3 => &[Mpi, Mpi],
        // Elgamal: p, g and y.
        16 => &[Mpi, Mpi, Mpi],
        // DSA: p, q, g and y.
        17 => &[Mpi, Mpi, Mpi, Mpi],
        // ECDH: the curve, the point, the KDF parameters.
        18 => &[Sized, Mpi, Sized],
        // ECDSA and EdDSALegacy: the curve, the point.
        19 | 22 => &[Sized, Mpi],
        // X25519, Ed25519, X448, Ed448: the public key alone.
        25 | 27 => &[Fixed(32)],
        26 => &[Fixed(56)],
        28 => &[Fixed(57)],
        other => return Err(KeyRefusal::UnknownAlgorithm(other)),
    };
    let mut rest = fields;
    for field in shape {
        let len = match *field {
            Mpi => {
                let (bits, _) = read_be(rest, 2).ok_or(KeyRefusal::Malformed)?;
                2 + (bits as usize).div_ceil(8)
            }
            Sized => match rest.first() {
                Some(&size @ 1..=254) => 1 + usize::from(size),
                _ => return Err(KeyRefusal::Malformed),
            },
            Fixed(len) => len,
        };
        rest = rest.get(len..).ok_or(KeyRefusal::Malformed)?;
    }
    Ok(fields.len() - rest.len())
}

/// Whether a public-key algorithm can sign (section 9.1): RSA, RSA
/// sign-only, DSA, ECDSA, EdDSALegacy, Ed25519 and Ed448. A primary key
/// must (section 10.1.5), since it certifies the rest of the key.
fn can_sign(algorithm: u8) -> bool {
    matches!(algorithm, 1 | 3 | 17 | 19 | 22 | 27 | 28)
}

/// Whether a public-key algorithm can encrypt (section 9.1): RSA, RSA
/// encrypt-only, Elgamal, ECDH, X25519 and X448. Whether a given subkey
/// may is in its binding signature, which the reading client checks.
fn can_encrypt(algorithm: u8) -> bool {
    matches!(algorithm, 1 | 2 | 16 | 18 | 25 | 26)
}

/// Whether a User ID names `address`, read as OpenPGP.js reads it: the text
/// from the first `<` to the last `>` after it, or else the whole text,
/// trimmed. Case is ignored. Stricter where the two could differ: the text
/// must be UTF-8 and only ASCII whitespace is trimmed, so a User ID this
/// accepts, at most [`MAX_USER_ID_LEN`] octets long, reads as `address`
/// there too.
fn names(user_id: &[u8], address: &str) -> bool {
    let Ok(text) = std::str::from_utf8(user_id) else {
        return false;
    };
    let named = match (text.find('<'), text.rfind('>')) {
        (Some(open), Some(close)) if open < close => &text[open + 1..close],
        _ => text.trim_ascii(),
    };
    named.eq_ignore_ascii_case(address)
}

/// The tag and body of the packet at the start of `input`, and the input
/// after it; `None` if its header is malformed, its length is partial or
/// indeterminate, or it runs past the end. Partial lengths are for data
/// packets only (section 4.2.1.4), so no key packet has one.
fn next_packet(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&first, rest) = input.split_first()?;
    if first & 0x80 == 0 {
        return None;
    }
    let (tag, len, rest) = if first & 0x40 != 0 {
        let (&octet, rest) = rest.split_first()?;
        let (len, rest) = match octet {
            0..=191 => (u32::from(octet), rest),
            192..=223 => {
                let (&second, rest) = rest.split_first()?;
                (
                    ((u32::from(octet) - 192) << 8) + u32::from(second) + 192,
                    rest,
                )
            }
            255 => read_be(rest, 4)?,
            224..=254 => return None,
        };
        (first & 0x3F, len, rest)
    } else {
        let octets = match first & 0x03 {
            0 => 1,
            1 => 2,
            2 => 4,
            _ => return None,
        };
        let (len, rest) = read_be(rest, octets)?;
        ((first >> 2) & 0x0F, len, rest)
    };
    let (body, rest) = rest.split_at_checked(usize::try_from(len).ok()?)?;
    Some((tag, body, rest))
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;

    use super::*;

    // Made by OpenPGP.js 6.3.2 as the web client makes a member's key, for
    // alice@chat.example: the public key, its private key, and a version 6
    // key for the same address.
    const ALICE: &str = concat!(
        "xjMEavjqZRYJKwYBBAHaRw8BAQdA5oE4yt77I6MVK+RSrLJTjbDwCc0heULrWKTG",
        "gYqvnu/NFDxhbGljZUBjaGF0LmV4YW1wbGU+wsATBBMWCgCFBYJq+OplAwsJBwkQ",
        "Hs6MfA5KHgJFFAAAAAAAHAAgc2FsdEBub3RhdGlvbnMub3BlbnBncGpzLm9yZzhZ",
        "DHPj92aNYwU8YkNKoAuK8B7uU/SlKvERSN7TbCZOBRUKCA4MBBYAAgECGQECmwMC",
        "HgEWIQR0ClYHSYhXuYAtv7Qezox8DkoeAgAA0xABAM/TfnHcoKW1vn0o0Uwp2QhQ",
        "ImZgB882mpwFD8FsYSt6AP9cs6q1aht0e0gqYymTxCOJYvBgdApitQsLx+8IlRUa",
        "As44BGr46mUSCisGAQQBl1UBBQEBB0DFVAx1f0dUbMnoIPGry9rRrJrvOitbME84",
        "ZwOVUNHoVQMBCAfCvgQYFgoAcAWCavjqZQkQHs6MfA5KHgJFFAAAAAAAHAAgc2Fs",
        "dEBub3RhdGlvbnMub3BlbnBncGpzLm9yZ3dlNTLKmpSQAXqaYEpLbHRl0jycju2I",
        "uPZWPNP6z9xpApsMFiEEdApWB0mIV7mALb+0Hs6MfA5KHgIAAAdvAQCcTv2++NY+",
        "1/9AJnvLM4A7X5pw3U+gz21yp6CThRZDvwD/WUQnMNB3WzAHO0nnULMbscQkeHbV",
        "viT8+YGoqGr42A4=",
    );
    const ALICE_SECRET: &str = concat!(
        "xVgEavjqZRYJKwYBBAHaRw8BAQdA5oE4yt77I6MVK+RSrLJTjbDwCc0heULrWKTG",
        "gYqvnu8AAQD3/bZe593WdCi52t8bViWLpqfyplfh1n28WQNOOhS8ChG8zRQ8YWxp",
        "Y2VAY2hhdC5leGFtcGxlPsLAEwQTFgoAhQWCavjqZQMLCQcJEB7OjHwOSh4CRRQA",
        "AAAAABwAIHNhbHRAbm90YXRpb25zLm9wZW5wZ3Bqcy5vcmc4WQxz4/dmjWMFPGJD",
        "SqALivAe7lP0pSrxEUje02wmTgUVCggODAQWAAIBAhkBApsDAh4BFiEEdApWB0mI",
        "V7mALb+0Hs6MfA5KHgIAANMQAQDP035x3KCltb59KNFMKdkIUCJmYAfPNpqcBQ/B",
        "bGEregD/XLOqtWobdHtIKmMpk8QjiWLwYHQKYrULC8fvCJUVGgLHXQRq+OplEgor",
        "BgEEAZdVAQUBAQdAxVQMdX9HVGzJ6CDxq8va0aya7zorWzBPOGcDlVDR6FUDAQgH",
        "AAD/eJ/C3o9DdMdhenwlCkNjTcfnqr6Eq0ThDiqhrkRxTogQuMK+BBgWCgBwBYJq",
        "+OplCRAezox8DkoeAkUUAAAAAAAcACBzYWx0QG5vdGF0aW9ucy5vcGVucGdwanMu",
        "b3Jnd2U1MsqalJABeppgSktsdGXSPJyO7Yi49lY80/rP3GkCmwwWIQR0ClYHSYhX",
        "uYAtv7Qezox8DkoeAgAAB28BAJxO/b741j7X/0Ame8szgDtfmnDdT6DPbXKnoJOF",
        "FkO/AP9ZRCcw0HdbMAc7SedQsxuxxCR4dtW+JPz5gaioavjYDg==",
    );
    const ALICE_V6: &str = concat!(
        "xioGavjqZRsAAAAgYYphmq7M/oqdo+w6sxLFraXfiyRdegYzl8w8Lzp3VsTCrQYf",
        "GwoAAAA+BYJq+OplAwsJBwUVCggODAQWAAIBApsDAh4BIqEGktbxZnDvGOYonm5T",
        "aWmPOcSgHFkibgLB+yJoP6dAWicAAAAAZPkgEi2P4BzqB7N97ShfHR7/eV74GafY",
        "pW0s3REcXcHZaf8TZhUayn3PjjxafcQbeoGUsCoUEAcboOMMCDo9UG71BmBZHgts",
        "8LXBB3yyXVe0AM9BcqothgHO8Tcv6sHQ04wDzRQ8YWxpY2VAY2hhdC5leGFtcGxl",
        "PsKbBhMbCgAAACwFgmr46mUCGQEioQaS1vFmcO8Y5iieblNpaY85xKAcWSJuAsH7",
        "Img/p0BaJwAAAAAbbyAf4PITwaMdVk8pUa1LPd0ZjFo16YANwE0+teXc7xjuPdbL",
        "aDI6QvHwH4DcKW6MsLOFc9pHVkgRJTzeSfsq7Pt2UGS9krVpPvYbLtqyn6B6EXmy",
        "5vCSZ0nOA1nNRyjiZw7OKgZq+OplGQAAACBw5fvw0RvvkWQUbG16R4j5hF9PMlYv",
        "+hcFN7LeLk+GRsKbBhgbCgAAACwFgmr46mUCmwwioQaS1vFmcO8Y5iieblNpaY85",
        "xKAcWSJuAsH7Img/p0BaJwAAAADkfyCDXFqAgRcDTr4x7WDOG5C4dScwMZLU1CPk",
        "w3mnv4ab3A4Q0eJEuPI7AQ/A+TFyoccI+bsPXpTZJAt4USUpopulqjacK9cffcVn",
        "fVadiySgs0IykOFDYlNqbwr12e2NUgU=",
    );
    // Made by GnuPG for bob@chat.test.local, with a bare User ID: the chat
    // interop suite's fixture key, exported.
    const BOB_GNUPG: &str = concat!(
        "mDMEavgcFBYJKwYBBAHaRw8BAQdAP1faY9/mjfPU5h3nZRMrL9FNsWDm4aUxn0C3",
        "J0uLq+O0E2JvYkBjaGF0LnRlc3QubG9jYWyIkAQTFgoAOBYhBCAD/7i4U8yCK/7h",
        "MFGagd2SrDY6BQJq+BwUAhsDBQsJCAcCBhUKCQgLAgQWAgMBAh4BAheAAAoJEFGa",
        "gd2SrDY6y8IBAO2JVkR5uOHOBEtuv+Hp5Lc5cHB19yfXDCAS+dgXznFSAP95Vodk",
        "qJKyoC0GOJ5NnCgGOlpQbHDOMXC6FIFBn2VUDrg4BGr4HBQSCisGAQQBl1UBBQEB",
        "B0BeIVOogOoRrbSMivm7RcJ4tTlYLqyHAQl/mAUcqQABawMBCAeIeAQYFgoAIBYh",
        "BCAD/7i4U8yCK/7hMFGagd2SrDY6BQJq+BwUAhsMAAoJEFGagd2SrDY6q/sBAIZ3",
        "VmtA3z8eE5P5WZPgFYYSnuqm6Q9wLM9nwxVRf4O8AP9aoP+Yf787hbVQw6w/YYgN",
        "dSm2K44MZLVFy4U/dDh9DA==",
    );

    const ADDRESS: &str = "alice@chat.example";

    fn key(b64: &str) -> Vec<u8> {
        STANDARD.decode(b64).expect("a fixture")
    }

    fn check(key: &[u8]) -> Result<(), KeyRefusal> {
        check_public_key(key, ADDRESS)
    }

    /// The tag and body of each packet in `key`.
    fn parts(key: &[u8]) -> Vec<(u8, Vec<u8>)> {
        let mut out = Vec::new();
        let mut rest = key;
        while !rest.is_empty() {
            let (tag, body, after) = next_packet(rest).expect("a whole packet");
            out.push((tag, body.to_vec()));
            rest = after;
        }
        out
    }

    /// Alice's key as parts: the key, her User ID, its certification, the
    /// subkey and its binding signature.
    fn alice() -> Vec<(u8, Vec<u8>)> {
        parts(&key(ALICE))
    }

    /// A packet with an OpenPGP-format header and the shortest length.
    fn packet(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut out = vec![0xC0 | tag];
        match body.len() {
            len @ 0..=191 => out.push(len as u8),
            len @ 192..=8383 => {
                out.push(((len - 192) >> 8) as u8 + 192);
                out.push((len - 192) as u8);
            }
            len => {
                out.push(0xFF);
                out.extend_from_slice(&(len as u32).to_be_bytes());
            }
        }
        out.extend_from_slice(body);
        out
    }

    fn join(parts: &[(u8, Vec<u8>)]) -> Vec<u8> {
        parts
            .iter()
            .flat_map(|(tag, body)| packet(*tag, body))
            .collect()
    }

    /// Every public-key algorithm whose fields the check reads.
    const ALGORITHMS: [u8; 12] = [1, 2, 3, 16, 17, 18, 19, 22, 25, 26, 27, 28];

    /// An MPI holding `value`, whose first octet is not zero.
    fn mpi(value: &[u8]) -> Vec<u8> {
        let bits = value.len() * 8 - value[0].leading_zeros() as usize;
        [&(bits as u16).to_be_bytes()[..], value].concat()
    }

    /// A curve point as an MPI: a prefix octet and `len - 1` more.
    fn point(prefix: u8, len: usize) -> Vec<u8> {
        mpi(&[vec![prefix], vec![0x11; len - 1]].concat())
    }

    /// The one-octet size and the octets of Curve25519's legacy OID.
    const CV25519: [u8; 11] = [10, 0x2B, 6, 1, 4, 1, 0x97, 0x55, 1, 5, 1];
    const ED25519: [u8; 10] = [9, 0x2B, 6, 1, 4, 1, 0xDA, 0x47, 0x0F, 1];
    const P256: [u8; 9] = [8, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 3, 1, 7];

    /// A version 4 key body for `algorithm` with these public fields.
    fn key_body_with(algorithm: u8, fields: &[u8]) -> Vec<u8> {
        [&[4, 0x6A, 0xF8, 0xEA, 0x65, algorithm][..], fields].concat()
    }

    /// A well-formed version 4 key body for `algorithm`. RSA's `e` is 65537,
    /// an MPI of 17 bits, so a bit count read as whole octets misframes it.
    fn key_body(algorithm: u8) -> Vec<u8> {
        let big = || mpi(&[0xC5; 256]);
        let fields = match algorithm {
            1..=3 => [big(), mpi(&[1, 0, 1])].concat(),
            16 => [big(), mpi(&[2]), big()].concat(),
            17 => [big(), mpi(&[0x9D; 32]), big(), big()].concat(),
            18 => [&CV25519[..], &point(0x40, 33), &[3, 1, 8, 9]].concat(),
            19 => [&P256[..], &point(0x04, 65)].concat(),
            22 => [&ED25519[..], &point(0x40, 33)].concat(),
            25 | 27 => vec![0x33; 32],
            26 => vec![0x33; 56],
            28 => vec![0x33; 57],
            _ => unreachable!("not in ALGORITHMS"),
        };
        key_body_with(algorithm, &fields)
    }

    /// Alice's key with `user_id` in place of hers.
    fn with_user_id(user_id: &[u8]) -> Vec<u8> {
        let mut parts = alice();
        parts[1].1 = user_id.to_vec();
        join(&parts)
    }

    #[test]
    fn a_key_made_as_the_client_makes_it_passes_in_any_case() {
        assert_eq!(check(&key(ALICE)), Ok(()));
        assert_eq!(check_public_key(&key(ALICE), "Alice@CHAT.example"), Ok(()));
        assert_eq!(
            join(&alice()),
            key(ALICE),
            "the helpers re-frame it unchanged"
        );
    }

    #[test]
    fn a_gnupg_key_with_a_bare_user_id_passes() {
        assert_eq!(
            check_public_key(&key(BOB_GNUPG), "bob@chat.test.local"),
            Ok(())
        );
    }

    #[test]
    fn a_key_for_another_address_is_refused() {
        for other in [
            "bob@chat.example",
            "alice@chat.example.org",
            "alice@chat.exampl",
            "lice@chat.example",
            "",
        ] {
            assert_eq!(
                check_public_key(&key(ALICE), other),
                Err(KeyRefusal::OtherAddress),
                "{other:?}"
            );
        }
        assert_eq!(check(&key(BOB_GNUPG)), Err(KeyRefusal::OtherAddress));
    }

    #[test]
    fn a_user_id_is_read_as_openpgp_js_reads_it() {
        for named in [
            "Alice <alice@chat.example>",
            "Alice (phone) <alice@chat.example>",
            "<ALICE@chat.example>",
            "alice@chat.example",
            "  alice@chat.example\t",
            "\r\nalice@chat.example\n",
        ] {
            assert_eq!(check(&with_user_id(named.as_bytes())), Ok(()), "{named:?}");
        }
        for other in [
            "<alice@chat.example",
            "alice@chat.example>",
            "alice@chat.example <mallory@chat.example>",
            "<mallory@chat.example> alice@chat.example",
            // From the first `<` to the last `>`, so neither address.
            "<alice@chat.example> <mallory@chat.example>",
            ">alice@chat.example<",
            "<alice @chat.example>",
            "<<alice@chat.example>",
            "< alice@chat.example >",
            // Unicode whitespace that Rust trims and JavaScript does not, and
            // the reverse, then a no-break space, which both trim.
            "\u{85}alice@chat.example",
            "alice@chat.example\u{85}",
            "\u{feff}alice@chat.example",
            "\u{a0}alice@chat.example",
        ] {
            assert_eq!(
                check(&with_user_id(other.as_bytes())),
                Err(KeyRefusal::OtherAddress),
                "{other:?}"
            );
        }
        let not_utf8 = [b"<alice@chat.example>".as_slice(), &[0xFF]].concat();
        assert_eq!(
            check(&with_user_id(&not_utf8)),
            Err(KeyRefusal::OtherAddress)
        );
    }

    /// OpenPGP.js refuses the whole key over a User ID longer than this,
    /// so no client could read one that passed.
    #[test]
    fn a_user_id_longer_than_openpgp_js_reads_is_refused() {
        let named = |len: usize| {
            let mut text = b"<alice@chat.example>".to_vec();
            text.resize(len, b'x');
            text
        };
        assert_eq!(check(&with_user_id(&named(MAX_USER_ID_LEN))), Ok(()));
        assert_eq!(
            check(&with_user_id(&named(MAX_USER_ID_LEN + 1))),
            Err(KeyRefusal::UserIdTooLong)
        );
    }

    #[test]
    fn every_user_id_must_name_the_address() {
        let mallory = (USER_ID, b"<mallory@chat.example>".to_vec());
        for at in [1, 3, 5] {
            let mut parts = alice();
            parts.insert(at, mallory.clone());
            assert_eq!(
                check(&join(&parts)),
                Err(KeyRefusal::OtherAddress),
                "at {at}"
            );
        }
        let mut parts = alice();
        parts.insert(3, (USER_ID, b"Alice <alice@chat.example>".to_vec()));
        assert_eq!(check(&join(&parts)), Ok(()), "two naming the address");
    }

    #[test]
    fn a_key_with_no_user_id_is_refused() {
        let mut parts = alice();
        parts.drain(1..3);
        assert_eq!(check(&join(&parts)), Err(KeyRefusal::NoUserId));
    }

    #[test]
    fn secret_key_material_is_refused() {
        assert_eq!(check(&key(ALICE_SECRET)), Err(KeyRefusal::SecretKey));
        let secret = parts(&key(ALICE_SECRET));
        let mut subkey = alice();
        subkey[3] = secret[3].clone();
        assert_eq!(check(&join(&subkey)), Err(KeyRefusal::SecretKey));
        let mut appended = alice();
        appended.push(secret[0].clone());
        assert_eq!(check(&join(&appended)), Err(KeyRefusal::SecretKey));
    }

    #[test]
    fn a_cut_key_or_trailing_bytes_are_refused() {
        // A cut between packets leaves whole ones, which the other tests
        // cover: cut after the subkey, the key lacks only the subkey's
        // binding signature, which the reading client checks.
        let whole = key(ALICE);
        let mut between = vec![0];
        for (tag, body) in alice() {
            between.push(between.last().unwrap() + packet(tag, &body).len());
        }
        for end in (1..whole.len()).filter(|end| !between.contains(end)) {
            assert_eq!(
                check(&whole[..end]),
                Err(KeyRefusal::Malformed),
                "cut at {end}"
            );
        }
        // The last is a signature whose header has bit 7 clear.
        for trailing in [&[0x00][..], &[0xC2], &[0xC2, 0x05, 1], &[0x42, 0x01, 0]] {
            let key = [whole.as_slice(), trailing].concat();
            assert_eq!(check(&key), Err(KeyRefusal::Malformed), "{trailing:02x?}");
        }
    }

    #[test]
    fn a_partial_length_is_refused() {
        // The User ID's 20 octets as a 16-octet chunk and a final 4.
        let parts = alice();
        let user_id = &parts[1].1;
        assert_eq!(user_id.len(), 20);
        let mut chunked = vec![0xC0 | USER_ID, 0xE4];
        chunked.extend_from_slice(&user_id[..16]);
        chunked.push(4);
        chunked.extend_from_slice(&user_id[16..]);
        let key = [packet(PUBLIC_KEY, &parts[0].1), chunked, join(&parts[2..])].concat();
        assert_eq!(check(&key), Err(KeyRefusal::Malformed));
        // A signature of a one-octet chunk and an empty final one, last.
        let last = [self::key(ALICE), vec![0xC2, 0xE0, 0xA5, 0x00]].concat();
        assert_eq!(check(&last), Err(KeyRefusal::Malformed));
    }

    #[test]
    fn only_user_ids_signatures_and_subkeys_follow_the_key() {
        for tag in [1, 3, 8, 10, 11, 12, 17, 18, 19, 20, 21, 60, 63] {
            let mut parts = alice();
            parts.insert(3, (tag, vec![1, 2, 3]));
            assert_eq!(
                check(&join(&parts)),
                Err(KeyRefusal::UnexpectedPacket(tag)),
                "tag {tag}"
            );
        }
        let two = [key(ALICE), key(ALICE)].concat();
        assert_eq!(check(&two), Err(KeyRefusal::UnexpectedPacket(PUBLIC_KEY)));
    }

    #[test]
    fn the_first_packet_must_be_a_public_key() {
        assert_eq!(check(&[]), Err(KeyRefusal::NotAPublicKey));
        for tag in [SIGNATURE, USER_ID, PUBLIC_SUBKEY, 1, 18] {
            let key = [packet(tag, &[4, 0, 0, 0, 0, 18]), key(ALICE)].concat();
            assert_eq!(check(&key), Err(KeyRefusal::NotAPublicKey), "tag {tag}");
        }
        let armoured = b"-----BEGIN PGP PUBLIC KEY BLOCK-----\n";
        assert_eq!(check(armoured), Err(KeyRefusal::Malformed));
    }

    #[test]
    fn only_version_4_keys_pass() {
        assert_eq!(check(&key(ALICE_V6)), Err(KeyRefusal::UnsupportedVersion));
        for version in [3, 5, 6] {
            let mut primary = alice();
            primary[0].1[0] = version;
            assert_eq!(check(&join(&primary)), Err(KeyRefusal::UnsupportedVersion));
            let mut subkey = alice();
            subkey[3].1[0] = version;
            assert_eq!(check(&join(&subkey)), Err(KeyRefusal::UnsupportedVersion));
        }
    }

    #[test]
    fn a_key_too_short_to_name_its_algorithm_is_refused() {
        for (at, len) in [(0, 0), (0, 5), (3, 0), (3, 5)] {
            let mut parts = alice();
            parts[at].1.truncate(len);
            assert_eq!(
                check(&join(&parts)),
                Err(KeyRefusal::Malformed),
                "{at} {len}"
            );
        }
    }

    #[test]
    fn an_encryption_subkey_is_required() {
        let mut none = alice();
        none.drain(3..5);
        assert_eq!(check(&join(&none)), Err(KeyRefusal::NoEncryptionSubkey));
        for algorithm in ALGORITHMS {
            let mut parts = alice();
            parts[3].1 = key_body(algorithm);
            let expected = if [1, 2, 16, 18, 25, 26].contains(&algorithm) {
                Ok(())
            } else {
                Err(KeyRefusal::NoEncryptionSubkey)
            };
            assert_eq!(check(&join(&parts)), expected, "algorithm {algorithm}");
        }
        // One encryption subkey among signing ones is enough, in any order.
        let parts = alice();
        let signing = (PUBLIC_SUBKEY, key_body(22));
        let (encryption, binding) = (parts[3].clone(), parts[4].clone());
        for subkeys in [
            [
                signing.clone(),
                binding.clone(),
                encryption.clone(),
                binding.clone(),
            ],
            [encryption, binding.clone(), signing, binding],
        ] {
            let key = [join(&parts[..3]), join(&subkeys)].concat();
            assert_eq!(check(&key), Ok(()));
        }
    }

    /// The primary key certifies the rest of the key, so an algorithm that
    /// can only encrypt cannot be one (section 10.1.5).
    #[test]
    fn a_primary_key_must_be_able_to_sign() {
        for algorithm in ALGORITHMS {
            let mut parts = alice();
            parts[0].1 = key_body(algorithm);
            let expected = if matches!(algorithm, 2 | 16 | 18 | 25 | 26) {
                Err(KeyRefusal::PrimaryCannotSign(algorithm))
            } else {
                Ok(())
            };
            assert_eq!(check(&join(&parts)), expected, "algorithm {algorithm}");
        }
    }

    #[test]
    fn each_algorithms_public_fields_are_read_exactly() {
        for algorithm in ALGORITHMS {
            let body = key_body(algorithm);
            // As the primary, then as the subkey.
            for at in [0, 3] {
                let mut parts = alice();
                parts[at].1 = body.clone();
                let whole = check(&join(&parts));
                assert!(
                    matches!(whole, Ok(()) | Err(KeyRefusal::NoEncryptionSubkey))
                        || (at == 0 && whole == Err(KeyRefusal::PrimaryCannotSign(algorithm))),
                    "{algorithm} at {at}: {whole:?}"
                );
                parts[at].1.push(0);
                let longer = check(&join(&parts));
                assert_eq!(
                    longer,
                    Err(KeyRefusal::Malformed),
                    "{algorithm} at {at}, longer"
                );
                parts[at].1.truncate(body.len() - 1);
                let shorter = check(&join(&parts));
                assert_eq!(
                    shorter,
                    Err(KeyRefusal::Malformed),
                    "{algorithm} at {at}, shorter"
                );
            }
        }
        // Sizes 0 and 255 are reserved, for a curve OID and for ECDH's KDF
        // parameters: refused even with as many octets as they claim.
        let filled = |size: u8| [vec![size], vec![1; usize::from(size)]].concat();
        let ecdh =
            |oid: &[u8], kdf: &[u8]| key_body_with(18, &[oid, &point(0x40, 33), kdf].concat());
        for body in [
            ecdh(&filled(0), &[3, 1, 8, 9]),
            ecdh(&filled(255), &[3, 1, 8, 9]),
            ecdh(&CV25519, &filled(0)),
            ecdh(&CV25519, &filled(255)),
        ] {
            let mut parts = alice();
            parts[3].1 = body;
            assert_eq!(check(&join(&parts)), Err(KeyRefusal::Malformed));
        }
    }

    #[test]
    fn secret_key_material_labelled_public_is_refused() {
        // Each secret packet's fields begin with the public ones, so only
        // what follows them gives it away.
        let secret = parts(&key(ALICE_SECRET));
        let public = alice();
        let primary = (PUBLIC_KEY, secret[0].1.clone());
        let subkey = (PUBLIC_SUBKEY, secret[3].1.clone());
        for parts in [
            [
                primary.clone(),
                public[1].clone(),
                public[2].clone(),
                subkey.clone(),
                public[4].clone(),
            ],
            [
                primary,
                public[1].clone(),
                public[2].clone(),
                public[3].clone(),
                public[4].clone(),
            ],
            [
                public[0].clone(),
                public[1].clone(),
                public[2].clone(),
                subkey,
                public[4].clone(),
            ],
        ] {
            assert_eq!(check(&join(&parts)), Err(KeyRefusal::Malformed));
        }
    }

    #[test]
    fn an_unknown_algorithm_is_refused() {
        for algorithm in [0, 20, 21, 29, 100, 110, 255] {
            for at in [0, 3] {
                let mut parts = alice();
                parts[at].1 = key_body_with(algorithm, &[0x33; 32]);
                assert_eq!(
                    check(&join(&parts)),
                    Err(KeyRefusal::UnknownAlgorithm(algorithm)),
                    "{algorithm} at {at}"
                );
            }
        }
    }

    #[test]
    fn the_limit_is_8_kib() {
        // Alice's key and a Signature packet with a two-octet length,
        // making up `total` bytes.
        let padded = |total: usize| {
            let filler = vec![0; total - key(ALICE).len() - 3];
            [key(ALICE), packet(SIGNATURE, &filler)].concat()
        };
        assert_eq!(padded(8192).len(), 8192);
        assert_eq!(check(&padded(8192)), Ok(()));
        assert_eq!(check(&padded(8193)), Err(KeyRefusal::TooLarge));
    }

    #[test]
    fn every_definite_length_form_is_read() {
        // Each packet re-framed with a legacy one-, two- and four-octet
        // length, then an OpenPGP-format five-octet one.
        for form in 0..4 {
            let key: Vec<u8> = alice()
                .into_iter()
                .flat_map(|(tag, body)| {
                    let len = body.len() as u32;
                    let header = match form {
                        0 => vec![0x80 | (tag << 2), len as u8],
                        1 => [&[0x81 | (tag << 2)][..], &(len as u16).to_be_bytes()].concat(),
                        2 => [&[0x82 | (tag << 2)][..], &len.to_be_bytes()].concat(),
                        _ => [&[0xC0 | tag, 0xFF][..], &len.to_be_bytes()].concat(),
                    };
                    [header, body].concat()
                })
                .collect();
            assert_ne!(key, self::key(ALICE));
            assert_eq!(check(&key), Ok(()), "form {form}");
        }
    }

    #[test]
    fn a_legacy_indeterminate_length_is_refused() {
        let mut first = key(BOB_GNUPG);
        assert_eq!(
            first[0], 0x98,
            "a legacy key packet with a one-octet length"
        );
        first[0] |= 0x03;
        assert_eq!(check(&first), Err(KeyRefusal::Malformed));
        // On the last packet, where it would run to the end of the input.
        let parts = alice();
        let (tag, body) = &parts[4];
        let last = [&[0x80 | (tag << 2) | 0x03][..], body].concat();
        let key = [join(&parts[..4]), last].concat();
        assert_eq!(check(&key), Err(KeyRefusal::Malformed));
    }

    #[test]
    fn huge_lengths_fail_without_overflow() {
        let max = [0xFF; 4];
        assert_eq!(
            check(&[&[0xC6, 0xFF][..], &max].concat()),
            Err(KeyRefusal::Malformed)
        );
        assert_eq!(
            check(&[&[0x9A][..], &max].concat()),
            Err(KeyRefusal::Malformed)
        );
        let after = [key(ALICE), vec![0xC2, 0xFF], max.to_vec()].concat();
        assert_eq!(check(&after), Err(KeyRefusal::Malformed));
    }
}
