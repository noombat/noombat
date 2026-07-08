// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! SHA-256 body-digest computation for HTTP Signature verification.

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;

/// Compute the SHA-256 digest of a body, returned as a Base64 string.
///
/// Used by the inbox handler to verify the `Digest` header of inbound
/// requests independently of the HTTP Signature verification itself.
pub fn sha256(body: &[u8]) -> String {
    use sha2::Digest;
    let hash = sha2::Sha256::digest(body);
    BASE64.encode(hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic() {
        let d1 = sha256(b"hello");
        let d2 = sha256(b"hello");
        assert_eq!(d1, d2);
        assert_ne!(d1, sha256(b"world"));
    }
}
