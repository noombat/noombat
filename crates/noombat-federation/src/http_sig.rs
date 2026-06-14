// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! HTTP Signature signing and verification (as per: draft-cavage-http-signatures-12).

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use chrono::Utc;
use rsa::pkcs1v15::{SigningKey, VerifyingKey};
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey};
use rsa::signature::{SignatureEncoding, Signer, Verifier};
use rsa::RsaPrivateKey;
use sha2::Sha256;

use noombat_core::error::{NoombatError, Result};

/// The components of a signed HTTP request.
pub struct SignedRequest {
    /// Value for the `Signature` header.
    pub signature_header: String,
    /// Value for the `Date` header.
    pub date: String,
}

/// Sign an outbound HTTP request.
///
/// This is CPU-bound (RSA modular exponentiation). Use
/// [`sign_request_async`] when calling from an async context.
///
/// # Arguments
/// * `key_id`: the actor's public key URI (e.g. `https://noombat.social/users/alice#main-key`).
/// * `private_key_pem`: RSA private key in PKCS#8 PEM format.
/// * `method`: HTTP method (lowercase).
/// * `path`: request path including query string.
/// * `host`: target hostname.
/// * `body_digest`: SHA-256 digest of the request body (Base64-encoded).
pub fn sign_request(
    key_id: &str,
    private_key_pem: &str,
    method: &str,
    path: &str,
    host: &str,
    body_digest: Option<&str>,
) -> Result<SignedRequest> {
    let date = Utc::now().format("%a, %d %b %Y %T GMT").to_string();

    let mut headers_list = vec!["(request-target)", "host", "date"];
    let mut signing_string =
        format!("(request-target): {method} {path}\nhost: {host}\ndate: {date}");

    if let Some(digest) = body_digest {
        headers_list.push("digest");
        signing_string.push_str(&format!("\ndigest: SHA-256={digest}"));
    }

    let private_key = RsaPrivateKey::from_pkcs8_pem(private_key_pem)
        .map_err(|e| NoombatError::Internal(format!("invalid private key: {e}")))?;
    let signing_key = SigningKey::<Sha256>::new(private_key);
    let signature = signing_key.sign(signing_string.as_bytes());
    let sig_b64 = BASE64.encode(signature.to_bytes());

    let signature_header = format!(
        r#"keyId="{key_id}",algorithm="rsa-sha256",headers="{}",signature="{sig_b64}""#,
        headers_list.join(" ")
    );

    Ok(SignedRequest {
        signature_header,
        date,
    })
}

/// Async wrapper that offloads [`sign_request`] to a blocking thread pool.
pub async fn sign_request_async(
    key_id: String,
    private_key_pem: String,
    method: String,
    path: String,
    host: String,
    body_digest: Option<String>,
) -> Result<SignedRequest> {
    tokio::task::spawn_blocking(move || {
        sign_request(
            &key_id,
            &private_key_pem,
            &method,
            &path,
            &host,
            body_digest.as_deref(),
        )
    })
    .await
    .map_err(|e| NoombatError::Internal(format!("signing task failed: {e}")))?
}

/// Compute the SHA-256 digest of a body, returned as a Base64 string.
pub fn digest_body(body: &[u8]) -> String {
    use sha2::Digest;
    let hash = sha2::Sha256::digest(body);
    BASE64.encode(hash)
}

/// Verify an inbound HTTP Signature against the claimed public key.
///
/// This is CPU-bound (RSA modular exponentiation). Use
/// [`verify_signature_async`] when calling from an async context.
///
/// Returns `Ok(())` on success, or `Err(SignatureVerification)` on failure.
pub fn verify_signature(
    public_key_pem: &str,
    signature_b64: &str,
    signing_string: &str,
) -> Result<()> {
    let public_key = rsa::RsaPublicKey::from_public_key_pem(public_key_pem)
        .map_err(|e| NoombatError::Internal(format!("invalid public key: {e}")))?;
    let verifying_key = VerifyingKey::<Sha256>::new(public_key);

    let sig_bytes = BASE64
        .decode(signature_b64)
        .map_err(|_| NoombatError::SignatureVerification)?;
    let signature = rsa::pkcs1v15::Signature::try_from(sig_bytes.as_slice())
        .map_err(|_| NoombatError::SignatureVerification)?;

    verifying_key
        .verify(signing_string.as_bytes(), &signature)
        .map_err(|_| NoombatError::SignatureVerification)
}

/// Async wrapper that offloads [`verify_signature`] to a blocking thread pool.
pub async fn verify_signature_async(
    public_key_pem: String,
    signature_b64: String,
    signing_string: String,
) -> Result<()> {
    tokio::task::spawn_blocking(move || {
        verify_signature(&public_key_pem, &signature_b64, &signing_string)
    })
    .await
    .map_err(|e| NoombatError::Internal(format!("verification task failed: {e}")))?
}

// ..... SIGNATURE HEADER PARSING .....

/// Parsed components of an HTTP `Signature` header.
#[derive(Debug, Clone)]
pub struct ParsedSignature {
    /// The URI identifying the signing key (e.g. `https://noombat.social/users/alice#main-key`).
    pub key_id: String,
    /// The signing algorithm (e.g. `rsa-sha256`).
    pub algorithm: String,
    /// The ordered list of header names included in the signing string.
    pub headers: Vec<String>,
    /// The Base64-encoded signature value.
    pub signature: String,
}

/// Parse the `Signature` header value into its components.
///
/// Expected format (as per: draft-cavage-http-signatures-12):
/// ```text
/// keyId="...",algorithm="...",headers="...",signature="..."
/// ```
pub fn parse_signature_header(header: &str) -> Result<ParsedSignature> {
    let mut key_id = None;
    let mut algorithm = None;
    let mut headers = None;
    let mut signature = None;

    for part in split_signature_params(header) {
        let (key, value) = part
            .split_once('=')
            .ok_or_else(|| NoombatError::SignatureVerification)?;
        let value = value.trim_matches('"');
        match key.trim() {
            "keyId" => key_id = Some(value.to_owned()),
            "algorithm" => algorithm = Some(value.to_owned()),
            "headers" => headers = Some(value.split_whitespace().map(String::from).collect()),
            "signature" => signature = Some(value.to_owned()),
            _ => {}
        }
    }

    Ok(ParsedSignature {
        key_id: key_id.ok_or(NoombatError::SignatureVerification)?,
        algorithm: algorithm.unwrap_or_else(|| "rsa-sha256".to_owned()),
        headers: headers.ok_or(NoombatError::SignatureVerification)?,
        signature: signature.ok_or(NoombatError::SignatureVerification)?,
    })
}

/// Split a Signature header into key=value pairs, respecting quoted values.
fn split_signature_params(header: &str) -> Vec<String> {
    let mut params = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;

    for ch in header.chars() {
        match ch {
            '"' => {
                in_quotes = !in_quotes;
                current.push(ch);
            }
            ',' if !in_quotes => {
                let trimmed = current.trim().to_owned();
                if !trimmed.is_empty() {
                    params.push(trimmed);
                }
                current.clear();
            }
            _ => current.push(ch),
        }
    }
    let trimmed = current.trim().to_owned();
    if !trimmed.is_empty() {
        params.push(trimmed);
    }
    params
}

/// Reconstruct the signing string from the request components and the
/// `headers` list declared in the Signature header.
///
/// Each entry in `headers` is a pseudo-header or real header name:
/// - `(request-target)`: `{method} {path}`.
/// - `host`: the Host header value.
/// - `date`: the Date header value.
/// - `digest`: the Digest header value.
pub fn reconstruct_signing_string(
    headers_list: &[String],
    method: &str,
    path: &str,
    request_headers: &[(String, String)],
) -> Result<String> {
    let mut lines = Vec::new();

    for name in headers_list {
        if name == "(request-target)" {
            lines.push(format!(
                "(request-target): {} {}",
                method.to_lowercase(),
                path
            ));
        } else {
            let value = request_headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.as_str())
                .ok_or_else(|| NoombatError::SignatureVerification)?;
            lines.push(format!("{}: {}", name.to_lowercase(), value));
        }
    }

    Ok(lines.join("\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn generate_test_keypair() -> (String, String) {
        noombat_identity::keys::generate_rsa_keypair().unwrap()
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let (public_pem, private_pem) = generate_test_keypair();

        let body = b"test body";
        let digest = digest_body(body);

        let signed = sign_request(
            "https://noombat.social/users/alice#main-key",
            &private_pem,
            "post",
            "/users/bob/inbox",
            "example.org",
            Some(&digest),
        )
        .unwrap();

        // Reconstruct the signing string as the verifier would.
        let signing_string = format!(
            "(request-target): post /users/bob/inbox\nhost: example.org\ndate: {}\ndigest: SHA-256={}",
            signed.date, digest
        );

        // Extract the signature value from the header.
        let sig_start = signed.signature_header.find("signature=\"").unwrap() + 11;
        let sig_end = signed.signature_header[sig_start..].find('"').unwrap() + sig_start;
        let signature_b64 = &signed.signature_header[sig_start..sig_end];

        verify_signature(&public_pem, signature_b64, &signing_string).unwrap();
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let (_pub1, priv1) = generate_test_keypair();
        let (pub2, _priv2) = generate_test_keypair();

        let signed = sign_request(
            "https://noombat.social/users/alice#main-key",
            &priv1,
            "get",
            "/users/bob",
            "example.org",
            None,
        )
        .unwrap();

        let signing_string = format!(
            "(request-target): get /users/bob\nhost: example.org\ndate: {}",
            signed.date
        );
        let sig_start = signed.signature_header.find("signature=\"").unwrap() + 11;
        let sig_end = signed.signature_header[sig_start..].find('"').unwrap() + sig_start;
        let signature_b64 = &signed.signature_header[sig_start..sig_end];

        let result = verify_signature(&pub2, signature_b64, &signing_string);
        assert!(result.is_err());
    }

    #[test]
    fn digest_body_deterministic() {
        let d1 = digest_body(b"hello");
        let d2 = digest_body(b"hello");
        assert_eq!(d1, d2);
        assert_ne!(d1, digest_body(b"world"));
    }

    #[test]
    fn parse_signature_header_valid() {
        let header = r#"keyId="https://noombat.social/users/alice#main-key",algorithm="rsa-sha256",headers="(request-target) host date digest",signature="abc123==""#;
        let parsed = parse_signature_header(header).unwrap();
        assert_eq!(parsed.key_id, "https://noombat.social/users/alice#main-key");
        assert_eq!(parsed.algorithm, "rsa-sha256");
        assert_eq!(
            parsed.headers,
            vec!["(request-target)", "host", "date", "digest"]
        );
        assert_eq!(parsed.signature, "abc123==");
    }

    #[test]
    fn parse_signature_header_missing_key_id() {
        let header = r#"algorithm="rsa-sha256",headers="host",signature="abc""#;
        assert!(parse_signature_header(header).is_err());
    }

    #[test]
    fn reconstruct_signing_string_basic() {
        let headers_list = vec![
            "(request-target)".to_owned(),
            "host".to_owned(),
            "date".to_owned(),
        ];
        let request_headers = vec![
            ("Host".to_owned(), "example.org".to_owned()),
            (
                "Date".to_owned(),
                "Mon, 01 Jan 2024 00:00:00 GMT".to_owned(),
            ),
        ];
        let result =
            reconstruct_signing_string(&headers_list, "POST", "/inbox", &request_headers).unwrap();
        assert_eq!(
            result,
            "(request-target): post /inbox\nhost: example.org\ndate: Mon, 01 Jan 2024 00:00:00 GMT"
        );
    }
}
