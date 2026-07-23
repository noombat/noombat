// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! FEP-8b32 Object Integrity Proofs using the `eddsa-jcs-2022`
//! cryptosuite.
//!
//! Implements the W3C Data Integrity EdDSA Cryptosuites v1.0
//! specification for the `eddsa-jcs-2022` algorithm:
//!
//! 1. **Transformation**: JCS-canonicalise (RFC 8785) the unsigned
//!    document.
//! 2. **Proof configuration**: construct the `DataIntegrityProof`
//!    object, JCS-canonicalise it, SHA-256 hash it.
//! 3. **Hashing**: SHA-256 hash the canonicalised document.
//! 4. **Signing**: concatenate `proofConfigHash || documentHash`
//!    (64 bytes), sign with Ed25519.
//! 5. **Encoding**: multibase-encode the signature (base58btc with
//!    `z` prefix).
//!
//! # Key format conventions
//!
//! - **Public key (multibase)**: `z` + base58btc(raw 32-byte Ed25519
//!   public key). This matches the encoding produced by
//!   [`noombat_identity::keys::generate_ed25519_keypair`].
//! - **Private key (Base64)**: standard Base64 encoding of the raw
//!   32-byte Ed25519 secret key, as stored in the `ed25519_private_key`
//!   column of the `actors` table.
//!
//! # References
//!
//! - FEP-8b32: <https://codeberg.org/fediverse/fep/src/branch/main/fep/8b32/fep-8b32.md>
//! - W3C Data Integrity EdDSA Cryptosuites v1.0: <https://www.w3.org/TR/vc-di-eddsa/>
//! - RFC 8785 (JCS): <https://datatracker.ietf.org/doc/rfc8785/>

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use chrono::Utc;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use noombat_ap::context::DATA_INTEGRITY_CONTEXT;
use noombat_core::error::{NoombatError, Result};
use serde_json::{Value, json};
use sha2::Digest as _;
use tracing::{debug, warn};

/// The cryptosuite identifier for EdDSA with JCS canonicalisation.
pub const CRYPTOSUITE: &str = "eddsa-jcs-2022";

/// The proof type per the W3C Data Integrity specification.
pub const PROOF_TYPE: &str = "DataIntegrityProof";

/// The proof purpose: the signature asserts the authenticity of the
/// document.
pub const PROOF_PURPOSE: &str = "assertionMethod";

// ..... Signing .....

/// Attach an FEP-8b32 integrity proof to an ActivityPub activity.
///
/// The activity is mutated in place: a `proof` property is added
/// containing the `DataIntegrityProof` object with the `eddsa-jcs-2022`
/// cryptosuite. If the activity's `@context` does not already include
/// the Data Integrity context URI, it is appended.
///
/// # Arguments
///
/// * `activity`: the ActivityPub activity (JSON object) to sign.
///   If a `proof` property already exists, it is replaced.
/// * `signing_key_bytes`: the raw 32-byte Ed25519 secret key.
/// * `verification_method_id`: the URI of the verification method,
///   e.g. `https://noombat.social/users/alice#ed25519-key`.
///
/// # Errors
///
/// Returns an error if JCS canonicalisation or Ed25519 signing fails.
pub fn sign(
    activity: &mut Value,
    signing_key_bytes: &[u8; 32],
    verification_method_id: &str,
) -> Result<()> {
    // Ensure the Data Integrity context is present.
    ensure_data_integrity_context(activity);

    // 1. The unsigned document is the activity without any existing `proof`.
    let mut unsigned_doc = activity.clone();
    unsigned_doc
        .as_object_mut()
        .ok_or_else(|| NoombatError::Internal("activity is not a JSON object".into()))?
        .remove("proof");

    // 2. Construct the proof configuration (without `proofValue`).
    let created = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let mut proof_config = json!({
        "type": PROOF_TYPE,
        "cryptosuite": CRYPTOSUITE,
        "verificationMethod": verification_method_id,
        "proofPurpose": PROOF_PURPOSE,
        "created": created,
    });

    // Per the W3C spec: if the unsigned document has `@context`,
    // set it on the proof configuration as well.
    if let Some(ctx) = unsigned_doc.get("@context") {
        proof_config["@context"] = ctx.clone();
    }

    // 3. Canonicalise and hash both the document and the proof config.
    let canonical_doc = jcs_canonicalise(&unsigned_doc)?;
    let canonical_proof_config = jcs_canonicalise(&proof_config)?;

    let doc_hash = sha256(canonical_doc.as_bytes());
    let proof_config_hash = sha256(canonical_proof_config.as_bytes());

    // 4. Concatenate: proofConfigHash || documentHash (64 bytes).
    let mut signature_input = [0u8; 64];
    signature_input[..32].copy_from_slice(&proof_config_hash);
    signature_input[32..].copy_from_slice(&doc_hash);

    // 5. Sign with Ed25519.
    let signing_key = SigningKey::from_bytes(signing_key_bytes);
    let signature: Signature = signing_key.sign(&signature_input);

    // 6. Multibase-encode: `z` prefix + base58btc(signature bytes).
    let proof_value = format!("z{}", bs58::encode(signature.to_bytes()).into_string());

    // 7. Add `proofValue` to the proof config and attach to the activity.
    proof_config["proofValue"] = Value::String(proof_value);

    // Remove `@context` from the proof before embedding: it was needed
    // for the hash computation but is redundant in the output (the
    // document's own `@context` is authoritative).
    proof_config
        .as_object_mut()
        .unwrap()
        .remove("@context");

    activity["proof"] = proof_config;

    debug!(
        verification_method = verification_method_id,
        "FEP-8b32 integrity proof attached"
    );
    Ok(())
}

// ..... Verification .....

/// The result of verifying an integrity proof on an inbound activity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationResult {
    /// The proof is valid: the signature matches the document content
    /// and the claimed verification method.
    Valid,
    /// The proof is present but invalid (signature mismatch, malformed
    /// encoding, or key-type mismatch).
    Invalid,
    /// No `proof` property is present on the activity.
    Absent,
}

/// Verify an FEP-8b32 integrity proof on an inbound ActivityPub activity.
///
/// This function does **not** fetch the verification method from the
/// network. The caller must supply the Ed25519 public key for the
/// claimed author. Use [`extract_verification_method_id`] to obtain
/// the verification method URI, then resolve the actor and retrieve
/// the `ed25519_public_key` from the local cache or via signed fetch.
///
/// # Arguments
///
/// * `activity`: the inbound ActivityPub activity (JSON object).
/// * `public_key_multibase`: the multibase-encoded Ed25519 public
///   key of the claimed author (e.g. `z6Mk...`).
///
/// # Returns
///
/// A [`VerificationResult`] indicating whether the proof is valid,
/// invalid, or absent.
pub fn verify(activity: &Value, public_key_multibase: &str) -> VerificationResult {
    let proof = match activity.get("proof") {
        Some(p) if p.is_object() => p,
        _ => return VerificationResult::Absent,
    };

    // Validate the proof metadata.
    let cryptosuite = proof.get("cryptosuite").and_then(|v| v.as_str());
    if cryptosuite != Some(CRYPTOSUITE) {
        debug!(
            ?cryptosuite,
            "integrity proof uses unsupported cryptosuite; skipping"
        );
        return VerificationResult::Absent;
    }

    let proof_type = proof.get("type").and_then(|v| v.as_str());
    if proof_type != Some(PROOF_TYPE) {
        debug!(
            ?proof_type,
            "integrity proof has unexpected type; skipping"
        );
        return VerificationResult::Absent;
    }

    // Extract and decode the proof value.
    let proof_value_str = match proof.get("proofValue").and_then(|v| v.as_str()) {
        Some(pv) => pv,
        None => {
            warn!("integrity proof is missing proofValue");
            return VerificationResult::Invalid;
        }
    };

    let signature_bytes = match decode_multibase_signature(proof_value_str) {
        Ok(bytes) => bytes,
        Err(e) => {
            warn!("failed to decode proofValue: {e}");
            return VerificationResult::Invalid;
        }
    };

    // Decode the public key.
    let public_key_bytes = match decode_multibase_public_key(public_key_multibase) {
        Ok(bytes) => bytes,
        Err(e) => {
            warn!("failed to decode public key: {e}");
            return VerificationResult::Invalid;
        }
    };

    let verifying_key = match VerifyingKey::from_bytes(&public_key_bytes) {
        Ok(vk) => vk,
        Err(e) => {
            warn!("invalid Ed25519 public key: {e}");
            return VerificationResult::Invalid;
        }
    };

    // Reconstruct the proof configuration (without proofValue).
    let mut proof_config = proof.clone();
    proof_config
        .as_object_mut()
        .unwrap()
        .remove("proofValue");

    // Per the W3C spec: if the proof config does not carry `@context`,
    // inherit it from the document.
    if proof_config.get("@context").is_none()
        && let Some(ctx) = activity.get("@context") {
            proof_config["@context"] = ctx.clone();
    }

    // Reconstruct the unsigned document (activity without `proof`).
    let mut unsigned_doc = activity.clone();
    unsigned_doc.as_object_mut().unwrap().remove("proof");

    // Canonicalise and hash.
    let canonical_doc = match jcs_canonicalise(&unsigned_doc) {
        Ok(c) => c,
        Err(e) => {
            warn!("JCS canonicalisation of document failed: {e}");
            return VerificationResult::Invalid;
        }
    };
    let canonical_proof_config = match jcs_canonicalise(&proof_config) {
        Ok(c) => c,
        Err(e) => {
            warn!("JCS canonicalisation of proof config failed: {e}");
            return VerificationResult::Invalid;
        }
    };

    let doc_hash = sha256(canonical_doc.as_bytes());
    let proof_config_hash = sha256(canonical_proof_config.as_bytes());

    let mut verify_input = [0u8; 64];
    verify_input[..32].copy_from_slice(&proof_config_hash);
    verify_input[32..].copy_from_slice(&doc_hash);

    // Verify the Ed25519 signature.
    let signature = match Signature::from_slice(&signature_bytes) {
        Ok(s) => s,
        Err(e) => {
            warn!("invalid Ed25519 signature encoding: {e}");
            return VerificationResult::Invalid;
        }
    };

    match verifying_key.verify(&verify_input, &signature) {
        Ok(()) => {
            debug!("FEP-8b32 integrity proof verified successfully");
            VerificationResult::Valid
        }
        Err(e) => {
            warn!("FEP-8b32 integrity proof verification failed: {e}");
            VerificationResult::Invalid
        }
    }
}

// ..... Helper: extract the verification method URI .....

/// Extract the `verificationMethod` URI from an activity's integrity
/// proof, if present.
///
/// Returns `None` if no proof exists or if the proof does not use the
/// `eddsa-jcs-2022` cryptosuite.
pub fn extract_verification_method_id(activity: &Value) -> Option<&str> {
    let proof = activity.get("proof")?;
    let cs = proof.get("cryptosuite").and_then(|v| v.as_str())?;
    if cs != CRYPTOSUITE {
        return None;
    }
    proof.get("verificationMethod").and_then(|v| v.as_str())
}

// ..... Helper: decode Ed25519 private key from Base64 .....

/// Decode a Base64-encoded Ed25519 private key (as stored in the
/// `ed25519_private_key` column) into a raw 32-byte array.
///
/// # Errors
///
/// Returns an error if the Base64 decoding fails or the decoded
/// length is not 32 bytes.
pub fn decode_private_key_base64(base64_str: &str) -> Result<[u8; 32]> {
    let bytes = BASE64
        .decode(base64_str)
        .map_err(|e| NoombatError::Internal(format!("Ed25519 private key Base64 decode: {e}")))?;

    bytes
        .try_into()
        .map_err(|v: Vec<u8>| {
            NoombatError::Internal(format!(
                "Ed25519 private key has unexpected length {} (expected 32)",
                v.len()
            ))
        })
}

// ..... Internal helpers .....

/// JCS-canonicalise a JSON value per RFC 8785.
fn jcs_canonicalise(value: &Value) -> Result<String> {
    serde_json_canonicalizer::to_string(value)
        .map_err(|e| NoombatError::Internal(format!("JCS canonicalisation failed: {e}")))
}

/// SHA-256 hash of a byte slice, returning a 32-byte array.
fn sha256(data: &[u8]) -> [u8; 32] {
    let digest = sha2::Sha256::digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Decode a multibase-encoded Ed25519 public key.
///
/// Expected format: `z` prefix followed by base58btc-encoded raw
/// 32-byte public key (as produced by
/// [`noombat_identity::keys::generate_ed25519_keypair`]).
fn decode_multibase_public_key(multibase: &str) -> Result<[u8; 32]> {
    let raw = multibase
        .strip_prefix('z')
        .ok_or_else(|| {
            NoombatError::Internal(format!(
                "multibase public key does not start with 'z': {multibase}"
            ))
        })?;

    let decoded = bs58::decode(raw)
        .into_vec()
        .map_err(|e| {
            NoombatError::Internal(format!("base58btc decode of public key failed: {e}"))
        })?;

    // The key may be stored with or without a multicodec prefix.
    // Noombat's key generation stores the raw 32-byte key without
    // a multicodec prefix. Remote actors may include the Ed25519
    // multicodec prefix `0xed 0x01`.
    let key_bytes: &[u8] = if decoded.len() == 34 && decoded[0] == 0xed && decoded[1] == 0x01 {
        &decoded[2..]
    } else if decoded.len() == 32 {
        &decoded
    } else {
        return Err(NoombatError::Internal(format!(
            "Ed25519 public key has unexpected length {} (expected 32 or 34 with multicodec prefix)",
            decoded.len()
        )));
    };

    key_bytes.try_into().map_err(|_| {
        NoombatError::Internal("Ed25519 public key slice conversion failed".into())
    })
}

/// Decode a multibase-encoded Ed25519 signature.
///
/// Expected format: `z` prefix followed by base58btc-encoded raw
/// 64-byte signature.
fn decode_multibase_signature(multibase: &str) -> Result<Vec<u8>> {
    let raw = multibase
        .strip_prefix('z')
        .ok_or_else(|| {
            NoombatError::Internal(format!(
                "multibase signature does not start with 'z': {multibase}"
            ))
        })?;

    let decoded = bs58::decode(raw)
        .into_vec()
        .map_err(|e| {
            NoombatError::Internal(format!("base58btc decode of signature failed: {e}"))
        })?;

    if decoded.len() != 64 {
        return Err(NoombatError::Internal(format!(
            "Ed25519 signature has unexpected length {} (expected 64)",
            decoded.len()
        )));
    }

    Ok(decoded)
}

/// Ensure the Data Integrity context URI is present in the activity's
/// `@context` array.
fn ensure_data_integrity_context(activity: &mut Value) {
    let context = match activity.get_mut("@context") {
        Some(ctx) => ctx,
        None => {
            // No @context at all; create one containing the DI context.
            activity["@context"] = json!([DATA_INTEGRITY_CONTEXT]);
            return;
        }
    };

    match context {
        Value::Array(arr) => {
            let already_present = arr.iter().any(|v| {
                v.as_str() == Some(DATA_INTEGRITY_CONTEXT)
            });
            if !already_present {
                arr.push(Value::String(DATA_INTEGRITY_CONTEXT.to_owned()));
            }
        }
        Value::String(s) => {
            // Single-string context; convert to array.
            let existing = Value::String(s.clone());
            *context = json!([existing, DATA_INTEGRITY_CONTEXT]);
        }
        _ => {
            // Unexpected type; wrap in array.
            let existing = context.clone();
            *context = json!([existing, DATA_INTEGRITY_CONTEXT]);
        }
    }
}

// ..... FederationSignature trait implementation .....

/// Concrete [`FederationSignature`] implementation using the
/// `eddsa-jcs-2022` cryptosuite.
///
/// This struct is constructed by the server binary and injected into
/// the delivery pipeline and inbox handler via the extension-point
/// trait.
pub struct EddsaJcs2022Signer {
    pool: sqlx::PgPool,
}

impl EddsaJcs2022Signer {
    /// Construct a new signer backed by a database connection pool
    /// (used to fetch the Ed25519 private key for the signing actor).
    pub fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl noombat_core::extension::FederationSignature for EddsaJcs2022Signer {
    /// Attach an `eddsa-jcs-2022` integrity proof to the activity.
    ///
    /// The `signing_key_id` must be the AP identifier of the signing
    /// actor (e.g. `https://noombat.social/users/alice`). The method
    /// looks up the actor's Ed25519 private key from the database and
    /// derives the verification method URI as `{ap_id}#ed25519-key`.
    async fn sign(&self, activity: &mut Value, signing_key_id: &str) -> Result<()> {
        let row: Option<(String, Option<String>)> = sqlx::query_as(
            "SELECT ap_id, ed25519_private_key FROM actors WHERE ap_id = $1",
        )
        .bind(signing_key_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(NoombatError::from)?;

        let (ap_id, ed25519_private) = match row {
            Some((ap_id, Some(key))) => (ap_id, key),
            _ => {
                debug!(
                    actor = signing_key_id,
                    "no Ed25519 private key available; skipping integrity proof"
                );
                return Ok(());
            }
        };

        let private_key_bytes = decode_private_key_base64(&ed25519_private)?;
        let verification_method = format!("{ap_id}#ed25519-key");

        // Ed25519 signing is fast and does not require spawn_blocking, unlike RSA.
        sign(activity, &private_key_bytes, &verification_method)
    }

    /// Verify an `eddsa-jcs-2022` integrity proof on an inbound activity.
    ///
    /// Returns `true` if a valid proof is present, `false` if the proof
    /// is invalid or absent.
    async fn verify(&self, activity: &Value) -> Result<bool> {
        let vm_id = match extract_verification_method_id(activity) {
            Some(id) => id.to_owned(),
            None => return Ok(false),
        };

        // Extract the actor AP ID from the verification method.
        // Convention: `{actor_ap_id}#ed25519-key`.
        let actor_ap_id = vm_id
            .split('#')
            .next()
            .unwrap_or(&vm_id);

        // Look up the actor's Ed25519 public key.
        let public_key: Option<String> = sqlx::query_scalar(
            "SELECT ed25519_public_key FROM actors WHERE ap_id = $1",
        )
        .bind(actor_ap_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(NoombatError::from)?
        .flatten();

        let public_key_multibase = match public_key {
            Some(pk) => pk,
            None => {
                debug!(
                    actor = actor_ap_id,
                    "no Ed25519 public key cached for actor; \
                     cannot verify integrity proof"
                );
                return Ok(false);
            }
        };

        Ok(verify(activity, &public_key_multibase) == VerificationResult::Valid)
    }
}

// ..... Tests .....

#[cfg(test)]
mod tests {
    use super::*;

    /// Generate a deterministic test key pair from a fixed seed.
    fn test_keypair() -> (SigningKey, VerifyingKey) {
        let seed: [u8; 32] = [
            0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
            0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
            0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
            0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
        ];
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();
        (signing_key, verifying_key)
    }

    fn test_activity() -> Value {
        json!({
            "@context": [
                "https://www.w3.org/ns/activitystreams",
                "https://w3id.org/security/v1",
                { "noombat": "https://noombat.org/ns#" }
            ],
            "id": "https://noombat.social/users/alice/activities/1",
            "type": "Create",
            "actor": "https://noombat.social/users/alice",
            "object": {
                "type": "Note",
                "content": "Hello, Fediverse!"
            }
        })
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let (signing_key, verifying_key) = test_keypair();
        let public_multibase = format!(
            "z{}",
            bs58::encode(verifying_key.as_bytes()).into_string()
        );

        let mut activity = test_activity();
        let vm_id = "https://noombat.social/users/alice#ed25519-key";

        sign(&mut activity, &signing_key.to_bytes(), vm_id).unwrap();

        // The activity must now carry a `proof`.
        assert!(activity.get("proof").is_some());

        let proof = &activity["proof"];
        assert_eq!(proof["type"], PROOF_TYPE);
        assert_eq!(proof["cryptosuite"], CRYPTOSUITE);
        assert_eq!(proof["verificationMethod"], vm_id);
        assert_eq!(proof["proofPurpose"], PROOF_PURPOSE);
        assert!(proof.get("proofValue").is_some());
        assert!(proof.get("created").is_some());

        // Verification must succeed.
        let result = verify(&activity, &public_multibase);
        assert_eq!(result, VerificationResult::Valid);
    }

    #[test]
    fn verify_fails_on_tampered_content() {
        let (signing_key, verifying_key) = test_keypair();
        let public_multibase = format!(
            "z{}",
            bs58::encode(verifying_key.as_bytes()).into_string()
        );

        let mut activity = test_activity();
        sign(
            &mut activity,
            &signing_key.to_bytes(),
            "https://noombat.social/users/alice#ed25519-key",
        )
        .unwrap();

        // Tamper with the content.
        activity["object"]["content"] = Value::String("Tampered!".into());

        let result = verify(&activity, &public_multibase);
        assert_eq!(result, VerificationResult::Invalid);
    }

    #[test]
    fn verify_fails_on_wrong_key() {
        let (signing_key, _) = test_keypair();

        // Generate a different key pair for verification.
        let wrong_seed: [u8; 32] = [0xab; 32];
        let wrong_verifying = SigningKey::from_bytes(&wrong_seed).verifying_key();
        let wrong_multibase = format!(
            "z{}",
            bs58::encode(wrong_verifying.as_bytes()).into_string()
        );

        let mut activity = test_activity();
        sign(
            &mut activity,
            &signing_key.to_bytes(),
            "https://noombat.social/users/alice#ed25519-key",
        )
        .unwrap();

        let result = verify(&activity, &wrong_multibase);
        assert_eq!(result, VerificationResult::Invalid);
    }

    #[test]
    fn verify_absent_when_no_proof() {
        let activity = test_activity();
        let result = verify(&activity, "z1234");
        assert_eq!(result, VerificationResult::Absent);
    }

    #[test]
    fn verify_absent_for_unsupported_cryptosuite() {
        let mut activity = test_activity();
        activity["proof"] = json!({
            "type": "DataIntegrityProof",
            "cryptosuite": "eddsa-rdfc-2022",
            "verificationMethod": "https://example.org/key/1",
            "proofPurpose": "assertionMethod",
            "proofValue": "zSomeValue",
        });

        let result = verify(&activity, "z1234");
        assert_eq!(result, VerificationResult::Absent);
    }

    #[test]
    fn data_integrity_context_added_to_array() {
        let mut activity = test_activity();
        ensure_data_integrity_context(&mut activity);

        let ctx = activity["@context"].as_array().unwrap();
        let has_di = ctx.iter().any(|v| {
            v.as_str() == Some(DATA_INTEGRITY_CONTEXT)
        });
        assert!(has_di);
    }

    #[test]
    fn data_integrity_context_not_duplicated() {
        let mut activity = test_activity();
        ensure_data_integrity_context(&mut activity);
        ensure_data_integrity_context(&mut activity);

        let ctx = activity["@context"].as_array().unwrap();
        let count = ctx
            .iter()
            .filter(|v| v.as_str() == Some(DATA_INTEGRITY_CONTEXT))
            .count();
        assert_eq!(count, 1);
    }

    #[test]
    fn extract_verification_method_id_present() {
        let mut activity = test_activity();
        activity["proof"] = json!({
            "type": PROOF_TYPE,
            "cryptosuite": CRYPTOSUITE,
            "verificationMethod": "https://example.org/users/bob#ed25519-key",
            "proofPurpose": PROOF_PURPOSE,
            "proofValue": "zSomething",
        });

        let vm = extract_verification_method_id(&activity);
        assert_eq!(vm, Some("https://example.org/users/bob#ed25519-key"));
    }

    #[test]
    fn decode_private_key_roundtrip() {
        let (signing_key, _) = test_keypair();
        let encoded = BASE64.encode(signing_key.to_bytes());
        let decoded = decode_private_key_base64(&encoded).unwrap();
        assert_eq!(decoded, signing_key.to_bytes());
    }

    #[test]
    fn multibase_public_key_with_multicodec_prefix() {
        let (_, verifying_key) = test_keypair();

        // Encode with multicodec prefix (0xed, 0x01) as some
        // implementations do.
        let mut prefixed = vec![0xed, 0x01];
        prefixed.extend_from_slice(verifying_key.as_bytes());
        let multibase = format!("z{}", bs58::encode(&prefixed).into_string());

        let decoded = decode_multibase_public_key(&multibase).unwrap();
        assert_eq!(&decoded, verifying_key.as_bytes());
    }

    #[test]
    fn multibase_public_key_without_multicodec_prefix() {
        let (_, verifying_key) = test_keypair();

        // Encode without multicodec prefix (Noombat's own format).
        let multibase = format!(
            "z{}",
            bs58::encode(verifying_key.as_bytes()).into_string()
        );

        let decoded = decode_multibase_public_key(&multibase).unwrap();
        assert_eq!(&decoded, verifying_key.as_bytes());
    }

    #[test]
    fn jcs_canonicalisation_sorts_keys() {
        let obj = json!({"z": 1, "a": 2});
        let canonical = jcs_canonicalise(&obj).unwrap();
        assert_eq!(canonical, r#"{"a":2,"z":1}"#);
    }

    #[test]
    fn sign_deterministic_for_same_inputs() {
        // Ed25519 signing is deterministic (RFC 8032): the same key,
        // document, and timestamp always produce the same proofValue.
        let (signing_key, _verifying_key) = test_keypair();
        let vm_id = "https://noombat.social/users/alice#ed25519-key";

        let mut a1 = test_activity();
        sign(&mut a1, &signing_key.to_bytes(), vm_id).unwrap();
        let created = a1["proof"]["created"].as_str().unwrap().to_owned();
        let pv1 = a1["proof"]["proofValue"].as_str().unwrap().to_owned();

        // Rebuild a fresh activity, sign it, then patch the timestamp
        // to match `a1` and re-sign so the inputs are identical.
        let mut a2 = test_activity();
        ensure_data_integrity_context(&mut a2);

        // Manually construct the proof config with the same timestamp.
        let mut proof_config = json!({
            "type": PROOF_TYPE,
            "cryptosuite": CRYPTOSUITE,
            "verificationMethod": vm_id,
            "proofPurpose": PROOF_PURPOSE,
            "created": created,
        });
        if let Some(ctx) = a2.get("@context") {
            proof_config["@context"] = ctx.clone();
        }

        let canonical_doc = jcs_canonicalise(&a2).unwrap();
        let canonical_pc = jcs_canonicalise(&proof_config).unwrap();
        let doc_hash = sha256(canonical_doc.as_bytes());
        let pc_hash = sha256(canonical_pc.as_bytes());
        let mut input = [0u8; 64];
        input[..32].copy_from_slice(&pc_hash);
        input[32..].copy_from_slice(&doc_hash);

        let sig = SigningKey::from_bytes(&signing_key.to_bytes()).sign(&input);
        let pv2 = format!("z{}", bs58::encode(sig.to_bytes()).into_string());

        assert_eq!(pv1, pv2, "same key + same document + same timestamp must produce the same proofValue");
    }
}
