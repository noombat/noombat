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
/// Mutates in place: adds a `proof` property, replacing any existing one,
/// and appends the Data Integrity context URI if it is absent.
pub fn sign(
    activity: &mut Value,
    signing_key_bytes: &[u8; 32],
    verification_method_id: &str,
) -> Result<()> {
    let created = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
    sign_with_config(
        activity,
        signing_key_bytes,
        json!({
            "type": PROOF_TYPE,
            "cryptosuite": CRYPTOSUITE,
            "verificationMethod": verification_method_id,
            "proofPurpose": PROOF_PURPOSE,
            "created": created,
        }),
    )
}

/// Sign with a caller-supplied proof configuration.
///
/// Split out from [`sign`] so tests can mint proofs this codebase would
/// never emit, such as one carrying `expires` or one made for another
/// `proofPurpose`. Those cases cannot be produced by editing a signed
/// document, because the configuration is itself covered by the
/// signature: editing it yields a broken proof rather than a differently
/// purposed one, and from the outside the two look identical.
fn sign_with_config(
    activity: &mut Value,
    signing_key_bytes: &[u8; 32],
    mut proof_config: Value,
) -> Result<()> {
    ensure_data_integrity_context(activity);

    // The unsigned document is the activity without any existing `proof`.
    let mut unsigned_doc = activity.clone();
    unsigned_doc
        .as_object_mut()
        .ok_or_else(|| NoombatError::Internal("activity is not a JSON object".into()))?
        .remove("proof");

    // Per the W3C spec: if the unsigned document has `@context`, set it on
    // the proof configuration as well.
    if let Some(ctx) = unsigned_doc.get("@context") {
        proof_config["@context"] = ctx.clone();
    }

    let canonical_doc = jcs_canonicalise(&unsigned_doc)?;
    let canonical_proof_config = jcs_canonicalise(&proof_config)?;

    let doc_hash = sha256(canonical_doc.as_bytes());
    let proof_config_hash = sha256(canonical_proof_config.as_bytes());

    // The signature input is proofConfigHash || documentHash, in that
    // order.
    let mut signature_input = [0u8; 64];
    signature_input[..32].copy_from_slice(&proof_config_hash);
    signature_input[32..].copy_from_slice(&doc_hash);

    let signing_key = SigningKey::from_bytes(signing_key_bytes);
    let signature: Signature = signing_key.sign(&signature_input);

    let proof_value = format!("z{}", bs58::encode(signature.to_bytes()).into_string());
    proof_config["proofValue"] = Value::String(proof_value);

    // Remove `@context` from the proof before embedding: it was needed
    // for the hash computation but is redundant in the output (the
    // document's own `@context` is authoritative).
    proof_config.as_object_mut().unwrap().remove("@context");

    activity["proof"] = proof_config;

    debug!("FEP-8b32 integrity proof attached");
    Ok(())
}

/// [`sign_with_config`], reachable from tests in other modules.
#[cfg(test)]
pub(crate) fn sign_with_config_for_test(
    activity: &mut Value,
    signing_key_bytes: &[u8; 32],
    proof_config: Value,
) -> Result<()> {
    sign_with_config(activity, signing_key_bytes, proof_config)
}

/// The verification method URI for a local actor's Ed25519 key.
///
/// Defined once. A signer and a verifier that disagree about this string
/// produce proofs that are individually well formed and mutually
/// useless, and nothing fails until federation does.
pub fn verification_method_id(actor_ap_id: &str) -> String {
    format!("{actor_ap_id}#ed25519-key")
}

/// Attach a proof to a locally authored document, using the actor's key
/// as stored in `actors.ed25519_private_key` (Base64).
///
/// Returns whether a proof was attached. Failure is deliberately not an
/// error for the caller to propagate: HTTP Signatures remain the primary
/// authentication mechanism, and an unproven post beats a failed publish.
pub fn sign_as_actor(
    document: &mut Value,
    ed25519_private_base64: &str,
    actor_ap_id: &str,
) -> bool {
    let signing_key = match decode_private_key_base64(ed25519_private_base64) {
        Ok(key) => key,
        Err(e) => {
            warn!(actor = actor_ap_id, "unusable Ed25519 private key: {e}");
            return false;
        }
    };
    match sign(document, &signing_key, &verification_method_id(actor_ap_id)) {
        Ok(()) => true,
        Err(e) => {
            warn!(actor = actor_ap_id, "failed to attach integrity proof: {e}");
            false
        }
    }
}

// ..... Verification .....

/// Largest document this will canonicalise in order to check a proof.
///
/// JCS canonicalisation sorts every object key recursively and clones the
/// document first, so the work is superlinear in a size the sender
/// chooses. Canonicalising is the denial of service; verifying the
/// signature afterwards is cheap.
///
/// This must stay equal to the inbox body limit
/// (`routes::federation::router`). While they differed, a signed document
/// between the two was accepted by the transport and then refused here,
/// so signing content was what made it undeliverable.
///
/// Over the bound reports [`VerificationResult::Invalid`] rather than
/// absent, because we were handed a proof and declined to check it. That
/// buys accuracy of reporting, not security: omitting `proof` reaches
/// `Absent` without any padding.
pub const MAX_PROOF_DOCUMENT_BYTES: usize = 1024 * 1024;

/// How far ahead of our clock a proof's `created` may sit.
///
/// Federated peers do not share a clock, and a proof signed a moment ago
/// on a host running slightly fast is ordinary. Beyond this the timestamp
/// is not skew.
const CREATED_SKEW_TOLERANCE: chrono::Duration = chrono::Duration::minutes(5);

/// The result of verifying an integrity proof on an inbound activity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationResult {
    /// The proof is valid: the signature matches the document content
    /// and the claimed verification method.
    Valid,
    /// The proof is present but invalid (signature mismatch, malformed
    /// encoding, key-type mismatch, or a document exceeding
    /// [`MAX_PROOF_DOCUMENT_BYTES`]).
    Invalid,
    /// No `proof` property is present on the activity.
    Absent,
}

/// Verify an FEP-8b32 integrity proof on an inbound ActivityPub activity.
///
/// Does **not** fetch the verification method: the caller supplies the
/// claimed author's multibase Ed25519 public key, obtained by resolving
/// the URI from [`extract_verification_method_id`].
pub fn verify(activity: &Value, public_key_multibase: &str) -> VerificationResult {
    let proof = match select_proof(activity) {
        Some(p) => p,
        None => return VerificationResult::Absent,
    };

    // The size bound comes first, ahead of the clone at `unsigned_doc`
    // and both `jcs_canonicalise` calls. Measuring costs one pass and no
    // allocation; canonicalising is what an oversized document is aimed
    // at. See [`MAX_PROOF_DOCUMENT_BYTES`].
    let doc_len = serialised_len(activity);
    if doc_len > MAX_PROOF_DOCUMENT_BYTES {
        warn!(
            doc_len,
            limit = MAX_PROOF_DOCUMENT_BYTES,
            "integrity proof document exceeds the size bound; refusing to canonicalise"
        );
        return VerificationResult::Invalid;
    }

    // `type` and `cryptosuite` were matched by `select_proof`.
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

    let mut proof_config = proof.clone();
    proof_config.as_object_mut().unwrap().remove("proofValue");

    // Per the W3C spec: if the proof config does not carry `@context`,
    // inherit it from the document.
    if proof_config.get("@context").is_none()
        && let Some(ctx) = activity.get("@context")
    {
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
            // Only now are the proof's own claims worth reading.
            //
            // `proofPurpose`, `created` and `expires` live inside the
            // proof configuration, which is hashed into the signature.
            // Checking them before verifying would mean acting on
            // unauthenticated input, and would hand anyone a way to
            // downgrade a good proof to "unproven" by editing a field in
            // transit. After verification they are the signer's own
            // statements, and a document whose configuration was edited
            // has already failed above as `Invalid`.
            if let Some(reason) = unusable_claim(proof) {
                warn!(
                    reason,
                    "integrity proof verifies but is not a usable authorship assertion"
                );
                return VerificationResult::Absent;
            }
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
    select_proof(activity)?
        .get("verificationMethod")
        .and_then(|v| v.as_str())
}

/// The proof this implementation can check, from a `proof` property that
/// may be a single object or a set.
///
/// VC-DI allows a proof *set*, and implementations do emit one. Requiring
/// an object meant a document carrying two proofs, one of them ours, read
/// as unproven: the strictly worse of the two failure modes, because it
/// is silent. Entries that are not `DataIntegrityProof` with our
/// cryptosuite are skipped rather than rejected; another suite is
/// somebody else's business, not a defect in the document.
fn select_proof(document: &Value) -> Option<&Value> {
    fn ours(candidate: &Value) -> bool {
        candidate.is_object()
            && candidate.get("type").and_then(|v| v.as_str()) == Some(PROOF_TYPE)
            && candidate.get("cryptosuite").and_then(|v| v.as_str()) == Some(CRYPTOSUITE)
    }

    match document.get("proof")? {
        Value::Array(entries) => entries.iter().find(|e| ours(e)),
        single if ours(single) => Some(single),
        _ => None,
    }
}

// ..... Helper: decode Ed25519 private key from Base64 .....

/// Decode a Base64-encoded Ed25519 private key (as stored in the
/// `ed25519_private_key` column) into a raw 32-byte array.
pub fn decode_private_key_base64(base64_str: &str) -> Result<[u8; 32]> {
    let bytes = BASE64
        .decode(base64_str)
        .map_err(|e| NoombatError::Internal(format!("Ed25519 private key Base64 decode: {e}")))?;

    bytes.try_into().map_err(|v: Vec<u8>| {
        NoombatError::Internal(format!(
            "Ed25519 private key has unexpected length {} (expected 32)",
            v.len()
        ))
    })
}

// ..... Internal helpers .....

/// Why a cryptographically sound proof still is not usable evidence of
/// authorship, or `None` when it is.
///
/// Every one of these is `Absent` rather than `Invalid` at the call site:
/// the document is not forged, we simply hold no assertion about it.
/// Discarding a peer's content over a property they set for their own
/// reasons would be a federation break, and recording a `TRUE` we cannot
/// justify would be worse.
fn unusable_claim(proof: &Value) -> Option<&'static str> {
    // A signature is evidence of whatever it was made for. One minted
    // over these bytes for `authentication` says the actor proved control
    // of a key, not that they assert authorship, and treating one as the
    // other is purpose confusion.
    if proof.get("proofPurpose").and_then(|v| v.as_str()) != Some(PROOF_PURPOSE) {
        return Some("proofPurpose is not assertionMethod");
    }

    // There is no freshness bound beyond what the signer declared,
    // deliberately: an object proof is meant to outlive its delivery, and
    // a post signed last year is still signed.
    if let Some(expires) = proof.get("expires").and_then(|v| v.as_str()) {
        match chrono::DateTime::parse_from_rfc3339(expires) {
            Ok(deadline) if Utc::now() > deadline.with_timezone(&Utc) => {
                return Some("proof has expired");
            }
            Ok(_) => {}
            Err(_) => return Some("proof has an unparseable expires"),
        }
    }

    // A proof that claims to have been made in the future cannot be what
    // it says it is, beyond ordinary clock skew between federated peers.
    if let Some(created) = proof.get("created").and_then(|v| v.as_str())
        && let Ok(stamp) = chrono::DateTime::parse_from_rfc3339(created)
        && stamp.with_timezone(&Utc) > Utc::now() + CREATED_SKEW_TOLERANCE
    {
        return Some("proof is dated in the future");
    }

    None
}

/// A sink that counts the bytes written to it and keeps none of them.
struct ByteCounter(usize);

impl std::io::Write for ByteCounter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0 += buf.len();
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Serialised byte length of a JSON value, without materialising it.
///
/// Used for the pre-canonicalisation size bound, where allocating the
/// serialised form of an oversized document would be the very cost the
/// bound exists to avoid.
fn serialised_len(value: &Value) -> usize {
    let mut counter = ByteCounter(0);
    // Writing into a counter cannot fail, and a `Value` is always
    // serialisable, so the result carries no information.
    let _ = serde_json::to_writer(&mut counter, value);
    counter.0
}

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

/// Whether a multibase string decodes as an Ed25519 public key.
///
/// The `z` prefix is base58btc, shared by every Multikey type, so
/// filtering on it selects P-256 and RSA keys just as happily as
/// Ed25519. Testing the decode is the only honest check: a wrong key
/// cached here fails every proof the peer sends until something forces a
/// refresh.
pub fn is_ed25519_multikey(multibase: &str) -> bool {
    decode_multibase_public_key(multibase).is_ok()
}

/// Decode a multibase-encoded Ed25519 public key.
///
/// Expected format: `z` prefix followed by base58btc-encoded raw
/// 32-byte public key (as produced by
/// [`noombat_identity::keys::generate_ed25519_keypair`]).
fn decode_multibase_public_key(multibase: &str) -> Result<[u8; 32]> {
    let raw = multibase.strip_prefix('z').ok_or_else(|| {
        NoombatError::Internal(format!(
            "multibase public key does not start with 'z': {multibase}"
        ))
    })?;

    let decoded = bs58::decode(raw).into_vec().map_err(|e| {
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

    key_bytes
        .try_into()
        .map_err(|_| NoombatError::Internal("Ed25519 public key slice conversion failed".into()))
}

/// Decode a multibase-encoded Ed25519 signature.
///
/// Expected format: `z` prefix followed by base58btc-encoded raw
/// 64-byte signature.
fn decode_multibase_signature(multibase: &str) -> Result<Vec<u8>> {
    let raw = multibase.strip_prefix('z').ok_or_else(|| {
        NoombatError::Internal(format!(
            "multibase signature does not start with 'z': {multibase}"
        ))
    })?;

    let decoded = bs58::decode(raw).into_vec().map_err(|e| {
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
            let already_present = arr
                .iter()
                .any(|v| v.as_str() == Some(DATA_INTEGRITY_CONTEXT));
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
        let row: Option<(String, Option<String>)> =
            sqlx::query_as("SELECT ap_id, ed25519_private_key FROM actors WHERE ap_id = $1")
                .bind(signing_key_id)
                .fetch_optional(&self.pool)
                .await
                .map_err(NoombatError::from)?;

        let (ap_id, sealed_ed25519) = match row {
            Some((ap_id, Some(key))) => (ap_id, key),
            _ => {
                debug!(
                    actor = signing_key_id,
                    "no Ed25519 private key available; skipping integrity proof"
                );
                return Ok(());
            }
        };

        // Decrypt the Ed25519 private key from the database.
        let ed25519_private = noombat_core::envelope::open_auto(&sealed_ed25519)?;

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
        let actor_ap_id = vm_id.split('#').next().unwrap_or(&vm_id);

        // Look up the actor's Ed25519 public key.
        let public_key: Option<String> =
            sqlx::query_scalar("SELECT ed25519_public_key FROM actors WHERE ap_id = $1")
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
            0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec,
            0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03,
            0x1c, 0xae, 0x7f, 0x60,
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
        let public_multibase = format!("z{}", bs58::encode(verifying_key.as_bytes()).into_string());

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

    /// The size bound must reject a document that would otherwise
    /// verify, which is what distinguishes "refused before
    /// canonicalisation" from "failed the signature check".
    ///
    /// Exercised just over the limit rather than at a realistic size: it
    /// is the same branch, taken before the document is cloned or
    /// canonicalised, and a 1 MiB fixture keeps the suite fast.
    #[test]
    fn oversized_document_is_refused_even_when_correctly_signed() {
        let (signing_key, verifying_key) = test_keypair();
        let public_multibase = format!("z{}", bs58::encode(verifying_key.as_bytes()).into_string());
        let vm_id = "https://noombat.social/users/alice#ed25519-key";

        // A control at the same shape but under the bound, to show the
        // fixture itself is signable and verifiable.
        let mut small = test_activity();
        small["content"] = serde_json::json!("x".repeat(1024));
        sign(&mut small, &signing_key.to_bytes(), vm_id).unwrap();
        assert_eq!(
            verify(&small, &public_multibase),
            VerificationResult::Valid,
            "control document under the bound must verify"
        );

        let mut oversized = test_activity();
        oversized["content"] = serde_json::json!("x".repeat(MAX_PROOF_DOCUMENT_BYTES));
        sign(&mut oversized, &signing_key.to_bytes(), vm_id).unwrap();
        assert!(serialised_len(&oversized) > MAX_PROOF_DOCUMENT_BYTES);

        // Signed with the very key we verify against, so anything other
        // than `Invalid` here means the bound did not fire.
        assert_eq!(
            verify(&oversized, &public_multibase),
            VerificationResult::Invalid,
            "a document over the bound must be refused, not verified"
        );
    }

    #[test]
    fn serialised_len_matches_a_real_serialisation() {
        let activity = test_activity();
        assert_eq!(
            serialised_len(&activity),
            serde_json::to_string(&activity).unwrap().len()
        );
    }

    /// What `post_outbox` publishes must be what the receiving inbox
    /// path can check: same verification method convention, same key.
    #[test]
    fn sign_as_actor_round_trips_through_the_convention() {
        let keypair = noombat_identity::keys::generate_ed25519_keypair().unwrap();
        let actor = "https://noombat.social/users/alice";

        let mut object = serde_json::json!({
            "@context": "https://www.w3.org/ns/activitystreams",
            "id": "https://noombat.social/posts/1",
            "type": "Note",
            "attributedTo": actor,
            "content": "<p>hello</p>",
        });

        assert!(sign_as_actor(&mut object, &keypair.private_base64, actor));

        // The verifier resolves the actor by stripping the fragment, so
        // the method must sit under the actor's own URI or the author
        // binding in `relay_verify` will reject it as somebody else's.
        let vm = extract_verification_method_id(&object).expect("proof carries a method");
        assert_eq!(vm, format!("{actor}#ed25519-key"));
        assert_eq!(vm.split('#').next().unwrap(), actor);

        assert_eq!(
            verify(&object, &keypair.public_multibase),
            VerificationResult::Valid
        );
    }

    #[test]
    fn sign_as_actor_reports_failure_on_an_unusable_key() {
        let mut object = serde_json::json!({ "id": "x", "type": "Note" });
        assert!(!sign_as_actor(
            &mut object,
            "not base64 at all!!",
            "https://noombat.social/users/alice"
        ));
        assert!(object.get("proof").is_none());
    }

    #[test]
    fn verify_accepts_a_proof_inside_a_proof_set() {
        let (signing_key, verifying_key) = test_keypair();
        let public_multibase = format!("z{}", bs58::encode(verifying_key.as_bytes()).into_string());
        let vm_id = "https://noombat.social/users/alice#ed25519-key";

        let mut activity = test_activity();
        sign(&mut activity, &signing_key.to_bytes(), vm_id).unwrap();
        let ours = activity["proof"].clone();

        // VC-DI permits a proof set, and a foreign suite alongside ours
        // must not hide ours.
        activity["proof"] = serde_json::json!([
            {
                "type": PROOF_TYPE,
                "cryptosuite": "ecdsa-jcs-2019",
                "verificationMethod": "https://elsewhere.example/keys/1",
                "proofPurpose": PROOF_PURPOSE,
                "proofValue": "zSomeoneElsesSignature"
            },
            ours
        ]);

        assert_eq!(
            verify(&activity, &public_multibase),
            VerificationResult::Valid
        );
        assert_eq!(extract_verification_method_id(&activity), Some(vm_id));
    }

    /// Build a proof config the production signer would not emit.
    fn config(extras: &[(&str, Value)]) -> Value {
        let mut cfg = json!({
            "type": PROOF_TYPE,
            "cryptosuite": CRYPTOSUITE,
            "verificationMethod": "https://noombat.social/users/alice#ed25519-key",
            "proofPurpose": PROOF_PURPOSE,
            "created": "2026-01-01T00:00:00Z",
        });
        for (k, v) in extras {
            cfg[*k] = v.clone();
        }
        cfg
    }

    #[test]
    fn verify_refuses_a_proof_made_for_another_purpose() {
        let (signing_key, verifying_key) = test_keypair();
        let public_multibase = format!("z{}", bs58::encode(verifying_key.as_bytes()).into_string());

        // Signed *as* an authentication proof, not edited into one: the
        // configuration is covered by the signature, so editing would
        // only produce a broken proof and test the wrong branch.
        let mut activity = test_activity();
        sign_with_config(
            &mut activity,
            &signing_key.to_bytes(),
            config(&[("proofPurpose", json!("authentication"))]),
        )
        .unwrap();

        assert_eq!(
            verify(&activity, &public_multibase),
            VerificationResult::Absent,
            "a proof of key control is not an assertion of authorship"
        );
    }

    #[test]
    fn editing_the_proof_configuration_is_invalid_not_merely_unusable() {
        let (signing_key, verifying_key) = test_keypair();
        let public_multibase = format!("z{}", bs58::encode(verifying_key.as_bytes()).into_string());

        let mut activity = test_activity();
        sign(
            &mut activity,
            &signing_key.to_bytes(),
            "https://noombat.social/users/alice#ed25519-key",
        )
        .unwrap();
        activity["proof"]["proofPurpose"] = json!("authentication");

        // The claim checks run after verification precisely so that this
        // is a broken proof rather than a quiet downgrade to unproven.
        assert_eq!(
            verify(&activity, &public_multibase),
            VerificationResult::Invalid
        );
    }

    #[test]
    fn verify_honours_expiry_and_rejects_future_dating() {
        let (signing_key, verifying_key) = test_keypair();
        let public_multibase = format!("z{}", bs58::encode(verifying_key.as_bytes()).into_string());

        let mut expired = test_activity();
        sign_with_config(
            &mut expired,
            &signing_key.to_bytes(),
            config(&[("expires", json!("2020-01-01T00:00:00Z"))]),
        )
        .unwrap();
        assert_eq!(
            verify(&expired, &public_multibase),
            VerificationResult::Absent
        );

        let mut future = test_activity();
        sign_with_config(
            &mut future,
            &signing_key.to_bytes(),
            config(&[("created", json!("2099-01-01T00:00:00Z"))]),
        )
        .unwrap();
        assert_eq!(
            verify(&future, &public_multibase),
            VerificationResult::Absent
        );

        // An expiry still ahead of us changes nothing.
        let mut live = test_activity();
        sign_with_config(
            &mut live,
            &signing_key.to_bytes(),
            config(&[("expires", json!("2099-01-01T00:00:00Z"))]),
        )
        .unwrap();
        assert_eq!(verify(&live, &public_multibase), VerificationResult::Valid);
    }

    #[test]
    fn is_ed25519_multikey_tests_the_decode_not_the_prefix() {
        let (_, verifying_key) = test_keypair();
        let real = format!("z{}", bs58::encode(verifying_key.as_bytes()).into_string());
        assert!(is_ed25519_multikey(&real));

        // Correct multibase, correct multicodec, still Ed25519.
        let mut prefixed = vec![0xed, 0x01];
        prefixed.extend_from_slice(verifying_key.as_bytes());
        assert!(is_ed25519_multikey(&format!(
            "z{}",
            bs58::encode(&prefixed).into_string()
        )));

        // A 33-byte compressed P-256 key is also base58btc with a `z`.
        let p256_shaped = format!("z{}", bs58::encode([0x02u8; 33]).into_string());
        assert!(
            !is_ed25519_multikey(&p256_shaped),
            "the `z` prefix says base58btc, not Ed25519"
        );
        assert!(!is_ed25519_multikey("not-multibase"));
    }

    /// Build the signature from the specification steps rather than by
    /// calling [`sign`], so the two cannot drift into a shared, mutually
    /// consistent, wrong format.
    ///
    /// This is not an interop fixture: it uses the same JCS and SHA-256
    /// crates the implementation does. What it pins independently is the
    /// *construction*, which is where `eddsa-jcs-2022` implementations
    /// actually diverge: which document is hashed, that `@context` is
    /// inherited by the proof configuration, that `proofValue` is excluded
    /// from it, and that the signing input is proofConfigHash then
    /// documentHash and not the reverse. A document signed by another
    /// implementation is still wanted and still absent.
    #[test]
    fn verify_accepts_a_signature_constructed_from_the_spec_steps() {
        use ed25519_dalek::Signer as _;

        let (signing_key, verifying_key) = test_keypair();
        let public_multibase = format!("z{}", bs58::encode(verifying_key.as_bytes()).into_string());

        let document = serde_json::json!({
            "@context": ["https://www.w3.org/ns/activitystreams", DATA_INTEGRITY_CONTEXT],
            "id": "https://noombat.social/posts/1",
            "type": "Note",
            "attributedTo": "https://noombat.social/users/alice",
            "content": "<p>hand rolled</p>",
        });

        let proof_config = serde_json::json!({
            "type": "DataIntegrityProof",
            "cryptosuite": "eddsa-jcs-2022",
            "verificationMethod": "https://noombat.social/users/alice#ed25519-key",
            "proofPurpose": "assertionMethod",
            "created": "2026-01-01T00:00:00Z",
            "@context": document["@context"].clone(),
        });

        let canon_doc = serde_json_canonicalizer::to_string(&document).unwrap();
        let canon_cfg = serde_json_canonicalizer::to_string(&proof_config).unwrap();

        let mut input = Vec::with_capacity(64);
        input.extend_from_slice(&sha2::Sha256::digest(canon_cfg.as_bytes()));
        input.extend_from_slice(&sha2::Sha256::digest(canon_doc.as_bytes()));

        let signature = signing_key.sign(&input);

        let mut signed = document.clone();
        let mut embedded = proof_config.clone();
        embedded.as_object_mut().unwrap().remove("@context");
        embedded["proofValue"] = serde_json::json!(format!(
            "z{}",
            bs58::encode(signature.to_bytes()).into_string()
        ));
        signed["proof"] = embedded;

        assert_eq!(
            verify(&signed, &public_multibase),
            VerificationResult::Valid
        );
    }

    #[test]
    fn verify_fails_on_tampered_content() {
        let (signing_key, verifying_key) = test_keypair();
        let public_multibase = format!("z{}", bs58::encode(verifying_key.as_bytes()).into_string());

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
        let has_di = ctx
            .iter()
            .any(|v| v.as_str() == Some(DATA_INTEGRITY_CONTEXT));
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
        let multibase = format!("z{}", bs58::encode(verifying_key.as_bytes()).into_string());

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

        assert_eq!(
            pv1, pv2,
            "same key + same document + same timestamp must produce the same proofValue"
        );
    }
}
