// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! RSA and Ed25519 key-pair generation for actor HTTP Signatures,
//! and FEP-8b32 Object Integrity Proofs.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use ed25519_dalek::SigningKey;
use rsa::RsaPrivateKey;
use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};

use noombat_core::error::{NoombatError, Result};

/// RSA key pair: `(public_pem, private_pem)`.
pub struct RsaKeypair {
    pub public_pem: String,
    pub private_pem: String,
}

/// Ed25519 key pair: multibase-encoded public key and raw private key bytes.
pub struct Ed25519Keypair {
    /// Multibase-encoded public key (`z` prefix + Base58btc), suitable
    /// for the `assertionMethod` / `multikey` property in the AP actor
    /// document (per FEP-521a).
    pub public_multibase: String,
    /// Base64-encoded Ed25519 private key (32 bytes).
    pub private_base64: String,
}

/// Combined key material for a new local actor.
pub struct ActorKeypair {
    pub rsa: RsaKeypair,
    pub ed25519: Ed25519Keypair,
}

/// Generate a 2048-bit RSA key pair, returning `(public_pem, private_pem)`.
///
/// This is a CPU-intensive operation (typically 20–200 ms). Use
/// [`generate_keypair_async`] when calling from an async context to
/// avoid blocking the Tokio worker thread.
pub fn generate_rsa_keypair() -> Result<RsaKeypair> {
    let mut rng = rand::thread_rng();
    let bits = 2048;
    let private_key = RsaPrivateKey::new(&mut rng, bits)
        .map_err(|e| NoombatError::Internal(format!("RSA key generation failed: {e}")))?;

    let private_pem = private_key
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|e| NoombatError::Internal(format!("private key PEM encoding failed: {e}")))?
        .to_string();

    let public_pem = private_key
        .to_public_key()
        .to_public_key_pem(LineEnding::LF)
        .map_err(|e| NoombatError::Internal(format!("public key PEM encoding failed: {e}")))?;

    Ok(RsaKeypair {
        public_pem,
        private_pem,
    })
}

/// Generate an Ed25519 key pair.
///
/// The public key is returned in multibase encoding (`z` prefix +
/// Base58btc of the raw 32-byte public key), suitable for the
/// `assertionMethod` property in the ActivityPub actor document
/// (per FEP-521a).
pub fn generate_ed25519_keypair() -> Result<Ed25519Keypair> {
    let mut rng = rand::thread_rng();
    let signing_key = SigningKey::generate(&mut rng);
    let verifying_key = signing_key.verifying_key();

    // Multibase: `z` prefix followed by Base58btc-encoded raw public key.
    let public_multibase = format!("z{}", bs58::encode(verifying_key.as_bytes()).into_string());

    // Store the 32-byte secret key as Base64.
    let private_base64 = BASE64.encode(signing_key.to_bytes());

    Ok(Ed25519Keypair {
        public_multibase,
        private_base64,
    })
}

/// Generate both RSA and Ed25519 key pairs for a new local actor.
pub fn generate_keypair() -> Result<ActorKeypair> {
    let rsa = generate_rsa_keypair()?;
    let ed25519 = generate_ed25519_keypair()?;
    Ok(ActorKeypair { rsa, ed25519 })
}

/// Async wrapper that offloads [`generate_keypair`] to a blocking
/// thread pool, preventing it from starving the Tokio worker threads.
pub async fn generate_keypair_async() -> Result<ActorKeypair> {
    tokio::task::spawn_blocking(generate_keypair)
        .await
        .map_err(|e| NoombatError::Internal(format!("key generation task failed: {e}")))?
}

/// Legacy async wrapper for RSA-only generation (used by callers that
/// do not yet need Ed25519).
pub async fn generate_rsa_keypair_async() -> Result<(String, String)> {
    let kp = tokio::task::spawn_blocking(generate_rsa_keypair)
        .await
        .map_err(|e| NoombatError::Internal(format!("key generation task failed: {e}")))?;
    kp.map(|k| (k.public_pem, k.private_pem))
}
