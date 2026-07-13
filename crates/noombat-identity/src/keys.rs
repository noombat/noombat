// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! RSA key-pair generation for actor HTTP Signatures.

use rsa::RsaPrivateKey;
use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};

use noombat_core::error::{NoombatError, Result};

/// Generate a 2048-bit RSA key pair, returning `(public_pem, private_pem)`.
///
/// This is a CPU-intensive operation (typically 20–200 ms). Use
/// [`generate_rsa_keypair_async`] when calling from an async context to
/// avoid blocking the Tokio worker thread.
pub fn generate_rsa_keypair() -> Result<(String, String)> {
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

    Ok((public_pem, private_pem))
}

/// Async wrapper that offloads [`generate_rsa_keypair`] to a blocking
/// thread pool, preventing it from starving the Tokio worker threads.
pub async fn generate_rsa_keypair_async() -> Result<(String, String)> {
    tokio::task::spawn_blocking(generate_rsa_keypair)
        .await
        .map_err(|e| NoombatError::Internal(format!("key generation task failed: {e}")))?
}
