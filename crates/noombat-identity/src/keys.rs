// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! RSA and Ed25519 key-pair generation for actor HTTP Signatures,
//! and FEP-8b32 Object Integrity Proofs.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use ed25519_dalek::SigningKey;
use getrandom::SysRng;
use getrandom::rand_core::UnwrapErr;
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
/// This is a CPU-intensive operation (typically 20-200 ms). Use
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
    // Entropy comes straight from the OS, not through `rand`.
    //
    // ed25519-dalek 3 requires an RNG implementing rand_core 0.10's
    // `CryptoRng`. The workspace's `rand` is pinned at 0.8 because
    // rsa 0.9 needs rand_core 0.6 for `generate_rsa_keypair` above, and
    // one `rand` cannot satisfy both. `SysRng` is getrandom's direct
    // interface to the operating system's CSPRNG, which is what a
    // signing key must be seeded from.
    //
    // `UnwrapErr` turns the fallible `TryCryptoRng` into the infallible
    // `CryptoRng` the API wants, by panicking if the OS cannot provide
    // entropy. That is the correct failure mode here and must not be
    // "fixed" into something that continues: a key generated from a
    // degraded source signs and verifies perfectly, so nothing downstream
    // would notice, and every actor key would be predictable.
    let mut csprng = UnwrapErr(SysRng);
    let signing_key = SigningKey::generate(&mut csprng);
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

// ..... Tests .....

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, Verifier, VerifyingKey};

    /// RFC 8032 section 7.1 TEST 1 secret seed.
    ///
    /// Chosen so the derived public key below can be checked against the
    /// RFC by anyone, rather than against a value this project produced.
    const SEED: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];

    /// The RFC 8032 TEST 1 public key for [`SEED`].
    const PUBLIC_KEY_HEX: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

    const MESSAGE: &[u8] = b"noombat FEP-8b32 integrity proof vector";

    /// Signature over [`MESSAGE`], captured from ed25519-dalek 2.2.0
    /// before the upgrade to 3.0.0.
    const SIGNATURE_HEX: &str = "2f788a1d4ebb5dd32ad41b5655dc8ca133cdf671d6e58b63616f75bfcdee9d6a\
                                 aa0378c61a157ad78e191f3a2dc76c1d8f0ecd605b769c6664c8b3ac3f8dba08";

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Signing is byte-for-byte stable across curve backends.
    ///
    /// Ed25519 is deterministic (RFC 8032): one seed and one message
    /// yield one signature, whatever implementation produces it. That
    /// makes this vector a real guard rather than a snapshot of our own
    /// behaviour, and it is why the seed is the RFC's rather than ours.
    ///
    /// It exists because the ed25519-dalek 2.2.0 to 3.0.0 upgrade
    /// swapped curve25519-dalek 4.1.3 for 5.0.0 underneath, i.e. new
    /// field arithmetic under the same API. Nothing in the type system
    /// or the test suite would have caught a change in the emitted
    /// bytes, and the consequence would not be a crash: every actor key
    /// already published in an `assertionMethod`, and every FEP-8b32
    /// proof already federated, would simply stop verifying against
    /// peers. The expected values here were captured from 2.2.0 before
    /// the bump and are unchanged under 3.0.0.
    #[test]
    fn signing_is_stable_across_curve_backends() {
        let signing_key = SigningKey::from_bytes(&SEED);
        let verifying_key: VerifyingKey = signing_key.verifying_key();

        assert_eq!(
            hex(verifying_key.as_bytes()),
            PUBLIC_KEY_HEX,
            "public key derivation changed; this is the RFC 8032 TEST 1 vector"
        );

        let signature = signing_key.sign(MESSAGE);
        assert_eq!(
            hex(&signature.to_bytes()),
            SIGNATURE_HEX.replace([' ', '\n'], ""),
            "signature bytes changed: previously published proofs will no longer verify"
        );

        assert!(
            verifying_key.verify(MESSAGE, &signature).is_ok(),
            "the implementation cannot verify its own signature"
        );
    }

    /// Generated keys are the right shape and are not constant.
    ///
    /// The second half matters more than it looks: `UnwrapErr(SysRng)`
    /// draws the seed from the OS, and a degraded or stubbed source
    /// would still produce keys that sign and verify perfectly. Two
    /// successive generations being identical is the cheapest signal
    /// that entropy is not entropy.
    #[test]
    fn generated_keys_are_well_formed_and_distinct() {
        let first = generate_ed25519_keypair().expect("key generation");
        let second = generate_ed25519_keypair().expect("key generation");

        assert!(first.public_multibase.starts_with('z'), "multibase prefix");
        assert_eq!(
            BASE64
                .decode(&first.private_base64)
                .expect("private key is base64")
                .len(),
            32,
            "an Ed25519 secret key is 32 bytes"
        );
        assert_ne!(
            first.public_multibase, second.public_multibase,
            "two generations produced the same key: the RNG is not random"
        );
    }
}
