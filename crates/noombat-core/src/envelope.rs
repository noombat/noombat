// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Envelope encryption for secrets at rest (AES-256-GCM).
//!
//! Provides [`seal`] and [`open`] helpers that encrypt and decrypt
//! UTF-8 strings using a 256-bit key-encryption key (KEK).
//! The ciphertext is stored as a Base64 string containing
//! `nonce (96 bits / 12 bytes, per the AES-GCM specification) ||
//! ciphertext || authentication tag (128 bits / 16 bytes)`.
//!
//! A process-global key is initialised once at startup via [`init`]
//! and retrieved via [`get_key`]. When the KEK is absent (development
//! mode), the `_auto` helpers pass data through unmodified.
//!
//! When the KEK is present and decryption fails, [`open`] falls back
//! to returning the raw value unchanged, logging a warning. This
//! allows a graceful migration period where pre-existing plaintext
//! rows coexist with newly encrypted ciphertext.

use std::sync::OnceLock;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{NoombatError, Result};

// ..... Process-global key .....

/// The singleton envelope key, set once at startup.
static KEY: OnceLock<Option<EnvelopeKey>> = OnceLock::new();

/// Initialise the process-global envelope key.
///
/// Must be called exactly once, before any encryption or decryption.
/// Passing `None` disables envelope encryption (development mode).
///
/// # Panics
///
/// Panics if called more than once.
pub fn init(key: Option<EnvelopeKey>) {
    KEY.set(key)
        .expect("envelope key already initialised (init called twice)");
}

/// Return a reference to the process-global envelope key, or `None`
/// if envelope encryption is disabled.
pub fn get_key() -> Option<&'static EnvelopeKey> {
    KEY.get().and_then(|opt| opt.as_ref())
}

// ..... Key type .....

/// A 256-bit key-encryption key for envelope encryption.
///
/// The inner byte array is scrubbed from memory when the value is
/// dropped ([`ZeroizeOnDrop`]). The [`Debug`] implementation redacts
/// the key material to prevent accidental leakage in log output.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct EnvelopeKey([u8; 32]);

impl std::fmt::Debug for EnvelopeKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EnvelopeKey([REDACTED])")
    }
}

impl EnvelopeKey {
    /// Parse a 64-character hex-encoded key.
    pub fn from_hex(hex: &str) -> Result<Self> {
        if hex.len() != 64 {
            return Err(NoombatError::Internal(
                "KEK must be 64 hex characters (32 bytes)".into(),
            ));
        }
        let mut buf = [0u8; 32];
        for (i, byte) in buf.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).map_err(|_| {
                NoombatError::Internal("KEK contains invalid hex characters".into())
            })?;
        }
        Ok(Self(buf))
    }
}

// ..... Core encrypt and decrypt .....

/// Encrypt `plaintext` under the given key, returning a Base64 string
/// containing `nonce || ciphertext || tag`.
pub fn seal(key: &EnvelopeKey, plaintext: &str) -> Result<String> {
    let cipher = Aes256Gcm::new_from_slice(&key.0)
        .map_err(|e| NoombatError::Internal(format!("AES-256-GCM key init failed: {e}")))?;

    // An AES-GCM nonce must never repeat under one key, so it comes from
    // the OS. Taken from getrandom directly, for the same reason
    // `noombat-identity::keys` does: the workspace `rand` is pinned at
    // 0.8 for rsa, and aes-gcm 0.11 wants a rand_core 0.9 RNG, which one
    // `rand` cannot provide alongside it.
    let mut nonce_bytes = [0u8; 12];
    getrandom::fill(&mut nonce_bytes)
        .map_err(|e| NoombatError::Internal(format!("nonce generation failed: {e}")))?;
    let nonce = Nonce::from(nonce_bytes);

    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_bytes())
        .map_err(|e| NoombatError::Internal(format!("envelope seal failed: {e}")))?;

    // nonce (12 bytes) || ciphertext+tag
    let mut blob = Vec::with_capacity(12 + ciphertext.len());
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ciphertext);

    Ok(B64.encode(&blob))
}

/// Decrypt a Base64 blob produced by [`seal`].
///
/// If decryption fails (e.g. the value is pre-existing plaintext
/// that was stored before envelope encryption was enabled), the raw
/// input is returned unchanged so that migration can proceed
/// gracefully. A warning is logged on each fallback.
pub fn open(key: &EnvelopeKey, sealed_b64: &str) -> Result<String> {
    // Attempt Base64 decode. If the value is not valid Base64
    // (e.g. a raw PEM key or a base32 TOTP secret), it is
    // pre-existing plaintext; return it unchanged.
    let blob = match B64.decode(sealed_b64) {
        Ok(b) => b,
        Err(_) => {
            tracing::warn!(
                "envelope: value is not valid Base64; \
                 assuming pre-existing plaintext (run re-encryption)"
            );
            return Ok(sealed_b64.to_owned());
        }
    };

    // A valid sealed blob contains at least a 12-byte nonce and a
    // 16-byte authentication tag. Shorter blobs are plaintext.
    if blob.len() < 12 + 16 {
        tracing::warn!(
            "envelope: decoded blob too short for AES-GCM; \
             assuming pre-existing plaintext (run re-encryption)"
        );
        return Ok(sealed_b64.to_owned());
    }

    let (nonce_bytes, ciphertext) = blob.split_at(12);
    // `from_slice` is deprecated in aes-gcm 0.11 in favour of TryFrom.
    // The length is already guaranteed by the split above, so the error
    // arm is unreachable rather than merely unlikely; it is mapped
    // anyway instead of unwrapped, because an unreachable panic in a
    // decrypt path is still a panic in a decrypt path.
    let nonce = Nonce::try_from(nonce_bytes)
        .map_err(|e| NoombatError::Internal(format!("nonce length invalid: {e}")))?;

    let cipher = Aes256Gcm::new_from_slice(&key.0)
        .map_err(|e| NoombatError::Internal(format!("AES-256-GCM key init failed: {e}")))?;

    match cipher.decrypt(&nonce, ciphertext) {
        Ok(plaintext) => String::from_utf8(plaintext).map_err(|e| {
            NoombatError::Internal(format!("envelope plaintext is not valid UTF-8: {e}"))
        }),
        Err(_) => {
            // Decryption failed. The most likely cause during a
            // migration is that the value is pre-existing plaintext
            // whose Base64 decoding happened to succeed but whose
            // bytes are not a valid AES-GCM ciphertext.
            tracing::warn!(
                "envelope: AES-GCM decryption failed; \
                 assuming pre-existing plaintext (run re-encryption)"
            );
            Ok(sealed_b64.to_owned())
        }
    }
}

// ..... Convenience wrappers (explicit key) .....

/// If `key` is `Some`, encrypt; otherwise return the plaintext
/// unchanged.
fn seal_opt(key: Option<&EnvelopeKey>, plaintext: &str) -> Result<String> {
    match key {
        Some(k) => seal(k, plaintext),
        None => Ok(plaintext.to_owned()),
    }
}

/// If `key` is `Some`, decrypt; otherwise return the value unchanged.
fn open_opt(key: Option<&EnvelopeKey>, sealed: &str) -> Result<String> {
    match key {
        Some(k) => open(k, sealed),
        None => Ok(sealed.to_owned()),
    }
}

/// Apply [`open_opt`] to an `Option<String>`.
fn open_opt_field(key: Option<&EnvelopeKey>, field: Option<String>) -> Result<Option<String>> {
    field.map(|v| open_opt(key, &v)).transpose()
}

// ..... Convenience wrappers (process-global key) .....

/// Encrypt using the process-global key (or pass through if unset).
pub fn seal_auto(plaintext: &str) -> Result<String> {
    seal_opt(get_key(), plaintext)
}

/// Decrypt using the process-global key (or pass through if unset).
pub fn open_auto(sealed: &str) -> Result<String> {
    open_opt(get_key(), sealed)
}

/// Decrypt an `Option<String>` field using the process-global key.
pub fn open_auto_field(field: Option<String>) -> Result<Option<String>> {
    open_opt_field(get_key(), field)
}

/// Encrypt an `Option<&str>` field using the process-global key.
pub fn seal_auto_field(field: Option<&str>) -> Result<Option<String>> {
    field.map(seal_auto).transpose()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> EnvelopeKey {
        EnvelopeKey::from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
            .unwrap()
    }

    #[test]
    fn roundtrip() {
        let key = test_key();
        let plaintext = "secret-totp-value";
        let sealed = seal(&key, plaintext).unwrap();
        assert_ne!(sealed, plaintext);
        let opened = open(&key, &sealed).unwrap();
        assert_eq!(opened, plaintext);
    }

    /// Two seals of the same plaintext under the same key differ.
    ///
    /// This is about the nonce, not the ciphertext. AES-GCM is broken by
    /// nonce reuse under one key: two messages sharing a nonce leak the
    /// XOR of their plaintexts and undermine the authentication tag, so
    /// "the nonce is fresh every time" is the security property, not a
    /// detail of the encoding.
    ///
    /// No other test in this module would catch it: a hard-coded all-zero
    /// nonce round-trips perfectly and passes all of them.
    #[test]
    fn each_seal_uses_a_fresh_nonce() {
        let key = test_key();

        let first = seal(&key, "same plaintext").expect("seals");
        let second = seal(&key, "same plaintext").expect("seals");

        assert_ne!(
            first, second,
            "two seals of one plaintext were identical, so the nonce is not \
             being regenerated; AES-GCM nonce reuse leaks plaintext"
        );

        // The nonce is the first 12 bytes, so compare those directly
        // rather than inferring from the whole blob differing.
        use base64::Engine as _;
        let decode = |b: &str| {
            base64::engine::general_purpose::STANDARD
                .decode(b)
                .expect("sealed output is base64")
        };
        assert_ne!(
            decode(&first)[..12],
            decode(&second)[..12],
            "the nonce prefix repeated across two seals"
        );

        // Both must still open, or "different" would be satisfied by
        // simply corrupting the output.
        assert_eq!(open(&key, &first).expect("opens"), "same plaintext");
        assert_eq!(open(&key, &second).expect("opens"), "same plaintext");
    }

    #[test]
    fn wrong_key_returns_plaintext_fallback() {
        let key1 = test_key();
        let key2 = EnvelopeKey::from_hex(
            "ff0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        )
        .unwrap();
        let sealed = seal(&key1, "data").unwrap();
        // Wrong key triggers the plaintext-fallback path (returns
        // the sealed value unchanged rather than erroring).
        let result = open(&key2, &sealed).unwrap();
        assert_eq!(result, sealed);
    }

    #[test]
    fn no_key_passthrough() {
        let val = "plain-value";
        assert_eq!(seal_opt(None, val).unwrap(), val);
        assert_eq!(open_opt(None, val).unwrap(), val);
    }

    #[test]
    fn plaintext_fallback_pem() {
        // A PEM string is not valid Base64(nonce||ciphertext||tag),
        // so `open` should return it unchanged.
        let key = test_key();
        let pem = "-----BEGIN PRIVATE KEY-----\nMIIE...==\n-----END PRIVATE KEY-----";
        let result = open(&key, pem).unwrap();
        assert_eq!(result, pem);
    }

    #[test]
    fn plaintext_fallback_base32() {
        // A base32 TOTP secret is not valid sealed ciphertext.
        let key = test_key();
        let secret = "JBSWY3DPEHPK3PXP";
        let result = open(&key, secret).unwrap();
        assert_eq!(result, secret);
    }

    #[test]
    fn auto_without_init_passes_through() {
        // Before `init` is called, `get_key()` returns `None`,
        // so the `_auto` functions pass through unchanged.
        // NOTE: this test works only when no other test in the
        // same process has called `init`. Since `OnceLock` is
        // per-process and cargo runs each test binary in its own
        // process, this is safe.
        let val = "passthrough-value";
        assert_eq!(seal_auto(val).unwrap(), val);
        assert_eq!(open_auto(val).unwrap(), val);
        assert_eq!(
            open_auto_field(Some(val.to_owned())).unwrap(),
            Some(val.to_owned())
        );
    }

    #[test]
    fn hex_key_validation() {
        assert!(EnvelopeKey::from_hex("tooshort").is_err());
        assert!(EnvelopeKey::from_hex(&"gg".repeat(32)).is_err());
        assert!(EnvelopeKey::from_hex(&"ab".repeat(32)).is_ok());
    }
}
