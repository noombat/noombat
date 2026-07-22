// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
#![forbid(unsafe_code)]
//! WASM bridge for the Noombat chat island.
//!
//! Compiles to `wasm32-unknown-unknown` via `wasm-pack`.
//!
//! Exposes:
//! - **Autocrypt state management** via `ChatCrypto`.
//! - **OpenPGP key generation, message encryption, and decryption**
//!   via the `pgp` crate (rPGP) with the `wasm` feature.

use wasm_bindgen::prelude::*;

use noombat_autocrypt::peer::{AutocryptHeader, IncomingMessage, PeerStateTable, PreferEncrypt};
use noombat_autocrypt::recommend::{self, Recommendation};

use pgp::composed::{
    Deserializable, EncryptionCaps, KeyType, Message, MessageBuilder, SecretKeyParamsBuilder,
    SignedPublicKey, SignedSecretKey, SubkeyParamsBuilder,
};
use pgp::crypto::ecc_curve::ECCCurve;
use pgp::crypto::hash::HashAlgorithm;
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::ser::Serialize;
use pgp::types::Password;

// ..... Autocrypt state .....

#[wasm_bindgen]
pub struct ChatCrypto {
    peers: PeerStateTable,
}

impl Default for ChatCrypto {
    fn default() -> Self {
        Self::new()
    }
}

#[wasm_bindgen]
impl ChatCrypto {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            peers: PeerStateTable::new(),
        }
    }

    #[wasm_bindgen(js_name = "fromJson")]
    pub fn from_json(json: &str) -> Result<ChatCrypto, JsError> {
        let peers: PeerStateTable =
            serde_json::from_str(json).map_err(|e| JsError::new(&e.to_string()))?;
        Ok(Self { peers })
    }

    #[wasm_bindgen(js_name = "toJson")]
    pub fn to_json(&self) -> Result<String, JsError> {
        serde_json::to_string(&self.peers).map_err(|e| JsError::new(&e.to_string()))
    }

    #[wasm_bindgen(js_name = "updatePeerState")]
    pub fn update_peer_state(
        &mut self,
        addr: &str,
        timestamp: u64,
        public_key: &[u8],
        prefer_mutual: bool,
    ) {
        let autocrypt_header = if public_key.is_empty() {
            None
        } else {
            Some(AutocryptHeader {
                addr: addr.into(),
                public_key: public_key.to_vec(),
                prefer_encrypt: if prefer_mutual {
                    PreferEncrypt::Mutual
                } else {
                    PreferEncrypt::NoPreference
                },
            })
        };
        let msg = IncomingMessage {
            from: addr.into(),
            effective_date: timestamp,
            autocrypt_header,
        };
        self.peers.update(&msg);
    }

    #[wasm_bindgen(js_name = "encryptionRecommendation")]
    pub fn encryption_recommendation(
        &self,
        recipients_json: &str,
        sender_prefers_mutual: bool,
    ) -> Result<String, JsError> {
        let addrs: Vec<String> =
            serde_json::from_str(recipients_json).map_err(|e| JsError::new(&e.to_string()))?;
        let refs: Vec<&str> = addrs.iter().map(|s| s.as_str()).collect();
        let rec = recommend::recommend(&self.peers, &refs, sender_prefers_mutual);
        let label = match rec {
            Recommendation::Disable => "disable",
            Recommendation::Discourage => "discourage",
            Recommendation::Available => "available",
            Recommendation::Encrypt => "encrypt",
        };
        Ok(label.into())
    }

    /// Return the peer's public key bytes (binary serialisation), or
    /// `null` if no key is known for the given address.
    ///
    /// This avoids serialising the entire peer state table on every
    /// outgoing message.
    #[wasm_bindgen(js_name = "getPeerPublicKey")]
    pub fn get_peer_public_key(&self, addr: &str) -> Option<Vec<u8>> {
        let canonical = addr.trim().to_lowercase();
        self.peers.get(&canonical).and_then(|peer| {
            if peer.public_key.is_empty() {
                None
            } else {
                Some(peer.public_key.clone())
            }
        })
    }
}

// ..... Message encryption .....

/// Sign and encrypt a plaintext message for the given recipient
/// (sign-then-encrypt per the Autocrypt Level 1 specification).
///
/// - `recipient_key_bytes`: the recipient's OpenPGP Transferable
///   Public Key (binary serialisation).
/// - `sender_key_bytes`: the sender's OpenPGP Transferable Secret
///   Key (binary serialisation). Used to sign the message before
///   encryption so the recipient can verify the sender's identity.
/// - `plaintext`: the raw message body.
///
/// Returns the signed-and-encrypted OpenPGP message as binary bytes.

#[wasm_bindgen(js_name = "encryptMessage")]
pub fn encrypt_message(
    recipient_key_bytes: &[u8],
    sender_key_bytes: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, JsError> {
    let mut rng = rand::thread_rng();

    let recipient_key = SignedPublicKey::from_bytes(recipient_key_bytes)
        .map_err(|e| JsError::new(&format!("failed to parse recipient key: {e}")))?;

    let sender_secret = SignedSecretKey::from_bytes(sender_key_bytes)
        .map_err(|e| JsError::new(&format!("failed to parse sender key: {e}")))?;

    // MessageBuilder::from_bytes requires 'static data. Leak the
    // copy into WASM linear memory; reclaimed when the instance is
    // dropped (page navigation or tab close).
    let data: &'static [u8] = Box::leak(plaintext.to_vec().into_boxed_slice());

    // Build the message: literal data --> sign --> SEIPD v1 encryption.
    //
    // `MessageBuilder::sign` accepts `&dyn SigningKey`, which is
    // implemented by `packet::SecretKey` (the inner primary key type)
    // but not by `SignedSecretKey` (the composite wrapper). Access
    // the primary key via `sender_secret.primary_key`.
    //
    // The builder chain is split because `sign` takes `&mut self`
    // (mutating in place), while `seipd_v1` consumes `self` and
    // returns a new `Builder<..., EncryptionSeipdV1>` on which
    // `encrypt_to_key` and `to_vec` are available.
    let mut builder = MessageBuilder::from_bytes("msg", data);
    builder.sign(
        &sender_secret.primary_key,
        Password::empty(),
        HashAlgorithm::Sha256,
    );
    let mut enc_builder = builder.seipd_v1(&mut rng, SymmetricKeyAlgorithm::AES256);

    // Encrypt to the first encryption-capable subkey.
    if let Some(subkey) = recipient_key.public_subkeys.first() {
        enc_builder
            .encrypt_to_key(&mut rng, subkey)
            .map_err(|e| JsError::new(&format!("encryption failed: {e}")))?;
    } else {
        return Err(JsError::new("recipient key has no encryption subkey"));
    }

    enc_builder
        .to_vec(&mut rng)
        .map_err(|e| JsError::new(&format!("message serialisation failed: {e}")))
}

// ..... Message decryption .....

/// Decrypt an OpenPGP-encrypted message.
///
/// - `private_key_bytes`: the recipient's Transferable Secret Key
///   (binary serialisation).
/// - `ciphertext`: the encrypted OpenPGP message (binary).
///
/// Returns the decrypted plaintext as bytes.
#[wasm_bindgen(js_name = "decryptMessage")]
pub fn decrypt_message(private_key_bytes: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, JsError> {
    let secret_key = SignedSecretKey::from_bytes(private_key_bytes)
        .map_err(|e| JsError::new(&format!("failed to parse private key: {e}")))?;

    let message = Message::from_bytes(ciphertext)
        .map_err(|e| JsError::new(&format!("failed to parse message: {e}")))?;

    let mut decrypted = message
        .decrypt(&Password::empty(), &secret_key)
        .map_err(|e| JsError::new(&format!("decryption failed: {e}")))?;

    let plaintext = decrypted
        .as_data_string()
        .map_err(|e| JsError::new(&format!("failed to extract plaintext: {e}")))?;

    Ok(plaintext.into_bytes())
}

// ..... Key generation .....

/// Generate a new OpenPGP key pair for the given email address.
///
/// Produces an Ed25519 primary key (signing) with a Curve25519
/// subkey (encryption), matching the Autocrypt Level 1 key profile.
///
/// Returns a JSON string:
/// `{ "public_key": "<base64>", "private_key": "<base64>" }`
///
/// The base64 values encode the binary (non-armored) Transferable
/// Secret Key and Transferable Public Key respectively.
#[wasm_bindgen(js_name = "generateKeyPair")]
pub fn generate_key_pair(email: &str) -> Result<String, JsError> {
    let mut rng = rand::thread_rng();

    // Ed25519 primary (signing) + Curve25519 subkey (encryption).
    let mut key_params = SecretKeyParamsBuilder::default();
    key_params
        .key_type(KeyType::Ed25519Legacy)
        .can_certify(false)
        .can_sign(true)
        .primary_user_id(email.to_string())
        .preferred_symmetric_algorithms(smallvec::smallvec![SymmetricKeyAlgorithm::AES256,])
        .subkeys(vec![
            SubkeyParamsBuilder::default()
                .key_type(KeyType::ECDH(ECCCurve::Curve25519Legacy))
                .can_encrypt(EncryptionCaps::All)
                .build()
                .map_err(|e| JsError::new(&format!("subkey params error: {e}")))?,
        ]);

    let params = key_params
        .build()
        .map_err(|e| JsError::new(&format!("key params error: {e}")))?;

    let signed_secret: SignedSecretKey = params
        .generate(&mut rng)
        .map_err(|e| JsError::new(&format!("key generation failed: {e}")))?;

    let signed_public: SignedPublicKey = signed_secret.to_public_key();

    // Serialise to binary (not armored) so that the output can be
    // passed directly to encryptMessage / decryptMessage, which
    // parse keys via SignedPublicKey::from_bytes.
    let secret_bytes = signed_secret
        .to_bytes()
        .map_err(|e| JsError::new(&format!("secret key serialisation failed: {e}")))?;
    let public_bytes = signed_public
        .to_bytes()
        .map_err(|e| JsError::new(&format!("public key serialisation failed: {e}")))?;

    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::STANDARD;
    let result = serde_json::json!({
        "public_key": b64.encode(&public_bytes),
        "private_key": b64.encode(&secret_bytes),
    });

    serde_json::to_string(&result)
        .map_err(|e| JsError::new(&format!("JSON serialisation failed: {e}")))
}
