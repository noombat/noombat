// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

/**
 * Credential blob encryption and decryption.
 *
 * The blob contains the Chatmail password, the OpenPGP private key,
 * and the serialised Autocrypt peer state. It is encrypted with an
 * AES-256-GCM key derived from the user's Noombat password via the
 * split key derivation chain:
 * PBKDF2 to HKDF-Expand("noombat-chat-crypto").
 *
 * The encrypted blob is stored server-side in `actors.chatmail_cred`
 * (BYTEA). The server cannot decrypt it.
 *
 * Wire format: `iv (12 bytes) || ciphertext || tag (16 bytes)`
 * (AES-GCM output from Web Crypto; the tag is appended automatically).
 */

/** The plaintext contents of the credential blob. */
export interface CredentialBlob {
  /** The Chatmail IMAP/SMTP password. */
  chatmailPassword: string;
  /** The OpenPGP private key bytes (base64-encoded). */
  privateKeyB64: string;
  /** The OpenPGP public key bytes (base64-encoded). */
  publicKeyB64: string;
  /** The serialised Autocrypt peer state table (JSON string). */
  peerStateJson: string;
}

/**
 * Encrypt a credential blob with the given AES-GCM key.
 *
 * Returns the raw bytes (`iv || ciphertext || tag`) suitable for
 * storage in the `chatmail_cred` BYTEA column.
 */
export async function encryptBlob(blobKey: CryptoKey, blob: CredentialBlob): Promise<Uint8Array> {
  const plaintext = new TextEncoder().encode(JSON.stringify(blob));
  const iv = crypto.getRandomValues(new Uint8Array(12));

  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, blobKey, plaintext);

  // Prepend the IV to the ciphertext.
  const result = new Uint8Array(iv.byteLength + ciphertext.byteLength);
  result.set(iv, 0);
  result.set(new Uint8Array(ciphertext), iv.byteLength);
  return result;
}

/**
 * Decrypt a credential blob with the given AES-GCM key.
 *
 * `encrypted` is the raw bytes from the `chatmail_cred` column
 * (`iv || ciphertext || tag`).
 */
export async function decryptBlob(
  blobKey: CryptoKey,
  encrypted: Uint8Array,
): Promise<CredentialBlob> {
  const iv = encrypted.slice(0, 12);
  const ciphertext = encrypted.slice(12);

  const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, blobKey, ciphertext);

  const json = new TextDecoder().decode(plaintext);
  return JSON.parse(json) as CredentialBlob;
}

// ..... Server round-trips .....

/**
 * Store the encrypted blob on the server.
 *
 * `PUT /api/v1/me/chatmail_cred` with the raw bytes as the body.
 */
export async function storeBlob(encrypted: Uint8Array): Promise<boolean> {
  const token = sessionStorage.getItem("noombat_access_token") ?? "";
  // The `as ArrayBuffer` assertion is safe: the Uint8Array produced
  // by Web Crypto (AES-GCM) is always backed by an ArrayBuffer, not
  // a SharedArrayBuffer. TypeScript 5.7+ models Uint8Array as
  // Uint8Array<ArrayBufferLike>, which is not assignable to BlobPart
  // due to the SharedArrayBuffer half of the union.
  const resp = await fetch("/api/v1/me/chatmail_cred", {
    method: "PUT",
    headers: {
      "Content-Type": "application/octet-stream",
      Authorization: `Bearer ${token}`,
    },
    body: new Blob([encrypted.buffer as ArrayBuffer]),
  });
  return resp.ok;
}

/**
 * Retrieve the encrypted blob from the server.
 *
 * `GET /api/v1/me/chatmail_cred` returns the raw bytes.
 * Returns `null` if the blob does not exist (HTTP 404).
 */
export async function fetchBlob(): Promise<Uint8Array | null> {
  const token = sessionStorage.getItem("noombat_access_token") ?? "";
  const resp = await fetch("/api/v1/me/chatmail_cred", {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!resp.ok) return null;
  const buf = await resp.arrayBuffer();
  return new Uint8Array(buf);
}
