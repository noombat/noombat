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
  /** The serialised Autocrypt peer state table (JSON string, or
   *  `null` for a freshly provisioned account with no peer state). */
  peerStateJson: string | null;
}

/**
 * Encode the AAD (Additional Authenticated Data) string as a
 * Uint8Array.
 *
 * The AAD binds the ciphertext to the owner's Chatmail address,
 * preventing a blob-swapping attack in which a compromised server
 * substitutes one user's encrypted blob for another's.
 */
function encodeAad(chatmailAddr: string): Uint8Array {
  return new TextEncoder().encode(`noombat-chatmail-cred:${chatmailAddr}`);
}

/**
 * Encrypt a credential blob with the given AES-GCM key.
 *
 * Returns the raw bytes (`iv || ciphertext || tag`) suitable for
 * storage in the `chatmail_cred` BYTEA column.
 *
 * @param blobKey: AES-256-GCM key (derived via split key derivation).
 * @param blob: The plaintext credential material.
 * @param chatmailAddr: The owner's Chatmail address, bound as AAD.
 */
export async function encryptBlob(
  blobKey: CryptoKey,
  blob: CredentialBlob,
  chatmailAddr: string,
): Promise<Uint8Array> {
  const plaintext = new TextEncoder().encode(JSON.stringify(blob));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const additionalData = encodeAad(chatmailAddr);

  // The `as Uint8Array<ArrayBuffer>` assertion is safe: the
  // Uint8Array produced by `TextEncoder.encode()` is always backed
  // by an ArrayBuffer, not a SharedArrayBuffer. TypeScript 5.7+
  // widens Uint8Array to Uint8Array<ArrayBufferLike>, which is not
  // assignable to the BufferSource union's ArrayBufferView<ArrayBuffer>.
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: additionalData as Uint8Array<ArrayBuffer> },
    blobKey,
    plaintext,
  );

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
 *
 * @param blobKey: AES-256-GCM key (derived via split key derivation).
 * @param encrypted: The raw ciphertext from the server.
 * @param chatmailAddr: The owner's Chatmail address, bound as AAD
 *   (must match the value used during encryption).
 */
export async function decryptBlob(
  blobKey: CryptoKey,
  encrypted: Uint8Array,
  chatmailAddr: string,
): Promise<CredentialBlob> {
  const iv = encrypted.slice(0, 12);
  const ciphertext = encrypted.slice(12);
  const additionalData = encodeAad(chatmailAddr);

  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv, additionalData: additionalData as Uint8Array<ArrayBuffer> },
    blobKey,
    ciphertext,
  );

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
 * Discriminated result type for {@link fetchBlob}.
 *
 * - `"ok"`: the blob was retrieved successfully.
 * - `"not_provisioned"`: HTTP 404; the blob does not exist (chat
 *   has not been provisioned).
 * - `"auth_error"`: HTTP 401 or 403; the access token has expired
 *   or is invalid.
 * - `"error"`: any other non-success HTTP status.
 */
export type FetchBlobResult =
  | { status: "ok"; data: Uint8Array }
  | { status: "not_provisioned" }
  | { status: "auth_error" }
  | { status: "error"; httpStatus: number };

/**
 * Retrieve the encrypted blob from the server.
 *
 * `GET /api/v1/me/chatmail_cred` returns the raw bytes on success.
 * The caller receives a discriminated result so that "token expired"
 * (401/403), "blob absent" (404), and other failures are
 * distinguishable.
 */
export async function fetchBlob(): Promise<FetchBlobResult> {
  const token = sessionStorage.getItem("noombat_access_token") ?? "";
  const resp = await fetch("/api/v1/me/chatmail_cred", {
    headers: { Authorization: `Bearer ${token}` },
  });

  if (resp.ok) {
    const buf = await resp.arrayBuffer();
    return { status: "ok", data: new Uint8Array(buf) };
  }

  if (resp.status === 404) {
    return { status: "not_provisioned" };
  }

  if (resp.status === 401 || resp.status === 403) {
    return { status: "auth_error" };
  }

  return { status: "error", httpStatus: resp.status };
}
