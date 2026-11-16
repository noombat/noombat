// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

/**
 * Chatmail account provisioning.
 *
 * This module is the single implementation of the provisioning
 * sequence:
 *
 * 1. Ask the server to create the Chatmail account.
 * 2. Generate an OpenPGP key pair for the returned address.
 * 3. Build the credential blob and encrypt it with the blob key
 *    derived from the user's password.
 * 4. Store the encrypted blob server-side.
 * 5. Publish the public key, once the blob holding its private half is
 *    stored, so that others can write to the member first.
 *
 * It is shared by the registration flow (`src/auth.ts`), the OAuth
 * account-upgrade flow (`src/upgrade.ts`), and the chat page's own
 * setup form.
 */

import { authHeaders } from "./session";

/**
 * Provision the Chatmail account, generate an OpenPGP key pair,
 * store the encrypted credential blob, then publish the public key.
 *
 * Requires the blob encryption key (derived from the user's
 * password) and an authenticated session. The session may be
 * carried either by a bearer token in `sessionStorage` (the
 * registration flow) or by the `noombat_session` cookie (the
 * upgrade flow); {@link authHeaders} selects whichever is present.
 *
 * Resolves to the chat address once the blob is stored, and to `null`
 * when the server refused or the blob was not stored, in which case
 * nothing is published. A failed request rejects the promise. Also sets
 * chat up again for a member whose setup is unusable, which the server
 * allows with a new Chatmail password.
 * Callers treat provisioning as best-effort: the account remains
 * usable and provisioning can be retried later from the chat page.
 *
 * The OpenPGP and blob modules are loaded with dynamic `import()`
 * so that they form separate chunks.
 */
export async function provisionChat(blobKey: CryptoKey, authKey: string): Promise<string | null> {
  // 1. Ask the server to provision the Chatmail account.
  const provResp = await fetch("/api/v1/me/provision_chat", {
    method: "POST",
    headers: authHeaders({ "Content-Type": "application/json" }),
    // The password's auth key, which the server checks before setting up.
    body: JSON.stringify({ auth_key: authKey }),
  });

  if (!provResp.ok) return null;

  const { chatmail_addr, chatmail_password } = (await provResp.json()) as {
    chatmail_addr: string;
    chatmail_password: string;
  };

  // 2. Generate an OpenPGP key pair for the Chatmail address.
  const { generateKeyPair } = await import("./crypto");
  const keyPair = await generateKeyPair(chatmail_addr);

  // 3. Build and encrypt the credential blob. The Chatmail address
  //    is bound as additional authenticated data.
  const { encryptBlob, storeBlob } = await import("./blob");
  const blob = {
    chatmailPassword: chatmail_password,
    publicKeyB64: uint8ToBase64(keyPair.publicKey),
    privateKeyB64: uint8ToBase64(keyPair.privateKey),
    peerStateJson: null,
  };

  const encrypted = await encryptBlob(blobKey, blob, chatmail_addr);

  // 4. Store the encrypted blob on the server.
  if (!(await storeBlob(encrypted))) return null;

  // 5. Publish the public key. Never before step 4: a key whose private
  //    half was lost would invite messages nobody can read.
  // Best-effort: the chat page publishes it at unlock if this fails.
  const { publishOwnKey } = await import("./directory");
  await publishOwnKey(keyPair.publicKey).catch(() => false);
  return chatmail_addr;
}

/**
 * Encode a Uint8Array as a base64 string.
 *
 * Chunked because the spread in `String.fromCharCode(...arr)`
 * exceeds the maximum call-stack argument count for arrays larger
 * than roughly 100 kiB.
 */
export function uint8ToBase64(bytes: Uint8Array): string {
  const CHUNK = 0x8000; // 32 kiB per chunk
  const parts: string[] = [];
  for (let i = 0; i < bytes.length; i += CHUNK) {
    parts.push(String.fromCharCode(...bytes.subarray(i, i + CHUNK)));
  }
  return btoa(parts.join(""));
}
