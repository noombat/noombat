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
 *
 * Each setup gives the relay a new password, so two at once would leave
 * the stored credentials holding one the relay no longer takes. Tabs of
 * one browser take turns, under a Web Lock; the server's setup numbers
 * cover two devices, refusing the credentials and key of any setup a
 * newer one has replaced.
 */

import { authHeaders } from "./session";

/**
 * How setting chat up ended: set up at `address`; set up meanwhile by
 * another tab or device, whose setup this one must not replace; refused,
 * the password not proving the member; refused for now, one having been
 * set up a moment ago; or failed otherwise, the blob not stored among it.
 */
export type ProvisionResult =
  | { status: "set_up"; address: string }
  | { status: "superseded" }
  | { status: "refused" }
  | { status: "too_soon" }
  | { status: "failed" };

/** Runs `task` while no other tab of this browser sets chat up, or at
 *  once where the browser has no Web Locks. */
async function oneTabAtATime<T>(task: () => Promise<T>): Promise<T> {
  const locks = globalThis.navigator?.locks;
  return locks ? locks.request("noombat-chat-setup", task) : task();
}

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
 * Resolves to how setting up ended, the address once the blob is stored. Nothing is
 * published when the server refused or the blob was not stored, nor when
 * another tab or device set chat up meanwhile. A failed request rejects
 * the promise. Also sets chat up again for a member whose setup is
 * unusable, which the server allows with a new Chatmail password.
 * Callers treat provisioning as best-effort: the account remains
 * usable and provisioning can be retried later from the chat page.
 *
 * The OpenPGP and blob modules are loaded with dynamic `import()`
 * so that they form separate chunks.
 */
export async function provisionChat(blobKey: CryptoKey, authKey: string): Promise<ProvisionResult> {
  return oneTabAtATime(() => setUp(blobKey, authKey));
}

async function setUp(blobKey: CryptoKey, authKey: string): Promise<ProvisionResult> {
  // 1. Ask the server to provision the Chatmail account.
  const provResp = await fetch("/api/v1/me/provision_chat", {
    method: "POST",
    headers: authHeaders({ "Content-Type": "application/json" }),
    // The password's auth key, which the server checks before setting up.
    body: JSON.stringify({ auth_key: authKey }),
  });

  // A conflict: chat was set up meanwhile, perhaps by the tab this one
  // waited for.
  if (provResp.status === 409) return { status: "superseded" };
  if (provResp.status === 403) return { status: "refused" };
  if (provResp.status === 429) return { status: "too_soon" };
  if (!provResp.ok) return { status: "failed" };

  const { chatmail_addr, chatmail_password, chat_setup } = (await provResp.json()) as {
    chatmail_addr: string;
    chatmail_password: string;
    chat_setup: number;
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

  // 4. Store the encrypted blob on the server, for this setup.
  const stored = await storeBlob(encrypted, chat_setup);
  if (stored !== "stored") return { status: stored === "superseded" ? "superseded" : "failed" };

  // 5. Publish the public key. Never before step 4: a key whose private
  //    half was lost would invite messages nobody can read.
  // Best-effort: the chat page publishes it at unlock if this fails.
  const { publishOwnKey } = await import("./directory");
  await publishOwnKey(keyPair.publicKey, chat_setup).catch(() => false);
  return { status: "set_up", address: chatmail_addr };
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
