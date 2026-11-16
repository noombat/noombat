// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

/**
 * The instance's directory of chat keys: each member publishes their
 * public key there, so that others can write to them first.
 */

import type { CredentialBlob } from "./blob";
import { authHeaders } from "./session";

/** Publish `publicKey` as the member's chat key; resolves to whether the server stored it. */
export async function publishOwnKey(publicKey: Uint8Array): Promise<boolean> {
  const resp = await fetch("/api/v1/me/chat_key", {
    method: "PUT",
    headers: authHeaders({ "Content-Type": "application/octet-stream" }),
    // A copy, so a view into a larger buffer sends only its own bytes.
    body: new Blob([publicKey.slice().buffer as ArrayBuffer]),
  });
  return resp.ok;
}

/**
 * Publish the member's key unless the instance already serves exactly
 * it, which repairs an upload that failed at setup. Resolves to true once
 * the instance is known to serve it.
 */
export async function ensureOwnKeyPublished(
  address: string,
  publicKey: Uint8Array,
): Promise<boolean> {
  const resp = await fetch(`/api/v1/chat/keys/${encodeURIComponent(address)}`, {
    headers: authHeaders(),
  });
  if (resp.ok) {
    const { key } = (await resp.json()) as { key: string };
    if (sameBytes(base64ToUint8(key), publicKey)) return true;
  } else if (resp.status !== 404) {
    return false;
  }
  return publishOwnKey(publicKey);
}

/**
 * At unlock, publish the public half of the decrypted credential blob as
 * the key for `address`, unless the instance already serves it. Never
 * rejects: an upload that fails is tried again at the next unlock.
 */
export async function repairOwnKey(address: string, blob: CredentialBlob): Promise<void> {
  await ensureOwnKeyPublished(address, base64ToUint8(blob.publicKeyB64)).catch(() => false);
}

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((byte, i) => byte === b[i]);
}

function base64ToUint8(b64: string): Uint8Array {
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}
