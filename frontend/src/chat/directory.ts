// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

/**
 * The instance's directory of chat keys: each member publishes their
 * public key there, so that others can write to them first, and looks up
 * the key of someone who has not written yet.
 */

import { CHAT_SETUP_HEADER, type CredentialBlob } from "./blob";
import { authHeaders } from "./session";

/**
 * Publish `publicKey` as the member's chat key, for chat setup `setup`;
 * resolves to whether the server stored it, which it does not once a
 * newer setup has replaced that one.
 */
export async function publishOwnKey(publicKey: Uint8Array, setup: number): Promise<boolean> {
  const resp = await fetch("/api/v1/me/chat_key", {
    method: "PUT",
    headers: authHeaders({
      "Content-Type": "application/octet-stream",
      [CHAT_SETUP_HEADER]: String(setup),
    }),
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
  setup: number,
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
  return publishOwnKey(publicKey, setup);
}

/**
 * At unlock, publish the public half of the decrypted credential blob as
 * the key for `address`, for chat setup `setup`, unless the instance
 * already serves it. Never rejects: an upload that fails is tried again at
 * the next unlock.
 */
export async function repairOwnKey(
  address: string,
  blob: CredentialBlob,
  setup: number,
): Promise<void> {
  await ensureOwnKeyPublished(address, base64ToUint8(blob.publicKeyB64), setup).catch(() => false);
}

/** A published key as looked up: checked, and with the address it is for. */
export type PublishedKeyResult =
  | { status: "found"; address: string; key: Uint8Array; fingerprint: string }
  | { status: "absent" }
  | { status: "malformed" }
  | { status: "invalid" }
  | { status: "error" };

/**
 * The key the instance publishes for `address`, checked against the
 * address asked for rather than the one the server answers with.
 */
export async function fetchPublishedKey(address: string): Promise<PublishedKeyResult> {
  return lookUp(`/api/v1/chat/keys/${encodeURIComponent(address)}`, address);
}

/**
 * The chat address and key of the member a handle names, `@user@domain`,
 * on this instance or another noombat instance.
 */
export async function fetchPublishedKeyByHandle(handle: string): Promise<PublishedKeyResult> {
  return lookUp(`/api/v1/chat/keys/by-handle/${encodeURIComponent(handle)}`, null);
}

async function lookUp(url: string, asked: string | null): Promise<PublishedKeyResult> {
  let resp: Response;
  try {
    resp = await fetch(url, { headers: authHeaders() });
  } catch {
    return { status: "error" };
  }
  if (resp.status === 404) return { status: "absent" };
  // Neither an address nor a handle: asking again changes nothing.
  if (resp.status === 400) return { status: "malformed" };
  if (!resp.ok) return { status: "error" };
  let address: string;
  let key: Uint8Array;
  try {
    const body = (await resp.json()) as { address: unknown; key: unknown };
    if (typeof body.address !== "string" || typeof body.key !== "string") {
      return { status: "invalid" };
    }
    address = asked ?? body.address;
    key = base64ToUint8(body.key);
  } catch {
    return { status: "invalid" };
  }
  const { checkPublishedKey } = await import("./crypto");
  const fingerprint = await checkPublishedKey(key, address);
  return fingerprint ? { status: "found", address, key, fingerprint } : { status: "invalid" };
}

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((byte, i) => byte === b[i]);
}

function base64ToUint8(b64: string): Uint8Array {
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}
