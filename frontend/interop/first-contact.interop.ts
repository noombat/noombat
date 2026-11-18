// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

/**
 * First contact between two members who use only the web client, against
 * the chat interop stack. Run by `tests/chat-interop/run.sh`, not by the
 * unit tests.
 *
 * The web client's own modules provision both members and publish their
 * keys. carol writes first: she names dave by handle, and the page's own
 * resolver finds his address and the key his instance publishes. She sends
 * over the chat WebSocket; dave fetches the message there, takes her key
 * from its Autocrypt header, decrypts it and verifies her signature. Her
 * second message reaches his open session with nothing asked, and asking
 * after it returns nothing. The page's wiring around these modules is not
 * run here.
 *
 * Needs NOOMBAT_URL, NOOMBAT_DOMAIN (the instance's, for handles),
 * CHAT_DOMAIN, and for carol and dave a session token
 * and the auth key their password gives: CAROL_TOKEN, CAROL_AUTH_KEY,
 * DAVE_TOKEN and DAVE_AUTH_KEY.
 */

import { expect, it, vi } from "vitest";
import { PeerStateTable, parseAutocryptHeader } from "../src/chat/autocrypt";
import { decryptBlob, fetchBlob, type CredentialBlob } from "../src/chat/blob";
import { decryptAndVerify, encryptMessage } from "../src/chat/crypto";
import { provisionChat, uint8ToBase64 } from "../src/chat/provision";
import { KeyLookups, resolveRecipient } from "../src/chat/recipient";

function need(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is not set`);
  return value;
}

const BASE = need("NOOMBAT_URL");
const INSTANCE = need("NOOMBAT_DOMAIN");
const CHAT_DOMAIN = need("CHAT_DOMAIN");
const realFetch = globalThis.fetch;

interface Member {
  token: string;
  address: string;
  blob: CredentialBlob;
}

interface ServerMsg {
  type: string;
  uid?: number;
  from?: string;
  body_b64?: string;
  autocrypt_header_b64?: string;
  timestamp?: number;
  message?: string;
}

const bytes = (b64: string): Uint8Array => Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));

/** Act as the browser of the member `token` signs in: the page's relative
 *  URLs reach the instance, and the session is theirs. */
function signInAs(token: string): void {
  vi.stubGlobal("sessionStorage", { getItem: () => token });
  vi.stubGlobal("fetch", (url: string, init?: RequestInit) => realFetch(new URL(url, BASE), init));
}

/** Provision `name` as the chat page's setup does, with a blob key of its
 *  own and the member's auth key, and read back what was stored. */
async function provision(name: string, token: string, authKey: string): Promise<Member> {
  signInAs(token);
  const blobKey = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, [
    "encrypt",
    "decrypt",
  ]);
  const provisioned = await provisionChat(blobKey, authKey);
  if (provisioned.status !== "set_up")
    throw new Error(`${name} was not set up: ${provisioned.status}`);
  const address = `${name}@${CHAT_DOMAIN}`;
  const stored = await fetchBlob();
  if (stored.status !== "ok") throw new Error(`${name}'s blob was not stored: ${stored.status}`);
  return { token, address, blob: await decryptBlob(blobKey, stored.data, address) };
}

/** The member's chat WebSocket, signed in to their Chatmail account. */
async function chatSocket(member: Member) {
  const url = new URL("/api/v1/chat/ws", BASE);
  url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
  // Node's WebSocket takes headers, which a browser sends as the cookie.
  const init = { headers: { Cookie: `__Host-noombat_session=${member.token}` } };
  const ws = new WebSocket(url, init as unknown as string[]);
  const received: ServerMsg[] = [];
  ws.onmessage = (event) => received.push(JSON.parse(String(event.data)) as ServerMsg);
  await new Promise((resolve, reject) => {
    ws.onopen = resolve;
    ws.onerror = () => reject(new Error(`the chat WebSocket did not open for ${member.address}`));
  });
  const send = (msg: object): void => ws.send(JSON.stringify(msg));
  async function waitFor(found: (msg: ServerMsg) => boolean, ms = 15_000): Promise<ServerMsg> {
    // Only what arrives from now on: an earlier error must not end a later wait.
    const from = received.length;
    for (const end = Date.now() + ms; Date.now() < end;) {
      const fresh = received.slice(from);
      const msg = fresh.find(found);
      if (msg) return msg;
      const error = fresh.find((m) => m.type === "error");
      if (error) throw new Error(`the server answered: ${error.message}`);
      await new Promise((resolve) => setTimeout(resolve, 200));
    }
    throw new Error(`nothing arrived for ${member.address}: ${JSON.stringify(received)}`);
  }
  send({ type: "auth", password: member.blob.chatmailPassword });
  await waitFor((m) => m.type === "ready");
  return { send, waitFor, close: () => ws.close() };
}

it("carol writes to dave first, on the key his instance publishes, and he reads it", async () => {
  const carol = await provision("carol", need("CAROL_TOKEN"), need("CAROL_AUTH_KEY"));
  const dave = await provision("dave", need("DAVE_TOKEN"), need("DAVE_AUTH_KEY"));

  // carol has never heard from dave and names him by handle, as on the
  // page: the instance gives her his address and his key, the very bytes
  // his client made and published, and she holds it from then on.
  signInAs(carol.token);
  const carolPeers = new PeerStateTable();
  const resolved = await resolveRecipient(`@dave@${INSTANCE}`, carolPeers, new KeyLookups());
  if (resolved.status !== "ready") throw new Error(`dave was not found: ${resolved.result.status}`);
  expect(resolved.address).toBe(dave.address);
  expect(resolved.key).toEqual(bytes(dave.blob.publicKeyB64));
  expect(resolved.adopted).not.toBeNull();
  expect(carolPeers.getPublicKey(dave.address)).toEqual(resolved.key);

  const daveKey = resolved.key;
  const carolSocket = await chatSocket(carol);
  const header = `addr=${carol.address}; prefer-encrypt=mutual; keydata=${carol.blob.publicKeyB64}`;
  async function sendToDave(text: string): Promise<void> {
    const cipher = await encryptMessage(
      daveKey,
      bytes(carol.blob.privateKeyB64),
      new TextEncoder().encode(text),
    );
    carolSocket.send({
      type: "send",
      to: dave.address,
      body_b64: uint8ToBase64(cipher),
      autocrypt_header_b64: btoa(header),
    });
    await carolSocket.waitFor((m) => m.type === "sent");
  }
  const plaintext = `first contact through the instance, ${Date.now()}`;
  await sendToDave(plaintext);

  // dave asks for what his mailbox holds, as the chat page does when it
  // connects, and the server pushes what arrives after.
  const daveSocket = await chatSocket(dave);
  const fromCarol = (m: ServerMsg): boolean => m.type === "message" && m.from === carol.address;
  const first = daveSocket.waitFor(fromCarol, 30_000);
  daveSocket.send({ type: "fetch", since_uid: 0 });
  const message = await first;
  const pushed = daveSocket.waitFor(fromCarol, 30_000);
  await sendToDave("a second message, pushed");
  const second = await pushed;
  expect(second.uid).toBeGreaterThan(message.uid ?? 0);
  // Asked while the session idles, a fetch is answered: after the first
  // message, with the second alone; after the second, with nothing.
  const again = daveSocket.waitFor((m) => m.type === "message", 15_000);
  daveSocket.send({ type: "fetch", since_uid: message.uid });
  expect((await again).uid).toBe(second.uid);
  daveSocket.send({ type: "fetch", since_uid: second.uid });
  await expect(daveSocket.waitFor((m) => m.type === "message", 2_000)).rejects.toThrow(
    "nothing arrived",
  );
  daveSocket.close();
  carolSocket.close();
  if (!message.body_b64 || !message.autocrypt_header_b64) {
    throw new Error(`carol's message reached dave incomplete: ${JSON.stringify(message)}`);
  }

  // dave reads it as the chat page does: carol's key from her Autocrypt
  // header, then the message decrypted and her signature verified.
  const davePeers = new PeerStateTable();
  const parsed = parseAutocryptHeader(
    new TextDecoder().decode(bytes(message.autocrypt_header_b64)),
  );
  expect(parsed).not.toBeNull();
  davePeers.update({
    from: message.from!,
    effectiveDate: message.timestamp ?? Math.floor(Date.now() / 1000),
    autocryptHeader: parsed!,
  });
  const result = await decryptAndVerify(
    bytes(dave.blob.privateKeyB64),
    davePeers.getPublicKey(carol.address)!,
    bytes(message.body_b64),
  );
  expect(result.plaintext).toBe(plaintext);
  expect(result.signatureVerified).toBe(true);
}, 120_000);
