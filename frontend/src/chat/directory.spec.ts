// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

/**
 * Tests for publishing the member's own chat key, with `fetch` stubbed:
 * what is sent, and when nothing is.
 */

import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import {
  ensureOwnKeyPublished,
  fetchPublishedKey,
  fetchPublishedKeyByHandle,
  publishOwnKey,
  repairOwnKey,
} from "./directory";
import { generateKeyPair, keyFingerprint, type KeyPair } from "./crypto";
import { provisionChat } from "./provision";
import { decryptBlob, fetchBlob } from "./blob";

interface Call {
  url: string;
  method: string;
  body: Uint8Array | null;
  contentType: string | null;
  authorization: string | null;
  setup: string | null;
}

let calls: Call[];

/** Answers each request with the first route whose prefix matches. */
function stubFetch(routes: [string, string, () => Response][]): void {
  vi.stubGlobal("fetch", async (url: string, init: RequestInit = {}) => {
    const method = init.method ?? "GET";
    const headers = (init.headers ?? {}) as Record<string, string>;
    const body =
      init.body instanceof Blob
        ? new Uint8Array(await init.body.arrayBuffer())
        : typeof init.body === "string"
          ? new TextEncoder().encode(init.body)
          : null;
    calls.push({
      url,
      method,
      body,
      contentType: headers["Content-Type"] ?? null,
      authorization: headers.Authorization ?? null,
      setup: headers["Noombat-Chat-Setup"] ?? null,
    });
    const route = routes.find(([m, prefix]) => m === method && url.startsWith(prefix));
    if (!route) throw new Error(`unexpected ${method} ${url}`);
    return route[2]();
  });
}

const KEY = new Uint8Array([0x98, 0x33, 0x04, 0x6a, 0xf8]);
const ADDRESS = "alice+chat@chat.example";
const published = (bytes: Uint8Array): Response =>
  Response.json({ address: ADDRESS, key: btoa(String.fromCharCode(...bytes)) });
const puts = (): Call[] =>
  calls.filter((c) => c.method === "PUT" && c.url === "/api/v1/me/chat_key");

beforeEach(() => {
  calls = [];
  vi.stubGlobal("sessionStorage", { getItem: () => "a-token" });
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("publishOwnKey", () => {
  it("sends exactly the key's bytes, even from a view into a larger buffer", async () => {
    stubFetch([["PUT", "/api/v1/me/chat_key", () => new Response(null, { status: 204 })]]);
    const larger = new Uint8Array([1, 2, ...KEY, 3]);
    expect(await publishOwnKey(larger.subarray(2, 2 + KEY.length), 3)).toBe(true);
    expect(puts()).toHaveLength(1);
    expect(puts()[0].body).toEqual(KEY);
    expect(puts()[0].contentType).toBe("application/octet-stream");
    expect(puts()[0].authorization).toBe("Bearer a-token");
    // The setup whose credentials hold the key's private half.
    expect(puts()[0].setup).toBe("3");
  });

  it("reports a refusal", async () => {
    stubFetch([["PUT", "/api/v1/me/chat_key", () => new Response("no", { status: 400 })]]);
    expect(await publishOwnKey(KEY, 3)).toBe(false);
  });
});

describe("repairOwnKey", () => {
  const blob = {
    chatmailPassword: "relay-password",
    privateKeyB64: btoa("the private half"),
    publicKeyB64: btoa(String.fromCharCode(...KEY)),
    peerStateJson: null,
  };

  it("publishes the blob's public half as the key for the address", async () => {
    stubFetch([
      ["GET", "/api/v1/chat/keys/", () => new Response(null, { status: 404 })],
      ["PUT", "/api/v1/me/chat_key", () => new Response(null, { status: 204 })],
    ]);
    await repairOwnKey(ADDRESS, blob, 3);
    expect(calls[0].url).toBe(`/api/v1/chat/keys/${encodeURIComponent(ADDRESS)}`);
    expect(puts()).toHaveLength(1);
    expect(puts()[0].body).toEqual(KEY);
    expect(puts()[0].setup).toBe("3");
  });

  it("never rejects, since unlocking does not wait for it", async () => {
    vi.stubGlobal("fetch", () => Promise.reject(new TypeError("offline")));
    await expect(repairOwnKey(ADDRESS, blob, 3)).resolves.toBeUndefined();
  });
});

describe("ensureOwnKeyPublished", () => {
  it("publishes when the instance serves no key", async () => {
    stubFetch([
      ["GET", "/api/v1/chat/keys/", () => new Response(null, { status: 404 })],
      ["PUT", "/api/v1/me/chat_key", () => new Response(null, { status: 204 })],
    ]);
    expect(await ensureOwnKeyPublished(ADDRESS, KEY, 3)).toBe(true);
    expect(puts()).toHaveLength(1);
    expect(calls[0].authorization).toBe("Bearer a-token");
  });

  it("publishes when the instance serves another key", async () => {
    // As long as this one and a byte apart, as two keys the client makes are.
    const other = KEY.map((byte, i) => (i === 0 ? byte ^ 1 : byte));
    stubFetch([
      ["GET", "/api/v1/chat/keys/", () => published(other)],
      ["PUT", "/api/v1/me/chat_key", () => new Response(null, { status: 204 })],
    ]);
    expect(await ensureOwnKeyPublished(ADDRESS, KEY, 3)).toBe(true);
    expect(puts()[0].body).toEqual(KEY);
    expect(puts()[0].setup).toBe("3");
  });

  it("sends nothing when the instance already serves this key", async () => {
    stubFetch([["GET", "/api/v1/chat/keys/", () => published(KEY)]]);
    expect(await ensureOwnKeyPublished(ADDRESS, KEY, 3)).toBe(true);
    expect(puts()).toHaveLength(0);
  });

  it("sends nothing when the instance cannot say", async () => {
    stubFetch([["GET", "/api/v1/chat/keys/", () => new Response(null, { status: 500 })]]);
    expect(await ensureOwnKeyPublished(ADDRESS, KEY, 3)).toBe(false);
    expect(puts()).toHaveLength(0);
  });

  it("asks for the address encoded as one path segment", async () => {
    stubFetch([["GET", "/api/v1/chat/keys/", () => published(KEY)]]);
    await ensureOwnKeyPublished(ADDRESS, KEY, 3);
    expect(calls[0].url).toBe("/api/v1/chat/keys/alice%2Bchat%40chat.example");
  });
});

describe("provisionChat", () => {
  const blobKey = (): Promise<CryptoKey> =>
    crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  const provisioned = (): Response =>
    Response.json({ chatmail_addr: "alice@chat.example", chatmail_password: "pw", chat_setup: 7 });
  const setUp = { status: "set_up", address: "alice@chat.example" };

  it("publishes the key it made once the blob is stored", async () => {
    stubFetch([
      ["POST", "/api/v1/me/provision_chat", provisioned],
      ["PUT", "/api/v1/me/chatmail_cred", () => new Response(null, { status: 204 })],
      ["PUT", "/api/v1/me/chat_key", () => new Response(null, { status: 204 })],
    ]);
    const key = await blobKey();
    expect(await provisionChat(key, "an-auth-key")).toEqual(setUp);
    const order = calls.map((c) => c.url);
    // The password's auth key travels with the request to provision.
    expect(new TextDecoder().decode(calls[0].body!)).toBe('{"auth_key":"an-auth-key"}');
    expect(order).toEqual([
      "/api/v1/me/provision_chat",
      "/api/v1/me/chatmail_cred",
      "/api/v1/me/chat_key",
    ]);
    // Both writes name the setup the server just made.
    expect([calls[1].setup, calls[2].setup]).toEqual(["7", "7"]);
    // The published key is the one whose private half the stored blob holds.
    const stored = calls[1].body;
    if (!stored) throw new Error("no blob was stored");
    const blob = await decryptBlob(key, stored, "alice@chat.example");
    expect(puts()[0].body).toEqual(
      Uint8Array.from(atob(blob.publicKeyB64), (c) => c.charCodeAt(0)),
    );
  }, 30_000);

  it("publishes nothing when the blob could not be stored", async () => {
    stubFetch([
      ["POST", "/api/v1/me/provision_chat", provisioned],
      ["PUT", "/api/v1/me/chatmail_cred", () => new Response(null, { status: 500 })],
    ]);
    expect(await provisionChat(await blobKey(), "an-auth-key")).toEqual({ status: "failed" });
    expect(puts()).toHaveLength(0);
  }, 30_000);

  it("stops, publishing nothing, once a newer setup has replaced this one", async () => {
    stubFetch([
      ["POST", "/api/v1/me/provision_chat", provisioned],
      ["PUT", "/api/v1/me/chatmail_cred", () => new Response("newer", { status: 409 })],
    ]);
    expect(await provisionChat(await blobKey(), "an-auth-key")).toEqual({ status: "superseded" });
    expect(puts()).toHaveLength(0);
  }, 30_000);

  it("reports chat set up meanwhile by another tab or device, and stores nothing", async () => {
    stubFetch([["POST", "/api/v1/me/provision_chat", () => new Response("set", { status: 409 })]]);
    expect(await provisionChat(await blobKey(), "an-auth-key")).toEqual({ status: "superseded" });
    expect(calls).toHaveLength(1);
  }, 30_000);

  it("lets one tab of the browser set up at a time", async () => {
    // A Web Lock as the browser grants it: one holder at a time, in turn.
    const names: string[] = [];
    let held = Promise.resolve();
    const locks = {
      request: (name: string, task: () => Promise<unknown>) => {
        names.push(name);
        const turn = held.then(task);
        held = turn.then(
          () => undefined,
          () => undefined,
        );
        return turn;
      },
    };
    vi.stubGlobal("navigator", { locks });
    stubFetch([
      ["POST", "/api/v1/me/provision_chat", provisioned],
      ["PUT", "/api/v1/me/chatmail_cred", () => new Response(null, { status: 204 })],
      ["PUT", "/api/v1/me/chat_key", () => new Response(null, { status: 204 })],
    ]);
    const key = await blobKey();
    await Promise.all([provisionChat(key, "an-auth-key"), provisionChat(key, "an-auth-key")]);
    expect(names).toEqual(["noombat-chat-setup", "noombat-chat-setup"]);
    const once = ["/api/v1/me/provision_chat", "/api/v1/me/chatmail_cred", "/api/v1/me/chat_key"];
    expect(calls.map((c) => c.url)).toEqual([...once, ...once]);
  }, 60_000);

  it("reports chat set up even when publishing the key fails, which unlock repairs", async () => {
    stubFetch([
      ["POST", "/api/v1/me/provision_chat", provisioned],
      ["PUT", "/api/v1/me/chatmail_cred", () => new Response(null, { status: 204 })],
      [
        "PUT",
        "/api/v1/me/chat_key",
        () => {
          throw new TypeError("offline");
        },
      ],
    ]);
    expect(await provisionChat(await blobKey(), "an-auth-key")).toEqual(setUp);
  }, 30_000);

  it("tells a refused password from a setup too soon and any other failure", async () => {
    for (const [status, result] of [
      [403, "refused"],
      [429, "too_soon"],
      [400, "failed"],
      [503, "failed"],
    ] as const) {
      calls = [];
      stubFetch([["POST", "/api/v1/me/provision_chat", () => new Response("no", { status })]]);
      expect(await provisionChat(await blobKey(), "an-auth-key")).toEqual({ status: result });
      expect(calls, "nothing stored").toHaveLength(1);
    }
  }, 30_000);
});

describe("fetchBlob", () => {
  it("reads the setup the credentials belong to", async () => {
    const bytes = new Uint8Array([1, 2, 3]);
    stubFetch([
      [
        "GET",
        "/api/v1/me/chatmail_cred",
        () => new Response(bytes, { headers: { "Noombat-Chat-Setup": "4" } }),
      ],
    ]);
    expect(await fetchBlob()).toEqual({ status: "ok", data: bytes, setup: 4 });
  });

  it("refuses credentials served without their setup, which no write could name", async () => {
    stubFetch([["GET", "/api/v1/me/chatmail_cred", () => new Response(new Uint8Array([1]))]]);
    expect(await fetchBlob()).toEqual({ status: "error", httpStatus: 200 });
  });
});

describe("looking a key up", () => {
  let bob: KeyPair;
  beforeAll(async () => {
    bob = await generateKeyPair("bob@chat.example");
  });
  const served = (address: string, key: Uint8Array) => (): Response =>
    Response.json({ address, key: btoa(String.fromCharCode(...key)) });

  it("finds a checked key, with its fingerprint", async () => {
    stubFetch([["GET", "/api/v1/chat/keys/", served("bob@chat.example", bob.publicKey)]]);
    const found = await fetchPublishedKey("bob@chat.example");
    expect(found).toEqual({
      status: "found",
      address: "bob@chat.example",
      key: bob.publicKey,
      fingerprint: await keyFingerprint(bob.publicKey),
    });
    expect(calls[0].url).toBe("/api/v1/chat/keys/bob%40chat.example");
    expect(calls[0].authorization).toBe("Bearer a-token");
  });

  it("checks the key against the address asked for, not the one answered", async () => {
    stubFetch([["GET", "/api/v1/chat/keys/", served("bob@chat.example", bob.publicKey)]]);
    expect(await fetchPublishedKey("alice@chat.example")).toEqual({ status: "invalid" });
    // Asked in another case, it is still the address asked for.
    const found = await fetchPublishedKey("Bob@Chat.Example");
    expect(found.status === "found" && found.address).toBe("Bob@Chat.Example");
  });

  it("tells absent, refused and broken answers apart", async () => {
    stubFetch([["GET", "/api/v1/chat/keys/", () => new Response(null, { status: 404 })]]);
    expect(await fetchPublishedKey("bob@chat.example")).toEqual({ status: "absent" });
    stubFetch([["GET", "/api/v1/chat/keys/", () => new Response(null, { status: 500 })]]);
    expect(await fetchPublishedKey("bob@chat.example")).toEqual({ status: "error" });
    stubFetch([["GET", "/api/v1/chat/keys/", () => new Response(null, { status: 403 })]]);
    expect(await fetchPublishedKey("bob@chat.example")).toEqual({ status: "error" });
    stubFetch([["GET", "/api/v1/chat/keys/", () => new Response(null, { status: 400 })]]);
    expect(await fetchPublishedKey("bob")).toEqual({ status: "malformed" });
    stubFetch([["GET", "/api/v1/chat/keys/", () => new Response("not json")]]);
    expect(await fetchPublishedKey("bob@chat.example")).toEqual({ status: "invalid" });
    stubFetch([["GET", "/api/v1/chat/keys/", served("bob@chat.example", bob.privateKey)]]);
    expect(await fetchPublishedKey("bob@chat.example")).toEqual({ status: "invalid" });
    vi.stubGlobal("fetch", () => Promise.reject(new TypeError("offline")));
    expect(await fetchPublishedKey("bob@chat.example")).toEqual({ status: "error" });
  });

  it("takes a handle's address from the answer, and checks the key against it", async () => {
    stubFetch([["GET", "/api/v1/chat/keys/by-handle/", served("bob@chat.example", bob.publicKey)]]);
    const found = await fetchPublishedKeyByHandle("@bob@other.example");
    expect(found.status).toBe("found");
    expect(found.status === "found" && found.address).toBe("bob@chat.example");
    expect(calls[0].url).toBe("/api/v1/chat/keys/by-handle/%40bob%40other.example");
    stubFetch([
      ["GET", "/api/v1/chat/keys/by-handle/", served("carol@chat.example", bob.publicKey)],
    ]);
    expect(await fetchPublishedKeyByHandle("@bob@other.example")).toEqual({ status: "invalid" });
  });
});
