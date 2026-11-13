// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

/**
 * Known answers for the password key derivation.
 *
 * The server keeps only a hash of the login key, and the chat credential
 * blob is sealed under the chat key. A change to the iteration count, the
 * salt, an HKDF label or an output length therefore locks out every
 * password account and leaves every stored blob unreadable, and nothing
 * else fails when it happens. The expected values were computed apart from
 * this module, with Node's own PBKDF2, HKDF and AES-GCM.
 */

import { describe, it, expect, vi } from "vitest";

// auth.ts registers a DOMContentLoaded listener when it loads, and these
// suites run under Node, which has no document.
vi.stubGlobal("document", { addEventListener: () => undefined });
const { deriveAuthKey, deriveBlobKey, deriveBothKeys } = await import("./auth");

const PASSWORD = "correct horse battery staple";
// Mixed case, because the salt is the lower-cased username at the domain.
const USERNAME = "Alice";
const DOMAIN = "noombat.example";

// PBKDF2-SHA256 over 600,000 iterations with salt "alice@noombat.example",
// then HKDF-SHA256 with an empty salt and info "noombat-auth", 32 bytes.
const LOGIN_KEY_HEX = "02cddc698fbce782cd4243ebb84449a456eee265cd40b012e99b0781f3d291d7";

// The chat key is not extractable, so it is pinned through one AES-256-GCM
// encryption under it: HKDF info "noombat-chat-crypto", a zero IV, and this
// plaintext. The last 16 bytes are the tag.
const IV = new Uint8Array(12);
const PLAINTEXT = new TextEncoder().encode("noombat known answer");
const SEALED_HEX = "9be9d31a6cea2c2f400f3b3934e1c300b5f532e477e3bccf695e10838ad880c49daaba1c";

function hex(buf: ArrayBuffer): string {
  return Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, "0")).join("");
}

async function sealedUnder(key: CryptoKey): Promise<string> {
  return hex(await crypto.subtle.encrypt({ name: "AES-GCM", iv: IV }, key, PLAINTEXT));
}

describe("password key derivation", () => {
  it("derives the login key sent to the server", async () => {
    expect(await deriveAuthKey(PASSWORD, USERNAME, DOMAIN)).toBe(LOGIN_KEY_HEX);
  });

  it("derives the chat key kept in the browser", async () => {
    const blobKey = await deriveBlobKey(PASSWORD, USERNAME, DOMAIN);
    expect(await sealedUnder(blobKey)).toBe(SEALED_HEX);
  });

  it("derives the same pair in a single pass", async () => {
    const { authKey, blobKey } = await deriveBothKeys(PASSWORD, USERNAME, DOMAIN);
    expect(authKey).toBe(LOGIN_KEY_HEX);
    expect(await sealedUnder(blobKey)).toBe(SEALED_HEX);
  });
});
