// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

/**
 * WASM crypto module loader.
 *
 * Lazy-loads the `noombat-wasm` WebAssembly module (built via
 * `wasm-pack build --target web crates/noombat-wasm`) and exposes a
 * typed API to the SolidJS chat island.
 *
 * The WASM binary is loaded only when the user navigates to the chat
 * interface, avoiding payload cost for users who never use chat.
 *
 * ## Build instructions
 *
 * ```sh
 * wasm-pack build --target web --out-dir ../../frontend/src/chat/wasm \
 *   crates/noombat-wasm
 * ```
 *
 * The output directory (`frontend/src/chat/wasm/`) is gitignored and
 * generated during the build step.
 */

// The wasm-pack output exposes an `init` default export and the
// bindgen-generated functions. The types below mirror the Rust API.

/* eslint-disable @typescript-eslint/no-explicit-any */
type WasmModule = {
  default: (input?: any) => Promise<any>;
  ChatCrypto: {
    new (): ChatCryptoHandle;
    fromJson: (json: string) => ChatCryptoHandle;
  };
  encryptMessage: (recipientKey: Uint8Array, senderKey: Uint8Array, plaintext: Uint8Array) => Uint8Array;
  decryptMessage: (privateKey: Uint8Array, ciphertext: Uint8Array) => Uint8Array;
  generateKeyPair: (email: string) => string;
};

interface ChatCryptoHandle {
  toJson: () => string;
  updatePeerState: (addr: string, ts: bigint, pubkey: Uint8Array, preferMutual: boolean) => void;
  encryptionRecommendation: (recipientsJson: string, senderPrefersMutual: boolean) => string;
  getPeerPublicKey: (addr: string) => Uint8Array | undefined;
}
/* eslint-enable @typescript-eslint/no-explicit-any */

let wasmModule: WasmModule | null = null;

/**
 * Load and initialise the WASM module. Subsequent calls return the
 * cached module.
 */
export async function loadCrypto(): Promise<WasmModule> {
  if (wasmModule) return wasmModule;

  try {
    // Dynamic import: Vite resolves this at build time. The WASM
    // binary is placed alongside the JS glue by wasm-pack.
    const mod = (await import("./wasm/noombat_wasm.js")) as WasmModule;
    await mod.default();
    wasmModule = mod;
    return mod;
  } catch {
    // WASM not available (build step not run, or browser lacks
    // WebAssembly support). Return a no-op fallback so the chat
    // island degrades gracefully to plaintext pass-through.
    console.warn("noombat-wasm not available; chat crypto is disabled.");
    return fallbackModule();
  }
}

// ..... Fallback (plaintext pass-through) .....

function fallbackModule(): WasmModule {
  const noop: ChatCryptoHandle = {
    toJson: () => "{}",
    updatePeerState: () => {},
    encryptionRecommendation: () => "disable",
    getPeerPublicKey: () => undefined,
  };

  const mod: WasmModule = {
    default: async () => {},
    ChatCrypto: {
      new: () => ({ ...noop }),
      fromJson: () => ({ ...noop }),
    } as unknown as WasmModule["ChatCrypto"],
    encryptMessage: (_rk, _sk, pt) => pt,
    decryptMessage: (_pk, ct) => ct,
    generateKeyPair: (_email) =>
      JSON.stringify({
        public_key: Array(32).fill(0),
        private_key: Array(32).fill(0),
      }),
  };

  wasmModule = mod;
  return mod;
}
