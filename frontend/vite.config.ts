// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { defineConfig, type Plugin } from "vite";
import tailwindcss from "@tailwindcss/vite";
import solidPlugin from "vite-plugin-solid";

/**
 * Vite plugin: provide a virtual stub for the `noombat-wasm` module
 * when `wasm-pack` has not been run.
 *
 * The chat island lazy-loads `./wasm/noombat_wasm.js` via a dynamic
 * `import()` wrapped in a `try/catch` (see `crypto.ts`). When the
 * real wasm-pack output exists on disk, Vite resolves and bundles it
 * normally. When it does not (e.g. in the Dockerfile `frontend`
 * stage, which has Node but not Rust), this plugin intercepts the
 * resolution and returns a virtual module whose `init()` throws,
 * triggering the existing `fallbackModule()` code path.
 */
function wasmStub(): Plugin {
  const STUB_ID = "\0noombat-wasm-stub";

  return {
    name: "noombat-wasm-stub",
    enforce: "pre",

    resolveId(source: string, importer: string | undefined) {
      if (source.endsWith("noombat_wasm.js") && importer) {
        const resolved = resolve(dirname(importer), source);
        if (!existsSync(resolved)) {
          return STUB_ID;
        }
      }
      return null;
    },

    load(id: string) {
      if (id === STUB_ID) {
        // Minimal ES module satisfying the WasmModule type surface.
        // Every function throws so that the try/catch in crypto.ts
        // falls through to fallbackModule().
        return [
          '// Virtual stub — wasm-pack output not found at build time.',
          'export default function init() { throw new Error("noombat-wasm not built"); }',
          "export class ChatCrypto {}",
          'export function encryptMessage() { throw new Error("stub"); }',
          'export function decryptMessage() { throw new Error("stub"); }',
          'export function generateKeyPair() { throw new Error("stub"); }',
          'export function initSync() { throw new Error("stub"); }',
        ].join("\n");
      }
      return null;
    },
  };
}

export default defineConfig({
  plugins: [wasmStub(), tailwindcss(), solidPlugin()],

  build: {
    outDir: "dist",
    rollupOptions: {
      // Suppress the eval warning from HTMX's own source code.
      // HTMX uses eval() internally for dynamic attribute evaluation
      // (e.g. hx-on:click).
      onwarn(warning, warn) {
        if (warning.code === "EVAL" && warning.id?.includes("htmx")) return;
        warn(warning);
      },
      input: {
        main: "src/main.css",
        htmx: "src/htmx.ts",
        auth: "src/auth.ts",
        editor: "src/editor/index.tsx",
        chat: "src/chat/index.tsx",
      },
      output: {
        // CSS assets keep stable names; JS islands get hashed names.
        // The htmx entry receives a stable name because base.html
        // references it with a fixed <script src="/assets/htmx.js">.
        assetFileNames: "assets/[name][extname]",
        entryFileNames: (chunkInfo) => {
          if (
            chunkInfo.name === "htmx" ||
            chunkInfo.name === "auth" ||
            chunkInfo.name === "editor" ||
            chunkInfo.name === "chat"
          ) {
            return "assets/[name].js";
          }
          return "assets/[name]-[hash].js";
        },
      },
    },
    // Emit a manifest so the server can resolve hashed filenames.
    manifest: true,
  },
});
