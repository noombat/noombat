// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

import { defineConfig } from "vite";
import tailwindcss from "@tailwindcss/vite";
import solidPlugin from "vite-plugin-solid";

export default defineConfig({
  plugins: [tailwindcss(), solidPlugin()],

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
        katex: "src/katex.ts",
        editor: "src/editor/index.tsx",
        chat: "src/chat/index.tsx",
        "chat-cred": "src/chat-cred.ts",
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
            chunkInfo.name === "chat" ||
            chunkInfo.name === "chat-cred" ||
            chunkInfo.name === "katex"
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
