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
        editor: "src/editor/index.tsx",
        chat: "src/chat/index.tsx",
        "chat-cred": "src/chat-cred.ts",
        compose: "src/compose.ts",
        upgrade: "src/upgrade.ts",
      },
      output: {
        // Every file is named by a hash of its content, so the server can
        // let browsers keep it for a year; pages find the names in the
        // manifest below.
        assetFileNames: "assets/[name]-[hash][extname]",
        entryFileNames: "assets/[name]-[hash].js",
      },
    },
    // Emit a manifest so the server can resolve hashed filenames.
    manifest: true,
  },
});
