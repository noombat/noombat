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
      input: {
        main: "src/main.css",
        htmx: "src/htmx.ts",
        editor: "src/editor/index.tsx",
      },
      output: {
        // CSS assets keep stable names; JS islands get hashed names.
        // The htmx entry receives a stable name because base.html
        // references it with a fixed <script src="/assets/htmx.js">.
        assetFileNames: "assets/[name][extname]",
        entryFileNames: (chunkInfo) => {
          if (chunkInfo.name === "htmx") {
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
