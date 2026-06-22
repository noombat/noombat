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
      },
      output: {
        assetFileNames: "assets/[name][extname]",
      },
    },
    // Emit a manifest so the server can resolve hashed filenames.
    manifest: true,
  },
});
