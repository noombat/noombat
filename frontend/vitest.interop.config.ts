// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

/**
 * Vitest configuration for the scripts that run the web client's modules
 * against a live stack, which `tests/chat-interop/run.sh` starts. Kept out
 * of the unit suite, whose configuration matches `src/` only.
 */

import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    include: ["interop/**/*.interop.ts"],
    testTimeout: 120_000,
  },
});
