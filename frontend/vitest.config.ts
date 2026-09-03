// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

/**
 * Vitest configuration.
 *
 * Deliberately separate from `vite.config.ts`. That file registers
 * `vite-plugin-solid`, which injects a jsdom test environment for
 * component rendering. The suites here cover the Autocrypt state
 * machine and the OpenPGP wrapper: pure logic and Web Crypto, with
 * no DOM. Running them under Node avoids pulling in jsdom and keeps
 * the cryptographic tests on the platform's own Web Crypto
 * implementation rather than a shim.
 */

import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    // Both spellings, though the suites here are named `.spec.ts`. The
    // pattern is what decides whether a file is a test, so admitting only
    // one spelling means a file named with the other is not reported as
    // unmatched: it is silently not a test, and the job stays green having
    // run one suite fewer. `vitest run` fails on no files at all, which
    // catches nothing once at least one suite matches.
    include: ["src/**/*.{spec,test}.ts"],
    // Key generation and signature verification dominate the runtime
    // of crypto.spec.ts; the default five-second timeout is tight on
    // a loaded CI runner.
    testTimeout: 30_000,
  },
});
