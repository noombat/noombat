// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

// @ts-check

// Separate from frontend/eslint.config.js rather than shared with it.
// Flat config resolves plugins relative to the config file's own
// directory, and tests/e2e is already its own pnpm package with its own
// lockfile, so reaching across from frontend/ would mean linting files
// outside the config's base path. Prettier is shared (one .prettierrc.json
// at the root) because its config is data with no imports to resolve.

import js from "@eslint/js";
import tseslint from "typescript-eslint";
import playwright from "eslint-plugin-playwright";

export default tseslint.config(
  { ignores: ["node_modules/**", "playwright-report/**", "test-results/**"] },

  js.configs.recommended,
  ...tseslint.configs.recommended,

  {
    files: ["**/*.ts"],
    ...playwright.configs["flat/recommended"],
    rules: {
      ...playwright.configs["flat/recommended"].rules,

      // Both suites assert through helpers as well as directly:
      // `expectNoViolations` from axe-fixture.ts, and the shared page
      // assertions in security-headers.spec.ts. The rule does not look
      // inside a callee, so without the pattern it reports every test
      // that delegates to one as having no assertions, which is noise
      // loud enough to bury anything real. The naming convention is the
      // contract: a helper called `expectSomething` must assert.
      "playwright/expect-expect": [
        "error",
        {
          assertFunctionNames: ["expect"],
          assertFunctionPatterns: ["^expect[A-Z]"],
        },
      ],

      // Both are genuine flakiness, and both are currently clean: the
      // six `waitUntil: "networkidle"` calls and the one
      // `waitForTimeout(2000)` were removed after measuring that they
      // bought nothing. Error, so they cannot come back unnoticed.
      "playwright/no-networkidle": "error",
      "playwright/no-wait-for-timeout": "error",

      // A skipped test looks exactly like a passing one. The four that
      // remain are conditional and annotated at their call sites; a new
      // unannotated one should fail rather than warn. The dangerous
      // case, CI skipping a suite because its credential was absent, is
      // caught earlier: session.ts throws rather than returning null
      // under CI, and accessibility.spec.ts throws when the admin token
      // is empty there.
      "playwright/no-skipped-test": "error",

      // Consistent with frontend/eslint.config.js.
      "@typescript-eslint/no-unused-vars": [
        "error",
        { argsIgnorePattern: "^_", varsIgnorePattern: "^_" },
      ],
    },
  },
);
