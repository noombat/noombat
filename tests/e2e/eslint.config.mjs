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

      // The accessibility suite asserts through a custom helper in
      // axe-fixture.ts. Without naming it, the rule reports all 27 of
      // those tests as having no assertions, which is noise loud enough
      // to bury anything real.
      "playwright/expect-expect": [
        "error",
        { assertFunctionNames: ["expect", "expectNoViolations"] },
      ],

      // Both are genuine flakiness, and both are currently clean: the
      // six `waitUntil: "networkidle"` calls and the one
      // `waitForTimeout(2000)` were removed after measuring that they
      // bought nothing. Error, so they cannot come back unnoticed.
      "playwright/no-networkidle": "error",
      "playwright/no-wait-for-timeout": "error",

      // A skipped test looks exactly like a passing one. The three that
      // remain are conditional and annotated at their call sites; a new
      // unannotated one should fail rather than warn. The dangerous
      // case, CI skipping the authenticated suites because the token
      // was absent, is caught earlier by the guard in
      // accessibility.spec.ts, which throws instead of skipping.
      "playwright/no-skipped-test": "error",

      // Consistent with frontend/eslint.config.js.
      "@typescript-eslint/no-unused-vars": [
        "error",
        { argsIgnorePattern: "^_", varsIgnorePattern: "^_" },
      ],
    },
  },
);
