// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

// @ts-check

import js from "@eslint/js";
import tseslint from "typescript-eslint";
import solid from "eslint-plugin-solid/configs/typescript";

export default tseslint.config(
  // Global ignores.
  { ignores: ["dist/**"] },

  // Base: ESLint recommended rules.
  js.configs.recommended,

  // TypeScript: recommended rules via typescript-eslint.
  ...tseslint.configs.recommended,

  // SolidJS: framework-specific rules (reactivity, no-destructure,
  // jsx-no-undef, no-react-specific-props, etc.).
  //
  // Both spreads below are load-bearing. A flat-config object has ONE
  // `rules` key and ONE `languageOptions` key, so writing either of them
  // after `...solid` replaces the plugin's version outright instead of
  // adding to it. That is what this block used to do, and the result was
  // that eslint-plugin-solid was installed, registered, and enforcing
  // nothing: `eslint --print-config` reported 88 active rules and zero
  // beginning with `solid/`. Nothing failed, because a rule that never
  // runs never complains. If you add another key here, spread the
  // plugin's value into it too, and check with:
  //
  //   pnpm exec eslint --print-config src/editor/Editor.tsx
  {
    files: ["src/**/*.{ts,tsx}"],
    ...solid,
    languageOptions: {
      ...solid.languageOptions,
      parser: tseslint.parser,
      parserOptions: {
        project: "./tsconfig.json",
      },
    },
    rules: {
      ...solid.rules,
      // Allow unused variables/parameters prefixed with _ (standard
      // TypeScript convention; consistent with Rust's _ prefix).
      "@typescript-eslint/no-unused-vars": [
        "error",
        {
          argsIgnorePattern: "^_",
          varsIgnorePattern: "^_",
        },
      ],
    },
  },
);
