// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

// @ts-check

import js from "@eslint/js";
import tseslint from "typescript-eslint";
import solid from "eslint-plugin-solid/configs/typescript";

export default tseslint.config(
  // Global ignores.
  { ignores: ["src/chat/wasm/**", "dist/**"] },

  // Base: ESLint recommended rules.
  js.configs.recommended,

  // TypeScript: recommended rules via typescript-eslint.
  ...tseslint.configs.recommended,

  // SolidJS: framework-specific rules (reactivity, no-destructure,
  // jsx-no-undef, no-react-specific-props, etc.).
  {
    files: ["src/**/*.{ts,tsx}"],
    ...solid,
    languageOptions: {
      parser: tseslint.parser,
      parserOptions: {
        project: "./tsconfig.json",
      },
    },
    rules: {
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
