// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

// Reusable Playwright fixture that wraps @axe-core/playwright for
// WCAG 2.2 AA automated accessibility testing.
//
// Usage in spec files:
//
//   import { test, expectNoViolations } from "./axe-fixture";
//
//   test("page has no WCAG 2.2 AA violations", async ({ page, axeScan }) => {
//     await page.goto("/some-page");
//     const results = await axeScan();
//     expectNoViolations(results);
//   });

import { test as base, expect } from "@playwright/test";
import { AxeBuilder } from "@axe-core/playwright";
import type { AxeResults } from "axe-core";

// ..... Fixture type .....

/**
 * Options accepted by the `axeScan` fixture function.
 */
interface AxeScanOptions {
  /**
   * CSS selectors to exclude from the scan (e.g. third-party widget
   * containers that the project does not control).
   */
  exclude?: string[];

  /**
   * Additional axe rule IDs to disable for this scan. Use sparingly
   * and document the reason for each disabled rule.
   */
  disableRules?: string[];
}

type AxeScanFn = (options?: AxeScanOptions) => Promise<AxeResults>;

/**
 * Extended test fixtures.
 */
interface AxeFixtures {
  /** Run an axe-core scan against the current page state. */
  axeScan: AxeScanFn;
}

// ..... Fixture definition .....

/**
 * Extended `test` function that provides the `axeScan` fixture.
 *
 * The fixture is scoped to WCAG 2.0 A, WCAG 2.0 AA, WCAG 2.1 A,
 * WCAG 2.1 AA, WCAG 2.2 A, and WCAG 2.2 AA tags.
 */
export const test = base.extend<AxeFixtures>({
  axeScan: async ({ page }, use) => {
    const scan: AxeScanFn = async (options?: AxeScanOptions) => {
      let builder = new AxeBuilder({ page }).withTags([
        "wcag2a",
        "wcag2aa",
        "wcag21a",
        "wcag21aa",
        "wcag22aa",
      ]);

      if (options?.exclude) {
        for (const selector of options.exclude) {
          builder = builder.exclude(selector);
        }
      }

      if (options?.disableRules) {
        builder = builder.disableRules(options.disableRules);
      }

      return builder.analyze();
    };

    await use(scan);
  },
});

// Re-export `expect` for convenience.
export { expect };

// ..... Assertion helper .....

/**
 * Format a single axe violation into a human-readable string suitable
 * for CI log output.
 */
function formatViolation(v: AxeResults["violations"][number]): string {
  const nodes = v.nodes
    .slice(0, 5) // Cap at 5 nodes per rule to keep output manageable.
    .map((n) => {
      const target = n.target.join(", ");
      const fix = n.failureSummary ?? "";
      return `      → ${target}\n        ${fix}`;
    })
    .join("\n");
  const extra = v.nodes.length > 5 ? `\n      … and ${v.nodes.length - 5} more` : "";
  return `  [${v.impact ?? "unknown"}] ${v.id}: ${v.help}\n` + `    ${v.helpUrl}\n` + nodes + extra;
}

/**
 * Assert that an axe scan produced zero violations. On failure, the
 * error message includes a formatted summary of every violation with
 * its impact level, rule ID, help URL, and the first five affected
 * DOM nodes.
 */
export function expectNoViolations(results: AxeResults): void {
  const violations = results.violations;
  if (violations.length === 0) {
    return;
  }

  const summary = violations.map(formatViolation).join("\n\n");
  const message =
    `Expected zero WCAG 2.2 AA violations but found ${violations.length}:\n\n` + summary;

  // Use `expect` so that Playwright's reporter captures the failure
  // with proper formatting and trace attachment.
  expect(violations, message).toHaveLength(0);
}
