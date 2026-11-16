// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

// The chat page in two browser contexts, against the chat interop stack
// (tests/chat-interop), which run.sh starts its check 19 against, rather
// than the stack the specs beside this file use.
//
// The page is loaded at https://NOOMBAT_DOMAIN, through the stack's Caddy:
// the keys it derives from a password name the host it is served from,
// and it opens its WebSocket on the instance's domain. Firefox maps that
// name to this machine, connects to it directly, whatever proxy the
// environment names, and accepts any certificate, as Caddy's own CA signs
// this one.

import { defineConfig, devices } from "@playwright/test";

const DOMAIN = process.env.NOOMBAT_DOMAIN ?? "test.local";

export default defineConfig({
  testDir: "chat",
  testMatch: "**/*.chat.ts",
  timeout: 180_000,
  workers: 1,
  reporter: "list",

  use: {
    baseURL: `https://${DOMAIN}`,
    ignoreHTTPSErrors: true,
    locale: "en-US",
    trace: "retain-on-failure",
  },

  projects: [
    {
      name: "firefox",
      use: {
        ...devices["Desktop Firefox"],
        launchOptions: {
          firefoxUserPrefs: { "network.dns.localDomains": DOMAIN, "network.proxy.type": 0 },
        },
      },
    },
  ],
});
