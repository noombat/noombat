// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

/**
 * Entry point for the OAuth account-upgrade page (`/auth/upgrade`).
 *
 * Intercepts the upgrade form, sets an account password using the
 * split key derivation in `src/auth.ts`, and provisions the
 * Chatmail account using the shared implementation in
 * `src/chat/provision.ts`.
 *
 * This module replaces an inline `<script type="module">` block
 * previously embedded in `templates/upgrade.html`. Extracting it
 * serves three purposes: the page becomes compatible with a
 * `script-src 'self'` Content-Security-Policy that omits
 * `'unsafe-inline'`; the duplicated key-derivation and provisioning
 * code is eliminated; and server-provided values reach the client
 * through `data-*` attributes rather than interpolation into a
 * JavaScript string literal. The latter matters because Askama
 * escapes for HTML contexts, not JavaScript ones, so template
 * interpolation inside a script body was a template-injection
 * surface.
 */

import { deriveBothKeys } from "./auth";
import { provisionChat } from "./chat/provision";
import { showFormAlert } from "./ui/alert";

/** Read a localised string from the document element, with fallback. */
function localised(key: string, fallback: string): string {
  return document.documentElement.dataset[key] || fallback;
}

/** Intercept the upgrade form and run the provisioning sequence. */
function setupUpgradeForm(): void {
  const form = document.getElementById("upgrade-form") as HTMLFormElement | null;
  if (!form) return;

  form.addEventListener("submit", async (e) => {
    e.preventDefault();

    const passwordInput = document.getElementById("upgrade-password") as HTMLInputElement;
    const confirmInput = document.getElementById("upgrade-password-confirm") as HTMLInputElement;

    const password = passwordInput.value;
    const confirm = confirmInput.value;

    if (password !== confirm) {
      showFormAlert(form, localised("passwordMismatch", "Passwords do not match."));
      return;
    }

    // The username forms part of the PBKDF2 salt and is supplied by
    // the server as a data attribute.
    const username = form.dataset.username ?? "";
    const domain = window.location.hostname;

    // Derive the authentication key and the blob encryption key
    // from a single PBKDF2 pass (600 000 iterations).
    const { authKey, blobKey } = await deriveBothKeys(password, username, domain);

    // Clear the raw password from the DOM. The local `password`
    // binding is no longer needed beyond this point.
    passwordInput.value = "";
    confirmInput.value = "";

    // Step 1: set the account password.
    let pwResp: Response;
    try {
      pwResp = await fetch("/api/v1/auth/password", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ auth_key: authKey }),
      });
    } catch {
      showFormAlert(form, localised("networkError", "Network error. Please try again."));
      return;
    }

    if (!pwResp.ok) {
      showFormAlert(
        form,
        localised("upgradePasswordFailed", "Failed to set the password. Please try again."),
      );
      return;
    }

    // Step 2: provision the Chatmail account and store the encrypted
    // credential blob. Best-effort: the password is already set, and
    // provisioning can be retried from the chat page.
    await provisionChat(blobKey).catch(() => {
      // Non-fatal; chat setup is deferred.
    });

    window.location.href = "/chat";
  });
}

document.addEventListener("DOMContentLoaded", setupUpgradeForm);
