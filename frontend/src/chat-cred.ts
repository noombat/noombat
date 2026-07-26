// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

/**
 * Chat credentials page: password reveal and QR code rendering.
 *
 * Loaded on `/settings/chat`. Reads `data-*` attributes from the
 * `#cred-data` element (server-rendered by Askama) and orchestrates:
 *
 * 1. Password prompt to PBKDF2 to HKDF to AES-GCM blob decryption.
 * 2. Display the Chatmail password.
 * 3. Render a Delta Chat configuration QR code on the canvas.
 */

import { deriveBlobKey } from "./auth";
import { fetchBlob, decryptBlob } from "./chat/blob";
import QRCode from "qrcode";

document.addEventListener("DOMContentLoaded", () => {
  const dataEl = document.getElementById("cred-data");
  if (!dataEl) return;

  const username = dataEl.dataset.username ?? "";
  const chatmailAddr = dataEl.dataset.chatmailAddr ?? "";
  const chatmailDomain = dataEl.dataset.chatmailDomain ?? "";

  const revealBtn = document.getElementById("reveal-password-btn");
  const outputEl = document.getElementById("chatmail-password");
  const qrSection = document.getElementById("qr-section");
  if (!revealBtn || !outputEl) return;
  const output = outputEl;

  revealBtn.addEventListener("click", () => {
    // Replace the button with a password prompt.
    const container = revealBtn.parentElement!;
    revealBtn.remove();

    const prompt = document.createElement("div");
    prompt.className = "flex gap-2 items-center mt-2";
    prompt.innerHTML = `
      <input type="password" id="cred-password"
             placeholder="Noombat password"
             class="border border-border rounded px-3 py-2 text-sm bg-surface text-fg">
      <button type="button" id="cred-unlock"
              class="bg-accent text-white rounded px-4 py-2 text-sm">
        Unlock
      </button>
    `;
    container.appendChild(prompt);

    const passwordInput = document.getElementById(
      "cred-password",
    ) as HTMLInputElement;
    const unlockBtn = document.getElementById(
      "cred-unlock",
    ) as HTMLButtonElement;
    passwordInput.focus();

    async function unlock(): Promise<void> {
      const password = passwordInput.value;
      if (!password) return;

      unlockBtn.disabled = true;
      unlockBtn.textContent = "Decrypting\u2026";

      try {
        const domain = window.location.hostname;
        const blobKey = await deriveBlobKey(password, username, domain);
        const encrypted = await fetchBlob();
        if (!encrypted) {
          showError(
            container,
            "No credential blob found. Chat may not be provisioned.",
          );
          return;
        }

        const blob = await decryptBlob(blobKey, encrypted);
        const chatmailPassword = blob.chatmailPassword;

        // Remove the prompt and display the password.
        prompt.remove();
        output.textContent = chatmailPassword;
        output.classList.remove("hidden");

        // Add a copy button next to the password.
        const copyBtn = document.createElement("button");
        copyBtn.type = "button";
        copyBtn.className = "cred-copy text-xs text-muted hover:text-fg mt-1";
        copyBtn.textContent = "Copy password";
        copyBtn.addEventListener("click", () => {
          navigator.clipboard.writeText(chatmailPassword).then(() => {
            const orig = copyBtn.textContent;
            copyBtn.textContent = "\u2713";
            setTimeout(() => {
              copyBtn.textContent = orig;
            }, 1500);
          });
        });
        output.after(copyBtn);

        // Render the QR code for Delta Chat import.
        if (qrSection) {
          qrSection.classList.remove("hidden");
          const canvas = document.getElementById(
            "cred-qr",
          ) as HTMLCanvasElement | null;
          if (canvas) {
            // Delta Chat DCACCOUNT URI format.
            const uri = `DCACCOUNT:https://${chatmailDomain}?p=${encodeURIComponent(chatmailPassword)}&a=${encodeURIComponent(chatmailAddr)}`;
            try {
              await QRCode.toCanvas(canvas, uri, {
                width: 200,
                margin: 2,
                color: { dark: "#000000", light: "#ffffff" },
              });
            } catch {
              // QR rendering failed; show the URI as fallback text.
              const ctx = canvas.getContext("2d");
              if (ctx) {
                ctx.fillStyle = "#f0f0f0";
                ctx.fillRect(0, 0, 200, 200);
                ctx.fillStyle = "#666";
                ctx.font = "11px sans-serif";
                ctx.textAlign = "center";
                ctx.fillText("QR rendering failed.", 100, 100);
              }
            }

            // Show the URI as a copyable fallback below the QR code.
            const uriDisplay = document.createElement("code");
            uriDisplay.className =
              "block mt-2 text-xs font-mono break-all select-all text-muted";
            uriDisplay.textContent = uri;
            canvas.after(uriDisplay);
          }
        }
      } catch {
        unlockBtn.disabled = false;
        unlockBtn.textContent = "Unlock";
        showError(container, "Incorrect password or decryption failed.");
      }
    }

    unlockBtn.addEventListener("click", () => void unlock());
    passwordInput.addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        e.preventDefault();
        void unlock();
      }
    });
  });
});

function showError(container: HTMLElement, message: string): void {
  let alert = container.querySelector("[role=alert]") as HTMLElement | null;
  if (!alert) {
    alert = document.createElement("div");
    alert.setAttribute("role", "alert");
    alert.className =
      "bg-red-50 border border-red-300 text-red-800 rounded px-4 py-3 mt-2 text-sm";
    container.appendChild(alert);
  }
  alert.textContent = message;
}
