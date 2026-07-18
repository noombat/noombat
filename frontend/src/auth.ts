// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

/**
 * Client-side split key derivation for Noombat authentication.
 *
 * Derives a master key from the user's password via PBKDF2-SHA256
 * (600,000 iterations), then splits it into two independent keys
 * via HKDF-Expand:
 *
 * 1. Authentication key ("noombat-auth"): sent to the server,
 *    which stores its Argon2id hash.
 * 2. Blob encryption key ("noombat-chat-crypto"): never leaves
 *    the browser; used to encrypt/decrypt the Chatmail credential
 *    blob.
 *
 * The raw password is never transmitted to the server.
 */

const PBKDF2_ITERATIONS = 600_000;
const KEY_LENGTH_BYTES = 32;

/** Derive the master key from a password and deterministic salt. */
async function deriveMasterKey(
  password: string,
  username: string,
  domain: string,
): Promise<CryptoKey> {
  const enc = new TextEncoder();
  const salt = enc.encode(`${username.toLowerCase()}@${domain}`);

  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"],
  );

  const masterBits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
    keyMaterial,
    KEY_LENGTH_BYTES * 8,
  );

  return crypto.subtle.importKey("raw", masterBits, "HKDF", false, [
    "deriveBits",
  ]);
}

/** HKDF-Expand the master key with an info string. */
async function hkdfExpand(
  masterKey: CryptoKey,
  info: string,
): Promise<ArrayBuffer> {
  const enc = new TextEncoder();
  return crypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new Uint8Array(0),
      info: enc.encode(info),
    },
    masterKey,
    KEY_LENGTH_BYTES * 8,
  );
}

/** Encode an ArrayBuffer as a hex string. */
function bufToHex(buf: ArrayBuffer): string {
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Derive the authentication key from a password.
 *
 * Returns a 64-character hex string (32 bytes).
 */
export async function deriveAuthKey(
  password: string,
  username: string,
  domain: string,
): Promise<string> {
  const masterKey = await deriveMasterKey(password, username, domain);
  const authBits = await hkdfExpand(masterKey, "noombat-auth");
  return bufToHex(authBits);
}

/**
 * Derive the blob encryption key from a password.
 *
 * Returns a CryptoKey suitable for AES-GCM encryption/decryption.
 * This key never leaves the browser.
 */
export async function deriveBlobKey(
  password: string,
  username: string,
  domain: string,
): Promise<CryptoKey> {
  const masterKey = await deriveMasterKey(password, username, domain);
  const blobBits = await hkdfExpand(masterKey, "noombat-chat-crypto");
  return crypto.subtle.importKey("raw", blobBits, "AES-GCM", false, [
    "encrypt",
    "decrypt",
  ]);
}

/**
 * Derive both the authentication key and the blob encryption key
 * from a single PBKDF2 master-key derivation.
 *
 * Use this when both keys are needed in the same flow (e.g. chat
 * credential provisioning) to avoid paying the 600,000-iteration
 * PBKDF2 cost twice.
 */
export async function deriveBothKeys(
  password: string,
  username: string,
  domain: string,
): Promise<{ authKey: string; blobKey: CryptoKey }> {
  const masterKey = await deriveMasterKey(password, username, domain);

  const authBits = await hkdfExpand(masterKey, "noombat-auth");
  const authKey = bufToHex(authBits);

  const blobBits = await hkdfExpand(masterKey, "noombat-chat-crypto");
  const blobKey = await crypto.subtle.importKey("raw", blobBits, "AES-GCM", false, [
    "encrypt",
    "decrypt",
  ]);

  return { authKey, blobKey };
}

// ..... Form interception .....

/** Extract the instance domain from the page URL. */
function getInstanceDomain(): string {
  return window.location.hostname;
}

/**
 * Intercept the login form: derive the auth key from the password
 * and populate the hidden field before submission.
 */
function setupLoginForm(): void {
  const form = document.getElementById("login-form") as HTMLFormElement | null;
  if (!form) return;

  form.addEventListener("submit", async (e) => {
    e.preventDefault();

    const usernameInput = document.getElementById("login-username") as HTMLInputElement;
    const passwordInput = document.getElementById("login-password") as HTMLInputElement;
    const authKeyInput = document.getElementById("login-auth-key") as HTMLInputElement;

    const username = usernameInput.value.trim();
    const password = passwordInput.value;

    if (!username || !password) return;

    const authKey = await deriveAuthKey(password, username, getInstanceDomain());
    authKeyInput.value = authKey;

    // Clear the raw password from the DOM before submission.
    passwordInput.value = "";

    // Submit as JSON to the API endpoint.
    const totpInput = document.getElementById("login-totp") as HTMLInputElement | null;
    const body: Record<string, string> = {
      username,
      auth_key: authKey,
    };
    if (totpInput?.value) {
      body.totp_code = totpInput.value;
    }

    try {
      const resp = await fetch("/api/v1/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });

      if (resp.ok) {
        const data = await resp.json();
        sessionStorage.setItem("noombat_access_token", data.access_token);
        sessionStorage.setItem("noombat_refresh_token", data.refresh_token);
        window.location.href = "/";
      } else if (resp.status === 400) {
        const data = await resp.json();
        if (data.error?.includes("TOTP")) {
          // Reveal the TOTP field.
          document.getElementById("totp-group")?.classList.remove("hidden");
          (document.getElementById("login-totp") as HTMLInputElement)?.focus();
        } else {
          showError(form, data.error || "Login failed.");
        }
      } else {
        showError(form, "Invalid username or password.");
      }
    } catch {
      showError(form, "Network error. Please try again.");
    }
  });
}

/**
 * Intercept the registration form: validate password confirmation,
 * derive the auth key, and submit.
 */
function setupRegisterForm(): void {
  const form = document.getElementById("register-form") as HTMLFormElement | null;
  if (!form) return;

  form.addEventListener("submit", async (e) => {
    e.preventDefault();

    const usernameInput = document.getElementById("reg-username") as HTMLInputElement;
    const passwordInput = document.getElementById("reg-password") as HTMLInputElement;
    const confirmInput = document.getElementById("reg-password-confirm") as HTMLInputElement;
    const displayNameInput = document.getElementById("reg-display-name") as HTMLInputElement;
    const authKeyInput = document.getElementById("reg-auth-key") as HTMLInputElement;

    const username = usernameInput.value.trim();
    const password = passwordInput.value;
    const confirm = confirmInput.value;

    if (password !== confirm) {
      showError(form, document.documentElement.dataset.passwordMismatch || "Passwords do not match.");
      return;
    }

    const authKey = await deriveAuthKey(password, username, getInstanceDomain());
    authKeyInput.value = authKey;

    passwordInput.value = "";
    confirmInput.value = "";

    const body: Record<string, string> = {
      username,
      auth_key: authKey,
    };
    const displayName = displayNameInput?.value.trim();
    if (displayName) {
      body.display_name = displayName;
    }

    try {
      const resp = await fetch("/api/v1/auth/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });

      if (resp.ok || resp.status === 201) {
        const data = await resp.json();
        sessionStorage.setItem("noombat_access_token", data.access_token);
        sessionStorage.setItem("noombat_refresh_token", data.refresh_token);
        window.location.href = "/";
      } else {
        const data = await resp.json().catch(() => ({}));
        showError(form, data.error || "Registration failed.");
      }
    } catch {
      showError(form, "Network error. Please try again.");
    }
  });
}

/** Display an error message above the form. */
function showError(form: HTMLFormElement, message: string): void {
  let alert = form.querySelector("[role=alert]") as HTMLElement | null;
  if (!alert) {
    alert = document.createElement("div");
    alert.setAttribute("role", "alert");
    alert.className = "bg-red-50 border border-red-300 text-red-800 rounded px-4 py-3 mb-6 text-sm";
    form.prepend(alert);
  }
  alert.textContent = message;
}

// ..... Token refresh .....

/** Interval handle for the session refresh heartbeat. */
let refreshTimer: ReturnType<typeof setInterval> | undefined;

/**
 * Attempt to refresh the session using the refresh token stored in
 * sessionStorage. On success, the server sets a new session cookie
 * (via Set-Cookie) and returns fresh tokens.
 *
 * Returns `true` if the refresh succeeded.
 */
async function refreshSession(): Promise<boolean> {
  const refreshToken = sessionStorage.getItem("noombat_refresh_token");
  if (!refreshToken) return false;

  try {
    const resp = await fetch("/api/v1/auth/refresh", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ refresh_token: refreshToken }),
    });

    if (resp.ok) {
      const data = await resp.json();
      sessionStorage.setItem("noombat_access_token", data.access_token);
      sessionStorage.setItem("noombat_refresh_token", data.refresh_token);
      return true;
    }

    // Refresh token is expired or revoked: clear stored tokens.
    sessionStorage.removeItem("noombat_access_token");
    sessionStorage.removeItem("noombat_refresh_token");
    return false;
  } catch {
    return false;
  }
}

/**
 * Start a periodic heartbeat that refreshes the session before the
 * access token (and cookie) expires.
 *
 * The heartbeat fires at 80% of the access-token TTL. If the TTL
 * is unknown, a conservative default of 12 minutes is used (80% of
 * the default 900-second TTL).
 */
function startRefreshHeartbeat(): void {
  if (refreshTimer !== undefined) return;

  const DEFAULT_INTERVAL_MS = 12 * 60 * 1000; // 12 minutes
  refreshTimer = setInterval(() => {
    void refreshSession();
  }, DEFAULT_INTERVAL_MS);
}

// ..... Initialisation .....

// Initialise on DOMContentLoaded.
document.addEventListener("DOMContentLoaded", () => {
  setupLoginForm();
  setupRegisterForm();

  // If the user has a refresh token, start the heartbeat so the
  // session cookie is renewed before it expires.
  if (sessionStorage.getItem("noombat_refresh_token")) {
    startRefreshHeartbeat();
  }
});
