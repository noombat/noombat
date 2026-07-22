// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

/**
 * SolidJS chat island component.
 *
 * Manages the WebSocket connection to the Noombat chat relay,
 * renders a contact list and conversation view, and delegates
 * cryptographic operations (encryption, decryption, Autocrypt state)
 * to the rPGP and noombat-autocrypt WASM modules.
 *
 * On narrow viewports the component renders a full-screen
 * conversation view with a drawer-based contact list. On wide
 * viewports it renders a two-column layout.
 */

import {
  createSignal,
  onCleanup,
  onMount,
  For,
  Show,
  type JSX,
} from "solid-js";
import { loadCrypto } from "./crypto";
import { decryptBlob, encryptBlob, fetchBlob, storeBlob, type CredentialBlob } from "./blob";
import { deriveBlobKey } from "../auth";

// ..... Base64 helpers .....

/** Encode a Uint8Array to a base64 string without stack overflow.
 *  The spread operator in `String.fromCharCode(...arr)` exceeds the
 *  maximum call-stack argument count for arrays larger than ~100 KiB.
 *  This chunked approach avoids that limit. */
function uint8ToBase64(bytes: Uint8Array): string {
  const CHUNK = 0x8000; // 32 KiB per chunk
  const parts: string[] = [];
  for (let i = 0; i < bytes.length; i += CHUNK) {
    parts.push(String.fromCharCode(...bytes.subarray(i, i + CHUNK)));
  }
  return btoa(parts.join(""));
}

/** Decode a base64 string to a Uint8Array. */
function base64ToUint8(b64: string): Uint8Array {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) {
    bytes[i] = bin.charCodeAt(i);
  }
  return bytes;
}

// Module-level handle for the loaded WASM module.
type CryptoMod = Awaited<ReturnType<typeof loadCrypto>>;

// ..... i18n .....

interface ChatStrings {
  heading: string;
  empty: string;
  send: string;
  placeholder: string;
  report: string;
  contacts: string;
  connecting: string;
  disconnected: string;
  notProvisioned: string;
  setupChat: string;
  enterPassword: string;
  unlock: string;
}

const TRANSLATIONS: Record<string, ChatStrings> = {
  "en-US": {
    heading: "Messages",
    empty: "No messages yet.",
    send: "Send",
    placeholder: "Write a message\u2026",
    report: "Report",
    contacts: "Contacts",
    connecting: "Connecting\u2026",
    disconnected: "Disconnected. Reconnecting\u2026",
    notProvisioned: "To send encrypted messages, set a password for your Noombat account.",
    setupChat: "Set up chat",
    enterPassword: "Enter your Noombat password to unlock encrypted chat.",
    unlock: "Unlock",
  },
  "en-AU": {
    heading: "Messages",
    empty: "No messages yet.",
    send: "Send",
    placeholder: "Write a message\u2026",
    report: "Report",
    contacts: "Contacts",
    connecting: "Connecting\u2026",
    disconnected: "Disconnected. Reconnecting\u2026",
    notProvisioned: "To send encrypted messages, set a password for your Noombat account.",
    setupChat: "Set up chat",
    enterPassword: "Enter your Noombat password to unlock encrypted chat.",
    unlock: "Unlock",
  },
  "pt-BR": {
    heading: "Mensagens",
    empty: "Nenhuma mensagem ainda.",
    send: "Enviar",
    placeholder: "Escreva uma mensagem\u2026",
    report: "Denunciar",
    contacts: "Contatos",
    connecting: "Conectando\u2026",
    disconnected: "Desconectado. Reconectando\u2026",
    notProvisioned: "Para enviar mensagens criptografadas, defina uma senha para sua conta Noombat.",
    setupChat: "Configurar chat",
    enterPassword: "Digite sua senha Noombat para desbloquear o chat criptografado.",
    unlock: "Desbloquear",
  },
};

function t(locale: string): ChatStrings {
  return TRANSLATIONS[locale] ?? TRANSLATIONS["en-US"];
}

// ..... Types .....

/** A message in the local message list. */
interface ChatMessage {
  id: string;
  uid: number;
  from: string;
  /** Recipient address (for outgoing messages). */
  to: string;
  /** Plaintext body (after client-side decryption). */
  body: string;
  timestamp: number;
  outgoing: boolean;
}

/** A message from the relay server. */
interface ServerMsg {
  type: "ready" | "message" | "sent" | "error";
  uid?: number;
  from?: string;
  body_b64?: string;
  autocrypt_header_b64?: string;
  timestamp?: number;
  to?: string;
  message?: string;
}

// ..... Component .....

export interface ChatProps {
  wsUrl: string;
  chatmailAddr: string;
  /** The Noombat username (used as the PBKDF2 salt component for
   *  blob encryption key derivation). This may differ from the
   *  Chatmail address local part. */
  username: string;
  locale?: string;
}

export default function Chat(props: ChatProps): JSX.Element {
  const strings = () => t(props.locale ?? "en-US");

  const [messages, setMessages] = createSignal<ChatMessage[]>([]);
  const [draft, setDraft] = createSignal("");
  const [recipient, setRecipient] = createSignal("");
  const [contacts, setContacts] = createSignal<string[]>([]);
  const [connected, setConnected] = createSignal(false);
  const [showContacts, setShowContacts] = createSignal(false);
  const [status, setStatus] = createSignal<string>("");
  const [needsUnlock, setNeedsUnlock] = createSignal(false);
  const [unlockPassword, setUnlockPassword] = createSignal("");

  let ws: WebSocket | null = null;
  let reconnectTimer: ReturnType<typeof setTimeout> | undefined;
  let msgCounter = 0;
  let crypto: CryptoMod | null = null;

  // Decrypted credential material (held in memory for the session).
  let credentials: CredentialBlob | null = null;
  let privateKeyBytes: Uint8Array | null = null;
  let publicKeyBytes: Uint8Array | null = null;
  let cryptoHandle: InstanceType<CryptoMod["ChatCrypto"]> | null = null;
  let blobKey: CryptoKey | null = null;

  // ..... Blob decryption .....

  /** Attempt to decrypt the credential blob. */
  async function unlockBlob(password: string): Promise<boolean> {
    const encryptedBlob = await fetchBlob();
    if (!encryptedBlob) return false;

    const domain = window.location.hostname;

    try {
      const key = await deriveBlobKey(password, props.username, domain);
      const blob = await decryptBlob(key, encryptedBlob);
      credentials = blob;
      blobKey = key;

      // Decode keys from base64.
      privateKeyBytes = base64ToUint8(blob.privateKeyB64);
      publicKeyBytes = base64ToUint8(blob.publicKeyB64);

      // Restore the Autocrypt peer state.
      if (crypto) {
        cryptoHandle = blob.peerStateJson
          ? crypto.ChatCrypto.fromJson(blob.peerStateJson)
          : new crypto.ChatCrypto();
      }

      return true;
    } catch {
      return false;
    }
  }

  /** Handle the unlock form submission. */
  async function handleUnlock(): Promise<void> {
    const ok = await unlockBlob(unlockPassword());
    if (ok) {
      setNeedsUnlock(false);
      setUnlockPassword("");
      connect();
      syncTimer = setInterval(() => { void syncPeerState(); }, SYNC_INTERVAL_MS);
    } else {
      setStatus("Incorrect password.");
    }
  }

  // ..... WebSocket lifecycle .....

  function connect(): void {
    if (!props.wsUrl || !credentials) return;

    setStatus(strings().connecting);

    ws = new WebSocket(props.wsUrl);

    ws.onopen = () => {
      // Send the Auth handshake with the Chatmail password.
      ws?.send(JSON.stringify({
        type: "auth",
        password: credentials!.chatmailPassword,
      }));
    };

    ws.onmessage = (event) => {
      const msg: ServerMsg = JSON.parse(event.data);

      if (msg.type === "ready") {
        setConnected(true);
        setStatus("");
        // Fetch unseen messages now that the session is established.
        ws?.send(JSON.stringify({ type: "fetch", since_uid: 0 }));
        return;
      }

      if (msg.type === "message" && msg.from && msg.body_b64) {
        const sender: string = msg.from;

        // Decrypt the message body via the WASM module.
        const ciphertext = base64ToUint8(msg.body_b64);
        let body: string;
        try {
          if (crypto && privateKeyBytes) {
            const plainBytes = crypto.decryptMessage(privateKeyBytes, ciphertext);
            body = new TextDecoder().decode(plainBytes);
          } else {
            body = new TextDecoder().decode(ciphertext);
          }
        } catch {
          body = "[decryption failed]";
        }

        // Update Autocrypt peer state if the message carried a header.
        if (cryptoHandle && msg.autocrypt_header_b64) {
          try {
            const headerBytes = Uint8Array.from(
              atob(msg.autocrypt_header_b64),
              (c) => c.charCodeAt(0),
            );
            // The Autocrypt header contains the sender's public key;
            // extract and update peer state.
            const ts = BigInt(msg.timestamp ?? Math.floor(Date.now() / 1000));
            cryptoHandle.updatePeerState(sender, ts, headerBytes, false);
          } catch {
            // Best-effort: peer state update failure is non-fatal.
          }
        }

        const chatMsg: ChatMessage = {
          id: `msg-${++msgCounter}`,
          uid: msg.uid ?? 0,
          from: sender,
          to: props.chatmailAddr,
          body,
          timestamp: msg.timestamp ?? Math.floor(Date.now() / 1000),
          outgoing: false,
        };

        setMessages((prev) => [...prev, chatMsg]);

        // Track contacts.
        if (!contacts().includes(sender)) {
          setContacts((prev) => [...prev, sender]);
        }

        // Acknowledge receipt.
        if (msg.uid) {
          ws?.send(JSON.stringify({ type: "ack", uid: msg.uid }));
        }
      }

      if (msg.type === "sent" && msg.to) {
        // Server confirmed the send.
      }

      if (msg.type === "error" && msg.message) {
        setStatus(msg.message);
      }
    };

    ws.onclose = () => {
      setConnected(false);
      setStatus(strings().disconnected);
      // Reconnect after 3 s.
      reconnectTimer = setTimeout(connect, 3000);
    };

    ws.onerror = () => {
      ws?.close();
    };
  }

  // ..... Peer state synchronisation .....

  let syncTimer: ReturnType<typeof setInterval> | undefined;
  const SYNC_INTERVAL_MS = 60_000;

  async function syncPeerState(): Promise<void> {
    if (!cryptoHandle || !blobKey || !credentials) return;

    try {
      const peerStateJson = cryptoHandle.toJson();
      const updatedBlob: CredentialBlob = {
        ...credentials,
        peerStateJson,
      };
      const encrypted = await encryptBlob(blobKey, updatedBlob);
      await storeBlob(encrypted);
    } catch {
      // Best-effort: sync failure is non-fatal.
    }
  }

  onMount(async () => {
    if (!props.chatmailAddr) return;

    crypto = await loadCrypto();

    // Try to unlock the blob without a password prompt if the blob
    // key is cached in sessionStorage (set during password-login).
    const cachedBlobKeyB64 = sessionStorage.getItem("noombat_blob_key");
    if (cachedBlobKeyB64) {
      // Import the cached key.
      try {
        const keyBytes = base64ToUint8(cachedBlobKeyB64);
        const key = await globalThis.crypto.subtle.importKey(
          "raw", keyBytes.buffer as ArrayBuffer, "AES-GCM", false, ["encrypt", "decrypt"],
        );
        blobKey = key;
        const encryptedBlob = await fetchBlob();
        if (encryptedBlob) {
          const blob = await decryptBlob(key, encryptedBlob);
          credentials = blob;
          privateKeyBytes = base64ToUint8(blob.privateKeyB64);
          publicKeyBytes = base64ToUint8(blob.publicKeyB64);
          cryptoHandle = blob.peerStateJson
            ? crypto!.ChatCrypto.fromJson(blob.peerStateJson)
            : new crypto!.ChatCrypto();
          connect();
          syncTimer = setInterval(() => { void syncPeerState(); }, SYNC_INTERVAL_MS);
          return;
        }
      } catch {
        // Cached key invalid or blob missing; fall through to prompt.
      }
    }

    // No cached key: prompt the user for their password.
    setNeedsUnlock(true);
  });

  onCleanup(() => {
    clearTimeout(reconnectTimer);
    clearInterval(syncTimer);
    // Final sync on session close.
    void syncPeerState();
    ws?.close();
  });

  // ..... Actions .....

  function sendMessage(): void {
    const body = draft().trim();
    const to = recipient().trim();
    if (!body || !to || !ws || ws.readyState !== WebSocket.OPEN) return;

    // Encrypt the message body via the WASM module.
    const plainBytes = new TextEncoder().encode(body);
    let cipherBytes: Uint8Array;

    // Look up the recipient's public key from peer state.
    let recipientKey: Uint8Array | null = null;
    if (cryptoHandle) {
      try {
        const keyBytes = cryptoHandle.getPeerPublicKey(to.trim().toLowerCase());
        if (keyBytes && keyBytes.length > 0) {
          recipientKey = keyBytes instanceof Uint8Array ? keyBytes : new Uint8Array(keyBytes);
        }
      } catch {
        // Peer lookup failed; fall through to plaintext.
      }
    }

    try {
      if (crypto && recipientKey && recipientKey.length > 0 && privateKeyBytes) {
        cipherBytes = crypto.encryptMessage(recipientKey, privateKeyBytes, plainBytes);
      } else {
        // No recipient key available; send plaintext (Chatmail
        // filtermail will reject this, so the user needs to
        // have exchanged keys first via an Autocrypt-bearing
        // message).
        cipherBytes = plainBytes;
      }
    } catch {
      cipherBytes = plainBytes;
    }

    const body_b64 = uint8ToBase64(cipherBytes);

    // Build the Autocrypt header with our public key for key exchange.
    let autocrypt_header_b64: string | null = null;
    if (publicKeyBytes && publicKeyBytes.length > 0) {
      const headerValue = `addr=${props.chatmailAddr}; prefer-encrypt=mutual; keydata=${uint8ToBase64(publicKeyBytes)}`;
      autocrypt_header_b64 = btoa(headerValue);
    }

    ws.send(
      JSON.stringify({
        type: "send",
        to,
        body_b64,
        autocrypt_header_b64,
      }),
    );

    setMessages((prev) => [
      ...prev,
      {
        id: `msg-${++msgCounter}`,
        uid: 0,
        from: props.chatmailAddr,
        to,
        body,
        timestamp: Math.floor(Date.now() / 1000),
        outgoing: true,
      },
    ]);

    setDraft("");
  }

  function reportMessage(msg: ChatMessage): void {
    const token = sessionStorage.getItem("noombat_access_token") ?? "";
    fetch("/api/v1/chat/reports", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({
        target_addr: msg.from,
        message_content: msg.body,
        message_date: new Date(msg.timestamp * 1000).toISOString(),
        reason: "other",
      }),
    }).catch(() => {
      /* best-effort */
    });
  }

  // ..... Render .....

  const filteredMessages = () =>
    recipient()
      ? messages().filter(
          (m) => m.from === recipient() || (m.outgoing && m.to === recipient()),
        )
      : messages();

  function formatTime(ts: number): string {
    return new Date(ts * 1000).toLocaleTimeString(props.locale, {
      hour: "2-digit",
      minute: "2-digit",
    });
  }

  const needsProvisioning = () => !props.chatmailAddr;

  return (
    <div class="noombat-chat">
      {/* Not provisioned: prompt to set a password. */}
      <Show when={needsProvisioning()}>
        <div class="max-w-md mx-auto py-12 text-center">
          <h2 class="text-lg font-semibold mb-4">{strings().heading}</h2>
          <p class="text-sm text-muted mb-6">{strings().notProvisioned}</p>
          <a
            href="/auth/upgrade"
            class="inline-block bg-accent text-white rounded px-6 py-2 no-underline hover:opacity-90"
          >
            {strings().setupChat}
          </a>
        </div>
      </Show>

      {/* Password unlock prompt (OAuth-login sessions). */}
      <Show when={!needsProvisioning() && needsUnlock()}>
        <div class="max-w-md mx-auto py-12 text-center">
          <h2 class="text-lg font-semibold mb-4">{strings().heading}</h2>
          <p class="text-sm text-muted mb-6">{strings().enterPassword}</p>
          <Show when={status()}>
            <p class="text-sm text-red-600 mb-4">{status()}</p>
          </Show>
          <div class="flex gap-2 justify-center">
            <input
              type="password"
              class="border border-gray-300 rounded px-3 py-2 text-sm"
              placeholder="Password"
              value={unlockPassword()}
              onInput={(e) => setUnlockPassword(e.currentTarget.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") {
                  e.preventDefault();
                  void handleUnlock();
                }
              }}
            />
            <button
              type="button"
              class="bg-accent text-white rounded px-4 py-2 text-sm"
              onClick={() => void handleUnlock()}
            >
              {strings().unlock}
            </button>
          </div>
        </div>
      </Show>

      {/* Main chat interface. */}
      <Show when={!needsProvisioning() && !needsUnlock()}>
      {/* Status bar */}
      <Show when={status()}>
        <div class="noombat-chat__status" role="status">
          {status()}
        </div>
      </Show>

      <div class="noombat-chat__layout">
        {/* Contact list (drawer on mobile, sidebar on desktop) */}
        <aside
          class={`noombat-chat__contacts ${showContacts() ? "noombat-chat__contacts--open" : ""}`}
          aria-label={strings().contacts}
        >
          <h2 class="text-sm font-semibold text-muted px-3 py-2">
            {strings().contacts}
          </h2>
          <Show
            when={contacts().length > 0}
            fallback={<p class="px-3 text-sm text-muted">{strings().empty}</p>}
          >
            <ul class="space-y-1">
              <For each={contacts()}>
                {(addr) => (
                  <li>
                    <button
                      type="button"
                      class={`w-full text-left px-3 py-2 text-sm hover:bg-surface rounded ${
                        recipient() === addr ? "bg-surface font-semibold" : ""
                      }`}
                      onClick={() => {
                        setRecipient(addr);
                        setShowContacts(false);
                      }}
                    >
                      {addr}
                    </button>
                  </li>
                )}
              </For>
            </ul>
          </Show>
        </aside>

        {/* Conversation */}
        <section
          class="noombat-chat__conversation"
          aria-label={strings().heading}
        >
          {/* Mobile: toggle contact list */}
          <div class="noombat-chat__topbar">
            <button
              type="button"
              class="noombat-chat__drawer-toggle"
              onClick={() => setShowContacts((v) => !v)}
              aria-expanded={showContacts()}
              aria-controls="chat-contacts"
            >
              ☰
            </button>
            <span class="text-sm font-semibold truncate">
              {recipient() || strings().heading}
            </span>
          </div>

          {/* Message list */}
          <div class="noombat-chat__messages" role="log" aria-live="polite">
            <Show
              when={filteredMessages().length > 0}
              fallback={
                <p class="text-center text-muted text-sm py-8">
                  {strings().empty}
                </p>
              }
            >
              <For each={filteredMessages()}>
                {(msg) => (
                  <div
                    class={`noombat-chat__bubble ${msg.outgoing ? "noombat-chat__bubble--outgoing" : ""}`}
                  >
                    <p class="text-sm">{msg.body}</p>
                    <div class="flex items-center gap-2 mt-1">
                      <time class="text-xs text-muted">
                        {formatTime(msg.timestamp)}
                      </time>
                      <Show when={!msg.outgoing}>
                        <button
                          type="button"
                          class="text-xs text-muted hover:text-red-600"
                          onClick={() => reportMessage(msg)}
                        >
                          {strings().report}
                        </button>
                      </Show>
                    </div>
                  </div>
                )}
              </For>
            </Show>
          </div>

          {/* Compose */}
          <div class="noombat-chat__compose">
            <input
              type="text"
              class="noombat-chat__recipient"
              placeholder="recipient@chat.example.com"
              value={recipient()}
              onInput={(e) => setRecipient(e.currentTarget.value)}
            />
            <div class="noombat-chat__input-row">
              <input
                type="text"
                class="noombat-chat__input"
                placeholder={strings().placeholder}
                value={draft()}
                onInput={(e) => setDraft(e.currentTarget.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter" && !e.shiftKey) {
                    e.preventDefault();
                    sendMessage();
                  }
                }}
              />
              <button
                type="button"
                class="noombat-chat__send"
                disabled={!connected() || !draft().trim() || !recipient().trim()}
                onClick={sendMessage}
              >
                {strings().send}
              </button>
            </div>
          </div>
        </section>
      </div>
      </Show>
    </div>
  );
}
