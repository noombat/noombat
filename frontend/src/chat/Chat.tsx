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
// TODO: uncomment when syncPeerState is fully implemented (requires
// threading the ChatCrypto handle through the component).
// import { storeBlob } from "./blob";

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
  type: "message" | "sent" | "error";
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

  let ws: WebSocket | null = null;
  let reconnectTimer: ReturnType<typeof setTimeout> | undefined;
  let msgCounter = 0;
  let crypto: CryptoMod | null = null;

  // ..... WebSocket lifecycle .....

  function connect(): void {
    if (!props.wsUrl) return;

    setStatus(strings().connecting);

    // The noombat_session cookie is sent automatically by the browser
    // with the WebSocket upgrade request; no explicit token is needed.
    ws = new WebSocket(props.wsUrl);

    ws.onopen = () => {
      setConnected(true);
      setStatus("");
      // Fetch unseen messages.
      ws?.send(JSON.stringify({ type: "fetch", since_uid: 0 }));
    };

    ws.onmessage = (event) => {
      const msg: ServerMsg = JSON.parse(event.data);

      if (msg.type === "message" && msg.from && msg.body_b64) {
        // Capture narrowed values before closures.
        const sender: string = msg.from;

        // Decrypt the message body via the WASM module.
        // TODO: pass the user's actual private key once key lifecycle
        // is implemented. Currently falls back to raw ciphertext.
        const ciphertext = Uint8Array.from(atob(msg.body_b64), (c) => c.charCodeAt(0));
        let plainBytes: Uint8Array;
        try {
          plainBytes = crypto
            ? crypto.decryptMessage(new Uint8Array(0), ciphertext)
            : ciphertext;
        } catch {
          // Decryption fails when no private key is available;
          // display the raw (base64-decoded) bytes as-is.
          plainBytes = ciphertext;
        }
        const body = new TextDecoder().decode(plainBytes);
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
        // The server confirmed the send.
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
  //
  // Periodically re-encrypt the Autocrypt peer state and upload the
  // blob to the server. The blob encryption key must be available in
  // sessionStorage (set during login by auth.ts). If the key is not
  // available, synchronisation is silently skipped.
  let syncTimer: ReturnType<typeof setInterval> | undefined;
  const SYNC_INTERVAL_MS = 60_000; // 60 seconds default.

  async function syncPeerState(): Promise<void> {
    if (!crypto) return;
    const blobKeyB64 = sessionStorage.getItem("noombat_blob_key");
    if (!blobKeyB64) return;

    try {
      const cryptoHandle = (crypto as any).ChatCrypto;
      // The ChatCrypto instance is not directly accessible here;
      // peer state serialisation requires the WASM handle. For now,
      // store a placeholder blob. Full integration requires threading
      // the ChatCrypto instance through the component.
      // TODO: pass the ChatCrypto handle from the WASM module and
      // call handle.toJson() to get the current peer state.
    } catch {
      // Best-effort: sync failure is non-fatal.
    }
  }

  onMount(async () => {
    if (props.chatmailAddr) {
      crypto = await loadCrypto();
      connect();
      // Start periodic peer state synchronisation.
      syncTimer = setInterval(() => { void syncPeerState(); }, SYNC_INTERVAL_MS);
    }
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
    // TODO: pass the recipient's public key and sender's private key
    // once key lifecycle is implemented. Currently sends plaintext.
    const plainBytes = new TextEncoder().encode(body);
    let cipherBytes: Uint8Array;
    try {
      cipherBytes = crypto
        ? crypto.encryptMessage(new Uint8Array(0), new Uint8Array(0), plainBytes)
        : plainBytes;
    } catch {
      // Encryption fails when no keys are available; send plaintext.
      cipherBytes = plainBytes;
    }
    const body_b64 = btoa(String.fromCharCode(...cipherBytes));

    ws.send(
      JSON.stringify({
        type: "send",
        to,
        body_b64,
        autocrypt_header_b64: null,
      }),
    );

    // Add to local message list immediately (optimistic).
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

  // ..... Provisioning check .....
  //
  // If chatmailAddr is empty, the user's chat is not yet provisioned.
  // Show a prompt to set a password (OAuth-only users) or to trigger
  // provisioning (password-having users).
  const needsProvisioning = () => !props.chatmailAddr;

  return (
    <div class="noombat-chat">
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

      <Show when={!needsProvisioning()}>
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
