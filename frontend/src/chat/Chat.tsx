// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

/**
 * SolidJS chat island component.
 *
 * Manages the WebSocket connection to the Noombat chat relay,
 * renders a contact list and conversation view, and delegates
 * cryptographic operations (encryption, decryption, Autocrypt state)
 * to OpenPGP.js and the TypeScript Autocrypt state machine.
 *
 * On narrow viewports the component renders a full-screen
 * conversation view with a drawer-based contact list. On wide
 * viewports it renders a two-column layout.
 */

import { createSignal, onCleanup, onMount, For, Show, type JSX } from "solid-js";
import {
  encryptMessage,
  decryptMessage,
  decryptAndVerify,
  keyFingerprint,
  formatFingerprint,
} from "./crypto";
import { PeerStateTable, parseAutocryptHeader } from "./autocrypt";
import { decryptBlob, encryptBlob, fetchBlob, storeBlob, type CredentialBlob } from "./blob";
import { repairOwnKey, type PublishedKeyResult } from "./directory";
import { KeyLookups, keyShown, resolveRecipient, type FoundKey } from "./recipient";
import { deriveBlobKey, deriveBothKeys } from "../auth";
import { provisionChat, type ProvisionResult } from "./provision";
import { Received } from "./received";
import { reportMessage } from "./report";
import { describeServerError } from "./server-error";

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
  setUpWithPassword: string;
  password: string;
  setupFailed: string;
  setupTooSoon: string;
  setupError: string;
  setUpElsewhere: string;
  enterPassword: string;
  unlock: string;
  keyChanged: (address: string, date: string) => string;
  verifyDetails: string;
  yourFingerprint: string;
  peerFingerprint: string;
  fingerprintHint: string;
  copy: string;
  copied: string;
  noPeerKey: string;
  usingInstanceKey: (address: string, fingerprint: string) => string;
  noPublishedKey: (who: string) => string;
  noPublishedKeyForHandle: (who: string) => string;
  notAddressOrHandle: (who: string) => string;
  recipientPlaceholder: string;
  invalidPublishedKey: (who: string) => string;
  lookupFailed: string;
  instanceKeyNote: string;
  chatNotSetUp: string;
  sessionExpired: string;
  httpError: (status: number) => string;
  incorrectPassword: string;
  encryptionFailed: (detail: string) => string;
  signatureVerified: string;
  signatureVerifiedBadge: string;
  signatureFailed: string;
  signatureFailedBadge: string;
  encryptedUnverified: string;
  loginFailed: string;
  connectFailed: string;
  idleTimeout: string;
  blocked: string;
  sendFailed: string;
  fetchFailed: string;
  serverFault: (detail: string) => string;
  encryptionUnavailable: string;
  decryptionFailed: string;
  close: string;
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
    password: "Password",
    setUpWithPassword: "Enter your Noombat password to set up encrypted chat on this account.",
    setupFailed: "Chat could not be set up. Check the password and try again.",
    setupTooSoon: "Chat was set up a moment ago. Try again in a minute.",
    setupError: "Chat could not be set up just now. Try again later.",
    setUpElsewhere:
      "Chat was set up in another tab or on another device. Reload this page to unlock it.",
    enterPassword: "Enter your Noombat password to unlock encrypted chat.",
    unlock: "Unlock",
    keyChanged: (address, date) =>
      `The encryption key for ${address} changed on ${date}. Verify the new fingerprint out of band if this is unexpected.`,
    verifyDetails: "Verify keys",
    yourFingerprint: "Your fingerprint",
    peerFingerprint: "Their fingerprint",
    fingerprintHint:
      "Compare these over a channel this server does not control, such as in person or by telephone. Matching fingerprints mean no one has substituted a key.",
    copy: "Copy",
    copied: "Copied",
    noPeerKey: "No key is known for this contact yet.",
    usingInstanceKey: (address, fingerprint) =>
      `Using the key published for ${address}, fingerprint ${fingerprint}. Compare it with them over another channel.`,
    noPublishedKeyForHandle: (who) =>
      `No key for ${who}: they have not set up chat, do not share their key with you, or chat here cannot reach their instance. If they have chat, ask them to write to you first.`,
    notAddressOrHandle: (who) => `${who} is neither a chat address nor a handle (@name@instance).`,
    recipientPlaceholder: "recipient@chat.example.com or @name@instance.example",
    noPublishedKey: (who) =>
      `No key for ${who}: they have not set up chat, do not share their key with you, or are on another instance, where their handle (@name@instance) finds them. Ask them to write to you first.`,
    invalidPublishedKey: (who) =>
      `The key this instance gave for ${who} is not valid. Nothing was sent.`,
    lookupFailed: "The key could not be looked up. Nothing was sent; try again.",
    instanceKeyNote: "Provided by this instance; not yet seen in a message from them.",
    chatNotSetUp: "Chat is not set up on this account yet.",
    sessionExpired: "Session expired. Please log in again.",
    httpError: (status) => `Server error (HTTP ${status}).`,
    incorrectPassword: "Incorrect password.",
    encryptionFailed: (detail) => `Encryption failed: ${detail}`,
    signatureVerified: "Signature verified",
    signatureVerifiedBadge: "verified",
    signatureFailed: "Signature verification failed",
    signatureFailedBadge: "signature failed",
    encryptedUnverified: "Encrypted (unverified key)",
    loginFailed: "The chat server did not accept this account's chat password.",
    connectFailed: "The chat server could not be reached. Trying again shortly.",
    idleTimeout: "Disconnected after a period of inactivity.",
    blocked: "Messages to this address are blocked.",
    sendFailed: "The message could not be sent. Try again.",
    fetchFailed: "New messages could not be fetched.",
    serverFault: (detail) => `The chat server reported an error: ${detail}`,
    encryptionUnavailable: "[the encryption module could not be loaded]",
    decryptionFailed: "[this message could not be decrypted]",
    close: "Close",
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
    password: "Password",
    setUpWithPassword: "Enter your Noombat password to set up encrypted chat on this account.",
    setupFailed: "Chat could not be set up. Check the password and try again.",
    setupTooSoon: "Chat was set up a moment ago. Try again in a minute.",
    setupError: "Chat could not be set up just now. Try again later.",
    setUpElsewhere:
      "Chat was set up in another tab or on another device. Reload this page to unlock it.",
    enterPassword: "Enter your Noombat password to unlock encrypted chat.",
    unlock: "Unlock",
    keyChanged: (address, date) =>
      `The encryption key for ${address} changed on ${date}. Verify the new fingerprint out of band if this is unexpected.`,
    verifyDetails: "Verify keys",
    yourFingerprint: "Your fingerprint",
    peerFingerprint: "Their fingerprint",
    fingerprintHint:
      "Compare these over a channel this server does not control, such as in person or by telephone. Matching fingerprints mean no one has substituted a key.",
    copy: "Copy",
    copied: "Copied",
    noPeerKey: "No key is known for this contact yet.",
    usingInstanceKey: (address, fingerprint) =>
      `Using the key published for ${address}, fingerprint ${fingerprint}. Compare it with them over another channel.`,
    noPublishedKeyForHandle: (who) =>
      `No key for ${who}: they have not set up chat, do not share their key with you, or chat here cannot reach their instance. If they have chat, ask them to write to you first.`,
    notAddressOrHandle: (who) => `${who} is neither a chat address nor a handle (@name@instance).`,
    recipientPlaceholder: "recipient@chat.example.com or @name@instance.example",
    noPublishedKey: (who) =>
      `No key for ${who}: they have not set up chat, do not share their key with you, or are on another instance, where their handle (@name@instance) finds them. Ask them to write to you first.`,
    invalidPublishedKey: (who) =>
      `The key this instance gave for ${who} is not valid. Nothing was sent.`,
    lookupFailed: "The key could not be looked up. Nothing was sent; try again.",
    instanceKeyNote: "Provided by this instance; not yet seen in a message from them.",
    chatNotSetUp: "Chat is not set up on this account yet.",
    sessionExpired: "Session expired. Please log in again.",
    httpError: (status) => `Server error (HTTP ${status}).`,
    incorrectPassword: "Incorrect password.",
    encryptionFailed: (detail) => `Encryption failed: ${detail}`,
    signatureVerified: "Signature verified",
    signatureVerifiedBadge: "verified",
    signatureFailed: "Signature verification failed",
    signatureFailedBadge: "signature failed",
    encryptedUnverified: "Encrypted (unverified key)",
    loginFailed: "The chat server did not accept this account's chat password.",
    connectFailed: "The chat server could not be reached. Trying again shortly.",
    idleTimeout: "Disconnected after a period of inactivity.",
    blocked: "Messages to this address are blocked.",
    sendFailed: "The message could not be sent. Try again.",
    fetchFailed: "New messages could not be fetched.",
    serverFault: (detail) => `The chat server reported an error: ${detail}`,
    encryptionUnavailable: "[the encryption module could not be loaded]",
    decryptionFailed: "[this message could not be decrypted]",
    close: "Close",
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
    notProvisioned:
      "Para enviar mensagens criptografadas, defina uma senha para sua conta Noombat.",
    setupChat: "Configurar chat",
    password: "Senha",
    setUpWithPassword:
      "Digite sua senha do Noombat para configurar o chat criptografado nesta conta.",
    setupFailed: "Não foi possível configurar o chat. Verifique a senha e tente novamente.",
    setupTooSoon: "O chat foi configurado há pouco. Tente novamente daqui a um minuto.",
    setupError: "Não foi possível configurar o chat agora. Tente novamente mais tarde.",
    setUpElsewhere:
      "O chat foi configurado em outra aba ou em outro dispositivo. Recarregue esta página para desbloqueá-lo.",
    enterPassword: "Digite sua senha Noombat para desbloquear o chat criptografado.",
    unlock: "Desbloquear",
    keyChanged: (address, date) =>
      `A chave de criptografia de ${address} mudou em ${date}. Verifique a nova impressão digital por outro meio se isso for inesperado.`,
    verifyDetails: "Verificar chaves",
    yourFingerprint: "Sua impressão digital",
    peerFingerprint: "Impressão digital do contato",
    fingerprintHint:
      "Compare estes valores por um canal que este servidor não controla, como pessoalmente ou por telefone. Impressões digitais iguais significam que ninguém substituiu uma chave.",
    copy: "Copiar",
    copied: "Copiado",
    noPeerKey: "Nenhuma chave é conhecida para este contato ainda.",
    usingInstanceKey: (address, fingerprint) =>
      `Usando a chave publicada para ${address}, impressão digital ${fingerprint}. Compare-a com a pessoa por outro canal.`,
    noPublishedKeyForHandle: (who) =>
      `Nenhuma chave para ${who}: a pessoa não configurou o chat, não compartilha a chave com você ou o chat daqui não alcança a instância dela. Se ela tiver chat, peça que escreva primeiro.`,
    notAddressOrHandle: (who) =>
      `${who} não é um endereço de chat nem um identificador (@nome@instância).`,
    recipientPlaceholder: "destinatario@chat.example.com ou @nome@instancia.example",
    noPublishedKey: (who) =>
      `Nenhuma chave para ${who}: a pessoa não configurou o chat, não compartilha a chave com você ou está em outra instância, onde o identificador dela (@nome@instância) a encontra. Peça que ela escreva primeiro.`,
    invalidPublishedKey: (who) =>
      `A chave que esta instância forneceu para ${who} não é válida. Nada foi enviado.`,
    lookupFailed: "Não foi possível consultar a chave. Nada foi enviado; tente novamente.",
    instanceKeyNote: "Fornecida por esta instância; ainda não vista em uma mensagem da pessoa.",
    chatNotSetUp: "O chat ainda não está configurado nesta conta.",
    sessionExpired: "Sessão expirada. Entre novamente.",
    httpError: (status) => `Erro do servidor (HTTP ${status}).`,
    incorrectPassword: "Senha incorreta.",
    encryptionFailed: (detail) => `Falha na criptografia: ${detail}`,
    signatureVerified: "Assinatura verificada",
    signatureVerifiedBadge: "verificada",
    signatureFailed: "Falha na verificação da assinatura",
    signatureFailedBadge: "falha na assinatura",
    encryptedUnverified: "Criptografada (chave não verificada)",
    loginFailed: "O servidor de chat não aceitou a senha de chat desta conta.",
    connectFailed: "Não foi possível alcançar o servidor de chat. Tentando novamente em instantes.",
    idleTimeout: "Desconectado após um período de inatividade.",
    blocked: "Mensagens para este endereço estão bloqueadas.",
    sendFailed: "Não foi possível enviar a mensagem. Tente novamente.",
    fetchFailed: "Não foi possível buscar novas mensagens.",
    serverFault: (detail) => `O servidor de chat informou um erro: ${detail}`,
    encryptionUnavailable: "[não foi possível carregar o módulo de criptografia]",
    decryptionFailed: "[não foi possível descriptografar esta mensagem]",
    close: "Fechar",
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
  /** Whether the embedded signature was verified against the
   *  sender's known public key. `null` if no sender key was
   *  available or the message was not signed. */
  signatureVerified: boolean | null;
  /** A locally generated notice rather than a received message.
   *  Rendered as an inline warning and never reportable. */
  system?: true;
}

/** A message from the relay server. */
interface ServerMsg {
  type: "ready" | "message" | "sent" | "error";
  /** For an error, what went wrong; `message` is the detail. */
  code?: string;
  uid?: number;
  /** For `ready`, the mailbox's UIDVALIDITY. */
  uid_validity?: number | null;
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
  /** An address with no usable setup: chat is to be set up again. */
  needsSetup?: boolean;
  /** Whether the account has a password to derive the blob key from. */
  hasPassword?: boolean;
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
  /** The member's chat address, known once chat is set up. */
  // The address the page was given; setting chat up on this page sets it.
  // eslint-disable-next-line solid/reactivity
  const [address, setAddress] = createSignal(props.needsSetup ? "" : props.chatmailAddr);
  const [setupPassword, setSetupPassword] = createSignal("");
  const [unlockPassword, setUnlockPassword] = createSignal("");
  const [showVerify, setShowVerify] = createSignal(false);
  const [ownFingerprint, setOwnFingerprint] = createSignal("");
  const [peerFingerprint, setPeerFingerprint] = createSignal("");
  /** Whether the fingerprint shown is of a key only the instance vouches for. */
  const [peerKeyFromInstance, setPeerKeyFromInstance] = createSignal(false);
  const [copied, setCopied] = createSignal("");

  let ws: WebSocket | null = null;
  let reconnectTimer: ReturnType<typeof setTimeout> | undefined;
  let msgCounter = 0;
  /** The messages this page holds, across connections. */
  const received = new Received();

  // ..... Reconnection backoff .....

  /** Current backoff delay in milliseconds. Doubles on each
   *  successive failure, capped at MAX_RECONNECT_MS. Reset to
   *  BASE_RECONNECT_MS on a successful connection. */
  let reconnectDelay = 0;
  const BASE_RECONNECT_MS = 1_000;
  const MAX_RECONNECT_MS = 60_000;

  /** Compute the next backoff delay with +/- 25 % jitter. */
  function nextReconnectDelay(): number {
    const base =
      reconnectDelay === 0 ? BASE_RECONNECT_MS : Math.min(reconnectDelay * 2, MAX_RECONNECT_MS);
    const jitter = base * (0.75 + Math.random() * 0.5);
    reconnectDelay = base;
    return Math.round(jitter);
  }

  // Decrypted credential material (held in memory for the session).
  let credentials: CredentialBlob | null = null;
  let privateKeyBytes: Uint8Array | null = null;
  let publicKeyBytes: Uint8Array | null = null;
  let peerState: PeerStateTable | null = null;
  let blobKey: CryptoKey | null = null;
  /** The chat setup the credentials belong to, which every write of them
   *  or of the published key names. */
  let setupNumber = 0;
  /** Set once a newer setup elsewhere has replaced this one: these
   *  credentials hold a password the relay no longer takes. */
  let superseded = false;

  // ..... Dirty flag for peer state synchronisation .....

  /** Set to `true` whenever the PeerStateTable is mutated; cleared
   *  after a successful sync. Prevents unnecessary re-encryption
   *  and PUT requests when peer state has not changed. */
  let peerStateDirty = false;

  /** Whether a send is under way, a key lookup inside it included. */
  let sending = false;

  /** Whether setting chat up is under way, which disables the button. */
  const [settingUp, setSettingUp] = createSignal(false);

  // ..... Blob decryption .....

  /** Attempt to decrypt the credential blob. Returns `true` on
   *  success; sets `status()` on distinguishable failure modes. */
  async function unlockBlob(password: string): Promise<boolean> {
    const result = await fetchBlob();

    if (result.status === "not_provisioned") {
      setStatus(strings().chatNotSetUp);
      return false;
    }
    if (result.status === "auth_error") {
      setStatus(strings().sessionExpired);
      return false;
    }
    if (result.status === "error") {
      setStatus(strings().httpError(result.httpStatus));
      return false;
    }

    const encryptedBlob = result.data;
    setupNumber = result.setup;
    const domain = window.location.hostname;

    try {
      const key = await deriveBlobKey(password, props.username, domain);
      const blob = await decryptBlob(key, encryptedBlob, address());
      credentials = blob;
      blobKey = key;

      // Decode keys from base64.
      privateKeyBytes = base64ToUint8(blob.privateKeyB64);
      publicKeyBytes = base64ToUint8(blob.publicKeyB64);

      // Restore the Autocrypt peer state.
      peerState = blob.peerStateJson
        ? PeerStateTable.fromJson(blob.peerStateJson)
        : new PeerStateTable();

      // Derive the user's own fingerprint once, for out-of-band
      // comparison by a peer.
      void keyFingerprint(publicKeyBytes)
        .then((fp) => setOwnFingerprint(formatFingerprint(fp)))
        .catch(() => setOwnFingerprint(""));

      return true;
    } catch {
      return false;
    }
  }

  /** Set chat up, or up again, with the member's password, then unlock it. */
  async function handleSetup(): Promise<void> {
    // Deriving the keys takes a while; a second click must not set up twice.
    if (settingUp()) return;
    setSettingUp(true);
    const password = setupPassword();
    setStatus("");
    let provisioned: ProvisionResult;
    try {
      const { authKey, blobKey } = await deriveBothKeys(
        password,
        props.username,
        window.location.hostname,
      );
      provisioned = await provisionChat(blobKey, authKey);
    } catch {
      provisioned = { status: "failed" };
    } finally {
      setSettingUp(false);
    }
    if (provisioned.status !== "set_up") {
      const why = {
        superseded: strings().setUpElsewhere,
        refused: strings().setupFailed,
        too_soon: strings().setupTooSoon,
        failed: strings().setupError,
      };
      setStatus(why[provisioned.status]);
      return;
    }
    setSetupPassword("");
    setAddress(provisioned.address);
    // The unlock prompt shows should unlocking fail.
    setNeedsUnlock(true);
    setUnlockPassword(password);
    await handleUnlock();
  }

  /** Handle the unlock form submission. */
  async function handleUnlock(): Promise<void> {
    const ok = await unlockBlob(unlockPassword());
    if (ok) {
      // Repairs a key that failed to publish at setup: one lookup, and an
      // upload when the instance serves another key or none.
      if (credentials) void repairOwnKey(address(), credentials, setupNumber);
      setNeedsUnlock(false);
      setUnlockPassword("");
      connect();
      syncTimer = setInterval(() => {
        void syncPeerState();
      }, SYNC_INTERVAL_MS);
      document.addEventListener("visibilitychange", handleVisibilityChange);
    } else {
      // unlockBlob sets a specific status message for discriminated
      // fetch errors (auth_error, not_provisioned, server error).
      // Only fall back to the generic message if no specific status
      // was set (i.e. the decryptBlob catch path was taken).
      if (!status()) {
        setStatus(strings().incorrectPassword);
      }
    }
  }

  // ..... WebSocket lifecycle .....

  /** The codes of the errors the server closes the socket after. */
  const CLOSING_CODES = new Set([
    "auth_timeout",
    "auth_required",
    "login_failed",
    "connect_failed",
    "idle_timeout",
  ]);
  /** The code the server closed this connection on, if any. */
  let closedFor: string | undefined;

  function connect(): void {
    if (!props.wsUrl || !credentials) return;

    closedFor = undefined;
    setStatus(strings().connecting);

    ws = new WebSocket(props.wsUrl);

    ws.onopen = () => {
      // Send the Auth handshake with the Chatmail password.
      ws?.send(
        JSON.stringify({
          type: "auth",
          password: credentials!.chatmailPassword,
        }),
      );
    };

    ws.onmessage = (event) => {
      const msg: ServerMsg = JSON.parse(event.data);

      if (msg.type === "ready") {
        setConnected(true);
        setStatus("");
        // Reset backoff on successful connection.
        reconnectDelay = 0;
        // A mailbox whose UIDs were assigned again holds the same messages
        // under new ones: those shown are dropped, to come back fetched.
        if (received.inMailbox(msg.uid_validity)) {
          setMessages((prev) => prev.filter((m) => m.outgoing || m.system));
        }
        // Every message newer than those held, all of them the first time;
        // the server pushes each later one as it arrives.
        ws?.send(JSON.stringify({ type: "fetch", since_uid: received.newest }));
        return;
      }

      if (msg.type === "message" && msg.from && msg.body_b64 && received.take(msg.uid ?? 0)) {
        // Decrypt asynchronously via OpenPGP.js.
        void handleIncomingMessage(msg);
      }

      if (msg.type === "sent" && msg.to) {
        // Server confirmed the send.
      }

      if (msg.type === "error") {
        if (msg.code && CLOSING_CODES.has(msg.code)) closedFor = msg.code;
        setStatus(describeServerError(strings(), msg.code, msg.message));
      }
    };

    ws.onclose = () => {
      setConnected(false);
      // The relay refused this password: asking again cannot succeed.
      if (closedFor === "login_failed") return;
      // The error the server closed on stays shown until the next try.
      if (!closedFor) setStatus(strings().disconnected);
      // Reconnect with bounded exponential backoff and jitter.
      const delay = nextReconnectDelay();
      reconnectTimer = setTimeout(connect, delay);
    };

    ws.onerror = () => {
      ws?.close();
    };
  }

  // ..... Incoming message handler (async) .....

  async function handleIncomingMessage(msg: ServerMsg): Promise<void> {
    const sender = msg.from!;

    // Update Autocrypt peer state first (if the message carried a
    // header) so the sender's key is available for signature
    // verification during decryption.
    if (peerState && msg.autocrypt_header_b64) {
      try {
        const headerBytes = Uint8Array.from(atob(msg.autocrypt_header_b64), (c) => c.charCodeAt(0));
        const headerStr = new TextDecoder().decode(headerBytes);
        const parsed = parseAutocryptHeader(headerStr);
        if (parsed) {
          const ts = msg.timestamp ?? Math.floor(Date.now() / 1000);
          const { mutated, keyChanged } = peerState.update({
            from: sender,
            effectiveDate: ts,
            autocryptHeader: parsed,
          });
          if (mutated) {
            peerStateDirty = true;
            // The fingerprint shown, or where its key came from, may
            // now be out of date.
            if (showVerify()) void refreshPeerFingerprint();
          }
          if (keyChanged) {
            // An already-known key was replaced. This is what an
            // operator substituting its own key looks like from the
            // client, so it is surfaced in the conversation rather
            // than absorbed silently.
            appendKeyChangeNotice(sender, ts);
          }
        }
      } catch {
        // Best-effort: peer state update failure is non-fatal.
      }
    }

    // Decrypt the message body via OpenPGP.js. When the sender's
    // public key is known, use decryptAndVerify to check the
    // embedded signature.
    const ciphertext = base64ToUint8(msg.body_b64!);
    let body: string;
    let signatureVerified: boolean | null = null;

    try {
      if (privateKeyBytes) {
        // Look up the sender's public key for signature verification.
        const senderKey = peerState?.getPublicKey(sender.trim().toLowerCase()) ?? null;

        if (senderKey && senderKey.length > 0) {
          // Decrypt and verify signature against known sender key.
          const result = await decryptAndVerify(privateKeyBytes, senderKey, ciphertext);
          body = result.plaintext;
          signatureVerified = result.signatureVerified;
        } else {
          // No sender key available; decrypt without verification.
          const plainBytes = await decryptMessage(privateKeyBytes, ciphertext);
          body = new TextDecoder().decode(plainBytes);
        }
      } else {
        body = strings().encryptionUnavailable;
      }
    } catch {
      body = strings().decryptionFailed;
    }

    const chatMsg: ChatMessage = {
      id: `msg-${++msgCounter}`,
      uid: msg.uid ?? 0,
      from: sender,
      to: address(),
      body,
      timestamp: msg.timestamp ?? Math.floor(Date.now() / 1000),
      outgoing: false,
      signatureVerified,
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

  // ..... Key verification .....

  function appendKeyChangeNotice(address: string, timestamp: number): void {
    const date = new Date(timestamp * 1000).toLocaleDateString(props.locale);
    appendSystemNotice(address, strings().keyChanged(address, date), timestamp);
  }

  /** Insert a system notice into the conversation with `peer`. */
  function appendSystemNotice(peer: string, body: string, timestamp: number): void {
    setMessages((prev) => [
      ...prev,
      {
        id: `sys-${++msgCounter}`,
        uid: 0,
        from: peer,
        to: address(),
        body,
        timestamp,
        outgoing: false,
        signatureVerified: null,
        system: true,
      },
    ]);
  }

  /** The status for a key lookup that found nothing to send to. */
  function lookupStatus(result: PublishedKeyResult, who: string): string {
    if (result.status === "absent") {
      return who.startsWith("@")
        ? strings().noPublishedKeyForHandle(who)
        : strings().noPublishedKey(who);
    }
    if (result.status === "malformed") return strings().notAddressOrHandle(who);
    if (result.status === "invalid") return strings().invalidPublishedKey(who);
    return strings().lookupFailed;
  }

  /** Say in the conversation that a key the instance published is now
   *  held, with its fingerprint. */
  function noteAdoptedKey(found: FoundKey): void {
    peerStateDirty = true;
    appendSystemNotice(
      found.address,
      strings().usingInstanceKey(found.address, formatFingerprint(found.fingerprint)),
      Math.floor(Date.now() / 1000),
    );
  }

  /** The instance's answers while the page is open, shared by the panel
   *  and sending, so a message goes to the key whose fingerprint was shown. */
  const lookups = new KeyLookups();

  /** Counts panel refreshes, so a slow lookup cannot paint over a newer one. */
  let fingerprintRefresh = 0;
  /** The contact whose key the panel last showed. */
  let fingerprintFor = "";

  /** Recompute the fingerprint shown for the selected contact. The
   *  instance is asked for a key none is held for only on request, never
   *  per keystroke, since each would reach the server. */
  async function refreshPeerFingerprint(lookUpMissing = false): Promise<void> {
    const run = ++fingerprintRefresh;
    const typed = recipient().trim();
    // Nothing of the previous contact stays up while this one is looked up.
    if (typed !== fingerprintFor) {
      fingerprintFor = typed;
      setPeerKeyFromInstance(false);
      setPeerFingerprint("");
    }
    const shown =
      typed && peerState ? await keyShown(typed, peerState, lookups, lookUpMissing) : null;
    // Painted only by the newest refresh, for the contact still selected.
    const current = (): boolean => run === fingerprintRefresh && recipient().trim() === typed;
    if (!current()) return;
    let fingerprint = "";
    if (shown) {
      try {
        fingerprint = formatFingerprint(await keyFingerprint(shown.key));
      } catch {
        fingerprint = "";
      }
      if (!current()) return;
    }
    setPeerKeyFromInstance(fingerprint !== "" && !!shown?.fromInstance);
    setPeerFingerprint(fingerprint);
  }

  /** Open the verification panel, refreshing the peer fingerprint. */
  function openVerify(): void {
    void refreshPeerFingerprint(true);
    setShowVerify(true);
  }

  /** Copy `value` to the clipboard and acknowledge briefly. */
  function copyFingerprint(label: string, value: string): void {
    if (!value || !navigator.clipboard) return;
    void navigator.clipboard.writeText(value).then(() => {
      setCopied(label);
      setTimeout(() => setCopied(""), 1500);
    });
  }

  // ..... Peer state synchronisation .....

  let syncTimer: ReturnType<typeof setInterval> | undefined;
  const SYNC_INTERVAL_MS = 30_000;

  /** Guards against concurrent sync invocations from the interval
   *  timer, the `visibilitychange` handler, and the `onCleanup`
   *  final flush. */
  let syncing = false;

  async function syncPeerState(): Promise<void> {
    if (!peerState || !blobKey || !credentials || superseded) return;
    // Skip the re-encryption and PUT if nothing changed.
    if (!peerStateDirty) return;
    // Prevent overlapping syncs.
    if (syncing) return;
    syncing = true;

    try {
      const peerStateJson = peerState.toJson();
      const updatedBlob: CredentialBlob = {
        ...credentials,
        peerStateJson,
      };
      const encrypted = await encryptBlob(blobKey, updatedBlob, address());
      const stored = await storeBlob(encrypted, setupNumber);
      if (stored === "superseded") {
        // Writing on would only be refused again; this page is done.
        superseded = true;
        clearInterval(syncTimer);
        setStatus(strings().setUpElsewhere);
      } else if (stored === "stored") {
        peerStateDirty = false;
      }
    } catch {
      // Best-effort: sync failure is non-fatal. The dirty flag
      // remains set so the next interval retries.
    } finally {
      syncing = false;
    }
  }

  // Sync peer state when the tab becomes hidden (mobile browsers
  // may terminate background tabs without firing beforeunload).
  function handleVisibilityChange(): void {
    if (document.visibilityState === "hidden") {
      void syncPeerState();
    }
  }

  onMount(async () => {
    if (!address()) return;

    // Prompt the user for their password to derive the blob key.
    setNeedsUnlock(true);
  });

  onCleanup(() => {
    clearTimeout(reconnectTimer);
    clearInterval(syncTimer);
    document.removeEventListener("visibilitychange", handleVisibilityChange);
    // Final sync on session close.
    void syncPeerState();
    ws?.close();
  });

  // ..... Actions .....

  async function sendMessage(): Promise<void> {
    const draftText = draft();
    const body = draftText.trim();
    const typed = recipient().trim();
    const to = typed;
    if (sending || !body || !to || !ws || ws.readyState !== WebSocket.OPEN || !privateKeyBytes) {
      return;
    }
    // A lookup is awaited below; a second click meanwhile must not send twice.
    sending = true;
    try {
      await sendTo(to, typed, draftText, body);
    } finally {
      sending = false;
    }
  }

  async function sendTo(to: string, typed: string, draftText: string, body: string): Promise<void> {
    // The key held for the recipient, else the one their instance
    // publishes, which first contact trusts; a handle names someone, here
    // or on another instance, whose address the instance looks up too.
    // Without a key nothing is sent: the relay refuses plaintext, and must
    // never see it.
    if (!peerState) return;
    const resolved = await resolveRecipient(to, peerState, lookups);
    if (resolved.status === "failed") {
      setStatus(lookupStatus(resolved.result, resolved.who));
      return;
    }
    if (resolved.adopted) noteAdoptedKey(resolved.adopted);
    // A member who moved on to someone else during a lookup did not mean
    // this one: nothing is sent, and the draft stays.
    if (recipient().trim() !== typed) return;
    to = resolved.address;
    if (to !== typed) setRecipient(to);
    if ((resolved.adopted || to !== typed) && showVerify()) void refreshPeerFingerprint();
    const recipientKey = resolved.key;

    // Encrypt the message body via OpenPGP.js.
    const plainBytes = new TextEncoder().encode(body);
    let cipherBytes: Uint8Array;

    try {
      if (!privateKeyBytes) return;
      cipherBytes = await encryptMessage(recipientKey, privateKeyBytes, plainBytes);
    } catch (err) {
      const detail = err instanceof Error ? err.message : String(err);
      setStatus(strings().encryptionFailed(detail));
      return;
    }

    const body_b64 = uint8ToBase64(cipherBytes);

    // Build the Autocrypt header with our public key for key exchange.
    let autocrypt_header_b64: string | null = null;
    if (publicKeyBytes && publicKeyBytes.length > 0) {
      const headerValue = `addr=${address()}; prefer-encrypt=mutual; keydata=${uint8ToBase64(publicKeyBytes)}`;
      autocrypt_header_b64 = btoa(headerValue);
    }

    // The socket may have closed during a lookup.
    if (!ws || ws.readyState !== WebSocket.OPEN || !privateKeyBytes) {
      setStatus(strings().disconnected);
      return;
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
        from: address(),
        to,
        body,
        timestamp: Math.floor(Date.now() / 1000),
        outgoing: true,
        signatureVerified: null,
      },
    ]);

    // Unless more was typed during a lookup.
    if (draft() === draftText) setDraft("");
    // Clear any transient error (e.g. a prior "no key" message)
    // now that a send has succeeded.
    if (status()) {
      setStatus("");
    }
  }

  // ..... Render .....

  const filteredMessages = () => {
    // Trimmed, as sending reads it, so a stray space hides nothing sent.
    const shown = recipient().trim();
    return shown
      ? messages().filter((m) => m.from === shown || (m.outgoing && m.to === shown))
      : messages();
  };

  function formatTime(ts: number): string {
    return new Date(ts * 1000).toLocaleTimeString(props.locale, {
      hour: "2-digit",
      minute: "2-digit",
    });
  }

  const needsProvisioning = () => !address();

  return (
    <div class="noombat-chat">
      {/* Not set up, without a password to derive the blob key from. */}
      <Show when={needsProvisioning() && !props.hasPassword}>
        <div class="max-w-md mx-auto py-12 text-center">
          <h2 class="text-lg font-semibold mb-4">{strings().heading}</h2>
          <p class="text-sm text-text-secondary mb-6">{strings().notProvisioned}</p>
          <a
            href="/auth/upgrade"
            class="inline-block bg-bg-brand text-text-on-brand rounded px-6 py-2 no-underline hover:opacity-90"
          >
            {strings().setupChat}
          </a>
        </div>
      </Show>

      {/* Not set up, or set up unusably: set it up with the password. */}
      <Show when={needsProvisioning() && props.hasPassword}>
        <div class="max-w-md mx-auto py-12 text-center">
          <h2 class="text-lg font-semibold mb-4">{strings().heading}</h2>
          <p class="text-sm text-text-secondary mb-6">{strings().setUpWithPassword}</p>
          <Show when={status()}>
            <p class="text-sm text-text-danger mb-4">{status()}</p>
          </Show>
          <div class="flex gap-2 justify-center">
            <input
              type="password"
              class="border border-border-strong rounded px-3 py-2 text-sm"
              placeholder={strings().password}
              value={setupPassword()}
              onInput={(e) => setSetupPassword(e.currentTarget.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") {
                  e.preventDefault();
                  void handleSetup();
                }
              }}
            />
            <button
              type="button"
              class="bg-bg-brand text-text-on-brand rounded px-4 py-2 text-sm disabled:opacity-50"
              disabled={settingUp()}
              onClick={() => void handleSetup()}
            >
              {strings().setupChat}
            </button>
          </div>
        </div>
      </Show>

      {/* Password unlock prompt (OAuth-login sessions). */}
      <Show when={!needsProvisioning() && needsUnlock()}>
        <div class="max-w-md mx-auto py-12 text-center">
          <h2 class="text-lg font-semibold mb-4">{strings().heading}</h2>
          <p class="text-sm text-text-secondary mb-6">{strings().enterPassword}</p>
          <Show when={status()}>
            <p class="text-sm text-text-danger mb-4">{status()}</p>
          </Show>
          <div class="flex gap-2 justify-center">
            <input
              type="password"
              class="border border-border-strong rounded px-3 py-2 text-sm"
              placeholder={strings().password}
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
              class="bg-bg-brand text-text-on-brand rounded px-4 py-2 text-sm"
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
            <h2 class="text-sm font-semibold text-text-secondary px-3 py-2">
              {strings().contacts}
            </h2>
            <Show
              when={contacts().length > 0}
              fallback={<p class="px-3 text-sm text-text-secondary">{strings().empty}</p>}
            >
              <ul class="space-y-1">
                <For each={contacts()}>
                  {(addr) => (
                    <li>
                      <button
                        type="button"
                        class={`w-full text-start px-3 py-2 text-sm hover:bg-bg-raised rounded ${
                          recipient() === addr ? "bg-bg-raised font-semibold" : ""
                        }`}
                        onClick={() => {
                          setRecipient(addr);
                          setShowContacts(false);
                          if (showVerify()) void refreshPeerFingerprint();
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
          <section class="noombat-chat__conversation" aria-label={strings().heading}>
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
              <span class="text-sm font-semibold truncate">{recipient() || strings().heading}</span>
              <span class="flex-1" />
              <button
                type="button"
                class="noombat-chat__verify-toggle"
                onClick={() => (showVerify() ? setShowVerify(false) : openVerify())}
                aria-expanded={showVerify()}
                aria-controls="chat-verify-panel"
              >
                {strings().verifyDetails}
              </button>
            </div>

            {/* Fingerprint comparison panel.

                Until SecureJoin is implemented, comparing fingerprints
                over a channel the server does not control is the only
                way a user can detect a substituted key. */}
            <Show when={showVerify()}>
              <section
                id="chat-verify-panel"
                class="noombat-chat__verify"
                aria-label={strings().verifyDetails}
              >
                <p class="noombat-chat__verify-hint">{strings().fingerprintHint}</p>

                <div class="noombat-chat__verify-row">
                  <span class="noombat-chat__verify-label">{strings().yourFingerprint}</span>
                  <code class="noombat-chat__fingerprint">{ownFingerprint()}</code>
                  <button
                    type="button"
                    class="noombat-chat__verify-copy"
                    disabled={!ownFingerprint()}
                    onClick={() => copyFingerprint("own", ownFingerprint())}
                  >
                    {copied() === "own" ? strings().copied : strings().copy}
                  </button>
                </div>

                <div class="noombat-chat__verify-row">
                  <span class="noombat-chat__verify-label">{strings().peerFingerprint}</span>
                  <Show
                    when={peerFingerprint()}
                    fallback={
                      <span class="text-xs text-text-secondary">{strings().noPeerKey}</span>
                    }
                  >
                    <code class="noombat-chat__fingerprint">{peerFingerprint()}</code>
                    <button
                      type="button"
                      class="noombat-chat__verify-copy"
                      onClick={() => copyFingerprint("peer", peerFingerprint())}
                    >
                      {copied() === "peer" ? strings().copied : strings().copy}
                    </button>
                  </Show>
                </div>
                <Show when={peerKeyFromInstance()}>
                  <p class="text-xs text-text-secondary">{strings().instanceKeyNote}</p>
                </Show>

                <button
                  type="button"
                  class="noombat-chat__verify-close"
                  onClick={() => setShowVerify(false)}
                >
                  {strings().close}
                </button>
              </section>
            </Show>

            {/* Message list */}
            <div class="noombat-chat__messages" role="log" aria-live="polite">
              <Show
                when={filteredMessages().length > 0}
                fallback={
                  <p class="text-center text-text-secondary text-sm py-8">{strings().empty}</p>
                }
              >
                <For each={filteredMessages()}>
                  {(msg) => (
                    <Show
                      when={!msg.system}
                      fallback={
                        <p class="noombat-chat__notice" role="status">
                          {msg.body}
                        </p>
                      }
                    >
                      <div
                        class={`noombat-chat__bubble ${msg.outgoing ? "noombat-chat__bubble--outgoing" : ""}`}
                      >
                        <p class="text-sm">{msg.body}</p>
                        <div class="flex items-center gap-2 mt-1">
                          <time class="text-xs noombat-chat__time">
                            {formatTime(msg.timestamp)}
                          </time>
                          {/* Signature / encryption trust indicator */}
                          <Show when={!msg.outgoing}>
                            <Show when={msg.signatureVerified === true}>
                              <span
                                class="text-xs text-text-success"
                                title={strings().signatureVerified}
                              >
                                &#x2713; {strings().signatureVerifiedBadge}
                              </span>
                            </Show>
                            <Show when={msg.signatureVerified === false}>
                              <span
                                class="text-xs text-text-warning"
                                title={strings().signatureFailed}
                              >
                                &#x26A0; {strings().signatureFailedBadge}
                              </span>
                            </Show>
                            <Show when={msg.signatureVerified === null}>
                              <span
                                class="text-xs text-text-secondary"
                                title={strings().encryptedUnverified}
                              >
                                &#x1F512;
                              </span>
                            </Show>
                          </Show>
                          <Show when={!msg.outgoing}>
                            <button
                              type="button"
                              class="text-xs text-text-secondary hover:text-text-danger"
                              onClick={() => void reportMessage(msg)}
                            >
                              {strings().report}
                            </button>
                          </Show>
                        </div>
                      </div>
                    </Show>
                  )}
                </For>
              </Show>
            </div>

            {/* Compose */}
            <div class="noombat-chat__compose">
              <input
                type="text"
                class="noombat-chat__recipient"
                placeholder={strings().recipientPlaceholder}
                value={recipient()}
                onInput={(e) => {
                  setRecipient(e.currentTarget.value);
                  if (showVerify()) void refreshPeerFingerprint();
                }}
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
                      void sendMessage();
                    }
                  }}
                />
                <button
                  type="button"
                  class="noombat-chat__send"
                  disabled={!connected() || !draft().trim() || !recipient().trim()}
                  onClick={() => void sendMessage()}
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
