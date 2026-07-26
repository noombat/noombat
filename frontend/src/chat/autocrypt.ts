// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

/**
 * Autocrypt Level 1 state machine.
 *
 * This module implements the Autocrypt Level 1 peer state update
 * algorithm and the encryption recommendation algorithm as specified
 * in https://autocrypt.org/level1.html.
 */

// ..... Types .....

export type PreferEncrypt = "mutual" | "nopreference";

export interface PeerState {
  /** Timestamp of the most recent message from this peer
   *  (regardless of whether it carried an Autocrypt header). */
  lastSeen: number;
  /** Timestamp of the most recent message that carried a valid
   *  Autocrypt header. */
  lastSeenAutocrypt: number;
  /** The peer's public key (binary OpenPGP Transferable Public Key). */
  publicKey: number[];
  /** The peer's stated encryption preference. */
  preferEncrypt: PreferEncrypt;
  /** Gossip key (from Autocrypt-Gossip headers in group messages). */
  gossipKey: number[] | null;
  /** Timestamp of the most recent gossip header. */
  gossipTimestamp: number | null;
}

export interface AutocryptHeader {
  /** The canonicalised sender address. */
  addr: string;
  /** The sender's public key bytes. */
  publicKey: Uint8Array;
  /** The sender's prefer-encrypt attribute. */
  preferEncrypt: PreferEncrypt;
}

export interface IncomingMessage {
  /** The canonicalised sender address. */
  from: string;
  /** Effective date of the message (Unix timestamp, in seconds). */
  effectiveDate: number;
  /** The parsed Autocrypt header, if present and valid. */
  autocryptHeader: AutocryptHeader | null;
}

export type Recommendation = "disable" | "discourage" | "available" | "encrypt";

// ..... Canonicalisation .....

function canonicalise(addr: string): string {
  return addr.trim().toLowerCase();
}

// ..... Autocrypt header parser .....

/**
 * Parse a raw Autocrypt header value string (e.g. `addr=alice@example.com;
 * prefer-encrypt=mutual; keydata=<base64>`) and return the parsed components.
 *
 * Returns `null` if the header is missing the `keydata` attribute or if the
 * base64 decoding fails.
 */
export function parseAutocryptHeader(
  headerValue: string,
): AutocryptHeader | null {
  let addr: string | null = null;
  let keydataB64: string | null = null;
  let preferEncrypt: PreferEncrypt = "nopreference";

  for (const part of headerValue.split(";")) {
    const trimmed = part.trim();
    const eqIdx = trimmed.indexOf("=");
    if (eqIdx === -1) continue;

    const key = trimmed.slice(0, eqIdx).trim().toLowerCase();
    const value = trimmed.slice(eqIdx + 1).trim();

    switch (key) {
      case "addr":
        addr = value;
        break;
      case "prefer-encrypt":
        if (value.toLowerCase() === "mutual") {
          preferEncrypt = "mutual";
        }
        break;
      case "keydata":
        keydataB64 = value;
        break;
      // Ignore unknown attributes per the specification.
    }
  }

  if (!keydataB64) return null;

  // Strip any whitespace that may remain from MIME header
  // unfolding. atob() does not tolerate embedded spaces.
  const cleaned = keydataB64.replace(/\s/g, "");

  let publicKey: Uint8Array;
  try {
    const bin = atob(cleaned);
    publicKey = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) {
      publicKey[i] = bin.charCodeAt(i);
    }
  } catch {
    return null;
  }

  if (publicKey.length === 0) return null;

  return {
    addr: addr ?? "",
    publicKey,
    preferEncrypt,
  };
}

// ..... Peer state table .....

export class PeerStateTable {
  private peers: Map<string, PeerState>;

  constructor() {
    this.peers = new Map();
  }

  /** Apply the Autocrypt Level 1 update algorithm on receipt of an
   *  incoming message. */
  update(msg: IncomingMessage): void {
    const addr = canonicalise(msg.from);

    // If no Autocrypt header is present, update only lastSeen.
    if (!msg.autocryptHeader) {
      const entry = this.peers.get(addr);
      if (entry && msg.effectiveDate > entry.lastSeen) {
        entry.lastSeen = msg.effectiveDate;
      }
      return;
    }

    const header = msg.autocryptHeader;

    // Ignore the header if the addr attribute does not match the sender.
    if (canonicalise(header.addr) !== addr) {
      const entry = this.peers.get(addr);
      if (entry && msg.effectiveDate > entry.lastSeen) {
        entry.lastSeen = msg.effectiveDate;
      }
      return;
    }

    let entry = this.peers.get(addr);
    if (!entry) {
      entry = {
        lastSeen: 0,
        lastSeenAutocrypt: 0,
        publicKey: [],
        preferEncrypt: "nopreference",
        gossipKey: null,
        gossipTimestamp: null,
      };
      this.peers.set(addr, entry);
    }

    // Update timestamps and key only if the message is newer.
    if (msg.effectiveDate > entry.lastSeen) {
      entry.lastSeen = msg.effectiveDate;
    }

    if (msg.effectiveDate > entry.lastSeenAutocrypt) {
      entry.lastSeenAutocrypt = msg.effectiveDate;
      entry.publicKey = Array.from(header.publicKey);
      entry.preferEncrypt = header.preferEncrypt;
    }
  }

  /** Apply a gossip header update (from Autocrypt-Gossip). */
  updateGossip(addr: string, key: Uint8Array, timestamp: number): void {
    const canonical = canonicalise(addr);
    let entry = this.peers.get(canonical);
    if (!entry) {
      entry = {
        lastSeen: 0,
        lastSeenAutocrypt: 0,
        publicKey: [],
        preferEncrypt: "nopreference",
        gossipKey: null,
        gossipTimestamp: null,
      };
      this.peers.set(canonical, entry);
    }

    const dominated =
      entry.gossipTimestamp === null || timestamp > entry.gossipTimestamp;
    if (dominated) {
      entry.gossipKey = Array.from(key);
      entry.gossipTimestamp = timestamp;
    }
  }

  /** Retrieve the peer state for the given address. */
  get(addr: string): PeerState | undefined {
    return this.peers.get(canonicalise(addr));
  }

  /** Return the peer's public key as a Uint8Array, or null. */
  getPublicKey(addr: string): Uint8Array | null {
    const peer = this.get(addr);
    if (!peer || peer.publicKey.length === 0) return null;
    return new Uint8Array(peer.publicKey);
  }

  /** Serialise the table to a JSON string for blob inclusion. */
  toJson(): string {
    const obj: Record<string, PeerState> = {};
    for (const [k, v] of this.peers) {
      obj[k] = v;
    }
    return JSON.stringify(obj);
  }

  /** Deserialise a table from a JSON string. */
  static fromJson(json: string): PeerStateTable {
    const table = new PeerStateTable();
    const obj = JSON.parse(json) as Record<string, PeerState>;
    for (const [k, v] of Object.entries(obj)) {
      table.peers.set(k, v);
    }
    return table;
  }
}

// ..... Encryption recommendation .....

/**
 * Compute the encryption recommendation for the given recipients.
 *
 * @param table: The sender's peer state table.
 * @param recipients: The email addresses of all recipients.
 * @param senderPrefersMutual: Whether the sender has set
 *   `prefer-encrypt: mutual` in their own Autocrypt header.
 */
export function recommend(
  table: PeerStateTable,
  recipients: string[],
  senderPrefersMutual: boolean,
): Recommendation {
  if (recipients.length === 0) return "disable";

  let allMutual = senderPrefersMutual;
  let anyStale = false;

  for (const addr of recipients) {
    const peer = table.get(addr);
    if (!peer) return "disable";
    if (peer.publicKey.length === 0) return "disable";

    // A key is considered stale if the most recent message from the
    // peer is newer than the most recent Autocrypt-bearing message.
    if (peer.lastSeen > peer.lastSeenAutocrypt) {
      anyStale = true;
    }

    if (peer.preferEncrypt !== "mutual") {
      allMutual = false;
    }
  }

  if (anyStale) return "discourage";
  if (allMutual) return "encrypt";
  return "available";
}
