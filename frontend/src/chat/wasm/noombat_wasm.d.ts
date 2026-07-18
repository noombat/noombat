/* tslint:disable */
/* eslint-disable */

export class ChatCrypto {
    free(): void;
    [Symbol.dispose](): void;
    encryptionRecommendation(recipients_json: string, sender_prefers_mutual: boolean): string;
    static fromJson(json: string): ChatCrypto;
    constructor();
    toJson(): string;
    updatePeerState(addr: string, timestamp: bigint, public_key: Uint8Array, prefer_mutual: boolean): void;
}

/**
 * Decrypt an OpenPGP-encrypted message.
 *
 * - `private_key_bytes`: the recipient's Transferable Secret Key
 *   (binary serialisation).
 * - `ciphertext`: the encrypted OpenPGP message (binary).
 *
 * Returns the decrypted plaintext as bytes.
 */
export function decryptMessage(private_key_bytes: Uint8Array, ciphertext: Uint8Array): Uint8Array;

/**
 * Encrypt a plaintext message for the given recipient.
 *
 * - `recipient_key_bytes`: the recipient's OpenPGP Transferable
 *   Public Key (binary serialisation).
 * - `sender_key_bytes`: the sender's OpenPGP Transferable Secret
 *   Key (binary). Reserved for message signing once implemented
 *   (Autocrypt Level 1 specification requires sign-then-encrypt).
 * - `plaintext`: the raw message body.
 *
 * Returns the encrypted OpenPGP message as binary bytes.
 *
 * # Limitations
 *
 * Messages are currently encrypted but not signed. The `pgp` 0.20
 * `MessageBuilder::sign` method accepts `&dyn SigningKey`, which
 * is an adapter trait not implemented by `SignedSecretKey` directly.
 * Unsigned messages are valid OpenPGP and decrypt correctly, but
 * Delta Chat will display them without sender verification until
 * signing is added.
 */
export function encryptMessage(recipient_key_bytes: Uint8Array, _sender_key_bytes: Uint8Array, plaintext: Uint8Array): Uint8Array;

/**
 * Generate a new OpenPGP key pair for the given email address.
 *
 * Produces an Ed25519 primary key (signing) with a Curve25519
 * subkey (encryption), matching the Autocrypt Level 1 key profile.
 *
 * Returns a JSON string:
 * `{ "public_key": "<base64>", "private_key": "<base64>" }`
 *
 * The base64 values encode the binary (non-armored) Transferable
 * Secret Key and Transferable Public Key respectively.
 */
export function generateKeyPair(email: string): string;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly __wbg_chatcrypto_free: (a: number, b: number) => void;
    readonly chatcrypto_encryptionRecommendation: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly chatcrypto_fromJson: (a: number, b: number) => [number, number, number];
    readonly chatcrypto_new: () => number;
    readonly chatcrypto_toJson: (a: number) => [number, number, number, number];
    readonly chatcrypto_updatePeerState: (a: number, b: number, c: number, d: bigint, e: number, f: number, g: number) => void;
    readonly decryptMessage: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly encryptMessage: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly generateKeyPair: (a: number, b: number) => [number, number, number, number];
    readonly __wbindgen_exn_store: (a: number) => void;
    readonly __externref_table_alloc: () => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __externref_table_dealloc: (a: number) => void;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
