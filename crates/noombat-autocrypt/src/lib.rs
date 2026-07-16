// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

#![forbid(unsafe_code)]
//! Autocrypt Level 1 state machine and rPGP integration.
//!
//! This crate implements the Autocrypt Level 1 specification as a pure
//! Rust state machine compiled to WASM alongside rPGP. It comprises:
//!
//! - **Peer state table.** Indexed by canonicalised email address.
//! - **State update algorithm.** Deterministic update rule applied on
//!   receipt of each incoming message.
//! - **Encryption recommendation algorithm.** Given a set of recipient
//!   addresses, produces one of: `disable`, `discourage`, `available`,
//!   or `encrypt`.
//! - **Serialisation.** The entire state serialises to a byte vector
//!   for inclusion in the encrypted credential blob.
