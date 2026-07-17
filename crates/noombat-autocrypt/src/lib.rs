// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

#![forbid(unsafe_code)]
#![no_std]
//! Autocrypt Level 1 state machine.
//!
//! This crate implements the Autocrypt Level 1 specification as a
//! pure, `no_std`-compatible Rust state machine. It is designed to
//! compile to `wasm32-unknown-unknown` alongside rPGP.
//!
//! The crate has no I/O, filesystem, SQLite, or async runtime
//! dependencies. All cryptographic operations are delegated to rPGP
//! (integrated at the WASM boundary in the SolidJS chat island).
//!
//! ## Modules
//!
//! - [`peer`]: peer state table and update algorithm.
//! - [`recommend`]: encryption recommendation algorithm.

extern crate alloc;

pub mod peer;
pub mod recommend;
