// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

#![forbid(unsafe_code)]
//! IMAP/SMTP ciphertext relay for Chatmail.
//!
//! This crate implements a thin server-side proxy that relays traffic
//! between the browser (via WebSocket) and a Chatmail relay (via
//! IMAP/SMTP). It handles MIME envelope metadata and Autocrypt
//! header extraction/injection, but never decrypts message bodies.
//!
//! ## Modules
//!
//! - [`provision`]: Chatmail account provisioning via IMAP first-login.
//! - [`relay`]: WebSocket <--> IMAP/SMTP relay.
//! - [`mime_bridge`]: Autocrypt header extraction/injection for MIME
//!   messages.
//! - [`report`]: Chat moderation report submission.

pub mod admin_client;
pub mod mime_bridge;
pub mod provision;
pub mod relay;
pub mod report;
pub mod session;
