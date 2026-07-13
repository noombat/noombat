// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

#![forbid(unsafe_code)]
//! ActivityPub S2S federation: inbox, outbox, delivery, WebFinger, NodeInfo,
//! and HTTP Signature verification.

pub mod crosspost;
pub mod delivery;
pub mod digest;
pub mod downgrade;
pub mod inbox;
pub mod move_actor;
pub mod nodeinfo;
pub mod relay;
pub mod update;
pub mod webfinger;
