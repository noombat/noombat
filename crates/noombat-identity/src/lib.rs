// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

#![forbid(unsafe_code)]
//! Actor repository, key generation, post persistence, profile section
//! CRUD, DOI resolution, domain verification, authentication, session
//! management, TOTP 2FA, and OAuth (Mastodon, ORCID).

pub mod connections;
pub mod cv;
pub mod doi_client;
pub mod email;
pub mod hashtags;
pub mod keys;
pub mod login;
pub mod mailer;
pub mod oauth_mastodon;
pub mod oauth_orcid;
pub mod oauth_util;
pub mod orcid_import;
pub mod profile;
pub mod registration;
pub mod repo;
pub mod session;
pub mod totp;
pub mod verification;
