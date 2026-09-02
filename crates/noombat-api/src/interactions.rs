// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! The database-backed [`InteractionService`]: blocks and mutes.
//!
//! [`noombat_core::authorisation`] declares the trait and owns the two
//! result enums; this is the half that reads the tables, and it lives
//! here because this is where the connection pool is.
//!
//! Both directions fail **closed** on a database error, returning the
//! restrictive value rather than the permissive one. A block that is
//! not read is a block that is not enforced, and the cost of the
//! conservative answer is one profile that does not load.

use std::collections::HashSet;

use noombat_core::authorisation::{InteractionService, OwnerRestriction, ViewerRestriction};
use sqlx::PgPool;
use tracing::error;
use uuid::Uuid;

/// Blocks and mutes, read from Postgres.
#[derive(Clone)]
pub struct Interactions {
    pool: PgPool,
}

impl Interactions {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Resolve mutes for a whole page of authors in one query.
    ///
    /// The feed asks `appears_in_feed` once per post, and answering it
    /// through [`InteractionService::viewer_restriction`] would be one
    /// round trip per row. This costs one per page, and it is keyed on
    /// the page's authors rather than on the viewer's whole mute list,
    /// so somebody who has muted thousands of accounts does not load
    /// thousands of rows to render twenty posts.
    ///
    /// On a database error every author comes back muted, which empties
    /// the page rather than showing a viewer somebody they muted.
    pub async fn muted_among(&self, viewer: &Uuid, authors: &[Uuid]) -> MutedAuthors {
        if authors.is_empty() {
            return MutedAuthors(HashSet::new());
        }

        match sqlx::query_scalar::<_, Uuid>(
            r#"SELECT target_id FROM mutes
               WHERE actor_id = $1
                 AND target_id = ANY($2)
                 AND (expires_at IS NULL OR expires_at > now())"#,
        )
        .bind(viewer)
        .bind(authors)
        .fetch_all(&self.pool)
        .await
        {
            Ok(muted) => MutedAuthors(muted.into_iter().collect()),
            Err(e) => {
                error!(error = %e, "mutes could not be read; treating the page as muted");
                MutedAuthors(authors.iter().copied().collect())
            }
        }
    }
}

/// The muted subset of one page's authors, as [`Interactions::muted_among`]
/// resolved it.
///
/// A type rather than a bare set, so the mapping from membership to
/// [`ViewerRestriction`] is written once here instead of at each call
/// site, exactly as the per-pair method already does.
#[derive(Debug, Default, Clone)]
pub struct MutedAuthors(HashSet<Uuid>);

impl MutedAuthors {
    /// The viewer's restriction towards one author on this page.
    pub fn restriction(&self, author: &Uuid) -> ViewerRestriction {
        if self.0.contains(author) {
            ViewerRestriction::Muted
        } else {
            ViewerRestriction::None
        }
    }
}

#[async_trait::async_trait]
impl InteractionService for Interactions {
    async fn owner_restriction(&self, owner: &Uuid, viewer: &Uuid) -> OwnerRestriction {
        if owner == viewer {
            return OwnerRestriction::None;
        }

        match sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM blocks WHERE actor_id = $1 AND target_id = $2)",
        )
        .bind(owner)
        .bind(viewer)
        .fetch_one(&self.pool)
        .await
        {
            Ok(true) => OwnerRestriction::Blocked,
            Ok(false) => OwnerRestriction::None,
            Err(e) => {
                error!(error = %e, "blocks could not be read; refusing the viewer");
                OwnerRestriction::Blocked
            }
        }
    }

    async fn viewer_restriction(&self, viewer: &Uuid, author: &Uuid) -> ViewerRestriction {
        if viewer == author {
            return ViewerRestriction::None;
        }

        // An expired mute is not a mute. The column is nullable and a
        // NULL means indefinite, so the comparison has to admit it.
        match sqlx::query_scalar::<_, bool>(
            r#"SELECT EXISTS(
                   SELECT 1 FROM mutes
                   WHERE actor_id = $1 AND target_id = $2
                     AND (expires_at IS NULL OR expires_at > now())
               )"#,
        )
        .bind(viewer)
        .bind(author)
        .fetch_one(&self.pool)
        .await
        {
            Ok(true) => ViewerRestriction::Muted,
            Ok(false) => ViewerRestriction::None,
            Err(e) => {
                error!(error = %e, "mutes could not be read; hiding the author");
                ViewerRestriction::Muted
            }
        }
    }
}
