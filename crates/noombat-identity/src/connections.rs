// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Connections: the mutual, accepted half of the social graph, and the
//! resolver that answers what a viewer's standing towards an actor is.
//!
//! A connection is independent of a follow. Both are stored, both are
//! read, and neither implies the other. What links them is one rule,
//! [`noombat_core::authorisation::Relationship::is_follower`]: an
//! accepted connection is admitted wherever followers are. That rule is
//! written once, in `noombat-core`, and nothing here or in the routes
//! restates it.

use noombat_core::authorisation::{ConnectionState, FollowStatus, Relationship};
use noombat_core::error::{NoombatError, Result};
use noombat_core::privacy::ListVisibility;
use sqlx::PgPool;
use uuid::Uuid;

// ..... Lifecycle .....

/// Invite `addressee_id` to connect.
///
/// Returns the row id. `ON CONFLICT DO NOTHING` against the unordered
/// pair index, so inviting somebody who already invited you is a no-op
/// rather than a second row: the two would otherwise disagree about who
/// may withdraw.
pub async fn invite(
    pool: &PgPool,
    requester_id: Uuid,
    addressee_id: Uuid,
    ap_id: Option<&str>,
) -> Result<Option<Uuid>> {
    if requester_id == addressee_id {
        return Err(NoombatError::BadRequest(
            "an actor cannot connect to itself".into(),
        ));
    }

    let id = sqlx::query_scalar::<_, Uuid>(
        r#"INSERT INTO connections (requester_id, addressee_id, ap_id)
           VALUES ($1, $2, $3)
           ON CONFLICT DO NOTHING
           RETURNING id"#,
    )
    .bind(requester_id)
    .bind(addressee_id)
    .bind(ap_id)
    .fetch_optional(pool)
    .await?;

    Ok(id)
}

/// Accept a pending invitation.
///
/// Only the addressee may accept, which is why the addressee is the
/// first argument and the statement matches on it rather than on the
/// pair. Returns false when there was nothing pending to accept.
pub async fn accept(pool: &PgPool, addressee_id: Uuid, requester_id: Uuid) -> Result<bool> {
    let affected = sqlx::query(
        r#"UPDATE connections SET accepted_at = now()
           WHERE addressee_id = $1 AND requester_id = $2 AND accepted_at IS NULL"#,
    )
    .bind(addressee_id)
    .bind(requester_id)
    .execute(pool)
    .await?
    .rows_affected();

    Ok(affected > 0)
}

/// Reject a pending invitation, as the addressee.
///
/// Deletes the row rather than marking it refused. A refused invitation
/// kept on file is a record of who asked, which is the thing the
/// addressee declined to enter into.
pub async fn reject(pool: &PgPool, addressee_id: Uuid, requester_id: Uuid) -> Result<bool> {
    let affected = sqlx::query(
        r#"DELETE FROM connections
           WHERE addressee_id = $1 AND requester_id = $2 AND accepted_at IS NULL"#,
    )
    .bind(addressee_id)
    .bind(requester_id)
    .execute(pool)
    .await?
    .rows_affected();

    Ok(affected > 0)
}

/// Withdraw an invitation, as the requester, before it is answered.
///
/// The `accepted_at IS NULL` clause is what makes this distinct from
/// [`disconnect`]: withdrawal is unilateral because nobody has agreed
/// to anything yet.
pub async fn withdraw(pool: &PgPool, requester_id: Uuid, addressee_id: Uuid) -> Result<bool> {
    let affected = sqlx::query(
        r#"DELETE FROM connections
           WHERE requester_id = $1 AND addressee_id = $2 AND accepted_at IS NULL"#,
    )
    .bind(requester_id)
    .bind(addressee_id)
    .execute(pool)
    .await?
    .rows_affected();

    Ok(affected > 0)
}

/// Remove an accepted connection, from either side.
///
/// Symmetric in the pair, because an accepted connection is undirected:
/// the requester has no standing the addressee lacks once both have
/// agreed.
pub async fn disconnect(pool: &PgPool, actor_id: Uuid, other_id: Uuid) -> Result<bool> {
    let affected = sqlx::query(
        r#"DELETE FROM connections
           WHERE accepted_at IS NOT NULL
             AND ((requester_id = $1 AND addressee_id = $2)
               OR (requester_id = $2 AND addressee_id = $1))"#,
    )
    .bind(actor_id)
    .bind(other_id)
    .execute(pool)
    .await?
    .rows_affected();

    Ok(affected > 0)
}

// ..... Reads .....

/// The connection state between two actors, in either direction.
pub async fn state(pool: &PgPool, actor_id: Uuid, other_id: Uuid) -> Result<ConnectionState> {
    if actor_id == other_id {
        return Ok(ConnectionState::None);
    }

    let accepted = sqlx::query_scalar::<_, Option<chrono::DateTime<chrono::Utc>>>(
        r#"SELECT accepted_at FROM connections
           WHERE (requester_id = $1 AND addressee_id = $2)
              OR (requester_id = $2 AND addressee_id = $1)"#,
    )
    .bind(actor_id)
    .bind(other_id)
    .fetch_optional(pool)
    .await?;

    Ok(match accepted {
        None => ConnectionState::None,
        Some(None) => ConnectionState::Pending,
        Some(Some(_)) => ConnectionState::Accepted,
    })
}

/// How a viewer stands towards `target_id`, on both axes at once.
///
/// One round trip. The alternative, a follow query and a connection
/// query per rendered object, is what makes a profile page quadratic.
///
/// An anonymous viewer, or a viewer looking at themselves, is
/// [`Relationship::NONE`]: self-access is an identity comparison the
/// predicates make directly, and routing it through a relationship
/// would invite the two answers to disagree.
pub async fn relationship(
    pool: &PgPool,
    viewer_id: Option<Uuid>,
    target_id: Uuid,
) -> Result<Relationship> {
    let Some(viewer_id) = viewer_id else {
        return Ok(Relationship::NONE);
    };
    if viewer_id == target_id {
        return Ok(Relationship::NONE);
    }

    let row = sqlx::query_as::<_, (Option<bool>, Option<bool>)>(
        r#"SELECT
               (SELECT accepted FROM follows
                 WHERE follower_id = $1 AND following_id = $2),
               (SELECT accepted_at IS NOT NULL FROM connections
                 WHERE (requester_id = $1 AND addressee_id = $2)
                    OR (requester_id = $2 AND addressee_id = $1))"#,
    )
    .bind(viewer_id)
    .bind(target_id)
    .fetch_one(pool)
    .await?;

    Ok(Relationship {
        follow: match row.0 {
            None => FollowStatus::None,
            Some(false) => FollowStatus::Pending,
            Some(true) => FollowStatus::Accepted,
        },
        connection: match row.1 {
            None => ConnectionState::None,
            Some(false) => ConnectionState::Pending,
            Some(true) => ConnectionState::Accepted,
        },
    })
}

/// Count an actor's accepted connections.
pub async fn count_connections(pool: &PgPool, actor_id: Uuid) -> Result<i64> {
    let count = sqlx::query_scalar::<_, i64>(
        r#"SELECT count(*) FROM connections
           WHERE accepted_at IS NOT NULL
             AND (requester_id = $1 OR addressee_id = $1)"#,
    )
    .bind(actor_id)
    .fetch_one(pool)
    .await?;

    Ok(count)
}

/// The AP ids of an actor's accepted connections, newest first.
pub async fn list_connection_ap_ids(
    pool: &PgPool,
    actor_id: Uuid,
    limit: i64,
    offset: i64,
) -> Result<Vec<String>> {
    let ids = sqlx::query_scalar::<_, String>(
        r#"SELECT a.ap_id
           FROM connections c
           JOIN actors a
             ON a.id = CASE WHEN c.requester_id = $1 THEN c.addressee_id ELSE c.requester_id END
           WHERE c.accepted_at IS NOT NULL
             AND (c.requester_id = $1 OR c.addressee_id = $1)
           ORDER BY c.accepted_at DESC
           LIMIT $2 OFFSET $3"#,
    )
    .bind(actor_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await?;

    Ok(ids)
}

/// Invitations awaiting this actor's answer, as (requester id, username).
pub async fn list_pending_for(pool: &PgPool, addressee_id: Uuid) -> Result<Vec<(Uuid, String)>> {
    let rows = sqlx::query_as::<_, (Uuid, String)>(
        r#"SELECT c.requester_id, a.username
           FROM connections c
           JOIN actors a ON a.id = c.requester_id
           WHERE c.addressee_id = $1 AND c.accepted_at IS NULL
           ORDER BY c.created_at DESC"#,
    )
    .bind(addressee_id)
    .fetch_all(pool)
    .await?;

    Ok(rows)
}

// ..... List visibility .....

/// Who may read each of an actor's three relationship lists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ListSettings {
    pub connections: ListVisibility,
    pub following: ListVisibility,
    pub followers: ListVisibility,
}

/// Read the three list-visibility settings for an actor.
///
/// Loaded here rather than carried on [`noombat_core::actor::Actor`],
/// for the reason that struct's doc comment gives for the other columns
/// it excludes: only the three collection handlers read them, and
/// widening the domain model would put them on every actor load.
pub async fn list_settings(pool: &PgPool, actor_id: Uuid) -> Result<ListSettings> {
    let row = sqlx::query_as::<_, (String, String, String)>(
        r#"SELECT connections_visibility, following_visibility, followers_visibility
           FROM actors WHERE id = $1"#,
    )
    .bind(actor_id)
    .fetch_one(pool)
    .await?;

    Ok(ListSettings {
        connections: parse_list_visibility(&row.0),
        following: parse_list_visibility(&row.1),
        followers: parse_list_visibility(&row.2),
    })
}

/// Set the three list-visibility settings for an actor.
pub async fn set_list_settings(
    pool: &PgPool,
    actor_id: Uuid,
    settings: ListSettings,
) -> Result<()> {
    sqlx::query(
        r#"UPDATE actors
           SET connections_visibility = $2,
               following_visibility   = $3,
               followers_visibility   = $4
           WHERE id = $1"#,
    )
    .bind(actor_id)
    .bind(list_visibility_str(settings.connections))
    .bind(list_visibility_str(settings.following))
    .bind(list_visibility_str(settings.followers))
    .execute(pool)
    .await?;

    Ok(())
}

/// The stored form of a [`ListVisibility`], as the check constraint
/// spells it.
pub fn list_visibility_str(v: ListVisibility) -> &'static str {
    match v {
        ListVisibility::Public => "public",
        ListVisibility::Followers => "followers",
        ListVisibility::Connections => "connections",
        ListVisibility::Private => "private",
    }
}

/// Read a stored list-visibility value.
///
/// An unrecognised string is `Private`, because the failure to parse a
/// setting must not be the thing that publishes a list.
pub fn parse_list_visibility(s: &str) -> ListVisibility {
    match s {
        "public" => ListVisibility::Public,
        "followers" => ListVisibility::Followers,
        "connections" => ListVisibility::Connections,
        _ => ListVisibility::Private,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unknown_setting_reads_as_private() {
        assert_eq!(parse_list_visibility(""), ListVisibility::Private);
        assert_eq!(parse_list_visibility("friends"), ListVisibility::Private);
        assert_eq!(parse_list_visibility("PUBLIC"), ListVisibility::Private);
    }

    #[test]
    fn every_stored_form_round_trips() {
        for v in [
            ListVisibility::Public,
            ListVisibility::Followers,
            ListVisibility::Connections,
            ListVisibility::Private,
        ] {
            assert_eq!(parse_list_visibility(list_visibility_str(v)), v);
        }
    }
}
