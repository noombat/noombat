// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Actor repository: CRUD operations against the `actors` table.

use noombat_core::actor::{Actor, ActorStatus, ActorType, InstanceRole, NewActor};
use noombat_core::error::{NoombatError, Result};
use noombat_core::privacy::ActorPrivacy;
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

/// Row returned by `INSERT ... RETURNING` in [`create_actor`].
#[derive(FromRow)]
struct InsertedActorRow {
    id: Uuid,
    ap_id: String,
    username: String,
    display_name: Option<String>,
    domain: String,
    is_local: bool,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
}

/// Full row returned by `SELECT` in [`find_local_by_username`].
#[derive(FromRow)]
struct ActorRow {
    id: Uuid,
    actor_type: ActorType,
    ap_id: String,
    username: String,
    display_name: Option<String>,
    headline: Option<String>,
    avatar_url: Option<String>,
    header_url: Option<String>,
    summary_md: Option<String>,
    summary_html: Option<String>,
    public_key_pem: String,
    private_key_pem: Option<String>,
    ed25519_public_key: Option<String>,
    ed25519_private_key: Option<String>,
    domain: String,
    is_local: bool,
    inbox_url: Option<String>,
    instance_role: InstanceRole,
    actor_status: ActorStatus,
    chatmail_addr: Option<String>,
    orcid: Option<String>,
    moved_to: Option<String>,
    actor_privacy: serde_json::Value,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
}

impl ActorRow {
    /// Convert the database row into the domain [`Actor`] type.
    fn into_actor(self) -> Result<Actor> {
        let actor_privacy: ActorPrivacy = serde_json::from_value(self.actor_privacy)?;

        Ok(Actor {
            id: self.id,
            actor_type: self.actor_type,
            ap_id: self.ap_id,
            username: self.username,
            display_name: self.display_name,
            headline: self.headline,
            avatar_url: self.avatar_url,
            header_url: self.header_url,
            summary_md: self.summary_md,
            summary_html: self.summary_html,
            public_key_pem: self.public_key_pem,
            private_key_pem: self.private_key_pem,
            ed25519_public_key: self.ed25519_public_key,
            ed25519_private_key: self.ed25519_private_key,
            domain: self.domain,
            is_local: self.is_local,
            inbox_url: self.inbox_url,
            instance_role: self.instance_role,
            actor_status: self.actor_status,
            chatmail_addr: self.chatmail_addr,
            orcid: self.orcid,
            moved_to: self.moved_to,
            actor_privacy,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

/// Create a new local actor, returning the populated [`Actor`].
pub async fn create_actor(pool: &PgPool, params: &NewActor) -> Result<Actor> {
    create_actor_on(pool, params).await
}

/// Create a new local actor within an existing transaction.
pub async fn create_actor_tx(tx: &mut sqlx::PgConnection, params: &NewActor) -> Result<Actor> {
    create_actor_on(&mut *tx, params).await
}

/// Shared implementation accepting any sqlx executor.
async fn create_actor_on<'e, E>(executor: E, params: &NewActor) -> Result<Actor>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    let id = Uuid::new_v4();
    let ap_id = format!("https://{}/users/{}", params.domain, params.username);
    let actor_type_str = match params.actor_type {
        ActorType::Individual => "individual",
        ActorType::Company => "company",
        ActorType::Group => "group",
    };
    let privacy = ActorPrivacy::default();
    let privacy_json = serde_json::to_value(&privacy)?;

    let row = sqlx::query_as::<_, InsertedActorRow>(
        r#"INSERT INTO actors
               (id, actor_type, ap_id, username, display_name, domain,
                public_key_pem, private_key_pem,
                ed25519_public_key, ed25519_private_key,
                is_local, actor_privacy)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, TRUE, $11)
           RETURNING id, ap_id, username, display_name, domain,
                     is_local, created_at, updated_at"#,
    )
    .bind(id)
    .bind(actor_type_str)
    .bind(&ap_id)
    .bind(&params.username)
    .bind(&params.display_name)
    .bind(&params.domain)
    .bind(&params.public_key_pem)
    .bind(&params.private_key_pem)
    .bind(&params.ed25519_public_key)
    .bind(&params.ed25519_private_key)
    .bind(&privacy_json)
    .fetch_one(executor)
    .await?;

    Ok(Actor {
        id: row.id,
        actor_type: params.actor_type,
        ap_id: row.ap_id,
        username: row.username,
        display_name: row.display_name,
        headline: None,
        avatar_url: None,
        header_url: None,
        summary_md: None,
        summary_html: None,
        public_key_pem: params.public_key_pem.clone(),
        private_key_pem: Some(params.private_key_pem.clone()),
        ed25519_public_key: Some(params.ed25519_public_key.clone()),
        ed25519_private_key: Some(params.ed25519_private_key.clone()),
        domain: row.domain,
        is_local: row.is_local,
        inbox_url: None,
        instance_role: InstanceRole::User,
        actor_status: ActorStatus::Active,
        chatmail_addr: None,
        orcid: None,
        moved_to: None,
        actor_privacy: privacy,
        created_at: row.created_at,
        updated_at: row.updated_at,
    })
}

/// Retrieve a local actor by username.
pub async fn find_local_by_username(pool: &PgPool, username: &str) -> Result<Actor> {
    let row = sqlx::query_as::<_, ActorRow>(
        r#"SELECT
               id, actor_type, ap_id, username, display_name,
               headline, avatar_url, header_url, summary_md, summary_html,
               public_key_pem, private_key_pem, ed25519_public_key, ed25519_private_key, domain, is_local,
               inbox_url, instance_role, actor_status,
               chatmail_addr, orcid, moved_to, actor_privacy,
               created_at, updated_at
           FROM actors
           WHERE username = $1 AND is_local = TRUE"#,
    )
    .bind(username)
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| NoombatError::ActorNotFound(username.to_owned()))?;

    row.into_actor()
}

/// Retrieve an actor by its ActivityPub identifier (local or remote).
pub async fn find_by_ap_id(pool: &PgPool, ap_id: &str) -> Result<Option<Actor>> {
    let row = sqlx::query_as::<_, ActorRow>(
        r#"SELECT
               id, actor_type, ap_id, username, display_name,
               headline, avatar_url, header_url, summary_md, summary_html,
               public_key_pem, private_key_pem, ed25519_public_key, ed25519_private_key, domain, is_local,
               inbox_url, instance_role, actor_status,
               chatmail_addr, orcid, moved_to, actor_privacy,
               created_at, updated_at
           FROM actors
           WHERE ap_id = $1"#,
    )
    .bind(ap_id)
    .fetch_optional(pool)
    .await?;

    row.map(|r| r.into_actor()).transpose()
}

// ..... POSTS .....

/// Parameters for creating a new local post.
pub struct NewPost {
    pub actor_id: Uuid,
    pub ap_id: String,
    pub post_type: String,
    /// Article title (ActivityStreams `name`). `None` for Notes.
    pub title: Option<String>,
    /// Featured image URL. Primarily relevant for Articles.
    pub featured_image_url: Option<String>,
    pub content_md: String,
    pub content_html: String,
    /// The AP URI of the post this is a reply to (`inReplyTo`).
    /// `None` for top-level posts.
    pub in_reply_to: Option<String>,
    pub visibility: String,
    pub ap_object: serde_json::Value,
}

/// Row returned by post queries.
#[derive(FromRow)]
pub struct PostSummary {
    pub id: Uuid,
    pub ap_id: String,
    pub ap_object: serde_json::Value,
}

/// Insert a new local post into the `posts` table.
pub async fn create_local_post(pool: &PgPool, post: &NewPost) -> Result<PostSummary> {
    let id = Uuid::new_v4();
    let row = sqlx::query_as::<_, PostSummary>(
        r#"INSERT INTO posts
               (id, actor_id, ap_id, post_type, title, featured_image_url,
                content_md, content_html, in_reply_to, visibility, ap_object)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
           RETURNING id, ap_id, ap_object"#,
    )
    .bind(id)
    .bind(post.actor_id)
    .bind(&post.ap_id)
    .bind(&post.post_type)
    .bind(&post.title)
    .bind(&post.featured_image_url)
    .bind(&post.content_md)
    .bind(&post.content_html)
    .bind(&post.in_reply_to)
    .bind(&post.visibility)
    .bind(&post.ap_object)
    .fetch_one(pool)
    .await?;

    Ok(row)
}

/// Retrieve the deduplicated inbox URIs of all accepted followers of a
/// local actor.
///
/// Prefers `shared_inbox_url` when available: if multiple followers
/// reside on the same remote instance (sharing the same
/// `shared_inbox_url`), only one copy is sent to the shared inbox.
/// Falls back to the per-actor `inbox_url`, then to `{ap_id}/inbox`.
///
/// The `DISTINCT` clause ensures that duplicate inbox URIs (whether
/// shared or individual) produce only one delivery.
pub async fn get_follower_inboxes(pool: &PgPool, actor_id: Uuid) -> Result<Vec<String>> {
    let inboxes = sqlx::query_scalar::<_, String>(
        r#"SELECT DISTINCT
               COALESCE(a.shared_inbox_url, a.inbox_url, a.ap_id || '/inbox')
           FROM follows f
           JOIN actors a ON a.id = f.follower_id
           WHERE f.following_id = $1 AND f.accepted = TRUE"#,
    )
    .bind(actor_id)
    .fetch_all(pool)
    .await?;

    Ok(inboxes)
}

/// Count the total number of public posts by a local actor.
pub async fn count_public_posts(pool: &PgPool, actor_id: Uuid) -> Result<i64> {
    let count = sqlx::query_scalar::<_, i64>(
        r#"SELECT COUNT(*) FROM posts
           WHERE actor_id = $1 AND visibility = 'public'"#,
    )
    .bind(actor_id)
    .fetch_one(pool)
    .await?;

    Ok(count)
}

/// Retrieve the AP objects of public posts by a local actor, ordered
/// newest first, for the outbox collection.
pub async fn list_public_posts(
    pool: &PgPool,
    actor_id: Uuid,
    limit: i64,
    offset: i64,
) -> Result<Vec<PostSummary>> {
    let rows = sqlx::query_as::<_, PostSummary>(
        r#"SELECT id, ap_id, ap_object FROM posts
           WHERE actor_id = $1 AND visibility = 'public'
           ORDER BY created_at DESC
           LIMIT $2 OFFSET $3"#,
    )
    .bind(actor_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await?;

    Ok(rows)
}

// ..... REMOTE ACTORS .....

/// Parameters for upserting a remote actor discovered via federation.
pub struct RemoteActor {
    pub ap_id: String,
    pub username: String,
    pub domain: String,
    pub display_name: Option<String>,
    pub summary_html: Option<String>,
    pub public_key_pem: String,
    pub actor_type: String,
    pub inbox_url: String,
    /// The `endpoints.sharedInbox` URI, if declared by the remote actor.
    pub shared_inbox_url: Option<String>,
    /// Multibase-encoded Ed25519 public key extracted from the remote
    /// actor's `assertionMethod` (FEP-521a). `None` if the remote
    /// actor does not publish an Ed25519 key. Stored for future
    /// FEP-8b32 Object Integrity Proof verification (Phase 5).
    pub ed25519_public_key: Option<String>,
}

/// Insert or update a remote actor in the `actors` table.
///
/// On conflict (same `ap_id`), updates the public key and display name
/// to reflect the latest data from the remote instance.
pub async fn upsert_remote_actor(pool: &PgPool, remote: &RemoteActor) -> Result<Actor> {
    let id = Uuid::new_v4();
    let privacy = ActorPrivacy::default();
    let privacy_json = serde_json::to_value(&privacy)?;

    sqlx::query(
        r#"INSERT INTO actors
               (id, actor_type, ap_id, username, display_name, summary_html,
                domain, public_key_pem, inbox_url, shared_inbox_url,
                ed25519_public_key, is_local, actor_privacy)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, FALSE, $12)
           ON CONFLICT (ap_id) DO UPDATE SET
               public_key_pem = EXCLUDED.public_key_pem,
               display_name = EXCLUDED.display_name,
               summary_html = EXCLUDED.summary_html,
               inbox_url = EXCLUDED.inbox_url,
               shared_inbox_url = EXCLUDED.shared_inbox_url,
               ed25519_public_key = EXCLUDED.ed25519_public_key"#,
    )
    .bind(id)
    .bind(&remote.actor_type)
    .bind(&remote.ap_id)
    .bind(&remote.username)
    .bind(&remote.display_name)
    .bind(&remote.summary_html)
    .bind(&remote.domain)
    .bind(&remote.public_key_pem)
    .bind(&remote.inbox_url)
    .bind(&remote.shared_inbox_url)
    .bind(&remote.ed25519_public_key)
    .bind(&privacy_json)
    .execute(pool)
    .await?;

    // Fetch the persisted row (may be the existing row on conflict).
    find_by_ap_id(pool, &remote.ap_id).await?.ok_or_else(|| {
        NoombatError::Internal("upsert_remote_actor: row not found after insert".into())
    })
}

// ..... FOLLOWS .....

/// Insert a pending follow relationship.
///
/// If `auto_accept` is `true`, the follow is immediately accepted;
/// otherwise it remains pending until explicitly accepted.
///
/// `follow_ap_id` is the AP `id` of the inbound `Follow` activity
/// (if known). It is stored so that the `Accept` or `Reject`
/// response can reference the original activity, as expected by
/// Mastodon and other AP implementations.
pub async fn create_follow(
    pool: &PgPool,
    follower_id: Uuid,
    following_id: Uuid,
    auto_accept: bool,
) -> Result<()> {
    create_follow_with_ap_id(pool, follower_id, following_id, auto_accept, None).await
}

/// Like [`create_follow`], but stores the Follow activity's AP `id`.
pub async fn create_follow_with_ap_id(
    pool: &PgPool,
    follower_id: Uuid,
    following_id: Uuid,
    auto_accept: bool,
    follow_ap_id: Option<&str>,
) -> Result<()> {
    sqlx::query(
        r#"INSERT INTO follows (follower_id, following_id, accepted, ap_id)
           VALUES ($1, $2, $3, $4)
           ON CONFLICT (follower_id, following_id) DO NOTHING"#,
    )
    .bind(follower_id)
    .bind(following_id)
    .bind(auto_accept)
    .bind(follow_ap_id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Retrieve the AP `id` of the original Follow activity for a given
/// follow relationship, if stored.
pub async fn get_follow_ap_id(
    pool: &PgPool,
    follower_id: Uuid,
    following_id: Uuid,
) -> Result<Option<String>> {
    let row = sqlx::query_scalar::<_, Option<String>>(
        r#"SELECT ap_id FROM follows
           WHERE follower_id = $1 AND following_id = $2"#,
    )
    .bind(follower_id)
    .bind(following_id)
    .fetch_optional(pool)
    .await?;

    Ok(row.flatten())
}

/// Accept a pending follow relationship.
pub async fn accept_follow(pool: &PgPool, follower_id: Uuid, following_id: Uuid) -> Result<()> {
    sqlx::query(
        r#"UPDATE follows SET accepted = TRUE
           WHERE follower_id = $1 AND following_id = $2"#,
    )
    .bind(follower_id)
    .bind(following_id)
    .execute(pool)
    .await?;

    Ok(())
}

/// Delete a follow relationship (used by Undo Follow).
pub async fn delete_follow(pool: &PgPool, follower_id: Uuid, following_id: Uuid) -> Result<()> {
    sqlx::query(
        r#"DELETE FROM follows
           WHERE follower_id = $1 AND following_id = $2"#,
    )
    .bind(follower_id)
    .bind(following_id)
    .execute(pool)
    .await?;

    Ok(())
}

// ..... REMOTE POSTS .....

/// Parameters for persisting an inbound remote post.
pub struct RemotePost {
    pub actor_id: Uuid,
    pub ap_id: String,
    pub post_type: String,
    /// Article title (ActivityStreams `name`). `None` for Notes.
    pub title: Option<String>,
    /// Featured image URL (first `Image` attachment or `image` property).
    /// Primarily relevant for Articles.
    pub featured_image_url: Option<String>,
    /// Original Markdown source from the Mastodon-convention `source`
    /// property (when available), otherwise a copy of `content_html`.
    pub content_md: String,
    pub content_html: String,
    /// The AP URI of the post this is a reply to (`inReplyTo`).
    /// `None` for top-level posts.
    pub in_reply_to: Option<String>,
    /// Visibility derived from the activity's `to`/`cc` addressing.
    pub visibility: String,
    pub ap_object: serde_json::Value,
}

/// Persist a post received from a remote instance.
///
/// Returns `Some(uuid)` when a new row is inserted, or `None` when
/// the `ap_id` already exists (the `ON CONFLICT` clause fires).
/// The caller uses the returned UUID to link hashtags and perform
/// other post-insert bookkeeping only for genuinely new posts.
pub async fn create_remote_post(pool: &PgPool, post: &RemotePost) -> Result<Option<Uuid>> {
    let id = Uuid::new_v4();
    let row = sqlx::query_scalar::<_, Uuid>(
        r#"INSERT INTO posts
               (id, actor_id, ap_id, post_type, title, featured_image_url,
                content_md, content_html, in_reply_to, visibility, ap_object)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
           ON CONFLICT (ap_id) DO NOTHING
           RETURNING id"#,
    )
    .bind(id)
    .bind(post.actor_id)
    .bind(&post.ap_id)
    .bind(&post.post_type)
    .bind(&post.title)
    .bind(&post.featured_image_url)
    .bind(&post.content_md)
    .bind(&post.content_html)
    .bind(&post.in_reply_to)
    .bind(&post.visibility)
    .bind(&post.ap_object)
    .fetch_optional(pool)
    .await?;

    Ok(row)
}

// ..... ACTOR UPDATE .....

/// Mutable fields for an actor update.
///
/// Each field uses `Option<Option<String>>`:
/// - `None`: do not change this field.
/// - `Some(None)`: set the field to `NULL` (clear it).
/// - `Some(Some(value))`: set the field to `value`.
pub struct UpdateActor {
    pub display_name: Option<Option<String>>,
    pub headline: Option<Option<String>>,
    pub summary_md: Option<Option<String>>,
    pub summary_html: Option<Option<String>>,
    pub avatar_url: Option<Option<String>>,
    pub header_url: Option<Option<String>>,
}

/// Update a local actor's editable fields.
///
/// Only fields that are `Some(...)` are modified. A field set to
/// `Some(None)` is explicitly cleared (set to `NULL`).
pub async fn update_actor(pool: &PgPool, actor_id: Uuid, params: &UpdateActor) -> Result<Actor> {
    // Fetch the current row to merge with partial updates.
    let current = find_by_id(pool, actor_id).await?;

    if !current.is_local {
        return Err(NoombatError::BadRequest(
            "cannot update a remote actor".into(),
        ));
    }

    let display_name = match &params.display_name {
        Some(inner) => inner.as_deref(),
        None => current.display_name.as_deref(),
    };
    let headline = match &params.headline {
        Some(inner) => inner.as_deref(),
        None => current.headline.as_deref(),
    };
    let summary_md = match &params.summary_md {
        Some(inner) => inner.as_deref(),
        None => current.summary_md.as_deref(),
    };
    let summary_html = match &params.summary_html {
        Some(inner) => inner.as_deref(),
        None => current.summary_html.as_deref(),
    };
    let avatar_url = match &params.avatar_url {
        Some(inner) => inner.as_deref(),
        None => current.avatar_url.as_deref(),
    };
    let header_url = match &params.header_url {
        Some(inner) => inner.as_deref(),
        None => current.header_url.as_deref(),
    };

    sqlx::query(
        r#"UPDATE actors SET
               display_name = $2,
               headline = $3,
               summary_md = $4,
               summary_html = $5,
               avatar_url = $6,
               header_url = $7
           WHERE id = $1 AND is_local = TRUE"#,
    )
    .bind(actor_id)
    .bind(display_name)
    .bind(headline)
    .bind(summary_md)
    .bind(summary_html)
    .bind(avatar_url)
    .bind(header_url)
    .execute(pool)
    .await?;

    find_by_id(pool, actor_id).await
}

/// Retrieve an actor by primary key.
pub async fn find_by_id(pool: &PgPool, id: Uuid) -> Result<Actor> {
    let row = sqlx::query_as::<_, ActorRow>(
        r#"SELECT
               id, actor_type, ap_id, username, display_name,
               headline, avatar_url, header_url, summary_md, summary_html,
               public_key_pem, private_key_pem, ed25519_public_key, ed25519_private_key, domain, is_local,
               inbox_url, instance_role, actor_status,
               chatmail_addr, orcid, moved_to, actor_privacy,
               created_at, updated_at
           FROM actors
           WHERE id = $1"#,
    )
    .bind(id)
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| NoombatError::NotFound {
        entity: "actor",
        id,
    })?;

    row.into_actor()
}

// ..... ACTOR STATUS .....

/// Update a local actor's moderation status.
///
/// Sets the `actor_status` column to the given value and returns the
/// updated [`Actor`].
///
/// # Search-Index Obligation
///
/// When the new status is `Silenced` or `Suspended`, the caller
/// **must** remove the actor's profile from the search index (via
/// `search_sync::remove_from_index("profiles", &actor.id.to_string())`)
/// to prevent the actor from appearing in public search results.
/// This function does not interact with the search layer because
/// the repository crate has no dependency on the search backend.
///
/// When the new status is `Active` (un-silencing or un-suspending),
/// the caller should re-index the actor's profile (via
/// `search_sync::reindex_profile_from_db`) if the actor is
/// discoverable.
pub async fn set_actor_status(pool: &PgPool, actor_id: Uuid, status: ActorStatus) -> Result<Actor> {
    let status_str = match status {
        ActorStatus::Active => "active",
        ActorStatus::Silenced => "silenced",
        ActorStatus::Suspended => "suspended",
    };

    let result = sqlx::query(
        "UPDATE actors SET actor_status = $1, updated_at = now() \
         WHERE id = $2 AND is_local = TRUE",
    )
    .bind(status_str)
    .bind(actor_id)
    .execute(pool)
    .await?;

    if result.rows_affected() == 0 {
        return Err(NoombatError::NotFound {
            entity: "actor",
            id: actor_id,
        });
    }

    find_by_id(pool, actor_id).await
}

// ..... ACTOR DELETE .....

/// Tombstone a local actor: clear all personal data, record the
/// tombstone for federation consistency, and delete all dependent
/// rows from the database.
///
/// This function does **not** broadcast the `Delete` activity; the
/// caller is responsible for fetching follower inboxes (via
/// [`get_follower_inboxes`]) **before** calling this function (which
/// deletes the follow relationships) and then passing those inboxes
/// to [`noombat_federation::delete::broadcast_delete`].
///
/// After this function returns, the actor row is retained with only
/// the `ap_id`, `username`, `domain`, and `public_key_pem` columns
/// populated; all other fields are cleared and the `actor_status` is
/// set to `"suspended"`. Dependent data (posts, profile sections,
/// follows, etc.) is explicitly deleted.
///
/// The two-phase approach (tombstone now, hard-delete later) ensures
/// that:
/// 1. The `Delete` activity can reference the actor's `ap_id` and be
///    signed with its private key.
/// 2. The `tombstoned_actors` table records the `ap_id` so that
///    future federation requests return `410 Gone`.
/// 3. A configurable grace period allows the user to cancel the
///    deletion before irreversible data loss.
///
/// The `moved_to` column is intentionally **not** cleared: if the
/// actor had previously migrated via a `Move` activity, the migration
/// pointer is preserved on the tombstoned row so that followers who
/// have not yet processed the `Move` can still discover the target
/// actor. The `Delete` broadcast informs followers of the deletion;
/// the `moved_to` pointer provides an alternative discovery path.
///
/// All deletion steps are executed within a single database
/// transaction to ensure atomicity: if the process crashes mid-way,
/// the entire tombstoning operation is rolled back rather than
/// leaving the actor in a partially-tombstoned state.
///
/// # Arguments
///
/// - `pool`: Database connection pool.
/// - `actor_id`: The UUID of the local actor to delete.
///
/// # Returns
///
/// The actor's data as it was immediately before tombstoning,
/// enabling the caller to perform follow-up actions (e.g.
/// broadcasting the `Delete` activity, purging search indices).
pub async fn tombstone_actor(pool: &PgPool, actor_id: Uuid) -> Result<Actor> {
    // Fetch the actor before clearing data (needed for the Delete
    // activity and follower inbox resolution).
    let actor = find_by_id(pool, actor_id).await?;

    if !actor.is_local {
        return Err(NoombatError::BadRequest(
            "cannot delete a remote actor".into(),
        ));
    }

    let mut tx = pool.begin().await?;

    // Record the tombstone so that future federation requests for
    // this ap_id return 410 Gone.
    sqlx::query(
        "INSERT INTO tombstoned_actors (ap_id) VALUES ($1) \
         ON CONFLICT (ap_id) DO NOTHING",
    )
    .bind(&actor.ap_id)
    .execute(&mut *tx)
    .await?;

    // Clear personal data from the actor row but retain the
    // structural fields needed for federation consistency.
    // NOTE: `moved_to` is intentionally preserved (see doc-comment).
    sqlx::query(
        r#"UPDATE actors SET
               display_name = NULL,
               headline = NULL,
               avatar_url = NULL,
               header_url = NULL,
               summary_md = NULL,
               summary_html = NULL,
               chatmail_addr = NULL,
               chatmail_cred = NULL,
               auth_key_hash = NULL,
               ed25519_private_key = NULL,
               orcid = NULL,
               actor_status = 'suspended',
               actor_privacy = '{"discoverable":false,"indexable":false,"require_follow_approval":true,"federate_profile":false,"chatmail_visible":false,"show_followers_count":false,"cv_download":"self"}'
           WHERE id = $1"#,
    )
    .bind(actor_id)
    .execute(&mut *tx)
    .await?;

    // Cascade-delete all dependent personal data. The FK constraints
    // with ON DELETE CASCADE would handle this if the actor row were
    // deleted, but since the row is retained (tombstoned), explicit
    // deletion of dependents is required.
    //
    // Deletion order matters: tables that reference `posts` (likes,
    // boosts, post_hashtags, media_attachments) must be deleted
    // before `posts` to avoid relying on cascade side-effects.
    //
    // Each query uses a literal `&'static str` (not `format!`) to
    // satisfy sqlx's `SqlSafeStr` compile-time injection check.

    // 1. Tables with `actor_id` FK column (excluding posts and
    //    media_attachments, which are handled later due to ordering).
    sqlx::query("DELETE FROM experiences WHERE actor_id = $1")
        .bind(actor_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM educations WHERE actor_id = $1")
        .bind(actor_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM skills WHERE actor_id = $1")
        .bind(actor_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM publications WHERE actor_id = $1")
        .bind(actor_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM verified_links WHERE actor_id = $1")
        .bind(actor_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM custom_profile_sections WHERE actor_id = $1")
        .bind(actor_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM applications WHERE applicant_id = $1")
        .bind(actor_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM actor_aliases WHERE actor_id = $1")
        .bind(actor_id)
        .execute(&mut *tx)
        .await?;

    // 2. Tables with non-standard FK column names.
    sqlx::query("DELETE FROM follows WHERE follower_id = $1 OR following_id = $1")
        .bind(actor_id)
        .execute(&mut *tx)
        .await?;

    sqlx::query("DELETE FROM blocks WHERE actor_id = $1 OR target_id = $1")
        .bind(actor_id)
        .execute(&mut *tx)
        .await?;

    sqlx::query("DELETE FROM mutes WHERE actor_id = $1 OR target_id = $1")
        .bind(actor_id)
        .execute(&mut *tx)
        .await?;

    // 3. Likes and boosts by this actor on OTHER actors' posts.
    //    (Likes/boosts by other actors on THIS actor's posts will be
    //    cascade-deleted when posts are deleted in step 5.)
    sqlx::query("DELETE FROM likes WHERE actor_id = $1")
        .bind(actor_id)
        .execute(&mut *tx)
        .await?;

    sqlx::query("DELETE FROM boosts WHERE actor_id = $1")
        .bind(actor_id)
        .execute(&mut *tx)
        .await?;

    // 4. Media attachments uploaded by this actor.
    sqlx::query("DELETE FROM media_attachments WHERE actor_id = $1")
        .bind(actor_id)
        .execute(&mut *tx)
        .await?;

    // 5. Posts by this actor (cascade-deletes remaining likes, boosts,
    //    post_hashtags, and media_attachments via FK ON DELETE CASCADE).
    sqlx::query("DELETE FROM posts WHERE actor_id = $1")
        .bind(actor_id)
        .execute(&mut *tx)
        .await?;

    // 6. Delivery queue entries for this actor.
    sqlx::query("DELETE FROM delivery_queue WHERE actor_id = $1")
        .bind(actor_id)
        .execute(&mut *tx)
        .await?;

    // 7. Reports: delete reports filed BY this actor; clear
    //    target_actor_id on reports filed AGAINST this actor (the
    //    report itself is retained for the moderation audit trail).
    sqlx::query("DELETE FROM reports WHERE reporter_id = $1")
        .bind(actor_id)
        .execute(&mut *tx)
        .await?;

    sqlx::query("UPDATE reports SET target_actor_id = NULL WHERE target_actor_id = $1")
        .bind(actor_id)
        .execute(&mut *tx)
        .await?;

    sqlx::query("UPDATE reports SET resolved_by = NULL WHERE resolved_by = $1")
        .bind(actor_id)
        .execute(&mut *tx)
        .await?;

    // 8. Events: delete events organised by this actor, and clear
    //    actor_id on events where this actor is listed as a
    //    participant (event_rsvps).
    sqlx::query("DELETE FROM event_rsvps WHERE actor_id = $1")
        .bind(actor_id)
        .execute(&mut *tx)
        .await?;

    sqlx::query("DELETE FROM events WHERE actor_id = $1 OR organiser_id = $1")
        .bind(actor_id)
        .execute(&mut *tx)
        .await?;

    // 9. Group memberships.
    sqlx::query("DELETE FROM group_memberships WHERE member_id = $1")
        .bind(actor_id)
        .execute(&mut *tx)
        .await?;

    // 10. Domain restrictions created by this actor: clear the
    //     created_by column (the restriction itself is retained).
    sqlx::query("UPDATE domain_restrictions SET created_by = NULL WHERE created_by = $1")
        .bind(actor_id)
        .execute(&mut *tx)
        .await?;

    // 11. Hashtag follows.
    sqlx::query("DELETE FROM hashtag_follows WHERE actor_id = $1")
        .bind(actor_id)
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;

    Ok(actor)
}

/// Hard-delete a tombstoned actor row. Called by a background worker
/// after the grace period (default: 30 days) has elapsed.
///
/// This final step removes the actor row itself. After this call, the
/// `tombstoned_actors` table is the sole record that the `ap_id` ever
/// existed (ensuring that federation requests continue to receive
/// `410 Gone`).
pub async fn purge_tombstoned_actor(pool: &PgPool, actor_id: Uuid) -> Result<()> {
    let result = sqlx::query("DELETE FROM actors WHERE id = $1 AND actor_status = 'suspended'")
        .bind(actor_id)
        .execute(pool)
        .await?;

    if result.rows_affected() == 0 {
        return Err(NoombatError::NotFound {
            entity: "actor",
            id: actor_id,
        });
    }

    Ok(())
}

// ..... SOCIAL GRAPH COUNTS AND LISTS .....

/// Count accepted followers of an actor.
pub async fn count_followers(pool: &PgPool, actor_id: Uuid) -> Result<i64> {
    let count = sqlx::query_scalar::<_, i64>(
        r#"SELECT COUNT(*) FROM follows
           WHERE following_id = $1 AND accepted = TRUE"#,
    )
    .bind(actor_id)
    .fetch_one(pool)
    .await?;

    Ok(count)
}

/// Count actors that a given actor follows (accepted only).
pub async fn count_following(pool: &PgPool, actor_id: Uuid) -> Result<i64> {
    let count = sqlx::query_scalar::<_, i64>(
        r#"SELECT COUNT(*) FROM follows
           WHERE follower_id = $1 AND accepted = TRUE"#,
    )
    .bind(actor_id)
    .fetch_one(pool)
    .await?;

    Ok(count)
}

/// Retrieve the AP identifiers of an actor's accepted followers.
pub async fn list_follower_ap_ids(
    pool: &PgPool,
    actor_id: Uuid,
    limit: i64,
    offset: i64,
) -> Result<Vec<String>> {
    let ids = sqlx::query_scalar::<_, String>(
        r#"SELECT a.ap_id FROM follows f
           JOIN actors a ON a.id = f.follower_id
           WHERE f.following_id = $1 AND f.accepted = TRUE
           ORDER BY f.created_at DESC
           LIMIT $2 OFFSET $3"#,
    )
    .bind(actor_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await?;

    Ok(ids)
}

/// Retrieve the AP identifiers of actors that a given actor follows.
pub async fn list_following_ap_ids(
    pool: &PgPool,
    actor_id: Uuid,
    limit: i64,
    offset: i64,
) -> Result<Vec<String>> {
    let ids = sqlx::query_scalar::<_, String>(
        r#"SELECT a.ap_id FROM follows f
           JOIN actors a ON a.id = f.following_id
           WHERE f.follower_id = $1 AND f.accepted = TRUE
           ORDER BY f.created_at DESC
           LIMIT $2 OFFSET $3"#,
    )
    .bind(actor_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await?;

    Ok(ids)
}
