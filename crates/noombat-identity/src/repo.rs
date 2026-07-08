// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Actor repository: CRUD operations against the `actors` table.

use noombat_core::actor::{Actor, ActorType, NewActor};
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
    actor_type: String,
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
    domain: String,
    is_local: bool,
    inbox_url: Option<String>,
    instance_role: String,
    actor_status: String,
    chatmail_addr: Option<String>,
    orcid: Option<String>,
    actor_privacy: serde_json::Value,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
}

impl ActorRow {
    /// Convert the database row into the domain [`Actor`] type.
    fn into_actor(self) -> Result<Actor> {
        let actor_type = match self.actor_type.as_str() {
            "individual" => ActorType::Individual,
            "company" => ActorType::Company,
            "group" => ActorType::Group,
            other => {
                return Err(NoombatError::Internal(format!(
                    "unknown actor type: {other}"
                )))
            }
        };
        let actor_privacy: ActorPrivacy = serde_json::from_value(self.actor_privacy)?;

        Ok(Actor {
            id: self.id,
            actor_type,
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
            domain: self.domain,
            is_local: self.is_local,
            inbox_url: self.inbox_url,
            instance_role: self.instance_role,
            actor_status: self.actor_status,
            chatmail_addr: self.chatmail_addr,
            orcid: self.orcid,
            actor_privacy,
            created_at: self.created_at,
            updated_at: self.updated_at,
        })
    }
}

/// Create a new local actor, returning the populated [`Actor`].
pub async fn create_actor(pool: &PgPool, params: &NewActor) -> Result<Actor> {
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
                public_key_pem, private_key_pem, is_local, actor_privacy)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, TRUE, $9)
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
    .bind(&privacy_json)
    .fetch_one(pool)
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
        domain: row.domain,
        is_local: row.is_local,
        inbox_url: None,
        instance_role: "user".to_owned(),
        actor_status: "active".to_owned(),
        chatmail_addr: None,
        orcid: None,
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
               public_key_pem, private_key_pem, domain, is_local,
               inbox_url, instance_role, actor_status,
               chatmail_addr, orcid, actor_privacy,
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
               public_key_pem, private_key_pem, domain, is_local,
               inbox_url, instance_role, actor_status,
               chatmail_addr, orcid, actor_privacy,
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
    pub content_md: String,
    pub content_html: String,
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
               (id, actor_id, ap_id, post_type, content_md, content_html,
                visibility, ap_object)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
           RETURNING id, ap_id, ap_object"#,
    )
    .bind(id)
    .bind(post.actor_id)
    .bind(&post.ap_id)
    .bind(&post.post_type)
    .bind(&post.content_md)
    .bind(&post.content_html)
    .bind(&post.visibility)
    .bind(&post.ap_object)
    .fetch_one(pool)
    .await?;

    Ok(row)
}

/// Retrieve the inbox URIs of all accepted followers of a local actor.
///
/// Uses each follower's stored `inbox_url` (populated during actor
/// resolution) with a fallback to `{ap_id}/inbox` for actors resolved
/// before the column was introduced.
pub async fn get_follower_inboxes(pool: &PgPool, actor_id: Uuid) -> Result<Vec<String>> {
    let inboxes = sqlx::query_scalar::<_, String>(
        r#"SELECT COALESCE(a.inbox_url, a.ap_id || '/inbox')
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
                domain, public_key_pem, inbox_url, is_local, actor_privacy)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, FALSE, $10)
           ON CONFLICT (ap_id) DO UPDATE SET
               public_key_pem = EXCLUDED.public_key_pem,
               display_name = EXCLUDED.display_name,
               summary_html = EXCLUDED.summary_html,
               inbox_url = EXCLUDED.inbox_url"#,
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
                content_md, content_html, visibility, ap_object)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
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
    .bind(&post.visibility)
    .bind(&post.ap_object)
    .fetch_optional(pool)
    .await?;

    Ok(row)
}

// ..... ACTOR UPDATE .....

/// Mutable fields for an actor update.
pub struct UpdateActor {
    pub display_name: Option<String>,
    pub headline: Option<String>,
    pub summary_md: Option<String>,
    pub summary_html: Option<String>,
    pub avatar_url: Option<String>,
    pub header_url: Option<String>,
}

/// Update a local actor's editable fields.
pub async fn update_actor(pool: &PgPool, actor_id: Uuid, params: &UpdateActor) -> Result<Actor> {
    sqlx::query(
        r#"UPDATE actors SET
               display_name = COALESCE($2, display_name),
               headline = COALESCE($3, headline),
               summary_md = COALESCE($4, summary_md),
               summary_html = COALESCE($5, summary_html),
               avatar_url = COALESCE($6, avatar_url),
               header_url = COALESCE($7, header_url)
           WHERE id = $1 AND is_local = TRUE"#,
    )
    .bind(actor_id)
    .bind(&params.display_name)
    .bind(&params.headline)
    .bind(&params.summary_md)
    .bind(&params.summary_html)
    .bind(&params.avatar_url)
    .bind(&params.header_url)
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
               public_key_pem, private_key_pem, domain, is_local,
               inbox_url, instance_role, actor_status,
               chatmail_addr, orcid, actor_privacy,
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

// ..... ACTOR DELETE .....

/// Delete a local actor and all dependent data (cascaded by FK constraints).
pub async fn delete_actor(pool: &PgPool, actor_id: Uuid) -> Result<()> {
    let result = sqlx::query("DELETE FROM actors WHERE id = $1 AND is_local = TRUE")
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
