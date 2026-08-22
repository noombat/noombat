// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Actor repository: CRUD operations against the `actors` table.

use noombat_core::actor::{Actor, ActorStatus, ActorType, InstanceRole, NewActor};
use noombat_core::envelope;
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
    location: Option<String>,
    avatar_url: Option<String>,
    header_url: Option<String>,
    summary_md: Option<String>,
    summary_html: Option<String>,
    public_key_pem: String,
    public_key_id: Option<String>,
    private_key_pem: Option<String>,
    ed25519_public_key: Option<String>,
    ed25519_private_key: Option<String>,
    domain: String,
    is_local: bool,
    inbox_url: Option<String>,
    instance_role: InstanceRole,
    actor_status: ActorStatus,
    chat_requires_reprovisioning: bool,
    chatmail_addr: Option<String>,
    orcid: Option<String>,
    moved_to: Option<String>,
    actor_privacy: serde_json::Value,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
}

impl ActorRow {
    /// Convert the database row into the domain [`Actor`] type.
    ///
    /// Private key fields are decrypted via the process-global
    /// envelope key (see [`envelope::open_auto_field`]).
    fn into_actor(self) -> Result<Actor> {
        let actor_privacy: ActorPrivacy = serde_json::from_value(self.actor_privacy)?;

        // Decrypt private key columns. When the KEK is not set
        // (development mode) the values pass through unchanged.
        let private_key_pem = envelope::open_auto_field(self.private_key_pem)?;
        let ed25519_private_key = envelope::open_auto_field(self.ed25519_private_key)?;

        Ok(Actor {
            id: self.id,
            actor_type: self.actor_type,
            ap_id: self.ap_id,
            username: self.username,
            display_name: self.display_name,
            headline: self.headline,
            location: self.location,
            avatar_url: self.avatar_url,
            header_url: self.header_url,
            summary_md: self.summary_md,
            summary_html: self.summary_html,
            public_key_pem: self.public_key_pem,
            public_key_id: self.public_key_id,
            private_key_pem,
            ed25519_public_key: self.ed25519_public_key,
            ed25519_private_key,
            domain: self.domain,
            is_local: self.is_local,
            inbox_url: self.inbox_url,
            instance_role: self.instance_role,
            actor_status: self.actor_status,
            chat_requires_reprovisioning: self.chat_requires_reprovisioning,
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
    let actor_type_str = params.actor_type.as_str();
    let privacy = ActorPrivacy::default();
    let privacy_json = serde_json::to_value(&privacy)?;

    // Encrypt private key columns before writing to the database.
    let sealed_rsa = envelope::seal_auto(&params.private_key_pem)?;
    let sealed_ed25519 = envelope::seal_auto(&params.ed25519_private_key)?;

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
    .bind(&sealed_rsa)
    .bind(&params.ed25519_public_key)
    .bind(&sealed_ed25519)
    .bind(&privacy_json)
    .fetch_one(executor)
    .await?;

    // Return the actor with plaintext keys in memory (the database
    // stores the encrypted form).
    Ok(Actor {
        id: row.id,
        actor_type: params.actor_type,
        ap_id: row.ap_id,
        username: row.username,
        display_name: row.display_name,
        headline: None,
        location: None,
        avatar_url: None,
        header_url: None,
        summary_md: None,
        summary_html: None,
        public_key_pem: params.public_key_pem.clone(),
        // Local, so the key id is `{ap_id}#main-key` by construction and
        // the column stays NULL. See the comment on the migration.
        public_key_id: None,
        private_key_pem: Some(params.private_key_pem.clone()),
        ed25519_public_key: Some(params.ed25519_public_key.clone()),
        ed25519_private_key: Some(params.ed25519_private_key.clone()),
        domain: row.domain,
        is_local: row.is_local,
        inbox_url: None,
        instance_role: InstanceRole::User,
        actor_status: ActorStatus::Active,
        chat_requires_reprovisioning: false,
        chatmail_addr: None,
        orcid: None,
        moved_to: None,
        actor_privacy: privacy,
        created_at: row.created_at,
        updated_at: row.updated_at,
    })
}

/// Retrieve an actor by the `publicKey.id` it publishes.
///
/// Only remote actors carry the column, so this never resolves a local
/// actor, which is the same restriction the inbound signer path wants.
pub async fn find_by_public_key_id(pool: &PgPool, public_key_id: &str) -> Result<Option<Actor>> {
    let row = sqlx::query_as::<_, ActorRow>(
        r#"SELECT
               id, actor_type, ap_id, username, display_name,
               headline, location, avatar_url, header_url, summary_md, summary_html,
               public_key_pem, public_key_id, private_key_pem, ed25519_public_key, ed25519_private_key, domain, is_local,
               inbox_url, instance_role, actor_status,
               chat_requires_reprovisioning,
               chatmail_addr, orcid, moved_to, actor_privacy,
               created_at, updated_at
           FROM actors
           WHERE public_key_id = $1"#,
    )
    .bind(public_key_id)
    .fetch_optional(pool)
    .await?;

    row.map(ActorRow::into_actor).transpose()
}

/// Retrieve a local actor by username.
pub async fn find_local_by_username(pool: &PgPool, username: &str) -> Result<Actor> {
    let row = sqlx::query_as::<_, ActorRow>(
        r#"SELECT
               id, actor_type, ap_id, username, display_name,
               headline, location, avatar_url, header_url, summary_md, summary_html,
               public_key_pem, public_key_id, private_key_pem, ed25519_public_key, ed25519_private_key, domain, is_local,
               inbox_url, instance_role, actor_status,
               chat_requires_reprovisioning,
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

/// Set a local actor's instance role.
///
/// Nothing wrote this column until now: it defaulted to `'user'` and no
/// code path ever changed it, so no administrator could exist on any
/// instance and the whole moderation surface was unreachable.
pub async fn set_instance_role(pool: &PgPool, actor_id: Uuid, role: InstanceRole) -> Result<()> {
    let affected = sqlx::query(
        "UPDATE actors SET instance_role = $2, updated_at = now() \
         WHERE id = $1 AND is_local = TRUE",
    )
    .bind(actor_id)
    .bind(role)
    .execute(pool)
    .await?
    .rows_affected();

    if affected == 0 {
        return Err(NoombatError::ActorNotFound(actor_id.to_string()));
    }

    Ok(())
}

/// How many local administrators there are.
///
/// Used to refuse the demotion that would leave none. Without that
/// guard an administrator can demote themselves and lock the instance
/// out of its own moderation tools, which is the state this whole
/// change exists to escape.
pub async fn count_admins(pool: &PgPool) -> Result<i64> {
    let n = sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM actors WHERE is_local = TRUE AND instance_role = 'admin'",
    )
    .fetch_one(pool)
    .await?;
    Ok(n)
}

/// Retrieve an actor by its ActivityPub identifier (local or remote).
pub async fn find_by_ap_id(pool: &PgPool, ap_id: &str) -> Result<Option<Actor>> {
    let row = sqlx::query_as::<_, ActorRow>(
        r#"SELECT
               id, actor_type, ap_id, username, display_name,
               headline, location, avatar_url, header_url, summary_md, summary_html,
               public_key_pem, public_key_id, private_key_pem, ed25519_public_key, ed25519_private_key, domain, is_local,
               inbox_url, instance_role, actor_status,
               chat_requires_reprovisioning,
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
    /// Sanitised profile summary. The peer's `summary` is raw HTML and is
    /// rendered with `|safe`, so it goes through
    /// `noombat_markup::sanitise::clean_strict` at ingestion like post
    /// content does.
    pub summary_html: Option<String>,
    /// The sanitiser policy version that produced `summary_html`.
    pub sanitiser_version: i16,
    pub public_key_pem: String,
    /// The `publicKey.id` the actor publishes. Peers that serve their
    /// keys at their own URLs are resolved by it, so it is stored rather
    /// than derived from `ap_id`.
    pub public_key_id: Option<String>,
    pub actor_type: String,
    pub inbox_url: String,
    /// The `endpoints.sharedInbox` URI, if declared by the remote actor.
    pub shared_inbox_url: Option<String>,
    /// Multibase-encoded Ed25519 public key extracted from the remote
    /// actor's `assertionMethod` (FEP-521a). `None` if the remote
    /// actor does not publish an Ed25519 key. Stored for future
    /// FEP-8b32 Object Integrity Proof verification.
    pub ed25519_public_key: Option<String>,
}

/// Insert or update a remote actor in the `actors` table.
///
/// On conflict (same `ap_id`) the six remote-owned columns are refreshed
/// from the remote instance: `public_key_pem`, `display_name`,
/// `summary_html`, `inbox_url`, `shared_inbox_url` and
/// `ed25519_public_key`.
///
/// **A conflicting LOCAL row is never modified.** The `ON CONFLICT`
/// clause is guarded by `WHERE actors.is_local = FALSE`, so a remote
/// document claiming a local actor's `ap_id` cannot overwrite that
/// actor's published signing key.
///
/// A local `ap_id` is [`NoombatError::Forbidden`]. Postgres skips a
/// guarded `DO UPDATE` silently rather than erroring, so that is the only
/// signal a caller gets that the write did not happen.
pub async fn upsert_remote_actor(pool: &PgPool, remote: &RemoteActor) -> Result<Actor> {
    let id = Uuid::new_v4();
    let privacy = ActorPrivacy::default();
    let privacy_json = serde_json::to_value(&privacy)?;

    sqlx::query(
        r#"INSERT INTO actors
               (id, actor_type, ap_id, username, display_name, summary_html,
                sanitiser_version, domain, public_key_pem, public_key_id, inbox_url,
                shared_inbox_url, ed25519_public_key, is_local, actor_privacy)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, FALSE, $14)
           ON CONFLICT (ap_id) DO UPDATE SET
               public_key_pem = EXCLUDED.public_key_pem,
               public_key_id = EXCLUDED.public_key_id,
               display_name = EXCLUDED.display_name,
               summary_html = EXCLUDED.summary_html,
               sanitiser_version = EXCLUDED.sanitiser_version,
               inbox_url = EXCLUDED.inbox_url,
               shared_inbox_url = EXCLUDED.shared_inbox_url,
               ed25519_public_key = EXCLUDED.ed25519_public_key
           WHERE actors.is_local = FALSE"#,
    )
    .bind(id)
    .bind(&remote.actor_type)
    .bind(&remote.ap_id)
    .bind(&remote.username)
    .bind(&remote.display_name)
    .bind(&remote.summary_html)
    .bind(remote.sanitiser_version)
    .bind(&remote.domain)
    .bind(&remote.public_key_pem)
    .bind(&remote.public_key_id)
    .bind(&remote.inbox_url)
    .bind(&remote.shared_inbox_url)
    .bind(&remote.ed25519_public_key)
    .bind(&privacy_json)
    .execute(pool)
    .await?;

    // Fetch the persisted row (may be the existing row on conflict).
    let actor = find_by_ap_id(pool, &remote.ap_id).await?.ok_or_else(|| {
        NoombatError::Internal("upsert_remote_actor: row not found after insert".into())
    })?;

    // The `WHERE actors.is_local = FALSE` above fails SILENTLY: Postgres
    // raises nothing when a DO UPDATE's WHERE is false, it just skips the
    // row (`rows_affected() == 0`). `find_by_ap_id` has no `is_local`
    // filter, so without this check the read-back would hand the caller
    // the LOCAL actor as though it were the remote one, i.e. turning a
    // key-overwrite bug into a confused deputy, with handlers attributing
    // remote activity to a local user. The SQL guard protects the row;
    // this guard protects the caller.
    if actor.is_local {
        tracing::warn!(
            ap_id = %remote.ap_id,
            "refusing to return a local actor from a remote upsert; \
             a remote document claimed a local actor's ap_id"
        );
        return Err(NoombatError::Forbidden);
    }

    Ok(actor)
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
    /// property. `None` when the peer sent none. It previously held a
    /// copy of `content_html`, i.e. HTML in a column named for Markdown.
    pub content_md: Option<String>,
    /// Sanitised HTML. Produced only by
    /// `noombat_federation::inbox::extract_remote_content`, never taken
    /// raw from the peer's document.
    pub content_html: String,
    /// The sanitiser policy version that produced `content_html`, so the
    /// value can be re-derived when the policy changes.
    pub sanitiser_version: i16,
    /// FEP-8b32 verification outcome for `ap_object`, as received:
    /// `None` when there was no checkable proof, `Some(true)` when one
    /// verified. `Some(false)` does not arise from ingestion, which
    /// discards a document whose proof fails rather than storing it.
    pub integrity_proof_verified: Option<bool>,
    /// The AP URI of the post this is a reply to (`inReplyTo`).
    /// `None` for top-level posts.
    pub in_reply_to: Option<String>,
    /// Visibility derived from the activity's `to`/`cc` addressing.
    pub visibility: String,
    /// The peer's document, stored **verbatim**. This is the wire record:
    /// FEP-8b32 proofs are computed over these bytes, so it must never be
    /// sanitised or rewritten. `content_html` is the sanitised projection
    /// of it.
    pub ap_object: serde_json::Value,
}

/// Record a verified integrity proof on a post that already exists.
///
/// `create_remote_post` returns `None` when the row was inserted by a
/// concurrent delivery, and the proof result computed for the losing
/// delivery would otherwise be dropped. Two deliveries of one object can
/// carry different evidence: the first may arrive with no proof and the
/// second with a good one.
///
/// Upgrades only, and only to `TRUE`. A proof that verified is a fact
/// about the stored bytes and cannot be undone by a later delivery that
/// happened to omit one, so `NULL` may become `TRUE` and nothing may
/// become `NULL`. The `IS DISTINCT FROM` guard makes the statement a
/// no-op when there is nothing to change, so calling it is always safe.
pub async fn record_verified_proof(pool: &PgPool, ap_id: &str) -> Result<bool> {
    let updated = sqlx::query(
        "UPDATE posts SET integrity_proof_verified = TRUE \
         WHERE ap_id = $1 AND integrity_proof_verified IS DISTINCT FROM TRUE",
    )
    .bind(ap_id)
    .execute(pool)
    .await?
    .rows_affected();

    Ok(updated > 0)
}

/// Persist a post received from a remote instance.
///
/// `None` means the `ap_id` already existed and `ON CONFLICT` fired; the
/// caller links hashtags only for the genuinely new posts.
pub async fn create_remote_post(pool: &PgPool, post: &RemotePost) -> Result<Option<Uuid>> {
    let id = Uuid::new_v4();
    let row = sqlx::query_scalar::<_, Uuid>(
        r#"INSERT INTO posts
               (id, actor_id, ap_id, post_type, title, featured_image_url,
                content_md, content_html, sanitiser_version,
                in_reply_to, visibility, ap_object, integrity_proof_verified)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
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
    .bind(post.sanitiser_version)
    .bind(&post.in_reply_to)
    .bind(&post.visibility)
    .bind(&post.ap_object)
    .bind(post.integrity_proof_verified)
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
    pub location: Option<Option<String>>,
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
    let location = match &params.location {
        Some(inner) => inner.as_deref(),
        None => current.location.as_deref(),
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
               location = $4,
               summary_md = $5,
               summary_html = $6,
               avatar_url = $7,
               header_url = $8
           WHERE id = $1 AND is_local = TRUE"#,
    )
    .bind(actor_id)
    .bind(display_name)
    .bind(headline)
    .bind(location)
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
               headline, location, avatar_url, header_url, summary_md, summary_html,
               public_key_pem, public_key_id, private_key_pem, ed25519_public_key, ed25519_private_key, domain, is_local,
               inbox_url, instance_role, actor_status,
               chat_requires_reprovisioning,
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
/// The caller owns the search index, because this crate has no dependency
/// on the search backend: `Silenced` or `Suspended` **must** be followed
/// by `search_sync::remove_from_index("profiles", ...)`, or the actor
/// keeps appearing in public results, and `Active` by
/// `search_sync::reindex_profile_from_db` if they are discoverable.
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

/// Tombstone a local actor: clear the personal data, record the tombstone
/// for federation consistency, and delete the dependent rows. Returns the
/// actor as it was immediately before, so the caller can broadcast the
/// `Delete` and purge search indices.
///
/// Does **not** broadcast that `Delete`. The caller must fetch follower
/// inboxes with [`get_follower_inboxes`] *before* calling this, which
/// deletes the follow relationships, then pass them to
/// [`noombat_federation::delete::broadcast_delete`].
///
/// The row is retained carrying only `ap_id`, `username`, `domain` and
/// `public_key_pem`, with `actor_status` set to `"suspended"`, so that the
/// `Delete` can still be signed with the actor's key, `tombstoned_actors`
/// can answer `410 Gone`, and the grace period can be cancelled before any
/// irreversible loss.
///
/// `moved_to` is deliberately not cleared: followers who have not yet
/// processed an earlier `Move` still need the pointer to find the target.
///
/// Every step runs in one transaction, so a crash part-way rolls back
/// rather than leaving the actor partly tombstoned.
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
               location = NULL,
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

    // The ON DELETE CASCADE constraints would cover this if the actor row
    // were deleted, but it is retained, so dependents go explicitly.
    // Order matters: everything referencing `posts` (likes, boosts,
    // post_hashtags, media_attachments) must go before `posts` itself.
    //
    // Each query is a literal `&'static str` rather than a `format!`, to
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
    // The recruiter's listings are their content and go with them.
    // `applications.job_listing_id` is SET NULL rather than CASCADE, so
    // applicants keep their own records; the snapshot columns on that
    // table are what keeps those records legible afterwards.
    sqlx::query("DELETE FROM job_listings WHERE actor_id = $1")
        .bind(actor_id)
        .execute(&mut *tx)
        .await?;

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

// ..... TESTS .....
//
// `#[ignore]`d because they need a live PostgreSQL, which `cargo test
// --workspace` does not have; the `integration` CI job runs them with
// `--include-ignored`, so they cannot rot unnoticed.
//
// `#[sqlx::test]` gives each one a fresh database with the migrations
// applied. `migrations` is named explicitly because migrations/ lives at
// the workspace root, not in this crate.

#[cfg(test)]
mod tests {
    use super::*;

    const LOCAL_AP_ID: &str = "https://noombat.social/users/admin";
    const LOCAL_KEY: &str = "-----BEGIN PUBLIC KEY-----LOCAL-----END PUBLIC KEY-----";
    const ATTACKER_KEY: &str = "-----BEGIN PUBLIC KEY-----ATTACKER-----END PUBLIC KEY-----";

    /// Insert an actor row directly. `create_actor` is deliberately not
    /// used: it seals the private key columns through `envelope`, which
    /// would make these tests depend on encryption being configured.
    async fn insert_actor(pool: &PgPool, ap_id: &str, key_pem: &str, is_local: bool) {
        sqlx::query(
            r#"INSERT INTO actors
                   (id, actor_type, ap_id, username, domain, public_key_pem, is_local)
               VALUES ($1, 'individual', $2, 'admin', 'noombat.social', $3, $4)"#,
        )
        .bind(Uuid::new_v4())
        .bind(ap_id)
        .bind(key_pem)
        .bind(is_local)
        .execute(pool)
        .await
        .expect("actor fixture inserted");
    }

    async fn stored_key(pool: &PgPool, ap_id: &str) -> String {
        sqlx::query_scalar::<_, String>("SELECT public_key_pem FROM actors WHERE ap_id = $1")
            .bind(ap_id)
            .fetch_one(pool)
            .await
            .expect("actor row present")
    }

    fn remote_claiming(ap_id: &str, key_pem: &str) -> RemoteActor {
        RemoteActor {
            ap_id: ap_id.to_owned(),
            username: "admin".to_owned(),
            domain: "remote.example".to_owned(),
            display_name: Some("Not The Admin".to_owned()),
            summary_html: None,
            sanitiser_version: noombat_markup::sanitise::STRICT_VERSION,
            public_key_pem: key_pem.to_owned(),
            public_key_id: Some(format!("{ap_id}#main-key")),
            actor_type: "individual".to_owned(),
            inbox_url: "https://remote.example/inbox".to_owned(),
            shared_inbox_url: None,
            ed25519_public_key: None,
        }
    }

    #[ignore = "requires a database; run with --include-ignored"]
    #[sqlx::test(migrations = "../../migrations")]
    async fn upsert_remote_actor_refuses_to_overwrite_a_local_actor(pool: PgPool) {
        insert_actor(&pool, LOCAL_AP_ID, LOCAL_KEY, true).await;

        let result = upsert_remote_actor(&pool, &remote_claiming(LOCAL_AP_ID, ATTACKER_KEY)).await;

        assert!(
            matches!(result, Err(NoombatError::Forbidden)),
            "a remote document claiming a local ap_id must be refused, got {result:?}"
        );
        assert_eq!(
            stored_key(&pool, LOCAL_AP_ID).await,
            LOCAL_KEY,
            "the local actor's published signing key must be untouched"
        );
    }

    #[ignore = "requires a database; run with --include-ignored"]
    #[sqlx::test(migrations = "../../migrations")]
    async fn upsert_remote_actor_still_updates_a_remote_actor(pool: PgPool) {
        // The guard must not break the legitimate path it sits on.
        let ap_id = "https://remote.example/users/alice";
        insert_actor(&pool, ap_id, "OLD-KEY", false).await;

        let actor = upsert_remote_actor(&pool, &remote_claiming(ap_id, "NEW-KEY"))
            .await
            .expect("a genuine remote actor update must succeed");

        assert!(!actor.is_local);
        assert_eq!(stored_key(&pool, ap_id).await, "NEW-KEY");
    }

    // ..... KEY ID LOOKUP .....

    #[ignore = "requires a database; run with --include-ignored"]
    #[sqlx::test(migrations = "../../migrations")]
    async fn a_remote_actor_is_found_by_the_key_id_it_publishes(pool: PgPool) {
        // GoToSocial's shape: the key id is a URL of its own, so it is
        // not reachable by `ap_id` and the column is the only route to it.
        let ap_id = "https://remote.example/users/alice";
        let key_id = "https://remote.example/users/alice/main-key";

        let mut remote = remote_claiming(ap_id, "KEY");
        remote.public_key_id = Some(key_id.to_owned());
        upsert_remote_actor(&pool, &remote)
            .await
            .expect("the remote actor is stored");

        let found = find_by_public_key_id(&pool, key_id)
            .await
            .expect("the lookup runs")
            .expect("the key id resolves to its actor");

        assert_eq!(found.ap_id, ap_id);
        assert!(!found.is_local);
    }

    #[ignore = "requires a database; run with --include-ignored"]
    #[sqlx::test(migrations = "../../migrations")]
    async fn two_actors_cannot_claim_one_key_id(pool: PgPool) {
        // This lookup decides which actor a signature is verified
        // against, so a second claimant would make that ambiguous. The
        // unique index is what refuses it.
        let key_id = "https://remote.example/users/alice/main-key";

        let mut first = remote_claiming("https://remote.example/users/alice", "KEY");
        first.public_key_id = Some(key_id.to_owned());
        upsert_remote_actor(&pool, &first)
            .await
            .expect("the first claim is stored");

        let mut impostor = remote_claiming("https://remote.example/users/mallory", "OTHER");
        impostor.public_key_id = Some(key_id.to_owned());
        let result = upsert_remote_actor(&pool, &impostor).await;

        assert!(
            result.is_err(),
            "a second actor claiming the same key id must be refused, got {result:?}"
        );

        let still = find_by_public_key_id(&pool, key_id)
            .await
            .expect("the lookup runs")
            .expect("the original claimant is still there");
        assert_eq!(still.ap_id, "https://remote.example/users/alice");
    }

    // ..... REMOTE POST PERSISTENCE .....
    //
    // These exist because the workspace uses sqlx's *runtime* query API,
    // not the compile-time macros: a `$n` placeholder that disagrees with
    // the `.bind()` sequence compiles cleanly, and fails (or silently
    // writes a value into the wrong column) only when executed. Nothing
    // but a live database catches that.

    async fn remote_post_fixture(pool: &PgPool, actor_id: Uuid, md: Option<&str>) -> RemotePost {
        let _ = pool;
        RemotePost {
            actor_id,
            ap_id: "https://remote.example/posts/1".to_owned(),
            post_type: "note".to_owned(),
            title: None,
            featured_image_url: None,
            content_md: md.map(str::to_owned),
            content_html: "<p>safe</p>".to_owned(),
            sanitiser_version: noombat_markup::sanitise::STRICT_VERSION,
            in_reply_to: None,
            visibility: "public".to_owned(),
            ap_object: serde_json::json!({ "content": "<p>safe</p><script>x</script>" }),
            integrity_proof_verified: None,
        }
    }

    async fn actor_id_of(pool: &PgPool, ap_id: &str) -> Uuid {
        sqlx::query_scalar::<_, Uuid>("SELECT id FROM actors WHERE ap_id = $1")
            .bind(ap_id)
            .fetch_one(pool)
            .await
            .expect("actor row present")
    }

    #[ignore = "requires a database; run with --include-ignored"]
    #[sqlx::test(migrations = "../../migrations")]
    async fn create_remote_post_writes_every_column_to_its_own_slot(pool: PgPool) {
        let ap_id = "https://remote.example/users/alice";
        insert_actor(&pool, ap_id, "KEY", false).await;
        let actor_id = actor_id_of(&pool, ap_id).await;

        let post = remote_post_fixture(&pool, actor_id, None).await;
        let id = create_remote_post(&pool, &post)
            .await
            .expect("insert succeeds")
            .expect("a new row");

        let (md, html, ver, title): (Option<String>, String, i16, Option<String>) = sqlx::query_as(
            "SELECT content_md, content_html, sanitiser_version, title \
                            FROM posts WHERE id = $1",
        )
        .bind(id)
        .fetch_one(&pool)
        .await
        .expect("row readable");

        assert_eq!(
            md, None,
            "no Markdown source means NULL, not a copy of the HTML"
        );
        assert_eq!(html, "<p>safe</p>");
        assert_eq!(
            ver,
            noombat_markup::sanitise::STRICT_VERSION,
            "sanitiser_version must land in its own column, not shift into a neighbour"
        );
        assert_eq!(title, None, "title must not receive the sanitiser version");
    }

    #[ignore = "requires a database; run with --include-ignored"]
    #[sqlx::test(migrations = "../../migrations")]
    async fn record_verified_proof_upgrades_but_never_downgrades(pool: PgPool) {
        let ap_id = "https://remote.example/users/alice";
        insert_actor(&pool, ap_id, "KEY", false).await;
        let actor_id = actor_id_of(&pool, ap_id).await;

        let post = remote_post_fixture(&pool, actor_id, None).await;
        create_remote_post(&pool, &post).await.expect("insert");

        let stored = |pool: PgPool, ap: String| async move {
            sqlx::query_scalar::<_, Option<bool>>(
                "SELECT integrity_proof_verified FROM posts WHERE ap_id = $1",
            )
            .bind(ap)
            .fetch_one(&pool)
            .await
            .expect("row present")
        };

        assert_eq!(stored(pool.clone(), post.ap_id.clone()).await, None);

        assert!(
            record_verified_proof(&pool, &post.ap_id)
                .await
                .expect("upgrade runs"),
            "NULL must be upgradeable to TRUE"
        );
        assert_eq!(stored(pool.clone(), post.ap_id.clone()).await, Some(true));

        // Idempotent, and reports that it changed nothing.
        assert!(
            !record_verified_proof(&pool, &post.ap_id)
                .await
                .expect("second upgrade runs"),
            "a second call must be a no-op"
        );
        assert_eq!(stored(pool.clone(), post.ap_id.clone()).await, Some(true));

        // A post nobody stored is not an error either.
        assert!(
            !record_verified_proof(&pool, "https://remote.example/posts/absent")
                .await
                .expect("missing row is not an error")
        );
    }

    #[ignore = "requires a database; run with --include-ignored"]
    #[sqlx::test(migrations = "../../migrations")]
    async fn create_remote_post_keeps_the_wire_record_unsanitised(pool: PgPool) {
        // `ap_object` is the bytes FEP-8b32 proofs are computed over. It
        // must survive verbatim even though `content_html` is scrubbed.
        let ap_id = "https://remote.example/users/alice";
        insert_actor(&pool, ap_id, "KEY", false).await;
        let actor_id = actor_id_of(&pool, ap_id).await;

        let post = remote_post_fixture(&pool, actor_id, Some("*md*")).await;
        let id = create_remote_post(&pool, &post)
            .await
            .expect("insert succeeds")
            .expect("a new row");

        let stored: serde_json::Value =
            sqlx::query_scalar("SELECT ap_object FROM posts WHERE id = $1")
                .bind(id)
                .fetch_one(&pool)
                .await
                .expect("row readable");

        assert_eq!(
            stored["content"].as_str(),
            Some("<p>safe</p><script>x</script>"),
            "ap_object must be stored verbatim, script tag and all"
        );
    }

    #[ignore = "requires a database; run with --include-ignored"]
    #[sqlx::test(migrations = "../../migrations")]
    async fn upsert_remote_actor_inserts_an_unseen_actor(pool: PgPool) {
        let ap_id = "https://remote.example/users/bob";

        let actor = upsert_remote_actor(&pool, &remote_claiming(ap_id, "BOB-KEY"))
            .await
            .expect("first sighting of a remote actor must insert");

        assert_eq!(actor.ap_id, ap_id);
        assert!(!actor.is_local);
        assert_eq!(stored_key(&pool, ap_id).await, "BOB-KEY");
    }

    // ..... Erasure runs in one transaction .....

    /// The source of `tombstone_actor`, from its signature to the closing
    /// brace in the first column.
    fn tombstone_actor_source() -> &'static str {
        const SOURCE: &str = include_str!("repo.rs");
        let start = SOURCE
            .find("pub async fn tombstone_actor")
            .expect("tombstone_actor is defined in this file");
        let rest = &SOURCE[start..];
        let end = rest
            .find("\n}\n")
            .expect("tombstone_actor has a closing brace in the first column");
        &rest[..end]
    }

    /// Every statement in `tombstone_actor` runs on the transaction.
    ///
    /// A source-level assertion, because the type system permits the
    /// defect: `.execute(pool)` and `.execute(&mut *tx)` both compile
    /// inside a transaction. A statement on `pool` takes a different
    /// connection and commits immediately, so a later failure rolls back
    /// every table except that one and leaves the account partly deleted;
    /// it can also deadlock against the transaction whose locks it waits
    /// for.
    ///
    /// `a_failed_erasure_leaves_the_job_listings_intact` asserts the same
    /// property behaviourally, but needs a database. This one runs on a
    /// bare `cargo test`, which is where a regression would be caught.
    #[test]
    fn erasure_runs_entirely_inside_its_transaction() {
        let body = tombstone_actor_source();

        assert!(
            body.contains("pool.begin()"),
            "tombstone_actor no longer opens a transaction, so this guard is \
             asserting nothing; rewrite it for whatever replaced the transaction"
        );

        let total = body.matches(".execute(").count();
        assert!(
            total >= 20,
            "found only {total} statements in the extracted body of tombstone_actor. \
             The function has far more than that, so the slice is wrong and a leaked \
             statement could sit outside it unseen"
        );

        let on_transaction = body.matches(".execute(&mut *tx)").count();
        assert_eq!(
            on_transaction,
            total,
            "{} of {total} statements in tombstone_actor do not run on the transaction. \
             Each one commits immediately on its own connection, so a later failure \
             rolls back everything except that statement and the erasure is silently \
             partial.",
            total - on_transaction
        );

        for leaked in [
            ".execute(pool)",
            ".fetch_one(pool)",
            ".fetch_optional(pool)",
            ".fetch_all(pool)",
        ] {
            assert!(
                !body.contains(leaked),
                "tombstone_actor uses `{leaked}`, which escapes the transaction"
            );
        }
    }

    /// Insert a local actor that owns one job listing, and return its id.
    async fn local_actor_with_a_job_listing(pool: &PgPool) -> Uuid {
        let actor_id = Uuid::new_v4();
        sqlx::query(
            r#"INSERT INTO actors
                   (id, actor_type, ap_id, username, domain, public_key_pem, is_local)
               VALUES ($1, 'individual', $2, 'recruiter', 'noombat.social', $3, TRUE)"#,
        )
        .bind(actor_id)
        .bind(format!("https://noombat.social/users/recruiter-{actor_id}"))
        .bind(LOCAL_KEY)
        .execute(pool)
        .await
        .expect("actor fixture inserted");

        sqlx::query(
            r#"INSERT INTO job_listings
                   (actor_id, ap_id, title, description_md, description_html)
               VALUES ($1, $2, 'Postdoctoral Fellow', 'A post.', '<p>A post.</p>')"#,
        )
        .bind(actor_id)
        .bind(format!("https://noombat.social/jobs/{actor_id}"))
        .execute(pool)
        .await
        .expect("job listing fixture inserted");

        actor_id
    }

    /// A failure part-way through erasure rolls the whole thing back,
    /// job listings included.
    ///
    /// The fault is injected by dropping `hashtag_follows`, which the last
    /// step of `tombstone_actor` deletes from, so the transaction fails
    /// *after* the listings are gone. That ordering is the only one that
    /// distinguishes a statement on the transaction from one on the pool.
    /// Each `#[sqlx::test]` gets its own database, so the drop affects
    /// nothing else.
    ///
    /// Against the unfixed code it fails, which is what makes this a test
    /// rather than a description.
    #[ignore = "requires a database; run with --include-ignored"]
    #[sqlx::test(migrations = "../../migrations")]
    async fn a_failed_erasure_leaves_the_job_listings_intact(pool: PgPool) {
        let actor_id = local_actor_with_a_job_listing(&pool).await;

        sqlx::query("DROP TABLE hashtag_follows CASCADE")
            .execute(&pool)
            .await
            .expect("fault injected");

        let result = tombstone_actor(&pool, actor_id).await;
        assert!(
            result.is_err(),
            "erasure must fail once one of its statements cannot run; if this passes, \
             the fault injection missed and the test proves nothing"
        );

        let listings: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM job_listings WHERE actor_id = $1")
                .bind(actor_id)
                .fetch_one(&pool)
                .await
                .expect("job_listings is readable");
        assert_eq!(
            listings, 1,
            "the job listing was destroyed by an erasure that rolled back, so the \
             delete ran outside the transaction"
        );

        let actors: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM actors WHERE id = $1")
            .bind(actor_id)
            .fetch_one(&pool)
            .await
            .expect("actors is readable");
        assert_eq!(
            actors, 1,
            "the actor row must come back with everything else the rollback restored"
        );
    }
}
