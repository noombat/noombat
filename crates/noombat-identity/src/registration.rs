// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Local account registration with split key derivation.
//!
//! The client derives an authentication key from the user's password
//! via PBKDF2-SHA256 to HKDF-Expand("noombat-auth") and sends it to
//! the server. The server hashes it with Argon2id and stores the
//! result. The blob-encryption key (HKDF-Expand("noombat-chat-crypto"))
//! never leaves the browser.

use argon2::Argon2;
use argon2::password_hash::PasswordHasher;
use noombat_core::actor::{Actor, ActorStatus, ActorType, NewActor, OrgKind};
use noombat_core::error::{NoombatError, Result};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tracing::info;
use uuid::Uuid;

use crate::keys;

/// Request body for `POST /api/v1/auth/register`.
///
/// The `auth_key` field is the authentication key derived client-side
/// via split key derivation. It is *not* the user's password.
#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub username: String,
    pub display_name: Option<String>,
    /// The address a recovery challenge is sent to.
    ///
    /// Required on this path, and only on this path. `auth_key` is derived
    /// in the browser and the server keeps only a hash of it, so there is
    /// nothing to reset: an account created with a password and no address
    /// is one a forgotten password destroys. The OAuth sign-up paths mint
    /// no password and are recoverable through the provider, which is why
    /// they do not ask for one.
    ///
    /// `Option` in the type and required in [`register`], so that a request
    /// omitting it is refused with a message about the field rather than
    /// rejected as malformed JSON.
    pub email: Option<String>,
    /// The authentication key (hex-encoded, 32 bytes / 64 hex chars),
    /// derived client-side from the user's password via
    /// PBKDF2-SHA256 to HKDF-Expand("noombat-auth").
    pub auth_key: String,
}

/// Response body for a successful registration.
#[derive(Debug, Serialize)]
pub struct RegisterResponse {
    pub actor_id: uuid::Uuid,
    pub username: String,
    pub ap_id: String,
    /// Whether the account was created awaiting admission.
    ///
    /// The caller must not mint a session for one: a pending account
    /// holds its username and nothing else, and `login` already refuses
    /// it, so issuing a token here would be the one way in.
    pub awaiting_approval: bool,
}

/// What the instance currently does with a sign-up request.
///
/// Read from `instance_settings.registration_mode`, which is what the
/// administration page writes. Before this existed the column had no
/// reader at all, so closing registration closed nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrationMode {
    /// Accounts are created active.
    Open,
    /// Accounts are created `pending` and cannot sign in until an
    /// administrator admits them.
    Approval,
    /// No account is created.
    Closed,
}

impl RegistrationMode {
    /// Read a stored value.
    ///
    /// An unrecognised setting is `Closed`. Every other reading admits
    /// accounts on a value the instance does not understand, and the
    /// cost of being wrong this way is a sign-up form that refuses.
    pub fn from_stored(s: &str) -> Self {
        match s {
            "open" => Self::Open,
            "approval" => Self::Approval,
            _ => Self::Closed,
        }
    }
}

/// The instance's current registration mode.
///
/// A missing settings row is `Closed`, for the same reason an unknown
/// value is.
pub async fn registration_mode(pool: &PgPool) -> Result<RegistrationMode> {
    let stored =
        sqlx::query_scalar::<_, String>("SELECT registration_mode FROM instance_settings LIMIT 1")
            .fetch_optional(pool)
            .await?;

    Ok(stored
        .as_deref()
        .map_or(RegistrationMode::Closed, RegistrationMode::from_stored))
}

/// Validate a proposed username.
///
/// Usernames must be 1 to 30 characters, consist solely of ASCII
/// lowercase letters, digits, and underscores, and must begin with a
/// letter.
pub fn validate_username(username: &str) -> Result<()> {
    if username.is_empty() || username.len() > 30 {
        return Err(NoombatError::BadRequest(
            "username must be 1-30 characters".into(),
        ));
    }
    let mut chars = username.chars();
    let first = chars.next().unwrap();
    if !first.is_ascii_lowercase() {
        return Err(NoombatError::BadRequest(
            "username must begin with a lowercase letter".into(),
        ));
    }
    if !chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_') {
        return Err(NoombatError::BadRequest(
            "username may contain only lowercase letters, digits, and underscores".into(),
        ));
    }
    Ok(())
}

/// Validate the auth key format (hex-encoded, 32 bytes).
fn validate_auth_key(auth_key: &str) -> Result<()> {
    if auth_key.len() != 64 {
        return Err(NoombatError::BadRequest(
            "auth_key must be 64 hex characters (32 bytes)".into(),
        ));
    }
    if !auth_key.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(NoombatError::BadRequest(
            "auth_key must be hex-encoded".into(),
        ));
    }
    Ok(())
}

/// Hash an authentication key with Argon2id.
///
/// Returns the PHC-formatted hash string.
pub fn hash_auth_key(auth_key: &str) -> Result<String> {
    // The salt is no longer passed in. `hash_password` generates a large
    // random one itself, from the operating system, and writes it into the
    // PHC string it returns, which is what `verify_password` reads back.
    let argon2 = Argon2::default();
    let hash = argon2
        .hash_password(auth_key.as_bytes())
        .map_err(|e| NoombatError::Internal(format!("Argon2id hashing failed: {e}")))?;
    Ok(hash.to_string())
}

/// Whether a local actor already holds this username on this domain.
///
/// Checked before key generation, which is the expensive part.
async fn username_taken(pool: &PgPool, domain: &str, username: &str) -> Result<bool> {
    Ok(sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM actors \
         WHERE username = $1 AND domain = $2 AND is_local = TRUE)",
    )
    .bind(username)
    .bind(domain)
    .fetch_one(pool)
    .await?)
}

/// Register a new local account.
///
/// `ActorAlreadyExists` if the username is taken, `BadRequest` if the
/// username, authentication key or address is invalid.
pub async fn register(
    pool: &PgPool,
    domain: &str,
    req: &RegisterRequest,
) -> Result<RegisterResponse> {
    // The instance setting first, before anything is validated or
    // generated. A closed instance should cost a sign-up attempt one
    // query, and should not disclose whether the username was free.
    let mode = registration_mode(pool).await?;
    if mode == RegistrationMode::Closed {
        return Err(NoombatError::Forbidden);
    }

    validate_username(&req.username)?;
    validate_auth_key(&req.auth_key)?;

    // Checked before any key generation, so a mistyped address costs a
    // round trip rather than an RSA keypair.
    let email = req.email.as_deref().ok_or_else(|| {
        NoombatError::BadRequest(
            "email is required: a password account with no address cannot be recovered".into(),
        )
    })?;
    noombat_core::email_address::qualify(email, "email")?;

    // Check uniqueness before generating keys (which is expensive).
    if username_taken(pool, domain, &req.username).await? {
        return Err(NoombatError::ActorAlreadyExists(req.username.clone()));
    }

    // Generate key material (offloaded to a blocking thread).
    let keypair = keys::generate_keypair_async().await?;

    // Hash the authentication key with Argon2id.
    let auth_key_clone = req.auth_key.clone();
    let auth_key_hash = tokio::task::spawn_blocking(move || hash_auth_key(&auth_key_clone))
        .await
        .map_err(|e| NoombatError::Internal(format!("hash task failed: {e}")))?
        .map_err(|e| NoombatError::Internal(format!("hash failed: {e}")))?;

    // Create the actor.
    let new_actor = NewActor {
        actor_type: ActorType::Individual,
        username: req.username.clone(),
        display_name: req.display_name.clone(),
        domain: domain.to_owned(),
        public_key_pem: keypair.rsa.public_pem,
        private_key_pem: keypair.rsa.private_pem,
        ed25519_public_key: keypair.ed25519.public_multibase,
        ed25519_private_key: keypair.ed25519.private_base64,
    };

    // Create the actor and store the auth_key_hash atomically.
    let mut tx = pool
        .begin()
        .await
        .map_err(|e| NoombatError::Internal(format!("transaction begin failed: {e}")))?;

    let actor = match crate::repo::create_actor_tx(&mut tx, &new_actor).await {
        Ok(a) => a,
        Err(NoombatError::Database(ref e))
            if e.as_database_error()
                .and_then(|dbe| dbe.code())
                .map(|c| c == "23505")
                .unwrap_or(false) =>
        {
            return Err(NoombatError::ActorAlreadyExists(req.username.clone()));
        }
        Err(e) => return Err(e),
    };

    // The status goes in the same transaction as the key, so there is
    // no window in which an approval-mode account exists as active.
    // `create_actor_tx` names no status and takes the column default,
    // which is `active` deliberately, so an approval instance has to
    // set it here rather than by changing that default: the default
    // also governs every federated actor.
    let awaiting_approval = mode == RegistrationMode::Approval;
    let status = if awaiting_approval {
        ActorStatus::Pending
    } else {
        ActorStatus::Active
    };

    sqlx::query("UPDATE actors SET auth_key_hash = $1, actor_status = $2 WHERE id = $3")
        .bind(&auth_key_hash)
        .bind(status.as_str())
        .bind(actor.id)
        .execute(&mut *tx)
        .await?;

    tx.commit()
        .await
        .map_err(|e| NoombatError::Internal(format!("transaction commit failed: {e}")))?;

    info!(
        username = %actor.username,
        awaiting_approval,
        "local account registered"
    );

    Ok(RegisterResponse {
        actor_id: actor.id,
        username: actor.username,
        ap_id: actor.ap_id,
        awaiting_approval,
    })
}

/// How long a ceiling's window is: an amount and a unit.
///
/// The unit is closed here as well as by the column's CHECK constraint,
/// because it becomes an argument of `make_interval`. Mapping it to a
/// named argument rather than building an interval string keeps a value
/// that somehow reached the database out of the SQL.
#[derive(Debug, Clone, Copy)]
struct Period {
    amount: i32,
    unit: PeriodUnit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PeriodUnit {
    Hours,
    Days,
    Weeks,
    Months,
    Years,
}

impl PeriodUnit {
    fn parse(raw: &str) -> Option<Self> {
        match raw {
            "hours" => Some(Self::Hours),
            "days" => Some(Self::Days),
            "weeks" => Some(Self::Weeks),
            "months" => Some(Self::Months),
            "years" => Some(Self::Years),
            _ => None,
        }
    }
}

impl std::fmt::Display for Period {
    /// For the refusal message, so a caller is told the window they hit.
    ///
    /// Singular when the amount is one, because "one organisation every 1
    /// days" is the shape of a message nobody proof-read.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let unit = match self.unit {
            PeriodUnit::Hours => "hour",
            PeriodUnit::Days => "day",
            PeriodUnit::Weeks => "week",
            PeriodUnit::Months => "month",
            PeriodUnit::Years => "year",
        };
        if self.amount == 1 {
            write!(f, "{unit}")
        } else {
            write!(f, "{} {unit}s", self.amount)
        }
    }
}

impl Period {
    /// The five `make_interval` arguments, exactly one of them non-zero.
    ///
    /// Returned as a tuple bound positionally, so the query text is fixed
    /// and the unit never reaches it as text.
    fn interval_args(self) -> (i32, i32, i32, i32, i32) {
        let (mut years, mut months, mut weeks, mut days, mut hours) = (0, 0, 0, 0, 0);
        match self.unit {
            PeriodUnit::Hours => hours = self.amount,
            PeriodUnit::Days => days = self.amount,
            PeriodUnit::Weeks => weeks = self.amount,
            PeriodUnit::Months => months = self.amount,
            PeriodUnit::Years => years = self.amount,
        }
        (years, months, weeks, days, hours)
    }
}

/// The instance's ceilings on organisation creation, from
/// `instance_settings`.
///
/// Read per enrolment rather than captured at boot. These are policy an
/// administrator changes while the instance is running, and the point of
/// a pause switch is that it takes effect without a restart.
struct OrganizationPolicy {
    enabled: bool,
    rate_limit_count: i32,
    rate_limit_period: Period,
    concurrent_cap: i32,
    period_cap_count: i32,
    cap_period: Period,
}

impl Default for OrganizationPolicy {
    /// The schema defaults, for an instance whose settings row does not
    /// exist yet. Enrolment stays available rather than being refused,
    /// which is how `registration_mode` reads its own missing row.
    fn default() -> Self {
        Self {
            enabled: true,
            rate_limit_count: 1,
            rate_limit_period: Period {
                amount: 7,
                unit: PeriodUnit::Days,
            },
            concurrent_cap: 5,
            period_cap_count: 10,
            cap_period: Period {
                amount: 1,
                unit: PeriodUnit::Years,
            },
        }
    }
}

/// Count this owner's enrolments inside a window.
///
/// One query for both time-based ceilings: they differ only in the window
/// and the number allowed inside it.
async fn enrolments_within(
    tx: &mut sqlx::PgConnection,
    owner_id: Uuid,
    period: Period,
) -> Result<i64> {
    let (years, months, weeks, days, hours) = period.interval_args();
    sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM organization_enrolments \
         WHERE owner_id = $1 AND created_at > now() - make_interval( \
             years => $2, months => $3, weeks => $4, days => $5, hours => $6)",
    )
    .bind(owner_id)
    .bind(years)
    .bind(months)
    .bind(weeks)
    .bind(days)
    .bind(hours)
    .fetch_one(&mut *tx)
    .await
    .map_err(NoombatError::from)
}

/// Refuse the enrolment if the instance or the owner has run out of room.
///
/// Deliberately independent of `registration_mode` and of the
/// `open_registrations` configuration flag, both of which govern people
/// signing up. An instance closed to new members may still want its
/// existing members enrolling organisations, and an instance open to
/// members may need organisation creation paused while moderation catches
/// up. One switch answering both questions cannot express either.
///
/// Every ceiling is per owner, and a count of `0` disables the one it
/// names.
async fn enforce_organization_policy(tx: &mut sqlx::PgConnection, owner_id: Uuid) -> Result<()> {
    let row = sqlx::query_as::<_, (bool, i32, i32, String, i32, i32, i32, String)>(
        "SELECT organization_creation_enabled, organization_rate_limit_count, \
                organization_rate_limit_amount, organization_rate_limit_unit, \
                organization_concurrent_cap, organization_period_cap_count, \
                organization_period_cap_amount, organization_period_cap_unit \
         FROM instance_settings LIMIT 1",
    )
    .fetch_optional(&mut *tx)
    .await?;

    let policy = match row {
        Some((
            enabled,
            rate_limit_count,
            rate_amount,
            rate_unit,
            concurrent_cap,
            period_cap_count,
            cap_amount,
            cap_unit,
        )) => {
            // An unparsable unit is a misconfiguration, not a reason to
            // stop enforcing: falling back to the default window keeps the
            // ceiling in force, where treating it as "no limit" would turn
            // a typo into an open door.
            let default = OrganizationPolicy::default();
            OrganizationPolicy {
                enabled,
                rate_limit_count,
                rate_limit_period: Period {
                    amount: rate_amount,
                    unit: PeriodUnit::parse(&rate_unit).unwrap_or(default.rate_limit_period.unit),
                },
                concurrent_cap,
                period_cap_count,
                cap_period: Period {
                    amount: cap_amount,
                    unit: PeriodUnit::parse(&cap_unit).unwrap_or(default.cap_period.unit),
                },
            }
        }
        None => OrganizationPolicy::default(),
    };

    if !policy.enabled {
        return Err(NoombatError::Forbidden);
    }

    // Serialise this owner's enrolments against each other, and only this
    // owner's: the counts below are read-then-write, and a row lock cannot
    // cover rows that do not exist yet. Held to the end of the
    // transaction, so it is released by the commit or the rollback.
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
        .bind(owner_id.to_string())
        .execute(&mut *tx)
        .await?;

    if policy.concurrent_cap > 0 {
        // `role = 'owner'` explicitly. The CHECK constraint also admits
        // `recruiter`, and an organisation somebody was invited to help
        // run is not one they created.
        let held = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM organization_members \
             WHERE member_id = $1 AND role = 'owner' AND accepted_at IS NOT NULL",
        )
        .bind(owner_id)
        .fetch_one(&mut *tx)
        .await?;
        if held >= i64::from(policy.concurrent_cap) {
            return Err(NoombatError::QuotaExceeded(format!(
                "you hold {held} organisations and this instance allows {}. \
                 Dissolve one before enrolling another",
                policy.concurrent_cap
            )));
        }
    }

    if policy.period_cap_count > 0 {
        // `organization_enrolments`, not `organization_members`: dissolving
        // an organisation frees a concurrent place and must not refund a
        // place in the period.
        let recent = enrolments_within(&mut *tx, owner_id, policy.cap_period).await?;
        if recent >= i64::from(policy.period_cap_count) {
            return Err(NoombatError::QuotaExceeded(format!(
                "you have enrolled {recent} organisations in the past {} and this instance \
                 allows {}",
                policy.cap_period, policy.period_cap_count
            )));
        }
    }

    if policy.rate_limit_count > 0 {
        // Counted from enrolments that actually happened, so a request
        // refused above or by a taken username costs nothing. A limiter
        // that counted attempts would spend the window on a typo.
        let recent = enrolments_within(&mut *tx, owner_id, policy.rate_limit_period).await?;
        if recent >= i64::from(policy.rate_limit_count) {
            return Err(NoombatError::QuotaExceeded(format!(
                "this instance allows {} organisation(s) every {} per account",
                policy.rate_limit_count, policy.rate_limit_period
            )));
        }
    }

    Ok(())
}

/// Enrol an organisation as its own actor, owned by the actor enrolling it.
///
/// Self-serve by decision: an administrator cannot adjudicate employment
/// at any scale, and a route that lets them try makes the operator the
/// arbiter of who is a real employer.
///
/// The organisation gets no auth key and no session. It is never signed
/// into; it is acted for, through `organization_members`. That keeps
/// "which person did this" answerable, which a shared login destroys.
///
/// Enrolment does not confer verification. `rel="me"` against the
/// organisation's own domain gates what it may publish, and is added
/// afterwards through `verification::add_link`.
pub async fn enrol_organization(
    pool: &PgPool,
    domain: &str,
    owner_id: Uuid,
    username: &str,
    display_name: Option<String>,
    claimed_domain: Option<&str>,
    org_kind: Option<OrgKind>,
) -> Result<Actor> {
    validate_username(username)?;

    if username_taken(pool, domain, username).await? {
        return Err(NoombatError::ActorAlreadyExists(username.to_owned()));
    }

    let keypair = keys::generate_keypair_async().await?;

    let new_actor = NewActor {
        actor_type: ActorType::Organization,
        username: username.to_owned(),
        display_name,
        domain: domain.to_owned(),
        public_key_pem: keypair.rsa.public_pem,
        private_key_pem: keypair.rsa.private_pem,
        ed25519_public_key: keypair.ed25519.public_multibase,
        ed25519_private_key: keypair.ed25519.private_base64,
    };

    let mut tx = pool
        .begin()
        .await
        .map_err(|e| NoombatError::Internal(format!("transaction begin failed: {e}")))?;

    // Before the actor exists, so a refusal writes nothing. The gate is
    // inside the transaction because it is a read followed by a write: two
    // concurrent requests that both counted four organisations would both
    // pass a cap of five.
    enforce_organization_policy(&mut tx, owner_id).await?;

    let actor = crate::repo::create_actor_tx(&mut tx, &new_actor).await?;

    // Stored as the registrable domain, so the gate compares like with
    // like and a claim on `careers.acme.example` is a claim on
    // `acme.example`. A claim that parses to nothing is refused rather
    // than stored, or it would be a claim no link could ever satisfy.
    if let Some(raw) = claimed_domain {
        let domain = crate::verification::registrable_domain(raw).ok_or_else(|| {
            NoombatError::BadRequest(format!("{raw} is not a registrable domain"))
        })?;
        sqlx::query("UPDATE actors SET claimed_domain = $1 WHERE id = $2")
            .bind(&domain)
            .bind(actor.id)
            .execute(&mut *tx)
            .await?;
    }

    // Optional here and required at the point it decides something,
    // which is publishing a job posting. An organisation enrolled to
    // hold a profile has nothing to declare yet, and refusing enrolment
    // over it would ask the question before it means anything.
    if let Some(kind) = org_kind {
        sqlx::query("UPDATE actors SET org_kind = $1 WHERE id = $2")
            .bind(kind.as_str())
            .bind(actor.id)
            .execute(&mut *tx)
            .await?;
    }

    // In the same transaction as the actor. An organisation nobody can
    // act for is unreachable: there is no login to fall back on, so a
    // failure here has to take the actor with it.
    // Accepted on the spot: the owner is the person enrolling, so there is
    // nobody to ask. Every other membership starts as an invitation with
    // `accepted_at` NULL.
    sqlx::query(
        "INSERT INTO organization_members (organization_id, member_id, role, accepted_at) \
         VALUES ($1, $2, 'owner', now())",
    )
    .bind(actor.id)
    .bind(owner_id)
    .execute(&mut *tx)
    .await?;

    // The durable record, in the same transaction as the actor. Separate
    // from `organization_members` because that row goes with the
    // organisation and the rolling-year count must not.
    sqlx::query("INSERT INTO organization_enrolments (owner_id, organization_id) VALUES ($1, $2)")
        .bind(owner_id)
        .bind(actor.id)
        .execute(&mut *tx)
        .await?;

    tx.commit()
        .await
        .map_err(|e| NoombatError::Internal(format!("transaction commit failed: {e}")))?;

    info!(
        organization = %actor.ap_id,
        owner = %owner_id,
        "organisation enrolled"
    );
    // The struct was built before the update above, so returning it
    // unchanged would answer `None` for an organisation that just
    // declared itself.
    Ok(Actor { org_kind, ..actor })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_usernames() {
        assert!(validate_username("alice").is_ok());
        assert!(validate_username("alice_bob").is_ok());
        assert!(validate_username("a123").is_ok());
        assert!(validate_username("a").is_ok());
    }

    #[test]
    fn invalid_usernames() {
        assert!(validate_username("").is_err());
        assert!(validate_username("Alice").is_err());
        assert!(validate_username("1alice").is_err());
        assert!(validate_username("alice-bob").is_err());
        assert!(validate_username("alice.bob").is_err());
        assert!(validate_username(&"a".repeat(31)).is_err());
    }

    #[test]
    fn valid_auth_key() {
        let key = "a".repeat(64);
        assert!(validate_auth_key(&key).is_ok());
    }

    #[test]
    fn invalid_auth_key_length() {
        assert!(validate_auth_key("abcd").is_err());
    }

    #[test]
    fn invalid_auth_key_chars() {
        let key = "g".repeat(64);
        assert!(validate_auth_key(&key).is_err());
    }

    #[test]
    fn argon2_hash_roundtrip() {
        use argon2::password_hash::PasswordVerifier;
        let auth_key = "ab".repeat(32);
        let hash = hash_auth_key(&auth_key).unwrap();
        let parsed = argon2::password_hash::phc::PasswordHash::new(&hash).unwrap();
        assert!(
            Argon2::default()
                .verify_password(auth_key.as_bytes(), &parsed)
                .is_ok()
        );
    }

    // ..... Organisation enrolment ceilings .....

    const DOMAIN: &str = "local.test";

    /// A local person who can enrol organisations.
    async fn seed_owner(pool: &PgPool, username: &str) -> Uuid {
        let keypair = crate::keys::generate_keypair_async().await.unwrap();
        crate::repo::create_actor(
            pool,
            &noombat_core::actor::NewActor {
                actor_type: noombat_core::actor::ActorType::Individual,
                username: username.to_owned(),
                display_name: None,
                domain: DOMAIN.to_owned(),
                public_key_pem: keypair.rsa.public_pem,
                private_key_pem: keypair.rsa.private_pem,
                ed25519_public_key: keypair.ed25519.public_multibase,
                ed25519_private_key: keypair.ed25519.private_base64,
            },
        )
        .await
        .unwrap()
        .id
    }

    async fn set_policy(pool: &PgPool, sql: &'static str) {
        sqlx::query(sql).execute(pool).await.unwrap();
    }

    async fn enrol(pool: &PgPool, owner: Uuid, username: &str) -> Result<Actor> {
        enrol_organization(pool, DOMAIN, owner, username, None, None, None).await
    }

    #[ignore = "requires a database; run with --include-ignored"]
    #[sqlx::test(migrations = "../../migrations")]
    async fn an_administrator_can_pause_organisation_creation(pool: PgPool) {
        let owner = seed_owner(&pool, "alice").await;
        set_policy(
            &pool,
            "UPDATE instance_settings SET organization_creation_enabled = FALSE",
        )
        .await;

        let result = enrol(&pool, owner, "acme").await;

        assert!(
            matches!(result, Err(NoombatError::Forbidden)),
            "a paused instance must refuse enrolment, got {result:?}"
        );
        // The refusal must leave nothing: the gate runs before the actor
        // is created, so a paused instance does not accumulate half-made
        // organisations.
        let orgs = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM actors WHERE actor_type = 'organization'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(orgs, 0, "a refused enrolment wrote an actor");
    }

    #[ignore = "requires a database; run with --include-ignored"]
    #[sqlx::test(migrations = "../../migrations")]
    async fn pausing_organisations_does_not_close_registration(pool: PgPool) {
        // The two switches are independent, which is the whole point of
        // adding a second one. Pausing organisations must leave
        // `registration_mode` alone.
        set_policy(
            &pool,
            "UPDATE instance_settings SET organization_creation_enabled = FALSE",
        )
        .await;

        assert_eq!(
            registration_mode(&pool).await.unwrap(),
            RegistrationMode::Open,
            "pausing organisation creation must not close member registration"
        );
    }

    #[ignore = "requires a database; run with --include-ignored"]
    #[sqlx::test(migrations = "../../migrations")]
    async fn the_rate_limit_holds_a_second_enrolment(pool: PgPool) {
        let owner = seed_owner(&pool, "alice").await;
        set_policy(
            &pool,
            "UPDATE instance_settings SET organization_rate_limit_count = 1, \
             organization_rate_limit_amount = 7, organization_rate_limit_unit = 'days', \
             organization_concurrent_cap = 0, organization_period_cap_count = 0",
        )
        .await;

        enrol(&pool, owner, "acme")
            .await
            .expect("the first is allowed");
        let second = enrol(&pool, owner, "globex").await;

        assert!(
            matches!(second, Err(NoombatError::QuotaExceeded(_))),
            "a second enrolment inside the window must be refused, got {second:?}"
        );
    }

    #[ignore = "requires a database; run with --include-ignored"]
    #[sqlx::test(migrations = "../../migrations")]
    async fn the_rate_limit_lets_go_once_the_window_passes(pool: PgPool) {
        let owner = seed_owner(&pool, "alice").await;
        set_policy(
            &pool,
            "UPDATE instance_settings SET organization_rate_limit_count = 1, \
             organization_rate_limit_amount = 7, organization_rate_limit_unit = 'days', \
             organization_concurrent_cap = 0, organization_period_cap_count = 0",
        )
        .await;

        enrol(&pool, owner, "acme")
            .await
            .expect("the first is allowed");
        // Age the enrolment record rather than sleeping.
        sqlx::query("UPDATE organization_enrolments SET created_at = now() - INTERVAL '8 days'")
            .execute(&pool)
            .await
            .unwrap();

        enrol(&pool, owner, "globex")
            .await
            .expect("the window has passed, so a second enrolment is allowed");
    }

    #[ignore = "requires a database; run with --include-ignored"]
    #[sqlx::test(migrations = "../../migrations")]
    async fn the_concurrent_cap_counts_what_is_held_now(pool: PgPool) {
        let owner = seed_owner(&pool, "alice").await;
        set_policy(
            &pool,
            "UPDATE instance_settings SET organization_rate_limit_count = 0, \
             organization_concurrent_cap = 2, organization_period_cap_count = 0",
        )
        .await;

        let first = enrol(&pool, owner, "acme").await.expect("one");
        enrol(&pool, owner, "globex").await.expect("two");
        let third = enrol(&pool, owner, "initech").await;
        assert!(
            matches!(third, Err(NoombatError::QuotaExceeded(_))),
            "the cap is two, so a third must be refused, got {third:?}"
        );

        // Dissolving one frees a place. `organization_members` cascades
        // from `actors`, so deleting the organisation removes the row the
        // concurrent count reads.
        sqlx::query("DELETE FROM actors WHERE id = $1")
            .bind(first.id)
            .execute(&pool)
            .await
            .unwrap();

        enrol(&pool, owner, "initech")
            .await
            .expect("a place was freed, so this fits");
    }

    #[ignore = "requires a database; run with --include-ignored"]
    #[sqlx::test(migrations = "../../migrations")]
    async fn dissolving_an_organisation_does_not_refund_a_year(pool: PgPool) {
        // The property `organization_enrolments` exists for. If the annual count read
        // `organization_members`, deleting an organisation would hand the
        // year-slot back and the cap would mean nothing.
        let owner = seed_owner(&pool, "alice").await;
        set_policy(
            &pool,
            "UPDATE instance_settings SET organization_rate_limit_count = 0, \
             organization_concurrent_cap = 0, organization_period_cap_count = 2, \
             organization_period_cap_amount = 1, organization_period_cap_unit = 'years'",
        )
        .await;

        let first = enrol(&pool, owner, "acme").await.expect("one");
        enrol(&pool, owner, "globex").await.expect("two");

        sqlx::query("DELETE FROM actors WHERE id = $1")
            .bind(first.id)
            .execute(&pool)
            .await
            .unwrap();

        let third = enrol(&pool, owner, "initech").await;
        assert!(
            matches!(third, Err(NoombatError::QuotaExceeded(_))),
            "the year's count must survive the organisation being dissolved, got {third:?}"
        );
        // The enrolment record survives, with its organisation reference
        // nulled rather than the row cascading away.
        let (rows, orphaned) = sqlx::query_as::<_, (i64, i64)>(
            "SELECT COUNT(*), COUNT(*) FILTER (WHERE organization_id IS NULL) \
             FROM organization_enrolments WHERE owner_id = $1",
        )
        .bind(owner)
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(rows, 2, "both enrolments must still be recorded");
        assert_eq!(
            orphaned, 1,
            "the dissolved organisation's reference is nulled"
        );
    }

    #[ignore = "requires a database; run with --include-ignored"]
    #[sqlx::test(migrations = "../../migrations")]
    async fn a_zero_ceiling_is_no_ceiling(pool: PgPool) {
        let owner = seed_owner(&pool, "alice").await;
        set_policy(
            &pool,
            "UPDATE instance_settings SET organization_rate_limit_count = 0, \
             organization_concurrent_cap = 0, organization_period_cap_count = 0",
        )
        .await;

        for name in ["acme", "globex", "initech", "umbrella"] {
            enrol(&pool, owner, name)
                .await
                .unwrap_or_else(|e| panic!("{name} refused with every ceiling disabled: {e:?}"));
        }
    }

    #[ignore = "requires a database; run with --include-ignored"]
    #[sqlx::test(migrations = "../../migrations")]
    async fn one_owner_reaching_a_ceiling_does_not_block_another(pool: PgPool) {
        // Every ceiling is per owner. A shared counter would make one
        // busy account close enrolment for everybody.
        let alice = seed_owner(&pool, "alice").await;
        let bob = seed_owner(&pool, "bob").await;
        set_policy(
            &pool,
            "UPDATE instance_settings SET organization_rate_limit_count = 0, \
             organization_concurrent_cap = 1, organization_period_cap_count = 0",
        )
        .await;

        enrol(&pool, alice, "acme").await.expect("alice's first");
        assert!(
            matches!(
                enrol(&pool, alice, "globex").await,
                Err(NoombatError::QuotaExceeded(_))
            ),
            "alice is at her cap"
        );
        enrol(&pool, bob, "initech")
            .await
            .expect("bob has his own budget");
    }

    #[ignore = "requires a database; run with --include-ignored"]
    #[sqlx::test(migrations = "../../migrations")]
    async fn the_rate_limit_window_is_the_administrators_to_choose(pool: PgPool) {
        // The point of the unit being configurable. The same policy, "one
        // organisation per window", enforced at an hour instead of a week.
        let owner = seed_owner(&pool, "alice").await;
        set_policy(
            &pool,
            "UPDATE instance_settings SET organization_rate_limit_count = 1, \
             organization_rate_limit_amount = 1, organization_rate_limit_unit = 'hours', \
             organization_concurrent_cap = 0, organization_period_cap_count = 0",
        )
        .await;

        enrol(&pool, owner, "acme")
            .await
            .expect("the first is allowed");
        assert!(
            matches!(
                enrol(&pool, owner, "globex").await,
                Err(NoombatError::QuotaExceeded(_))
            ),
            "a second inside the hour must be refused"
        );

        // Older than an hour, and younger than the week the previous
        // default would have used: only an hour-shaped window lets this in.
        sqlx::query(
            "UPDATE organization_enrolments SET created_at = now() - INTERVAL '90 minutes'",
        )
        .execute(&pool)
        .await
        .unwrap();
        enrol(&pool, owner, "globex")
            .await
            .expect("the hour has passed, so a second enrolment is allowed");
    }

    #[ignore = "requires a database; run with --include-ignored"]
    #[sqlx::test(migrations = "../../migrations")]
    async fn the_period_cap_window_is_the_administrators_to_choose(pool: PgPool) {
        // A month rather than a year, with the same count.
        let owner = seed_owner(&pool, "alice").await;
        set_policy(
            &pool,
            "UPDATE instance_settings SET organization_rate_limit_count = 0, \
             organization_concurrent_cap = 0, organization_period_cap_count = 2, \
             organization_period_cap_amount = 1, organization_period_cap_unit = 'months'",
        )
        .await;

        enrol(&pool, owner, "acme").await.expect("one");
        enrol(&pool, owner, "globex").await.expect("two");
        assert!(
            matches!(
                enrol(&pool, owner, "initech").await,
                Err(NoombatError::QuotaExceeded(_))
            ),
            "two in the month is the cap"
        );

        // Older than a month, younger than a year. A year-shaped window
        // would still refuse.
        sqlx::query("UPDATE organization_enrolments SET created_at = now() - INTERVAL '40 days'")
            .execute(&pool)
            .await
            .unwrap();
        enrol(&pool, owner, "initech")
            .await
            .expect("the month has rolled over");
    }

    #[ignore = "requires a database; run with --include-ignored"]
    #[sqlx::test(migrations = "../../migrations")]
    async fn a_rate_limit_may_allow_more_than_one_per_window(pool: PgPool) {
        // The count is configurable too, so "three a day" is expressible
        // and is not the same policy as "one every eight hours".
        let owner = seed_owner(&pool, "alice").await;
        set_policy(
            &pool,
            "UPDATE instance_settings SET organization_rate_limit_count = 3, \
             organization_rate_limit_amount = 1, organization_rate_limit_unit = 'days', \
             organization_concurrent_cap = 0, organization_period_cap_count = 0",
        )
        .await;

        for name in ["acme", "globex", "initech"] {
            enrol(&pool, owner, name)
                .await
                .unwrap_or_else(|e| panic!("{name}: {e:?}"));
        }
        assert!(
            matches!(
                enrol(&pool, owner, "umbrella").await,
                Err(NoombatError::QuotaExceeded(_))
            ),
            "the fourth in the day must be refused"
        );
    }

    #[ignore = "requires a database; run with --include-ignored"]
    #[sqlx::test(migrations = "../../migrations")]
    async fn an_unreadable_unit_keeps_the_ceiling_rather_than_dropping_it(pool: PgPool) {
        // A unit the code cannot parse is a misconfiguration. Falling back
        // to the default window keeps the ceiling in force; treating it as
        // "no limit" would turn a typo into an open door. The CHECK
        // constraint makes this unreachable through the admin form, so the
        // column is written directly to reach the branch at all.
        let owner = seed_owner(&pool, "alice").await;
        set_policy(
            &pool,
            "ALTER TABLE instance_settings DROP CONSTRAINT \
             instance_settings_organization_rate_limit_unit_check",
        )
        .await;
        set_policy(
            &pool,
            "UPDATE instance_settings SET organization_rate_limit_count = 1, \
             organization_rate_limit_amount = 7, organization_rate_limit_unit = 'fortnights', \
             organization_concurrent_cap = 0, organization_period_cap_count = 0",
        )
        .await;

        enrol(&pool, owner, "acme")
            .await
            .expect("the first is allowed");
        assert!(
            matches!(
                enrol(&pool, owner, "globex").await,
                Err(NoombatError::QuotaExceeded(_))
            ),
            "an unreadable unit must still enforce a window, not disable the ceiling"
        );

        // And the window is the default unit, days, not merely some
        // window. Six days in, `7 fortnights` read as `7 days` still
        // refuses; read as `7 hours` it would not, so this is what tells
        // the two fallbacks apart.
        sqlx::query("UPDATE organization_enrolments SET created_at = now() - INTERVAL '6 days'")
            .execute(&pool)
            .await
            .unwrap();
        assert!(
            matches!(
                enrol(&pool, owner, "globex").await,
                Err(NoombatError::QuotaExceeded(_))
            ),
            "the fallback window must be the default unit"
        );

        sqlx::query("UPDATE organization_enrolments SET created_at = now() - INTERVAL '8 days'")
            .execute(&pool)
            .await
            .unwrap();
        enrol(&pool, owner, "globex")
            .await
            .expect("past the seven-day fallback window");
    }

    #[test]
    fn a_period_reads_as_english() {
        // The refusal message names the window, so it has to be readable.
        assert_eq!(
            Period {
                amount: 1,
                unit: PeriodUnit::Weeks
            }
            .to_string(),
            "week"
        );
        assert_eq!(
            Period {
                amount: 3,
                unit: PeriodUnit::Days
            }
            .to_string(),
            "3 days"
        );
    }

    #[test]
    fn each_unit_sets_exactly_one_interval_argument() {
        // `make_interval` takes five named arguments and the unit picks
        // one. Two non-zero arguments would silently widen the window.
        for unit in [
            PeriodUnit::Hours,
            PeriodUnit::Days,
            PeriodUnit::Weeks,
            PeriodUnit::Months,
            PeriodUnit::Years,
        ] {
            let (y, mo, w, d, h) = Period { amount: 5, unit }.interval_args();
            let set: Vec<i32> = [y, mo, w, d, h].into_iter().filter(|v| *v != 0).collect();
            assert_eq!(set, vec![5], "{unit:?} did not set exactly one argument");
        }
    }

    #[test]
    fn every_unit_the_schema_allows_is_one_the_code_can_read() {
        // The CHECK constraint and `PeriodUnit::parse` are two lists of the
        // same five strings in two files. If they drift, the fallback
        // branch starts firing on a value an administrator legitimately set.
        for unit in ["hours", "days", "weeks", "months", "years"] {
            assert!(
                PeriodUnit::parse(unit).is_some(),
                "{unit} is allowed by the schema but unreadable here"
            );
        }
        assert!(PeriodUnit::parse("fortnights").is_none());
    }
}

// ..... Organisation enrolment .....
