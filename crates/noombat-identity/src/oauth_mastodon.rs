// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! "Sign in with Mastodon" via OAuth 2.0 dynamic client registration.
//!
//! Flow:
//! 1. User enters their Mastodon handle (e.g. `@alice@mastodon.social`).
//! 2. Noombat performs WebFinger: discovers the instance domain.
//! 3. Noombat registers (or reuses a cached) OAuth 2.0 client on that
//!    instance via `POST /api/v1/apps`.
//! 4. The user is redirected to their Mastodon instance to authorise.
//! 5. On callback, Noombat exchanges the code for an access token,
//!    fetches the user's Mastodon profile, and creates or links a
//!    local Noombat account.

use noombat_core::actor::{ActorType, NewActor};
use noombat_core::envelope;
use noombat_core::error::{NoombatError, Result};
use noombat_core::net::is_private_ip;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tracing::info;
use uuid::Uuid;

use crate::keys;

// ..... Data types .....

/// Cached OAuth client credentials for a remote Mastodon instance.
#[derive(Debug)]
#[allow(dead_code)] // Fields deserialised from the database; read by the OAuth flow.
struct OAuthClient {
    client_id: String,
    client_secret: String,
    redirect_uri: String,
}

/// Response from `POST /api/v1/apps` on a Mastodon instance.
#[derive(Debug, Deserialize)]
struct MastodonAppRegistration {
    client_id: String,
    client_secret: String,
    redirect_uri: String,
}

/// Response from `POST /oauth/token` on a Mastodon instance.
#[derive(Debug, Deserialize)]
struct MastodonTokenResponse {
    access_token: String,
}

/// Response from `GET /api/v1/accounts/verify_credentials`.
#[derive(Debug, Deserialize)]
struct MastodonAccount {
    /// The account name. For local users this is just the username
    /// (e.g. `"alice"`); for remote users it includes the domain
    /// (e.g. `"alice@other.social"`). The `handle_callback` function
    /// always appends the instance domain, so both cases produce a
    /// fully-qualified identifier.
    acct: String,
    display_name: Option<String>,
}

/// The result of a successful Mastodon OAuth callback.
#[derive(Debug, Serialize)]
pub struct MastodonAuthResult {
    pub actor_id: Uuid,
    pub username: String,
    pub is_new: bool,
}

// ..... WebFinger discovery .....

/// Extract the instance domain from a Mastodon handle.
///
/// Accepts `@user@domain`, `user@domain`, or a bare `domain`.
pub fn parse_mastodon_handle(handle: &str) -> Result<(String, String)> {
    let handle = handle.trim().trim_start_matches('@');
    let parts: Vec<&str> = handle.splitn(2, '@').collect();
    match parts.as_slice() {
        [user, domain] if !user.is_empty() && !domain.is_empty() => {
            Ok(((*user).to_owned(), (*domain).to_owned()))
        }
        _ => Err(NoombatError::BadRequest(
            "handle must be in the form @user@domain or user@domain".into(),
        )),
    }
}

/// Discover the Mastodon instance URL via WebFinger.
///
/// Returns the instance base URL (e.g. `https://mastodon.social`).
///
/// The domain is resolved to IP addresses via [`tokio::net::lookup_host`]
/// and each address is checked against private, loopback, and link-local
/// ranges before issuing an HTTP request. This prevents SSRF attacks
/// where a user-controlled domain resolves to an internal network address.
async fn discover_instance(domain: &str) -> Result<String> {
    // Resolve the domain to IP addresses and reject private ranges
    // to prevent SSRF.
    let addr_str = format!("{domain}:443");
    let addrs: Vec<std::net::SocketAddr> = tokio::net::lookup_host(&addr_str)
        .await
        .map_err(|e| NoombatError::Federation(format!("DNS resolution failed for {domain}: {e}")))?
        .collect();

    if addrs.is_empty() {
        return Err(NoombatError::Federation(format!(
            "DNS resolution returned no addresses for {domain}"
        )));
    }

    for addr in &addrs {
        if is_private_ip(addr.ip()) {
            return Err(NoombatError::BadRequest(format!(
                "domain {domain} resolves to a private/reserved IP address"
            )));
        }
    }

    // Pin the validated address to a purpose-built client so that a
    // DNS rebinding attack between resolution and connection cannot
    // redirect to an internal address.
    //
    // `reqwest::RequestBuilder` does not support per-request DNS
    // overrides, so a new `Client` is constructed. The user-agent
    // and timeout are replicated from the shared client constructed
    // in `main.rs`. If those defaults change, this block must be
    // updated to match.
    let resolved_addr = addrs[0];
    let pinned_client = reqwest::Client::builder()
        .user_agent(format!("Noombat/{}", env!("CARGO_PKG_VERSION")))
        .timeout(std::time::Duration::from_secs(30))
        .resolve(domain, resolved_addr)
        .build()
        .map_err(|e| NoombatError::Internal(format!("failed to build pinned HTTP client: {e}")))?;
    let base = format!("https://{domain}");
    let webfinger_url = format!("{base}/.well-known/webfinger?resource=acct:test@{domain}");
    let resp = pinned_client
        .get(&webfinger_url)
        .send()
        .await
        .map_err(|e| NoombatError::Federation(format!("instance discovery failed: {e}")))?;

    if resp.status().is_server_error() {
        return Err(NoombatError::Federation(format!(
            "instance {domain} returned {}",
            resp.status()
        )));
    }

    Ok(base)
}

// ..... Client registration .....

/// Retrieve a cached OAuth client for the given instance domain, or
/// register a new one via `POST /api/v1/apps`.
async fn get_or_register_client(
    pool: &PgPool,
    http_client: &reqwest::Client,
    instance_domain: &str,
    instance_base: &str,
    our_domain: &str,
) -> Result<OAuthClient> {
    // Check the cache first.
    if let Some(row) = sqlx::query_as::<_, (String, String, String)>(
        "SELECT client_id, client_secret, redirect_uri FROM oauth_clients WHERE instance_domain = $1",
    )
    .bind(instance_domain)
    .fetch_optional(pool)
    .await?
    {
        return Ok(OAuthClient {
            client_id: row.0,
            client_secret: envelope::open_auto(&row.1)?,
            redirect_uri: row.2,
        });
    }

    // Register a new client.
    let redirect_uri = format!("https://{our_domain}/api/v1/auth/mastodon/callback");

    let resp = http_client
        .post(format!("{instance_base}/api/v1/apps"))
        .form(&[
            ("client_name", "Noombat"),
            ("redirect_uris", redirect_uri.as_str()),
            ("scopes", "read:accounts"),
            ("website", &format!("https://{our_domain}")),
        ])
        .send()
        .await
        .map_err(|e| NoombatError::Federation(format!("client registration failed: {e}")))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(NoombatError::Federation(format!(
            "client registration on {instance_domain} returned {status}: {body}"
        )));
    }

    let app: MastodonAppRegistration = resp.json().await.map_err(|e| {
        NoombatError::Federation(format!("malformed app registration response: {e}"))
    })?;

    // Cache the client credentials (encrypt the secret at rest).
    let sealed_secret = envelope::seal_auto(&app.client_secret)?;
    sqlx::query(
        r#"INSERT INTO oauth_clients (instance_domain, client_id, client_secret, redirect_uri)
           VALUES ($1, $2, $3, $4)
           ON CONFLICT (instance_domain)
           DO UPDATE SET client_id = $2, client_secret = $3, redirect_uri = $4"#,
    )
    .bind(instance_domain)
    .bind(&app.client_id)
    .bind(&sealed_secret)
    .bind(&app.redirect_uri)
    .execute(pool)
    .await?;

    info!(instance = %instance_domain, "OAuth client registered");

    Ok(OAuthClient {
        client_id: app.client_id,
        client_secret: app.client_secret,
        redirect_uri: app.redirect_uri,
    })
}

// ..... Public interface .....

/// Build the authorisation URL to redirect the user to their Mastodon
/// instance.
///
/// Returns `(authorise_url, state_token)`. The caller must store the
/// state token in the `oauth_states` table for CSRF validation.
pub async fn build_authorise_url(
    pool: &PgPool,
    http_client: &reqwest::Client,
    handle: &str,
    our_domain: &str,
) -> Result<(String, String)> {
    let (_user, instance_domain) = parse_mastodon_handle(handle)?;
    let instance_base = discover_instance(&instance_domain).await?;
    let client = get_or_register_client(
        pool,
        http_client,
        &instance_domain,
        &instance_base,
        our_domain,
    )
    .await?;

    let state = crate::oauth_util::generate_state_token();

    // Persist the OAuth state for CSRF validation on callback.
    let expires = chrono::Utc::now() + chrono::Duration::minutes(10);
    sqlx::query(
        r#"INSERT INTO oauth_states (state, provider, instance_domain, expires_at)
           VALUES ($1, 'mastodon', $2, $3)"#,
    )
    .bind(&state)
    .bind(&instance_domain)
    .bind(expires)
    .execute(pool)
    .await?;

    let url = format!(
        "{instance_base}/oauth/authorize?client_id={}&redirect_uri={}&response_type=code&scope=read:accounts&state={state}",
        crate::oauth_util::urlencoding(&client.client_id),
        crate::oauth_util::urlencoding(&client.redirect_uri),
    );

    Ok((url, state))
}

/// Handle the OAuth callback from a Mastodon instance.
///
/// Exchanges the authorisation code for an access token, fetches the
/// user's Mastodon profile, and creates or links a local Noombat
/// account.
pub async fn handle_callback(
    pool: &PgPool,
    http_client: &reqwest::Client,
    our_domain: &str,
    code: &str,
    state: &str,
) -> Result<MastodonAuthResult> {
    // Validate and consume the OAuth state.
    let row = sqlx::query_as::<_, (String,)>(
        r#"DELETE FROM oauth_states
           WHERE state = $1 AND provider = 'mastodon' AND expires_at > now()
           RETURNING instance_domain"#,
    )
    .bind(state)
    .fetch_optional(pool)
    .await?
    .ok_or(NoombatError::Forbidden)?;

    let instance_domain = row.0;
    let instance_base = format!("https://{instance_domain}");

    let client = sqlx::query_as::<_, (String, String, String)>(
        "SELECT client_id, client_secret, redirect_uri FROM oauth_clients WHERE instance_domain = $1",
    )
    .bind(&instance_domain)
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| NoombatError::Internal("OAuth client not found after state validation".into()))?;

    let decrypted_secret = envelope::open_auto(&client.1)?;

    // Exchange the code for an access token.
    let token_resp = http_client
        .post(format!("{instance_base}/oauth/token"))
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("client_id", &client.0),
            ("client_secret", &decrypted_secret),
            ("redirect_uri", &client.2),
            ("scope", "read:accounts"),
        ])
        .send()
        .await
        .map_err(|e| NoombatError::Federation(format!("token exchange failed: {e}")))?;

    if !token_resp.status().is_success() {
        let status = token_resp.status();
        let body = token_resp.text().await.unwrap_or_default();
        return Err(NoombatError::Federation(format!(
            "token exchange on {instance_domain} returned {status}: {body}"
        )));
    }

    let token: MastodonTokenResponse = token_resp
        .json()
        .await
        .map_err(|e| NoombatError::Federation(format!("malformed token response: {e}")))?;

    // Fetch the user's Mastodon profile.
    let profile_resp = http_client
        .get(format!(
            "{instance_base}/api/v1/accounts/verify_credentials"
        ))
        .bearer_auth(&token.access_token)
        .send()
        .await
        .map_err(|e| NoombatError::Federation(format!("profile fetch failed: {e}")))?;

    let account: MastodonAccount = profile_resp
        .json()
        .await
        .map_err(|e| NoombatError::Federation(format!("malformed profile response: {e}")))?;

    // Derive a local username from the Mastodon account. Replace
    // characters not valid in Noombat usernames.
    let remote_acct = format!("{}@{}", account.acct, instance_domain);

    // Check whether a local actor already exists for this Mastodon
    // account (linked via the `oauth_identities` table).
    let existing = sqlx::query_as::<_, (Uuid, String)>(
        r#"SELECT a.id, a.username FROM actors a
           JOIN oauth_identities oi ON oi.actor_id = a.id
           WHERE oi.provider = 'mastodon'
             AND oi.external_id = $1
             AND a.is_local = TRUE"#,
    )
    .bind(&remote_acct)
    .fetch_optional(pool)
    .await?;

    if let Some((actor_id, username)) = existing {
        return Ok(MastodonAuthResult {
            actor_id,
            username,
            is_new: false,
        });
    }

    // Create a new local actor.
    let local_username = derive_username(&account.acct, &instance_domain);

    // Ensure uniqueness by appending a numeric suffix if needed.
    let final_username =
        crate::oauth_util::ensure_unique_username(pool, &local_username, our_domain).await?;

    let keypair = keys::generate_keypair_async().await?;

    let new_actor = NewActor {
        actor_type: ActorType::Individual,
        username: final_username.clone(),
        display_name: account.display_name.filter(|s| !s.is_empty()),
        domain: our_domain.to_owned(),
        public_key_pem: keypair.rsa.public_pem,
        private_key_pem: keypair.rsa.private_pem,
        ed25519_public_key: keypair.ed25519.public_multibase,
        ed25519_private_key: keypair.ed25519.private_base64,
    };

    let actor = crate::repo::create_actor(pool, &new_actor).await?;

    // Record the OAuth identity linkage.
    sqlx::query(
        r#"INSERT INTO oauth_identities (actor_id, provider, external_id)
           VALUES ($1, 'mastodon', $2)"#,
    )
    .bind(actor.id)
    .bind(&remote_acct)
    .execute(pool)
    .await?;

    info!(
        username = %final_username,
        mastodon_acct = %remote_acct,
        "Mastodon OAuth account created"
    );

    Ok(MastodonAuthResult {
        actor_id: actor.id,
        username: final_username,
        is_new: true,
    })
}

// ..... Helpers .....

/// Derive a Noombat-compatible username from a Mastodon account.
fn derive_username(acct: &str, instance_domain: &str) -> String {
    // Take the local part and sanitise: lowercase, ASCII letters,
    // digits, and underscores only.
    let base: String = acct
        .split('@')
        .next()
        .unwrap_or(acct)
        .to_lowercase()
        .chars()
        .filter(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == '_')
        .collect();

    let base = if base.is_empty() || !base.starts_with(|c: char| c.is_ascii_lowercase()) {
        format!("m_{base}")
    } else {
        base
    };

    // Truncate to 24 characters to leave room for a numeric suffix.
    let truncated: String = base.chars().take(24).collect();

    // Append a short domain discriminator to reduce collisions.
    let domain_short: String = instance_domain
        .split('.')
        .next()
        .unwrap_or("fedi")
        .chars()
        .filter(|c| c.is_ascii_lowercase())
        .take(4)
        .collect();

    format!("{truncated}_{domain_short}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_handle_with_leading_at() {
        let (user, domain) = parse_mastodon_handle("@alice@mastodon.social").unwrap();
        assert_eq!(user, "alice");
        assert_eq!(domain, "mastodon.social");
    }

    #[test]
    fn parse_handle_without_leading_at() {
        let (user, domain) = parse_mastodon_handle("alice@mastodon.social").unwrap();
        assert_eq!(user, "alice");
        assert_eq!(domain, "mastodon.social");
    }

    #[test]
    fn parse_handle_invalid() {
        assert!(parse_mastodon_handle("alice").is_err());
        assert!(parse_mastodon_handle("@alice").is_err());
        assert!(parse_mastodon_handle("").is_err());
    }

    #[test]
    fn derive_username_basic() {
        let u = derive_username("Alice", "mastodon.social");
        assert!(u.starts_with("alice_mast"));
        assert!(u.len() <= 30);
    }

    #[test]
    fn derive_username_numeric_start() {
        let u = derive_username("123test", "example.org");
        assert!(u.starts_with("m_123test"));
    }

    // ..... is_private_ip / is_private_v4 .....

    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn rejects_ipv4_loopback() {
        assert!(is_private_ip(IpAddr::V4(Ipv4Addr::LOCALHOST)));
    }

    #[test]
    fn rejects_ipv4_private() {
        assert!(is_private_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(is_private_ip(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))));
        assert!(is_private_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
    }

    #[test]
    fn rejects_ipv4_link_local() {
        assert!(is_private_ip(IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1))));
    }

    #[test]
    fn rejects_ipv4_documentation() {
        assert!(is_private_ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))));
        assert!(is_private_ip(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1))));
        assert!(is_private_ip(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1))));
    }

    #[test]
    fn rejects_ipv4_cgn() {
        assert!(is_private_ip(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))));
        assert!(is_private_ip(IpAddr::V4(Ipv4Addr::new(100, 127, 255, 254))));
        // 100.128.0.1 is outside 100.64/10.
        assert!(!is_private_ip(IpAddr::V4(Ipv4Addr::new(100, 128, 0, 1))));
    }

    #[test]
    fn accepts_public_ipv4() {
        assert!(!is_private_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert!(!is_private_ip(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
        assert!(!is_private_ip(IpAddr::V4(Ipv4Addr::new(93, 184, 215, 14))));
    }

    #[test]
    fn rejects_ipv6_loopback() {
        assert!(is_private_ip(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }

    #[test]
    fn rejects_ipv6_ula() {
        assert!(is_private_ip(IpAddr::V6(Ipv6Addr::new(
            0xfc00, 0, 0, 0, 0, 0, 0, 1
        ))));
        assert!(is_private_ip(IpAddr::V6(Ipv6Addr::new(
            0xfd12, 0x3456, 0, 0, 0, 0, 0, 1
        ))));
    }

    #[test]
    fn rejects_ipv6_link_local() {
        assert!(is_private_ip(IpAddr::V6(Ipv6Addr::new(
            0xfe80, 0, 0, 0, 0, 0, 0, 1
        ))));
        // fe80:0001::1 is within fe80::/10.
        assert!(is_private_ip(IpAddr::V6(Ipv6Addr::new(
            0xfe80, 1, 0, 0, 0, 0, 0, 1
        ))));
        // febf::1 is the last address in fe80::/10.
        assert!(is_private_ip(IpAddr::V6(Ipv6Addr::new(
            0xfebf, 0, 0, 0, 0, 0, 0, 1
        ))));
        // fec0::1 is outside fe80::/10.
        assert!(!is_private_ip(IpAddr::V6(Ipv6Addr::new(
            0xfec0, 0, 0, 0, 0, 0, 0, 1
        ))));
    }

    #[test]
    fn rejects_ipv4_mapped_ipv6_loopback() {
        // ::ffff:127.0.0.1
        assert!(is_private_ip(IpAddr::V6(Ipv6Addr::new(
            0, 0, 0, 0, 0, 0xffff, 0x7f00, 0x0001
        ))));
    }

    #[test]
    fn rejects_ipv4_mapped_ipv6_documentation() {
        // ::ffff:192.0.2.1
        assert!(is_private_ip(IpAddr::V6(Ipv6Addr::new(
            0, 0, 0, 0, 0, 0xffff, 0xc000, 0x0201
        ))));
    }

    #[test]
    fn rejects_ipv4_mapped_ipv6_cgn() {
        // ::ffff:100.64.0.1
        assert!(is_private_ip(IpAddr::V6(Ipv6Addr::new(
            0, 0, 0, 0, 0, 0xffff, 0x6440, 0x0001
        ))));
    }

    #[test]
    fn accepts_public_ipv6() {
        assert!(!is_private_ip(IpAddr::V6(Ipv6Addr::new(
            0x2001, 0xdb8, 0, 0, 0, 0, 0, 1
        ))));
        assert!(!is_private_ip(IpAddr::V6(Ipv6Addr::new(
            0x2606, 0x4700, 0, 0, 0, 0, 0, 0x1111
        ))));
    }
}
