// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! TOTP two-factor authentication (RFC 6238).
//!
//! Enrolment generates a secret and returns a `otpauth://` URI for
//! rendering as a QR code. Verification checks the submitted code
//! against the stored secret with a +/- 1 time step tolerance.

use noombat_core::envelope;
use noombat_core::error::{NoombatError, Result};
use serde::Serialize;
use sqlx::PgPool;
use totp_rs::{Algorithm, Builder, Secret, Totp};
use uuid::Uuid;

/// Response body for TOTP enrolment initiation.
#[derive(Debug, Serialize)]
pub struct TotpEnrolment {
    /// The `otpauth://` URI for QR code generation.
    pub otpauth_uri: String,
    /// The base32-encoded secret (for manual entry).
    pub secret_base32: String,
}

/// Begin TOTP enrolment for the given actor.
///
/// If the actor already has a verified TOTP secret, this returns an
/// error. If a prior unverified secret exists, it is replaced.
pub async fn enrol_totp(
    pool: &PgPool,
    actor_id: Uuid,
    username: &str,
    issuer: &str,
) -> Result<TotpEnrolment> {
    // Generate a new secret.
    let secret = Secret::generate();
    let secret_base32 = secret.to_base32();

    let totp = build_totp(&secret_base32, username, issuer)?;
    let otpauth_uri = totp
        .to_url()
        .map_err(|e| NoombatError::Internal(format!("TOTP URL construction failed: {e}")))?;

    // Encrypt the secret before writing to the database.
    let sealed_secret = envelope::seal_auto(&secret_base32)?;

    // Replace an unverified secret, never a verified one: one statement, so
    // a set-up racing a verification cannot switch two-factor off.
    let stored = sqlx::query(
        r#"INSERT INTO totp_secrets (actor_id, secret, verified)
           VALUES ($1, $2, FALSE)
           ON CONFLICT (actor_id)
           DO UPDATE SET secret = $2, verified = FALSE, created_at = now()
           WHERE totp_secrets.verified = FALSE"#,
    )
    .bind(actor_id)
    .bind(&sealed_secret)
    .execute(pool)
    .await?;
    if stored.rows_affected() == 0 {
        return Err(NoombatError::BadRequest(
            "TOTP is already enrolled; disable it first".into(),
        ));
    }

    Ok(TotpEnrolment {
        otpauth_uri,
        secret_base32,
    })
}

/// The enrolment an unverified secret stands for, if the actor has one:
/// what the TOTP page shows, read without writing, so loading the page
/// changes nothing.
pub async fn pending_totp(
    pool: &PgPool,
    actor_id: Uuid,
    username: &str,
    issuer: &str,
) -> Result<Option<TotpEnrolment>> {
    let sealed: Option<String> = sqlx::query_scalar(
        "SELECT secret FROM totp_secrets WHERE actor_id = $1 AND verified = FALSE",
    )
    .bind(actor_id)
    .fetch_optional(pool)
    .await?;
    let Some(sealed) = sealed else {
        return Ok(None);
    };

    let secret_base32 = envelope::open_auto(&sealed)?;
    let otpauth_uri = build_totp(&secret_base32, username, issuer)?
        .to_url()
        .map_err(|e| NoombatError::Internal(format!("TOTP URL construction failed: {e}")))?;
    Ok(Some(TotpEnrolment {
        otpauth_uri,
        secret_base32,
    }))
}

/// Verify a TOTP code during enrolment (marks the secret as verified)
/// or during login (validates only).
///
/// Accepts the current code and +/- 1 adjacent time step.
pub async fn verify_totp(pool: &PgPool, actor_id: Uuid, code: &str) -> Result<()> {
    let row = sqlx::query_as::<_, (String, bool)>(
        "SELECT secret, verified FROM totp_secrets WHERE actor_id = $1",
    )
    .bind(actor_id)
    .fetch_optional(pool)
    .await?
    .ok_or(NoombatError::Forbidden)?;

    let (sealed_secret, verified) = row;

    // Decrypt the secret from the database.
    let secret_base32 = envelope::open_auto(&sealed_secret)?;

    // Build the TOTP with a placeholder account name (not needed for
    // code validation).
    let totp = build_totp(&secret_base32, "user", "noombat")?;

    // `Some` carries the matching timestep, which nothing here needs.
    let valid = totp.check_current(code).is_some();

    if !valid {
        return Err(NoombatError::Forbidden);
    }

    // If this is the first successful verification (enrolment),
    // mark the secret as verified.
    if !verified {
        mark_verified(pool, actor_id, &sealed_secret).await?;
    }

    Ok(())
}

/// Mark `sealed_secret` verified, if it is still the member's. Refused if
/// a set-up since the code was checked against it has put a new secret in
/// its place, which the member's authenticator does not hold.
async fn mark_verified(pool: &PgPool, actor_id: Uuid, sealed_secret: &str) -> Result<()> {
    let marked =
        sqlx::query("UPDATE totp_secrets SET verified = TRUE WHERE actor_id = $1 AND secret = $2")
            .bind(actor_id)
            .bind(sealed_secret)
            .execute(pool)
            .await?;
    if marked.rows_affected() == 1 {
        Ok(())
    } else {
        Err(NoombatError::Forbidden)
    }
}

/// Disable (remove) TOTP for the given actor.
pub async fn disable_totp(pool: &PgPool, actor_id: Uuid) -> Result<()> {
    sqlx::query("DELETE FROM totp_secrets WHERE actor_id = $1")
        .bind(actor_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Construct a [`Totp`] instance from a base32 secret.
///
/// The parameters match what was issued before, so an authenticator
/// enrolled against an earlier release keeps working.
fn build_totp(secret_base32: &str, account_name: &str, issuer: &str) -> Result<Totp> {
    let secret = Secret::try_from_base32(secret_base32)
        .map_err(|e| NoombatError::Internal(format!("invalid TOTP secret: {e}")))?;

    Builder::new()
        .with_algorithm(Algorithm::SHA1)
        .with_digits(6)
        .with_skew(1)
        .with_step_duration(30)
        .with_secret(secret)
        .with_issuer(Some(issuer))
        .with_account_name(account_name)
        .build()
        .map_err(|e| NoombatError::Internal(format!("TOTP construction failed: {e}")))
}

/// Render an `otpauth://` URI as an SVG QR code and return a
/// `data:image/svg+xml;base64,...` URI suitable for `<img src>`.
pub fn otpauth_to_qr_data_uri(otpauth_uri: &str) -> Result<String> {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as B64;
    use qrcode::QrCode;
    use qrcode::render::svg;

    let code = QrCode::new(otpauth_uri.as_bytes())
        .map_err(|e| NoombatError::Internal(format!("QR code generation failed: {e}")))?;

    let svg_string = code
        .render::<svg::Color>()
        .min_dimensions(200, 200)
        .quiet_zone(true)
        .build();

    let b64 = B64.encode(svg_string.as_bytes());
    Ok(format!("data:image/svg+xml;base64,{b64}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    // The RFC 6238 test secret, ASCII "12345678901234567890" in base32.
    // Its published codes pin the algorithm, the digit count and the step
    // together: an authenticator enrolled against an earlier release
    // stops working if any of the three moves.
    const RFC6238_SECRET_BASE32: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    #[test]
    fn the_rfc6238_vectors_still_produce_the_documented_codes() {
        let totp =
            build_totp(RFC6238_SECRET_BASE32, "alice", "noombat").expect("the secret should build");

        // The published values are eight digits; this instance issues six.
        for (time, expected) in [
            (59_u64, "287082"),
            (1_111_111_109, "081804"),
            (1_234_567_890, "005924"),
        ] {
            assert_eq!(totp.generate(time).to_string(), expected, "at t={time}");
        }
    }

    #[test]
    fn a_code_this_instance_issues_is_one_it_accepts() {
        let totp = build_totp(RFC6238_SECRET_BASE32, "alice", "noombat").expect("build");

        let code = totp.generate_current().to_string();

        assert!(totp.check_current(&code).is_some());
    }

    #[test]
    fn a_secret_that_is_not_base32_is_rejected_rather_than_panicking() {
        assert!(build_totp("not base32!", "alice", "noombat").is_err());
    }

    /// A set-up between a verification's read and its update leaves the
    /// new secret unverified: the code was checked against the old one.
    #[ignore = "requires a database; run with --include-ignored"]
    #[sqlx::test(migrations = "../../migrations")]
    async fn verification_marks_only_the_secret_it_checked(pool: PgPool) {
        use noombat_core::actor::{ActorType, NewActor};
        let keypair = crate::keys::generate_keypair_async().await.unwrap();
        let actor = crate::repo::create_actor(
            &pool,
            &NewActor {
                actor_type: ActorType::Individual,
                username: "alice".to_owned(),
                display_name: None,
                domain: "local.test".to_owned(),
                public_key_pem: keypair.rsa.public_pem,
                private_key_pem: keypair.rsa.private_pem,
                ed25519_public_key: keypair.ed25519.public_multibase,
                ed25519_private_key: keypair.ed25519.private_base64,
            },
        )
        .await
        .unwrap();
        let sealed = || async {
            sqlx::query_scalar::<_, String>("SELECT secret FROM totp_secrets WHERE actor_id = $1")
                .bind(actor.id)
                .fetch_one(&pool)
                .await
                .unwrap()
        };

        enrol_totp(&pool, actor.id, "alice", "local.test")
            .await
            .unwrap();
        let checked = sealed().await;
        enrol_totp(&pool, actor.id, "alice", "local.test")
            .await
            .unwrap();
        let replacing = sealed().await;
        assert_ne!(
            checked, replacing,
            "a second set-up must replace the secret"
        );

        let stale = mark_verified(&pool, actor.id, &checked).await;
        let verified_after_stale: bool =
            sqlx::query_scalar("SELECT verified FROM totp_secrets WHERE actor_id = $1")
                .bind(actor.id)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(
            matches!(stale, Err(NoombatError::Forbidden)) && !verified_after_stale,
            "the secret a set-up replaced must be refused, leaving the new one unverified"
        );
        assert!(mark_verified(&pool, actor.id, &replacing).await.is_ok());
    }
}
