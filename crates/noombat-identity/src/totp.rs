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
    // Reject if a verified secret already exists.
    let verified = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM totp_secrets WHERE actor_id = $1 AND verified = TRUE)",
    )
    .bind(actor_id)
    .fetch_one(pool)
    .await
    .unwrap_or(false);

    if verified {
        return Err(NoombatError::BadRequest(
            "TOTP is already enrolled; disable it first".into(),
        ));
    }

    // Generate a new secret.
    let secret = Secret::generate();
    let secret_base32 = secret.to_base32();

    let totp = build_totp(&secret_base32, username, issuer)?;
    let otpauth_uri = totp
        .to_url()
        .map_err(|e| NoombatError::Internal(format!("TOTP URL construction failed: {e}")))?;

    // Encrypt the secret before writing to the database.
    let sealed_secret = envelope::seal_auto(&secret_base32)?;

    // Upsert: replace any prior unverified secret.
    sqlx::query(
        r#"INSERT INTO totp_secrets (actor_id, secret, verified)
           VALUES ($1, $2, FALSE)
           ON CONFLICT (actor_id)
           DO UPDATE SET secret = $2, verified = FALSE, created_at = now()"#,
    )
    .bind(actor_id)
    .bind(&sealed_secret)
    .execute(pool)
    .await?;

    Ok(TotpEnrolment {
        otpauth_uri,
        secret_base32,
    })
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
        sqlx::query("UPDATE totp_secrets SET verified = TRUE WHERE actor_id = $1")
            .bind(actor_id)
            .execute(pool)
            .await?;
    }

    Ok(())
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
}
