// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! TOTP two-factor authentication (RFC 6238).
//!
//! Enrolment generates a secret and returns a `otpauth://` URI for
//! rendering as a QR code. Verification checks the submitted code
//! against the stored secret with a +/- 1 time step tolerance.

use noombat_core::error::{NoombatError, Result};
use serde::Serialize;
use sqlx::PgPool;
use totp_rs::{Algorithm, Secret, TOTP};
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
    let secret = Secret::generate_secret();
    let secret_base32 = secret.to_encoded().to_string();

    let totp = build_totp(&secret_base32, username, issuer)?;
    let otpauth_uri = totp.get_url();

    // Upsert: replace any prior unverified secret.
    sqlx::query(
        r#"INSERT INTO totp_secrets (actor_id, secret, verified)
           VALUES ($1, $2, FALSE)
           ON CONFLICT (actor_id)
           DO UPDATE SET secret = $2, verified = FALSE, created_at = now()"#,
    )
    .bind(actor_id)
    .bind(&secret_base32)
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

    let (secret_base32, verified) = row;

    // Build the TOTP with a placeholder account name (not needed for
    // code validation).
    let totp = build_totp(&secret_base32, "user", "noombat")?;

    let valid = totp
        .check_current(code)
        .map_err(|e| NoombatError::Internal(format!("TOTP system time error: {e}")))?;

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

/// Construct a [`TOTP`] instance from a base32 secret.
fn build_totp(secret_base32: &str, account_name: &str, issuer: &str) -> Result<TOTP> {
    let secret_bytes = Secret::Encoded(secret_base32.to_owned())
        .to_bytes()
        .map_err(|e| NoombatError::Internal(format!("invalid TOTP secret: {e}")))?;

    TOTP::new(
        Algorithm::SHA1,
        6,  // digits
        1,  // skew (+/- 1 time step)
        30, // step (seconds)
        secret_bytes,
        Some(issuer.to_owned()),
        account_name.to_owned(),
    )
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
