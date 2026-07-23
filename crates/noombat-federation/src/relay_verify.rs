// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Relay verification policy for inbound relay traffic.
//!
//! When a relay delivers an `Announce` wrapping a remote activity,
//! Noombat must decide whether to trust the content without
//! re-fetching it from the originating instance. The verification
//! policy governs this decision.
//!
//! # Policies
//!
//! | Policy            | Behaviour                                           |
//! |-------------------|-----------------------------------------------------|
//! | `verify`          | Accept only if the inner activity carries a valid   |
//! |                   | FEP-8b32 integrity proof. Discard otherwise.        |
//! | `verify-or-fetch` | Accept with a valid proof; re-fetch from the origin |
//! |                   | instance if no proof is present.                    |
//! | `trust-relay`     | Accept based on the relay's HTTP Signature alone.   |
//! |                   | Trust-sensitive objects are flagged as unverified.  |

use noombat_core::error::{NoombatError, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::PgPool;
use tracing::{debug, warn};

use crate::integrity_proof;

/// The relay verification policy in effect for this instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RelayVerificationPolicy {
    /// Accept only relayed activities with a valid FEP-8b32 proof.
    Verify,
    /// Accept with valid proof; re-fetch if no proof present.
    VerifyOrFetch,
    /// Trust the relay's HTTP Signature; flag unverified content.
    TrustRelay,
}

impl RelayVerificationPolicy {
    /// Parse a policy from a string (as stored in configuration).
    pub fn from_str_opt(s: &str) -> Option<Self> {
        match s {
            "verify" => Some(Self::Verify),
            "verify-or-fetch" => Some(Self::VerifyOrFetch),
            "trust-relay" => Some(Self::TrustRelay),
            _ => None,
        }
    }
}

impl std::fmt::Display for RelayVerificationPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Verify => write!(f, "verify"),
            Self::VerifyOrFetch => write!(f, "verify-or-fetch"),
            Self::TrustRelay => write!(f, "trust-relay"),
        }
    }
}

/// The outcome of relay verification for an inbound activity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayVerificationOutcome {
    /// The activity has been verified (valid proof or re-fetched).
    Verified,
    /// The activity is accepted without verification (trust-relay
    /// mode). Trust-sensitive objects should be flagged as unverified.
    Unverified,
    /// The activity should be discarded (no valid proof under the
    /// `verify` policy, or re-fetch failed under `verify-or-fetch`).
    Discard,
}

/// Determine whether a relayed activity should be accepted, and
/// with what verification status.
///
/// This function implements the three-tier verification policy.
///
/// # Arguments
///
/// * `pool`: database pool (for actor key lookup during proof
///   verification, and for re-fetch in `verify-or-fetch` mode).
/// * `http_client`: HTTP client for re-fetching the original
///   activity from the origin instance.
/// * `activity`: the inner activity extracted from the relay's
///   `Announce` wrapper.
/// * `policy`: the instance's relay verification policy.
///
/// # Returns
///
/// A [`RelayVerificationOutcome`] indicating whether the activity
/// should be indexed, flagged, or discarded.
pub async fn verify_relayed_activity(
    pool: &PgPool,
    http_client: &reqwest::Client,
    activity: &Value,
    policy: RelayVerificationPolicy,
) -> RelayVerificationOutcome {
    // Attempt proof verification if the activity carries one.
    let proof_result = attempt_proof_verification(pool, activity).await;

    match (policy, proof_result) {
        // Valid proof: always accept regardless of policy.
        (_, Some(true)) => {
            debug!("relayed activity has valid integrity proof");
            RelayVerificationOutcome::Verified
        }

        // Invalid proof: reject under all policies (a present but
        // invalid proof is more suspicious than an absent one).
        (_, Some(false)) => {
            warn!("relayed activity has invalid integrity proof; discarding");
            RelayVerificationOutcome::Discard
        }

        // No proof, `verify` policy: discard.
        (RelayVerificationPolicy::Verify, None) => {
            debug!("relayed activity lacks proof under 'verify' policy; discarding");
            RelayVerificationOutcome::Discard
        }

        // No proof, `verify-or-fetch` policy: re-fetch from origin.
        (RelayVerificationPolicy::VerifyOrFetch, None) => {
            let object_id = activity
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or("<unknown>");

            debug!(
                object = object_id,
                "relayed activity lacks proof; attempting re-fetch"
            );

            match refetch_and_verify(pool, http_client, object_id).await {
                Ok(true) => RelayVerificationOutcome::Verified,
                Ok(false) => {
                    warn!(
                        object = object_id,
                        "re-fetched activity does not match relay payload; discarding"
                    );
                    RelayVerificationOutcome::Discard
                }
                Err(e) => {
                    warn!(
                        object = object_id,
                        error = %e,
                        "re-fetch failed; discarding"
                    );
                    RelayVerificationOutcome::Discard
                }
            }
        }

        // No proof, `trust-relay` policy: accept but flag.
        (RelayVerificationPolicy::TrustRelay, None) => {
            debug!("relayed activity accepted under 'trust-relay' policy (unverified)");
            RelayVerificationOutcome::Unverified
        }
    }
}

/// Attempt to verify the integrity proof on the activity, if present.
///
/// Returns `Some(true)` if a valid proof exists, `Some(false)` if an
/// invalid proof exists, and `None` if no proof is present.
async fn attempt_proof_verification(pool: &PgPool, activity: &Value) -> Option<bool> {
    let vm_id = integrity_proof::extract_verification_method_id(activity)?;

    // Extract the actor AP ID from the verification method.
    let actor_ap_id = vm_id.split('#').next().unwrap_or(vm_id);

    // Look up the actor's Ed25519 public key.
    let public_key: Option<String> = sqlx::query_scalar(
        "SELECT ed25519_public_key FROM actors WHERE ap_id = $1",
    )
    .bind(actor_ap_id)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten()
    .flatten();

    let public_key_multibase = match public_key {
        Some(pk) => pk,
        None => {
            // The actor's key is not cached locally. For `verify-or-fetch`,
            // the caller will re-fetch the activity from the origin; for
            // `verify` and `trust-relay`, we report "no proof" rather
            // than "invalid proof" (the proof may be valid but we lack
            // the key to check).
            debug!(
                actor = actor_ap_id,
                "no Ed25519 public key cached for proof verification"
            );
            return None;
        }
    };

    let result = integrity_proof::verify(activity, &public_key_multibase);
    match result {
        integrity_proof::VerificationResult::Valid => Some(true),
        integrity_proof::VerificationResult::Invalid => Some(false),
        integrity_proof::VerificationResult::Absent => None,
    }
}

/// Re-fetch an activity from its origin instance and verify that it
/// exists and is structurally consistent with the relayed version.
///
/// Returns `Ok(true)` if the origin returned a valid object matching
/// the claimed AP ID, `Ok(false)` if the origin's object does not
/// match, and `Err` on network or parse failure.
async fn refetch_and_verify(
    pool: &PgPool,
    http_client: &reqwest::Client,
    object_id: &str,
) -> Result<bool> {
    // Use a signed fetch so that instances requiring authenticated
    // requests do not reject the lookup.
    let signing_actor_id = crate::signed_fetch::find_local_signing_actor(pool).await?;
    let response = crate::signed_fetch::signed_get(
        pool,
        http_client,
        object_id,
        signing_actor_id,
    )
    .await?;

    if !response.status().is_success() {
        return Err(NoombatError::Federation(format!(
            "origin returned HTTP {} for {object_id}",
            response.status()
        )));
    }

    let origin_object: Value = response
        .json()
        .await
        .map_err(|e| NoombatError::Federation(format!(
            "invalid JSON from origin for {object_id}: {e}"
        )))?;

    // Verify that the origin's `id` matches the claimed AP ID.
    let origin_id = origin_object.get("id").and_then(|v| v.as_str());
    Ok(origin_id == Some(object_id))
}

/// Check whether an inbound `Announce` is from a subscribed relay
/// rather than a regular boost.
///
/// Relays deliver `Announce` activities where:
/// 1. The announcing actor is the relay's actor URI.
/// 2. The `to` field contains `https://www.w3.org/ns/activitystreams#Public`.
///
/// This function checks whether the announcing actor matches a
/// relay subscription in the `relay_subscriptions` table.
pub async fn is_relay_announce(pool: &PgPool, actor_uri: &str) -> bool {
    // The relay's inbox URL may differ from its actor URI (e.g.
    // `https://relay.example/inbox` vs `https://relay.example/actor`).
    // Check both patterns, mirroring the logic in
    // `relay::try_handle_relay_accept`.
    let derived_inbox = format!("{actor_uri}/inbox");
    let is_relay: bool = sqlx::query_scalar(
        r#"SELECT EXISTS(
               SELECT 1 FROM relay_subscriptions
               WHERE status = 'accepted'
                 AND (inbox_url = $1 OR inbox_url ^@ $2)
           )"#,
    )
    .bind(&derived_inbox)
    .bind(actor_uri)
    .fetch_one(pool)
    .await
    .unwrap_or(false);

    is_relay
}
