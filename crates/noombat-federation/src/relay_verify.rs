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

use std::sync::LazyLock;
use std::time::Duration;

use noombat_core::error::{NoombatError, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::PgPool;
use tokio::sync::Semaphore;
use tracing::{debug, warn};

use crate::integrity_proof;
use crate::integrity_proof::VerificationResult;

/// Origin fetches allowed to be in flight at once, across both paths that
/// reach out to another instance during verification: the
/// `verify-or-fetch` re-fetch, and the key refresh in
/// [`verify_inbound_proof`].
///
/// Both are driven by inbound traffic, so both are burst-shaped and both
/// let a sender influence our target. Uncapped, that makes Noombat an
/// amplifier: the sender picks the victim and the burst size, and we
/// supply the connections. One counter covers both because the resource
/// being protected, outbound sockets aimed at a third party, is the same.
static ORIGIN_FETCH_PERMITS: LazyLock<Semaphore> = LazyLock::new(|| Semaphore::new(4));

/// How long a fetch waits for a permit before giving up.
///
/// Waiting beats failing (a discarded activity is lost content), but not
/// indefinitely: a queue with no bound is the same resource exhaustion one
/// layer down. Exceeding this is treated as a fetch failure, which both
/// callers already handle.
const ORIGIN_FETCH_PERMIT_TIMEOUT: Duration = Duration::from_secs(10);

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

/// Verify the FEP-8b32 proof on a directly delivered document.
///
/// This is the ingestion-time counterpart to [`verify_relayed_activity`].
/// There is no policy argument because direct delivery has no policy to
/// apply: the HTTP Signature is already bound to `activity.actor`, so an
/// absent proof is normal rather than suspicious. What the proof adds is
/// evidence that survives redistribution, which is what a Group or a
/// relay forwarding this document onward will rely on.
///
/// # The author binding is the whole point
///
/// `expected_author` is the actor the caller is about to attribute this
/// document to. The proof must be signed by *that* actor. Without the
/// check, a valid signature proves only "somebody whose key we happen to
/// have cached signed these bytes", which is not authorship: sign an
/// object `attributedTo: alice` with bob's key, name bob's verification
/// method, and the row lands attributed to alice carrying a `TRUE`. This
/// is the same binding [`crate::inbox::process_activity`] applies to the
/// HTTP Signature signer, for the same reason.
///
/// The check runs *before* the key lookup, so naming an actor we have
/// never heard of is `Invalid` (a proof we were not meant to be able to
/// check) rather than `Absent` (nothing to check). Otherwise a sender
/// could switch verification off by pointing `verificationMethod` at an
/// unknown URI, which would silently turn the discard below into a store.
///
/// # Return value
///
/// The tri-state stored in `integrity_proof_verified`:
///
/// - [`VerificationResult::Absent`]: no proof, or a proof from the right
///   actor whose key we do not hold and could not fetch. Not the same as
///   a bad proof and must not be recorded as one.
/// - [`VerificationResult::Valid`]: verified against the document exactly
///   as received.
/// - [`VerificationResult::Invalid`]: a proof that did not verify, or one
///   signed by somebody other than `expected_author`. Callers discard.
///
/// The document passed here must be the bytes as received. JCS hashes
/// every property that was present, so a value round-tripped through a
/// type that drops unknown properties will not verify.
pub async fn verify_inbound_proof(
    pool: &PgPool,
    http_client: &reqwest::Client,
    document: &Value,
    expected_author: &str,
) -> VerificationResult {
    let vm_id = match integrity_proof::extract_verification_method_id(document) {
        Some(vm) => vm.to_owned(),
        None => return VerificationResult::Absent,
    };
    let signer = vm_id.split('#').next().unwrap_or(&vm_id);

    if !crate::inbox::same_actor_uri(signer, expected_author) {
        warn!(
            signer,
            expected_author, "integrity proof is signed by an actor other than the author"
        );
        return VerificationResult::Invalid;
    }

    let cached = cached_assertion_key(pool, signer).await;

    if let Some(ref key) = cached {
        match integrity_proof::verify(document, key) {
            integrity_proof::VerificationResult::Valid => return VerificationResult::Valid,
            integrity_proof::VerificationResult::Absent => return VerificationResult::Absent,
            // Fall through: the cached key may simply be stale.
            integrity_proof::VerificationResult::Invalid => {}
        }
    }

    // One bounded refresh before calling it a forgery.
    //
    // A cached key can be wrong without anybody misbehaving: the peer
    // rotated, or published several keys and we stored the first. Treating
    // that as an invalid proof would return `Forbidden` from the inbox,
    // and the only path that refreshes a cached key is an `Update` that
    // has to pass through the same gate, so the peer would be locked out
    // permanently with no way back. Holding the wrong key is the same
    // epistemic state as holding no key, and this module already refuses
    // to call that a bad proof.
    //
    // The fetch targets `expected_author`, which the caller has already
    // resolved, so this reaches no host the request was not going to
    // reach anyway. It is capped by [`ORIGIN_FETCH_PERMITS`] regardless.
    let refreshed = crate::inbox::refresh_assertion_key(pool, http_client, signer, &vm_id).await;

    match refreshed {
        Some(key) if Some(&key) != cached.as_ref() => match integrity_proof::verify(document, &key)
        {
            integrity_proof::VerificationResult::Valid => VerificationResult::Valid,
            integrity_proof::VerificationResult::Absent => VerificationResult::Absent,
            integrity_proof::VerificationResult::Invalid => VerificationResult::Invalid,
        },
        // Nothing new to try. If we never had a key at all, we still have
        // not checked anything, so this is `Absent` rather than a verdict.
        _ => {
            if cached.is_none() {
                VerificationResult::Absent
            } else {
                VerificationResult::Invalid
            }
        }
    }
}

/// The Ed25519 key cached for an actor, if any.
async fn cached_assertion_key(pool: &PgPool, actor_ap_id: &str) -> Option<String> {
    sqlx::query_scalar::<_, Option<String>>(
        "SELECT ed25519_public_key FROM actors WHERE ap_id = $1",
    )
    .bind(actor_ap_id)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten()
    .flatten()
}

/// Acquire an outbound-fetch permit, or `None` if the wait ran out.
///
/// Exposed to [`crate::inbox`] so the key refresh shares one counter with
/// the relay re-fetch. See [`ORIGIN_FETCH_PERMITS`].
pub(crate) async fn origin_fetch_permit() -> Option<tokio::sync::SemaphorePermit<'static>> {
    match tokio::time::timeout(ORIGIN_FETCH_PERMIT_TIMEOUT, ORIGIN_FETCH_PERMITS.acquire()).await {
        Ok(Ok(permit)) => Some(permit),
        _ => None,
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
    let public_key: Option<String> =
        sqlx::query_scalar("SELECT ed25519_public_key FROM actors WHERE ap_id = $1")
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
    // Held for the whole fetch, so the cap counts requests in flight
    // rather than requests started. See [`ORIGIN_FETCH_PERMITS`].
    let _permit =
        match tokio::time::timeout(ORIGIN_FETCH_PERMIT_TIMEOUT, ORIGIN_FETCH_PERMITS.acquire())
            .await
        {
            Ok(Ok(permit)) => permit,
            Ok(Err(e)) => {
                return Err(NoombatError::Internal(format!(
                    "re-fetch semaphore closed: {e}"
                )));
            }
            Err(_) => {
                return Err(NoombatError::Federation(format!(
                    "re-fetch of {object_id} gave up waiting for a concurrency permit"
                )));
            }
        };

    // Use a signed fetch so that instances requiring authenticated
    // requests do not reject the lookup.
    let signing_actor_id = crate::signed_fetch::find_local_signing_actor(pool).await?;
    let response =
        crate::signed_fetch::signed_get(pool, http_client, object_id, signing_actor_id).await?;

    if !response.status().is_success() {
        return Err(NoombatError::Federation(format!(
            "origin returned HTTP {} for {object_id}",
            response.status()
        )));
    }

    let origin_object: Value = response.json().await.map_err(|e| {
        NoombatError::Federation(format!("invalid JSON from origin for {object_id}: {e}"))
    })?;

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
