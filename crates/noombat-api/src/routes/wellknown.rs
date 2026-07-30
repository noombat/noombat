// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Well-known endpoints supporting external integrity monitoring.
//!
//! Noombat performs its cryptography in the browser, using JavaScript
//! this server delivers. That places the operator inside the trust
//! boundary: serving one modified script to one user on one page load
//! is sufficient to recover plaintext, and nothing in the transport or
//! the published source detects it.
//!
//! The manifest served here does not close that gap. It narrows it, by
//! letting anyone (the user, or a third-party monitor polling many
//! instances) compare the assets an instance actually serves against
//! hashes attested to at release time.
//!
//! The authoritative copy of those hashes is the Sigstore-signed
//! artefact attached to the GitHub release, **not** this endpoint. A
//! server willing to serve modified assets is equally willing to serve
//! a manifest describing them. This endpoint is a convenience for
//! monitors, and is only meaningful when checked against the signed
//! release. See `docs/verifying-builds.md`.

use std::sync::OnceLock;

use axum::Router;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;

use crate::state::AppState;

/// Location of the manifest emitted beside the built assets.
///
/// Relative to the working directory.
const MANIFEST_PATH: &str = "frontend/dist/assets-manifest.json";

/// Manifest contents, read once. `None` when the file is absent,
/// which is the normal state for a development checkout that has not
/// run `scripts/asset-manifest.sh`.
static MANIFEST: OnceLock<Option<String>> = OnceLock::new();

pub fn router() -> Router<AppState> {
    Router::new().route("/.well-known/noombat/assets.json", get(assets_manifest))
}

/// `GET /.well-known/noombat/assets.json`
///
/// Returns the asset manifest for the running build, or `404 Not
/// Found` when the deployment was built without one.
async fn assets_manifest() -> Response {
    // Read at most once for the process lifetime. The file is a few
    // kilobytes, so the single blocking read on the first request is
    // not worth moving to a worker thread.
    let manifest = MANIFEST.get_or_init(|| std::fs::read_to_string(MANIFEST_PATH).ok());

    match manifest {
        Some(body) => (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, "application/json"),
                // Monitors poll; the manifest changes only on deploy.
                (header::CACHE_CONTROL, "public, max-age=300"),
            ],
            body.clone(),
        )
            .into_response(),
        None => (
            StatusCode::NOT_FOUND,
            "asset manifest not available for this deployment",
        )
            .into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_path_sits_beside_the_served_assets() {
        // build_router serves /assets from frontend/dist/assets, so the
        // manifest must be resolvable from the same working directory.
        assert!(MANIFEST_PATH.starts_with("frontend/dist/"));
        assert!(MANIFEST_PATH.ends_with(".json"));
    }
}
