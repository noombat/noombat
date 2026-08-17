// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Server-rendered Markdown preview.
//!
//! - `POST /api/v1/preview`  render Markdown exactly as the persist path does
//!
//! The point is not convenience: it is that there is one Markdown
//! engine. The preview an author reads before publishing is produced by
//! the same function that produces the bytes that get stored and
//! federated, so the two cannot disagree about a document that cannot be
//! recalled once it federates.
//!
//! The session requirement and the input cap below are conditions of
//! that design rather than decoration: this endpoint runs a parser over
//! attacker-supplied input on demand.

use axum::extract::State;
use axum::response::Html;
use axum::routing::post;
use axum::{Form, Router};
use noombat_core::error::NoombatError;
use serde::Deserialize;

use crate::error::ApiError;
use crate::middleware::Principal;
use crate::state::AppState;

/// Largest source accepted for preview, in bytes.
///
/// Generous next to any plausible post and small enough that rendering
/// stays cheap. The persist path applies its own limits; this one exists
/// so that a preview cannot be used to spend more server time than
/// publishing would.
const MAX_SOURCE_BYTES: usize = 64 * 1024;

pub fn router() -> Router<AppState> {
    Router::new().route("/api/v1/preview", post(preview))
}

#[derive(Deserialize)]
pub struct PreviewRequest {
    /// The raw Markdown source.
    content: String,
    /// Whether to render as an Article rather than a Note.
    ///
    /// This selects the same `MarkupOptions` the outbox handler selects
    /// from `is_article`, and it must stay in step with it: Articles use
    /// the strict sanitisation profile and get heading anchors, Notes
    /// get neither. A preview rendered in the wrong mode is exactly the
    /// class of divergence this endpoint exists to remove.
    #[serde(default)]
    article: bool,
}

/// `POST /api/v1/preview`
///
/// Renders Markdown and returns a sanitised HTML fragment.
async fn preview(
    State(_state): State<AppState>,
    principal: Option<axum::Extension<Principal>>,
    Form(request): Form<PreviewRequest>,
) -> Result<Html<String>, ApiError> {
    // A session is required. Without it this is an anonymous endpoint
    // that runs a parser on demand for anyone who asks.
    if principal
        .as_ref()
        .and_then(|principal| principal.actor_id())
        .is_none()
    {
        return Err(ApiError(NoombatError::Forbidden));
    }

    if request.content.len() > MAX_SOURCE_BYTES {
        return Err(ApiError(NoombatError::BadRequest(format!(
            "preview source exceeds {MAX_SOURCE_BYTES} bytes"
        ))));
    }

    Ok(Html(
        render_preview(request.content, request.article).await?,
    ))
}

/// Render preview HTML through the persist path's own options.
///
/// Extracted so the parity test can call exactly what the handler calls
/// without going through the router, and so there is one place where
/// the options are chosen.
pub(crate) async fn render_preview(source: String, article: bool) -> Result<String, ApiError> {
    let options = noombat_markup::MarkupOptions {
        strict_sanitisation: article,
        inject_heading_ids: article,
    };

    Ok(noombat_markup::render_async_with_options(source, options)
        .await?
        .html)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The preview and the persist path render identically.
    ///
    /// With both sides calling one function this is close to a
    /// tautology, which is the point: it fails when a later change gives
    /// one call site different options, a different sanitiser profile,
    /// or a post-processing step the other does not have.
    ///
    /// The corpus must stay sensitive to BOTH `MarkupOptions` fields or
    /// a call site that sets the wrong one passes unnoticed: the styled
    /// span is what `strict_sanitisation` strips, and the heading is
    /// what `inject_heading_ids` anchors. Without those two every
    /// fixture renders identically in both modes and the assertion
    /// proves nothing, as a mutation test found.
    #[tokio::test]
    async fn preview_matches_the_persist_path() {
        const FIXTURES: &[&str] = &[
            "plain text",
            "visit https://example.org for details",
            "\"quoted\" and -- dashed ... elided",
            "# A heading\n\nwith body text",
            r#"<span style="background-image:url(https://evil.example/t)">tracked</span>"#,
            "tagged #Rust and #ActivityPub",
            "cites 10.1000/182 inline",
            "maths $E = mc^2$ inline",
            "$$\\sum_{i=1}^{n} i$$",
            "*emphasis*, **strong**, `code`, ~~struck~~",
            "- [ ] a task\n- [x] a done task",
        ];

        for source in FIXTURES {
            for article in [false, true] {
                let options = noombat_markup::MarkupOptions {
                    strict_sanitisation: article,
                    inject_heading_ids: article,
                };
                let persisted =
                    noombat_markup::render_async_with_options((*source).to_owned(), options)
                        .await
                        .expect("persist path renders")
                        .html;

                // `ApiError` has no `Debug`, so unwrap it by hand.
                let Ok(previewed) = render_preview((*source).to_owned(), article).await else {
                    panic!("preview failed to render {source:?}");
                };

                assert_eq!(
                    previewed, persisted,
                    "preview and persist diverged for {source:?} (article = {article})"
                );
            }
        }
    }
}
