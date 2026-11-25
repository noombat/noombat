// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes

//! An htmx request whose session has ended gets a short message, not the
//! login page.
//!
//! A page handler answers a visitor without a session by redirecting to
//! `/auth/login`. A browser loading a page follows that, as it should.
//! htmx follows it too, inside its own request, and swaps the whole login
//! page into whatever part of the page asked, such as the privacy preview.
//! So for an htmx request the redirect becomes a 401 with
//! the reason as text and a marker header, which the page shows as an
//! alert, as it does a refused write. Done here rather than in each
//! handler, so a handler written later is covered too.

use axum::body::Body;
use axum::http::header::{CONTENT_TYPE, LOCATION};
use axum::http::{Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::i18n::{I18n, negotiate_locale};

/// Marks the 401 an htmx request gets once its session has ended.
pub const SIGNED_OUT_HEADER: &str = "x-signed-out";

const LOGIN: &str = "/auth/login";

/// Turn a redirect to the login page into a 401 with its reason, for an
/// htmx request only.
pub async fn htmx_sign_in(request: Request<Body>, next: Next) -> Response {
    let locale = request
        .headers()
        .contains_key("hx-request")
        .then(|| negotiate_locale(request.headers()));
    let response = next.run(request).await;
    let Some(locale) = locale else {
        return response;
    };
    let to_login = response
        .headers()
        .get(LOCATION)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|to| to == LOGIN || to.starts_with("/auth/login?"));
    if !response.status().is_redirection() || !to_login {
        return response;
    }
    let message = I18n { locale }.t("session_ended_sign_in");
    let marked = [
        (SIGNED_OUT_HEADER, "1"),
        (CONTENT_TYPE.as_str(), "text/plain; charset=utf-8"),
    ];
    (StatusCode::UNAUTHORIZED, marked, message).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::response::Redirect;
    use axum::routing::get;
    use tower::ServiceExt;

    fn app() -> Router {
        Router::new()
            .route("/guarded", get(|| async { Redirect::temporary(LOGIN) }))
            .route("/start", get(|| async { Redirect::to(LOGIN) }))
            .route("/elsewhere", get(|| async { Redirect::temporary("/") }))
            .route("/page", get(|| async { "a fragment" }))
            .layer(axum::middleware::from_fn(htmx_sign_in))
    }

    async fn ask(path: &str, htmx: bool, language: &str) -> Response {
        let mut request = Request::get(path).header("accept-language", language);
        if htmx {
            request = request.header("hx-request", "true");
        }
        app()
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    async fn text(response: Response) -> String {
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 16)
            .await
            .unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn an_htmx_request_without_a_session_gets_the_reason_not_the_login_page() {
        for path in ["/guarded", "/start"] {
            let response = ask(path, true, "pt-BR").await;
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{path}");
            assert_eq!(response.headers()[SIGNED_OUT_HEADER], "1");
            assert!(response.headers().get(LOCATION).is_none());
            let said = I18n {
                locale: "pt-BR".into(),
            }
            .t("session_ended_sign_in");
            assert_eq!(text(response).await, said);
        }
    }

    #[tokio::test]
    async fn a_page_load_still_goes_to_the_login_page() {
        let response = ask("/guarded", false, "en-US").await;
        assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
        assert_eq!(response.headers()[LOCATION], LOGIN);
        assert!(response.headers().get(SIGNED_OUT_HEADER).is_none());
    }

    #[tokio::test]
    async fn other_answers_to_htmx_pass_unchanged() {
        let response = ask("/elsewhere", true, "en-US").await;
        assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
        assert_eq!(response.headers()[LOCATION], "/");
        let response = ask("/page", true, "en-US").await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(text(response).await, "a fragment");
    }
}
