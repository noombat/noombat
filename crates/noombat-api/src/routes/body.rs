// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! One extractor for the two ways a body reaches this application.

use axum::extract::{FromRequest, Request};
use axum::http::header::CONTENT_TYPE;
use axum::response::{IntoResponse, Response};
use axum::{Form, Json};
use serde::de::DeserializeOwned;

/// A body sent either as JSON or as an HTML form.
///
/// The API speaks JSON and the pages are server-rendered forms, and some
/// routes are reached both ways: the compose page posts to the same
/// outbox route an API client does. `Json` alone answers 415 to a plain
/// `<form method="post">`, which is a page that silently cannot submit,
/// so the content type decides the parser rather than the request being
/// refused for having the wrong one.
///
/// Anything that is not a form is parsed as JSON, so a client sending no
/// content type at all still reaches the JSON path, which is the one the
/// API contract describes.
pub struct JsonOrForm<T> {
    pub value: T,
    /// True when the body arrived as an HTML form. A handler serving
    /// both reads this to decide between redirecting a browser and
    /// answering an API client with a document, since a form submit that
    /// renders raw JSON is a page that appears to have failed.
    pub from_form: bool,
}

impl<S, T> FromRequest<S> for JsonOrForm<T>
where
    S: Send + Sync,
    T: DeserializeOwned + Send + 'static,
{
    type Rejection = Response;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let from_form = req
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            // The header carries parameters (`; charset=utf-8`), so this
            // is a prefix test rather than an equality one.
            .is_some_and(|value| value.starts_with("application/x-www-form-urlencoded"));

        if from_form {
            let Form(value) = Form::<T>::from_request(req, state)
                .await
                .map_err(IntoResponse::into_response)?;
            return Ok(Self {
                value,
                from_form: true,
            });
        }

        let Json(value) = Json::<T>::from_request(req, state)
            .await
            .map_err(IntoResponse::into_response)?;
        Ok(Self {
            value,
            from_form: false,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request as HttpRequest;

    #[derive(serde::Deserialize, Debug, PartialEq, Eq)]
    struct Sample {
        content: String,
        title: Option<String>,
    }

    async fn extract(content_type: Option<&str>, body: &'static str) -> Option<(Sample, bool)> {
        let mut builder = HttpRequest::builder().method("POST").uri("/");
        if let Some(ct) = content_type {
            builder = builder.header(CONTENT_TYPE, ct);
        }
        let req = builder.body(Body::from(body)).unwrap();
        JsonOrForm::<Sample>::from_request(req, &())
            .await
            .ok()
            .map(|parsed| (parsed.value, parsed.from_form))
    }

    #[tokio::test]
    async fn a_form_body_is_parsed_as_a_form() {
        let got = extract(
            Some("application/x-www-form-urlencoded"),
            "content=hello&title=Post",
        )
        .await;
        assert_eq!(
            got,
            Some((
                Sample {
                    content: "hello".to_owned(),
                    title: Some("Post".to_owned()),
                },
                true
            ))
        );
    }

    /// The charset the browser appends must not send the body to the
    /// JSON parser, which is what an equality test on the header would do.
    #[tokio::test]
    async fn a_form_body_with_a_charset_is_still_a_form() {
        let got = extract(
            Some("application/x-www-form-urlencoded; charset=UTF-8"),
            "content=hello",
        )
        .await;
        assert_eq!(
            got,
            Some((
                Sample {
                    content: "hello".to_owned(),
                    title: None,
                },
                true
            ))
        );
    }

    #[tokio::test]
    async fn a_json_body_is_parsed_as_json() {
        let got = extract(Some("application/json"), r#"{"content":"hello"}"#).await;
        assert_eq!(
            got,
            Some((
                Sample {
                    content: "hello".to_owned(),
                    title: None,
                },
                false
            ))
        );
    }

    /// A form body announced as JSON is a mistake, not a second chance:
    /// accepting it would mean guessing at the parser, and a guess that
    /// is sometimes right is worse than a refusal.
    #[tokio::test]
    async fn a_form_body_announced_as_json_is_refused() {
        assert_eq!(
            extract(Some("application/json"), "content=hello").await,
            None
        );
    }
}
