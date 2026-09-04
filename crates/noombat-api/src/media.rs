// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Gabriel Henrique Lopes Gomes Alves Nunes
//! Uploaded media: validation, re-encoding, and where the bytes rest.
//!
//! Two rules shape everything here, and both are about the reader rather
//! than the uploader.
//!
//! **The browser talks to this application, never to the storage.** A
//! backend is where bytes rest, not an origin the reader connects to.
//! Serving media through the application keeps one request log, under
//! the operator's control, and keeps access rules applicable to media
//! after the fact. Presigned URLs, single-use or not, give the object
//! store a per-viewer record of who looked at whom and cannot be
//! recalled once issued.
//!
//! **Nothing an uploader supplies is trusted, including the bytes.** The
//! format is decided by decoding, never by the filename or the declared
//! content type. The image is re-encoded rather than passed through,
//! which is what removes EXIF, and EXIF is where the coordinates of the
//! photograph live. A professional network serving unmodified phone
//! photographs publishes the home addresses of people who took a picture
//! indoors.

use std::path::{Path, PathBuf};

use image::ImageFormat;
use uuid::Uuid;

/// The largest upload accepted, before decoding.
///
/// Enforced twice: as a body limit on the route, so an oversized request
/// is refused without being read, and again on the extracted field,
/// because a multipart body can carry several parts under one limit.
pub const MAX_UPLOAD_BYTES: usize = 4 * 1024 * 1024;

/// The longest edge an avatar is stored at.
///
/// Larger uploads are scaled down rather than refused: a phone camera
/// produces several thousand pixels, and refusing that would reject the
/// most common case for no benefit. The bound exists because the decoded
/// pixel buffer, not the file, is what a decode bomb inflates.
pub const AVATAR_MAX_EDGE: u32 = 512;

/// The longest edge a post attachment is stored at.
///
/// Larger than an avatar because an attachment is looked at rather than
/// glanced at: a photograph in a post is the content, where an avatar is
/// a 96-pixel circle beside a name. Still bounded, for the same reason
/// the avatar is.
pub const ATTACHMENT_MAX_EDGE: u32 = 1600;

/// Components the BlurHash carries on each axis.
///
/// Four by three is what Mastodon uses, and the hash is a wire format
/// other implementations decode, so matching it means a peer renders the
/// same placeholder this instance does. More components means a sharper
/// blur and a longer string, which defeats the point: this is meant to
/// be small enough to sit inside the document.
const BLURHASH_COMPONENTS: (u32, u32) = (4, 3);

/// The size the hash is computed from.
///
/// The output is a handful of frequency components, so computing it from
/// the full image costs time and changes nothing. Downscaling first is
/// what keeps a 1600-pixel attachment from being read pixel by pixel.
const BLURHASH_SAMPLE_EDGE: u32 = 64;

/// The largest decoded pixel count accepted.
///
/// A few hundred kilobytes of PNG can declare dimensions that decode to
/// gigabytes. The dimensions are read from the header and checked before
/// any pixel buffer is allocated.
pub const MAX_PIXELS: u64 = 50_000_000;

/// The two formats this instance accepts and serves.
///
/// A closed list, matching the `media_type` check constraint on
/// `media_attachments`. A block list cannot see the format nobody
/// thought of; a closed list can only be widened deliberately.
///
/// JPEG XL is the format worth wanting here and is deliberately absent:
/// see the `image` dependency comment in the workspace manifest.
pub const ACCEPTED: [&str; 2] = ["image/jpeg", "image/png"];

/// Why an upload was refused.
///
/// Each variant maps to a message the uploader can act on. Nothing here
/// carries the decoder's own error text: that describes a file the
/// uploader cannot inspect and would only confuse.
#[derive(Debug, PartialEq, Eq)]
pub enum MediaError {
    TooLarge,
    UnsupportedFormat,
    TooManyPixels,
    Undecodable,
}

/// An image that has been decoded, bounded, and re-encoded.
#[derive(Debug)]
pub struct ProcessedImage {
    pub bytes: Vec<u8>,
    /// One of [`ACCEPTED`], decided by decoding rather than by any claim
    /// the uploader made.
    pub media_type: &'static str,
    /// The BlurHash of the stored image, for an attachment. `None` for
    /// an avatar, which is never shown blurred: a profile picture is not
    /// sensitive media, and Mastodon computes none for one either.
    pub blurhash: Option<String>,
}

/// Decide the format from the content, bound it, and re-encode it.
///
/// The output format matches the input: a PNG stays a PNG because it may
/// carry transparency that JPEG cannot represent, and a JPEG stays a
/// JPEG because re-encoding it as PNG would multiply its size.
pub fn process_avatar(raw: &[u8]) -> Result<ProcessedImage, MediaError> {
    process(raw, AVATAR_MAX_EDGE, false)
}

/// The same pipeline for an image attached to a post.
///
/// Two differences from an avatar, and both are about what the image is
/// for. It is bounded larger, because it is the content rather than a
/// thumbnail beside a name. And it carries a BlurHash, because a post
/// can be marked sensitive and an avatar cannot.
pub fn process_attachment(raw: &[u8]) -> Result<ProcessedImage, MediaError> {
    process(raw, ATTACHMENT_MAX_EDGE, true)
}

/// Validate, bound and re-encode, optionally computing a BlurHash.
///
/// Shared so that an attachment cannot drift from an avatar on the parts
/// that are about safety rather than presentation: the format is decided
/// by decoding, the pixel count is bounded before allocation, and the
/// bytes are re-encoded rather than passed through, which is what strips
/// the EXIF that carries where a photograph was taken.
fn process(raw: &[u8], max_edge: u32, want_blurhash: bool) -> Result<ProcessedImage, MediaError> {
    if raw.len() > MAX_UPLOAD_BYTES {
        return Err(MediaError::TooLarge);
    }

    // From the bytes. `guess_format` reads magic numbers, so a `.png`
    // holding a JPEG, or holding something that is not an image at all,
    // is decided correctly here rather than trusted.
    let format = image::guess_format(raw).map_err(|_| MediaError::UnsupportedFormat)?;
    let media_type = match format {
        ImageFormat::Jpeg => "image/jpeg",
        ImageFormat::Png => "image/png",
        _ => return Err(MediaError::UnsupportedFormat),
    };

    // Dimensions before pixels. `ImageReader` reads the header only, so
    // a file declaring an enormous canvas is refused before anything
    // allocates on its behalf.
    let reader = image::ImageReader::with_format(std::io::Cursor::new(raw), format);
    let (width, height) = reader
        .into_dimensions()
        .map_err(|_| MediaError::Undecodable)?;
    if u64::from(width) * u64::from(height) > MAX_PIXELS {
        return Err(MediaError::TooManyPixels);
    }

    let decoded =
        image::load_from_memory_with_format(raw, format).map_err(|_| MediaError::Undecodable)?;

    // Only when it exceeds the bound. `thumbnail` preserves the aspect
    // ratio but scales *to* the box in both directions, so a 16 by 16
    // avatar would come back 512 by 512: upscaled, blurry, and larger
    // than what was uploaded. Measured, not assumed; the test below
    // failed on the first version of this line.
    let bounded = if decoded.width() > max_edge || decoded.height() > max_edge {
        decoded.thumbnail(max_edge, max_edge)
    } else {
        decoded
    };

    // From the bounded image, so the hash describes what readers are
    // actually served rather than what was uploaded.
    let blurhash = want_blurhash.then(|| encode_blurhash(&bounded));

    let mut bytes = Vec::new();
    bounded
        .write_to(&mut std::io::Cursor::new(&mut bytes), format)
        .map_err(|_| MediaError::Undecodable)?;

    Ok(ProcessedImage {
        bytes,
        media_type,
        blurhash,
    })
}

/// The BlurHash of an image, as the string peers exchange.
///
/// Downscaled first, and to RGBA8 because that is the buffer layout the
/// encoder reads. A failure returns an empty string rather than an
/// error: the hash is a nicety, and refusing an upload because a
/// placeholder could not be computed would trade the image for the blur.
fn encode_blurhash(image: &image::DynamicImage) -> String {
    let sample = image.thumbnail(BLURHASH_SAMPLE_EDGE, BLURHASH_SAMPLE_EDGE);
    let rgba = sample.to_rgba8();
    let (components_x, components_y) = BLURHASH_COMPONENTS;
    blurhash::encode(
        components_x,
        components_y,
        rgba.width(),
        rgba.height(),
        rgba.as_raw(),
    )
    .unwrap_or_default()
}

/// The edge length the placeholder is decoded at.
///
/// The hash carries a handful of frequency components, so decoding it
/// larger produces the same picture in more bytes. Thirty-two pixels
/// stretched over the image's box is what the format is for, and it
/// keeps the data URI small enough to sit inline in the page.
const PLACEHOLDER_EDGE: u32 = 32;

/// A BlurHash rendered as an inline PNG, ready for `img src`.
///
/// Inline rather than a URL, for the reason the blur exists: a
/// placeholder served from `/media/{key}` would be a second request that
/// says which sensitive image the reader is about to be shown, and the
/// real image is not fetched until they ask for it.
///
/// `None` for a hash that is absent or does not decode, which the caller
/// renders as a plain panel. A stored hash can predate this code or come
/// from a peer, so failing to decode one is an ordinary case rather than
/// an error.
pub fn blurhash_placeholder(hash: &str) -> Option<String> {
    if hash.is_empty() {
        return None;
    }

    let pixels = blurhash::decode(hash, PLACEHOLDER_EDGE, PLACEHOLDER_EDGE, 1.0).ok()?;
    let buffer: image::RgbaImage =
        image::ImageBuffer::from_raw(PLACEHOLDER_EDGE, PLACEHOLDER_EDGE, pixels)?;

    let mut png = Vec::new();
    buffer
        .write_to(&mut std::io::Cursor::new(&mut png), ImageFormat::Png)
        .ok()?;

    use base64::Engine as _;
    let encoded = base64::engine::general_purpose::STANDARD.encode(&png);
    Some(format!("data:image/png;base64,{encoded}"))
}

/// A fresh object key.
///
/// Random, and derived from nothing. Not the username, which would let
/// anyone enumerate the instance's accounts by requesting keys; not a
/// content hash, which would let anyone test whether a given photograph
/// is in use here; not a sequence, which would date every account.
pub fn new_object_key() -> String {
    Uuid::new_v4().simple().to_string()
}

/// The object keys a post's attachments occupy.
///
/// Read before the post is deleted, because `media_attachments.post_id`
/// cascades: once the post is gone the rows are gone, and the only
/// record of which objects belonged to it has gone with them.
pub async fn post_object_keys(pool: &sqlx::PgPool, post_id: Uuid) -> Vec<String> {
    sqlx::query_scalar("SELECT object_key FROM media_attachments WHERE post_id = $1")
        .bind(post_id)
        .fetch_all(pool)
        .await
        .unwrap_or_default()
}

/// Remove the objects behind keys collected by [`post_object_keys`].
///
/// Called after the post is deleted, so nothing can serve an object
/// whose bytes have already gone. A failure is reported rather than
/// swallowed: it is the state where the database says the post is gone
/// and the disk disagrees.
pub async fn purge_objects(media: &MediaStore, keys: &[String]) {
    for key in keys {
        if let Err(error) = media.delete(key).await {
            tracing::error!(
                %error,
                object_key = %key,
                "a deleted post's image could not be removed"
            );
        }
    }
}

/// Where uploaded media rests.
///
/// Every row records which backend wrote it, so turning object storage
/// on cannot orphan what was written while it was local.
///
/// Which backend an instance uses appears in no response, header or
/// NodeInfo field: it is not a capability a peer needs, and publishing
/// it names a provider to attack.
#[derive(Clone)]
pub enum MediaStore {
    Local {
        root: PathBuf,
    },
    S3 {
        client: reqwest::Client,
        /// Base URL of the endpoint, without the bucket.
        endpoint: String,
        bucket: String,
        region: String,
        /// Prepended to every key. Empty unless the operator shares a
        /// bucket between deployments.
        prefix: String,
        access_key: String,
        secret_key: String,
        /// `{endpoint}/{bucket}/{key}` rather than
        /// `{bucket}.{endpoint}/{key}`. True suits the self-hosted
        /// S3-compatible servers this is most likely to point at.
        path_style: bool,
    },
}

/// Written by hand so the secret cannot be logged: the derived
/// implementation prints `secret_key` in full anywhere a `MediaStore`
/// reaches a `{:?}`, including a `tracing` field or a panic.
impl std::fmt::Debug for MediaStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Local { root } => f.debug_struct("Local").field("root", root).finish(),
            Self::S3 {
                endpoint,
                bucket,
                region,
                prefix,
                path_style,
                ..
            } => f
                .debug_struct("S3")
                .field("endpoint", endpoint)
                .field("bucket", bucket)
                .field("region", region)
                .field("prefix", prefix)
                .field("path_style", path_style)
                .field("access_key", &"<redacted>")
                .field("secret_key", &"<redacted>")
                .finish(),
        }
    }
}

impl MediaStore {
    /// A store rooted at `root`, creating it if absent.
    pub fn local(root: impl Into<PathBuf>) -> std::io::Result<Self> {
        let root = root.into();
        std::fs::create_dir_all(&root)?;
        Ok(Self::Local { root })
    }

    /// A store backed by an S3-compatible endpoint.
    ///
    /// Nothing is contacted here, so a third party's outage is a failed
    /// upload rather than an instance that will not start.
    #[allow(clippy::too_many_arguments)]
    pub fn s3(
        endpoint: impl Into<String>,
        bucket: impl Into<String>,
        region: impl Into<String>,
        prefix: impl Into<String>,
        access_key: impl Into<String>,
        secret_key: impl Into<String>,
        path_style: bool,
    ) -> Self {
        Self::S3 {
            client: reqwest::Client::new(),
            endpoint: endpoint.into().trim_end_matches('/').to_string(),
            bucket: bucket.into(),
            region: region.into(),
            prefix: prefix.into(),
            access_key: access_key.into(),
            secret_key: secret_key.into(),
            path_style,
        }
    }

    /// The discriminator stored on every row this store writes.
    pub fn backend(&self) -> &'static str {
        match self {
            Self::Local { .. } => "local",
            Self::S3 { .. } => "s3",
        }
    }

    /// Reject a key that is not one this module produced.
    ///
    /// Keys come from the database, so this should never fire. It exists
    /// because the consequence if it ever did is path traversal out of
    /// the media root, and a hex check is cheaper than being sure no
    /// future caller ever passes something else.
    fn object_path(root: &Path, key: &str) -> Option<PathBuf> {
        if key.len() != 32 || !key.chars().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }
        Some(root.join(key))
    }

    pub async fn put(&self, key: &str, bytes: &[u8]) -> std::io::Result<()> {
        match self {
            Self::Local { root } => {
                let path = Self::object_path(root, key).ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::InvalidInput, "malformed object key")
                })?;
                tokio::fs::write(path, bytes).await
            }
            Self::S3 { .. } => {
                self.s3_request(reqwest::Method::PUT, key, bytes).await?;
                Ok(())
            }
        }
    }

    pub async fn get(&self, key: &str) -> std::io::Result<Vec<u8>> {
        match self {
            Self::Local { root } => {
                let path = Self::object_path(root, key).ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::InvalidInput, "malformed object key")
                })?;
                tokio::fs::read(path).await
            }
            Self::S3 { .. } => {
                let body = self.s3_request(reqwest::Method::GET, key, &[]).await?;
                Ok(body)
            }
        }
    }

    /// Remove an object, treating "already gone" as success.
    ///
    /// Erasure calls this, and an erasure that fails because the bytes
    /// were already removed would leave the rows behind for no reason.
    pub async fn delete(&self, key: &str) -> std::io::Result<()> {
        match self {
            Self::Local { root } => {
                let Some(path) = Self::object_path(root, key) else {
                    return Ok(());
                };
                match tokio::fs::remove_file(path).await {
                    Ok(()) => Ok(()),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                    Err(e) => Err(e),
                }
            }
            Self::S3 { .. } => match self.s3_request(reqwest::Method::DELETE, key, &[]).await {
                Ok(_) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(e),
            },
        }
    }

    /// The URL an object lives at, and the path to sign for it.
    fn s3_url(&self, key: &str) -> Option<(reqwest::Url, String)> {
        let Self::S3 {
            endpoint,
            bucket,
            prefix,
            path_style,
            ..
        } = self
        else {
            return None;
        };

        // Each segment is percent-encoded separately so the separators
        // survive. `urlencoding::encode` leaves exactly the RFC 3986
        // unreserved set alone, which is what SigV4 canonicalisation
        // wants, and encodes a space as `%20` rather than `+`.
        let object = format!("{prefix}{key}");
        let encoded: String = object
            .split('/')
            .map(|segment| urlencoding::encode(segment).into_owned())
            .collect::<Vec<_>>()
            .join("/");

        let (base, path) = if *path_style {
            (
                endpoint.clone(),
                format!("/{}/{}", urlencoding::encode(bucket), encoded),
            )
        } else {
            let host = endpoint.split("://").nth(1)?;
            let scheme = endpoint.split("://").next()?;
            (format!("{scheme}://{bucket}.{host}"), format!("/{encoded}"))
        };

        let url = reqwest::Url::parse(&format!("{base}{path}")).ok()?;
        Some((url, path))
    }

    /// Sign and send one request, returning the body.
    ///
    /// The provider's error text is logged and never returned: it names
    /// the provider, the bucket and sometimes the account, to a reader
    /// who asked only for an avatar.
    async fn s3_request(
        &self,
        method: reqwest::Method,
        key: &str,
        body: &[u8],
    ) -> std::io::Result<Vec<u8>> {
        let Self::S3 {
            client,
            region,
            access_key,
            secret_key,
            ..
        } = self
        else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "not an object store",
            ));
        };

        if key.len() != 32 || !key.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "malformed object key",
            ));
        }

        let (url, canonical_path) = self.s3_url(key).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "unusable endpoint")
        })?;
        let host = url
            .host_str()
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "endpoint has no host")
            })?
            .to_string();
        let host = match url.port() {
            Some(port) => format!("{host}:{port}"),
            None => host,
        };

        let payload_hash = hex(&sha256(body));
        let now = chrono::Utc::now();
        let authorization = sign_v4(
            method.as_str(),
            &canonical_path,
            &host,
            &payload_hash,
            now,
            region,
            "s3",
            access_key,
            secret_key,
        );

        let mut request = client
            .request(method.clone(), url)
            .header("host", &host)
            .header("x-amz-content-sha256", &payload_hash)
            .header("x-amz-date", now.format("%Y%m%dT%H%M%SZ").to_string())
            .header("authorization", authorization);
        if method == reqwest::Method::PUT {
            request = request.body(body.to_vec());
        }

        let response = request.send().await.map_err(|error| {
            tracing::error!(%error, "the object store could not be reached");
            std::io::Error::other("object store unreachable")
        })?;

        let status = response.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "no such object",
            ));
        }
        if !status.is_success() {
            let detail = response.text().await.unwrap_or_default();
            tracing::error!(%status, %detail, "the object store refused a request");
            return Err(std::io::Error::other("object store refused the request"));
        }

        response.bytes().await.map(|b| b.to_vec()).map_err(|error| {
            tracing::error!(%error, "the object store's response could not be read");
            std::io::Error::other("object store response unreadable")
        })
    }
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(bytes).into()
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    use hmac::Mac;
    let mut mac =
        hmac::Hmac::<sha2::Sha256>::new_from_slice(key).expect("HMAC accepts a key of any length");
    mac.update(message);
    mac.finalize().into_bytes().into()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Build an AWS Signature Version 4 `Authorization` header.
///
/// `service` is a parameter rather than a constant so published test
/// vectors, which sign for other service names, can be run against this
/// function unchanged.
#[allow(clippy::too_many_arguments)]
fn sign_v4(
    method: &str,
    canonical_path: &str,
    host: &str,
    payload_hash: &str,
    now: chrono::DateTime<chrono::Utc>,
    region: &str,
    service: &str,
    access_key: &str,
    secret_key: &str,
) -> String {
    let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
    let date_stamp = now.format("%Y%m%d").to_string();

    // Headers are signed lowercase, sorted, and with the value trimmed.
    // Only these three: everything else the request carries is
    // deliberately unsigned, which S3 permits and which keeps a proxy
    // that adds a header from invalidating the signature.
    let signed_headers = "host;x-amz-content-sha256;x-amz-date";
    let canonical_headers =
        format!("host:{host}\nx-amz-content-sha256:{payload_hash}\nx-amz-date:{amz_date}\n");

    // No query string on any request this makes, so the canonical query
    // string is empty rather than absent: the newline still counts.
    let canonical_request = format!(
        "{method}\n{canonical_path}\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
    );

    let scope = format!("{date_stamp}/{region}/{service}/aws4_request");
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
        hex(&sha256(canonical_request.as_bytes()))
    );

    let date_key = hmac_sha256(
        format!("AWS4{secret_key}").as_bytes(),
        date_stamp.as_bytes(),
    );
    let region_key = hmac_sha256(&date_key, region.as_bytes());
    let service_key = hmac_sha256(&region_key, service.as_bytes());
    let signing_key = hmac_sha256(&service_key, b"aws4_request");
    let signature = hex(&hmac_sha256(&signing_key, string_to_sign.as_bytes()));

    format!(
        "AWS4-HMAC-SHA256 Credential={access_key}/{scope}, \
         SignedHeaders={signed_headers}, Signature={signature}"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A tiny valid PNG, built rather than checked in as a fixture.
    fn png(width: u32, height: u32) -> Vec<u8> {
        let img = image::RgbaImage::new(width, height);
        let mut out = Vec::new();
        image::DynamicImage::ImageRgba8(img)
            .write_to(&mut std::io::Cursor::new(&mut out), ImageFormat::Png)
            .unwrap();
        out
    }

    fn jpeg(width: u32, height: u32) -> Vec<u8> {
        let img = image::RgbImage::new(width, height);
        let mut out = Vec::new();
        image::DynamicImage::ImageRgb8(img)
            .write_to(&mut std::io::Cursor::new(&mut out), ImageFormat::Jpeg)
            .unwrap();
        out
    }

    #[test]
    fn a_png_stays_a_png_and_a_jpeg_stays_a_jpeg() {
        assert_eq!(process_avatar(&png(8, 8)).unwrap().media_type, "image/png");
        assert_eq!(
            process_avatar(&jpeg(8, 8)).unwrap().media_type,
            "image/jpeg"
        );
    }

    #[test]
    fn the_format_comes_from_the_content_not_the_claim() {
        // The route never sees a filename or a declared type, which is
        // the point: this is the only thing that decides.
        let err = process_avatar(b"GIF89a not really a gif either").unwrap_err();
        assert_eq!(err, MediaError::UnsupportedFormat);
    }

    #[test]
    fn a_gif_is_refused_even_though_it_is_a_real_image() {
        // Built by hand: the crate is compiled without GIF support, so
        // it cannot produce one. A closed list means a valid image in an
        // unaccepted format is still refused.
        let gif = b"GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff\x21\
                    \xf9\x04\x00\x00\x00\x00\x00\x2c\x00\x00\x00\x00\x01\x00\x01\
                    \x00\x00\x02\x02\x44\x01\x00\x3b";
        assert_eq!(
            process_avatar(gif).unwrap_err(),
            MediaError::UnsupportedFormat
        );
    }

    #[test]
    fn an_oversized_upload_is_refused_before_decoding() {
        let too_big = vec![0u8; MAX_UPLOAD_BYTES + 1];
        assert_eq!(process_avatar(&too_big).unwrap_err(), MediaError::TooLarge);
    }

    #[test]
    fn a_large_image_is_scaled_down_rather_than_refused() {
        let out = process_avatar(&png(2000, 1000)).unwrap();
        let decoded = image::load_from_memory(&out.bytes).unwrap();
        assert!(
            decoded.width() <= AVATAR_MAX_EDGE && decoded.height() <= AVATAR_MAX_EDGE,
            "stored at {}x{}",
            decoded.width(),
            decoded.height()
        );
        // Aspect ratio preserved: 2:1 in, 2:1 out.
        assert_eq!(decoded.width(), AVATAR_MAX_EDGE);
        assert_eq!(decoded.height(), AVATAR_MAX_EDGE / 2);
    }

    #[test]
    fn a_small_image_is_not_enlarged() {
        let out = process_avatar(&png(16, 16)).unwrap();
        let decoded = image::load_from_memory(&out.bytes).unwrap();
        assert_eq!((decoded.width(), decoded.height()), (16, 16));
    }

    #[test]
    fn re_encoding_drops_the_metadata_block() {
        // An EXIF segment carrying a location, spliced into a real JPEG
        // after the SOI marker. Re-encoding must not carry it through:
        // this is the assertion that stands between a phone photograph
        // and the address it was taken at.
        let mut with_exif = jpeg(32, 32);
        let exif = b"\xff\xe1\x00\x20Exif\x00\x00MM\x00\x2a\x00\x00\x00\x08GPSLAT51.5";
        with_exif.splice(2..2, exif.iter().copied());

        assert!(
            with_exif.windows(4).any(|w| w == b"Exif"),
            "the fixture itself must contain the marker"
        );
        let out = process_avatar(&with_exif).unwrap();
        assert!(
            !out.bytes.windows(4).any(|w| w == b"Exif"),
            "EXIF survived re-encoding"
        );
        assert!(!out.bytes.windows(6).any(|w| w == b"GPSLAT"));
    }

    #[test]
    fn object_keys_are_opaque_and_unique() {
        let a = new_object_key();
        let b = new_object_key();
        assert_ne!(a, b);
        assert_eq!(a.len(), 32);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn a_key_that_is_not_ours_cannot_escape_the_media_root() {
        let root = Path::new("/var/lib/noombat/media");
        assert!(MediaStore::object_path(root, "../../etc/passwd").is_none());
        assert!(MediaStore::object_path(root, "a/b").is_none());
        assert!(MediaStore::object_path(root, "").is_none());
        assert!(MediaStore::object_path(root, &new_object_key()).is_some());
    }

    #[tokio::test]
    async fn a_local_store_round_trips_and_forgets() {
        let dir = tempfile::tempdir().unwrap();
        let store = MediaStore::local(dir.path()).unwrap();
        let key = new_object_key();

        store.put(&key, b"bytes").await.unwrap();
        assert_eq!(store.get(&key).await.unwrap(), b"bytes");

        store.delete(&key).await.unwrap();
        assert!(store.get(&key).await.is_err());
        // Deleting what is already gone is success: erasure must not
        // fail because the bytes went first.
        store.delete(&key).await.unwrap();
    }

    // ..... THE OBJECT STORE BACKEND .....

    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Debug)]
    struct Seen {
        method: String,
        path: String,
        headers: HashMap<String, String>,
        body: Vec<u8>,
    }

    #[derive(Clone, Default)]
    struct FakeBucket {
        objects: Arc<Mutex<HashMap<String, Vec<u8>>>>,
        seen: Arc<Mutex<Vec<Seen>>>,
        /// When set, every request is answered with this status and body
        /// instead of being served.
        forced_error: Arc<Mutex<Option<(u16, String)>>>,
    }

    /// An S3-shaped server, so the three verbs run over real HTTP.
    async fn fake_bucket() -> (String, FakeBucket) {
        use axum::body::Bytes;
        use axum::extract::{Path as AxPath, State};
        use axum::http::{HeaderMap, Method, StatusCode};
        use axum::routing::any;

        let state = FakeBucket::default();

        async fn handle(
            State(state): State<FakeBucket>,
            AxPath((bucket, key)): AxPath<(String, String)>,
            method: Method,
            headers: HeaderMap,
            body: Bytes,
        ) -> (StatusCode, Vec<u8>) {
            state.seen.lock().unwrap().push(Seen {
                method: method.to_string(),
                path: format!("/{bucket}/{key}"),
                headers: headers
                    .iter()
                    .map(|(k, v)| {
                        (
                            k.as_str().to_string(),
                            v.to_str().unwrap_or_default().to_string(),
                        )
                    })
                    .collect(),
                body: body.to_vec(),
            });

            if let Some((status, text)) = state.forced_error.lock().unwrap().clone() {
                return (StatusCode::from_u16(status).unwrap(), text.into_bytes());
            }

            let mut objects = state.objects.lock().unwrap();
            match method {
                Method::PUT => {
                    objects.insert(key, body.to_vec());
                    (StatusCode::OK, Vec::new())
                }
                Method::GET => match objects.get(&key) {
                    Some(bytes) => (StatusCode::OK, bytes.clone()),
                    None => (StatusCode::NOT_FOUND, b"<Error>NoSuchKey</Error>".to_vec()),
                },
                Method::DELETE => {
                    objects.remove(&key);
                    (StatusCode::NO_CONTENT, Vec::new())
                }
                _ => (StatusCode::METHOD_NOT_ALLOWED, Vec::new()),
            }
        }

        let app = axum::Router::new()
            .route("/{bucket}/{key}", any(handle))
            .with_state(state.clone());

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        (format!("http://{addr}"), state)
    }

    fn test_store(endpoint: &str) -> MediaStore {
        MediaStore::s3(
            endpoint,
            "media",
            "us-east-1",
            "",
            "AKIAIOSFODNN7EXAMPLE",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            true,
        )
    }

    #[tokio::test]
    async fn an_object_store_round_trips_and_forgets() {
        let (endpoint, bucket) = fake_bucket().await;
        let store = test_store(&endpoint);
        let key = new_object_key();

        store.put(&key, b"bytes").await.unwrap();
        assert_eq!(store.get(&key).await.unwrap(), b"bytes");
        store.delete(&key).await.unwrap();

        let missing = store.get(&key).await.unwrap_err();
        assert_eq!(missing.kind(), std::io::ErrorKind::NotFound);
        // As for the local store: erasure must not fail because the
        // bytes were already gone.
        store.delete(&key).await.unwrap();

        let seen = bucket.seen.lock().unwrap();
        let methods: Vec<&str> = seen.iter().map(|s| s.method.as_str()).collect();
        assert_eq!(methods, ["PUT", "GET", "DELETE", "GET", "DELETE"]);
        assert!(seen.iter().all(|s| s.path == format!("/media/{key}")));
    }

    #[tokio::test]
    async fn every_request_is_signed_over_the_body_it_carries() {
        let (endpoint, bucket) = fake_bucket().await;
        let store = test_store(&endpoint);
        let key = new_object_key();

        store.put(&key, b"the payload").await.unwrap();

        let seen = bucket.seen.lock().unwrap();
        let put = seen.first().unwrap();

        // The content hash must cover what was actually sent: hashing
        // an empty body and then sending bytes is rejected by the store
        // as a credentials error.
        assert_eq!(put.body, b"the payload");
        assert_eq!(
            put.headers.get("x-amz-content-sha256").map(String::as_str),
            Some(hex(&sha256(b"the payload")).as_str())
        );

        let auth = put.headers.get("authorization").expect("no authorization");
        assert!(auth.starts_with("AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/"));
        assert!(auth.contains("/us-east-1/s3/aws4_request"));
        assert!(auth.contains("SignedHeaders=host;x-amz-content-sha256;x-amz-date"));
        // Every header named in SignedHeaders has to be on the request,
        // or the store recomputes over something it did not receive.
        for name in ["host", "x-amz-content-sha256", "x-amz-date"] {
            assert!(put.headers.contains_key(name), "{name} was not sent");
        }
    }

    #[tokio::test]
    async fn the_provider_s_error_text_does_not_escape() {
        let (endpoint, bucket) = fake_bucket().await;
        *bucket.forced_error.lock().unwrap() = Some((
            403,
            "<Error><Message>Access denied for \
              arn:aws:iam::123456789012:user/backups</Message></Error>"
                .to_string(),
        ));
        let store = test_store(&endpoint);

        let error = store.get(&new_object_key()).await.unwrap_err();
        let rendered = error.to_string();
        assert!(
            !rendered.contains("arn:aws")
                && !rendered.contains("123456789012")
                && !rendered.contains("Access denied"),
            "the provider's error text reached the caller: {rendered}"
        );
    }

    #[tokio::test]
    async fn a_key_that_is_not_ours_never_reaches_the_object_store() {
        let (endpoint, bucket) = fake_bucket().await;
        let store = test_store(&endpoint);

        for bad in ["../../etc/passwd", "a/b", "", "media/../../secret"] {
            assert!(store.get(bad).await.is_err(), "{bad} was not refused");
            assert!(store.put(bad, b"x").await.is_err(), "{bad} was not refused");
        }
        assert!(
            bucket.seen.lock().unwrap().is_empty(),
            "a malformed key was sent to the object store"
        );
    }

    #[test]
    fn the_secret_is_not_printable() {
        let store = test_store("https://example.invalid");
        let rendered = format!("{store:?}");
        assert!(
            !rendered.contains("wJalrXUtnFEMI"),
            "the secret key is in the Debug output: {rendered}"
        );
        assert!(
            !rendered.contains("AKIAIOSFODNN7EXAMPLE"),
            "the access key is in the Debug output: {rendered}"
        );
        // Still useful for diagnosis: the parts that are not secret.
        assert!(rendered.contains("example.invalid"));
        assert!(rendered.contains("media"));
    }

    #[test]
    fn the_backend_discriminator_distinguishes_the_two() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(MediaStore::local(dir.path()).unwrap().backend(), "local");
        assert_eq!(test_store("https://example.invalid").backend(), "s3");
    }

    #[test]
    fn a_prefix_is_applied_and_the_bucket_placement_follows_the_style() {
        let key = new_object_key();

        let path_style = MediaStore::s3(
            "https://s3.example.invalid",
            "media",
            "us-east-1",
            "noombat/",
            "id",
            "secret",
            true,
        );
        let (url, path) = path_style.s3_url(&key).unwrap();
        assert_eq!(path, format!("/media/noombat/{key}"));
        assert_eq!(url.host_str(), Some("s3.example.invalid"));

        let virtual_style = MediaStore::s3(
            "https://s3.example.invalid",
            "media",
            "us-east-1",
            "noombat/",
            "id",
            "secret",
            false,
        );
        let (url, path) = virtual_style.s3_url(&key).unwrap();
        assert_eq!(path, format!("/noombat/{key}"));
        assert_eq!(url.host_str(), Some("media.s3.example.invalid"));
    }

    /// The reference timestamp for the vectors below: 2015-08-30
    /// 12:36:00 UTC, the one AWS uses in its own worked examples.
    fn reference_time() -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::from_timestamp(1_440_938_160, 0).unwrap()
    }

    /// Agree with an independent implementation, not just with itself.
    ///
    /// These four headers came from botocore 1.43.78, which the AWS CLI
    /// signs with, given the same inputs. To regenerate: sign with
    /// `botocore.auth.SigV4Auth`, replacing
    /// `botocore.auth.get_current_datetime` to return the timestamp
    /// above, and set only `Host` and `x-amz-content-sha256` so
    /// botocore signs the same three headers this does.
    #[test]
    fn the_signature_matches_an_independent_implementation() {
        let empty = hex(&sha256(b""));
        let payload = hex(&sha256(b"the payload"));
        let cases = [
            (
                "GET",
                "/media/abc",
                empty.as_str(),
                "9b1732efa9e6e6a6b29b81fb16683f4e646b90ef91c65dc151d2ddf9af066fd0",
            ),
            (
                "PUT",
                "/media/abc",
                payload.as_str(),
                "3aa7e0a2f0e20c90758ef65a7fe3f63434458b84831c956073f6b4ba9a3389f7",
            ),
            (
                "DELETE",
                "/media/abc",
                empty.as_str(),
                "a4d2a1b3cbe19f90f9e45853a358e9423af40f7bf236c7bc66c3ccca6647e4fa",
            ),
            (
                "GET",
                "/media/noombat/deadbeef",
                empty.as_str(),
                "e12fa510f339f9740aed0248df32a904f3364be7a357102cf46917844e8a7682",
            ),
        ];

        for (method, path, payload_hash, expected) in cases {
            let header = sign_v4(
                method,
                path,
                "s3.example.invalid",
                payload_hash,
                reference_time(),
                "us-east-1",
                "s3",
                "AKID",
                "secret",
            );
            assert_eq!(
                header,
                format!(
                    "AWS4-HMAC-SHA256 Credential=AKID/20150830/us-east-1/s3/aws4_request, \
                     SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature={expected}"
                ),
                "{method} {path} disagrees with botocore"
            );
        }
    }

    /// The signature must change when any signed input changes, which
    /// catches a signer that drops one the vectors above do not vary.
    #[test]
    fn the_signature_depends_on_every_signed_input() {
        let at = reference_time();
        let base = || {
            sign_v4(
                "GET",
                "/media/abc",
                "s3.example.invalid",
                "payloadhash",
                at,
                "us-east-1",
                "s3",
                "AKID",
                "secret",
            )
        };
        let reference = base();
        assert_eq!(reference, base(), "signing is not deterministic");

        let variants = [
            sign_v4(
                "PUT",
                "/media/abc",
                "s3.example.invalid",
                "payloadhash",
                at,
                "us-east-1",
                "s3",
                "AKID",
                "secret",
            ),
            sign_v4(
                "GET",
                "/media/xyz",
                "s3.example.invalid",
                "payloadhash",
                at,
                "us-east-1",
                "s3",
                "AKID",
                "secret",
            ),
            sign_v4(
                "GET",
                "/media/abc",
                "other.invalid",
                "payloadhash",
                at,
                "us-east-1",
                "s3",
                "AKID",
                "secret",
            ),
            sign_v4(
                "GET",
                "/media/abc",
                "s3.example.invalid",
                "otherhash",
                at,
                "us-east-1",
                "s3",
                "AKID",
                "secret",
            ),
            sign_v4(
                "GET",
                "/media/abc",
                "s3.example.invalid",
                "payloadhash",
                at + chrono::Duration::seconds(1),
                "us-east-1",
                "s3",
                "AKID",
                "secret",
            ),
            sign_v4(
                "GET",
                "/media/abc",
                "s3.example.invalid",
                "payloadhash",
                at,
                "eu-west-1",
                "s3",
                "AKID",
                "secret",
            ),
            sign_v4(
                "GET",
                "/media/abc",
                "s3.example.invalid",
                "payloadhash",
                at,
                "us-east-1",
                "s3",
                "AKID",
                "other-secret",
            ),
        ];
        for (i, variant) in variants.iter().enumerate() {
            assert_ne!(
                &reference, variant,
                "changing signed input {i} left the signature unchanged"
            );
        }
    }
}
