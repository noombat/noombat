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
}

/// Decide the format from the content, bound it, and re-encode it.
///
/// The output format matches the input: a PNG stays a PNG because it may
/// carry transparency that JPEG cannot represent, and a JPEG stays a
/// JPEG because re-encoding it as PNG would multiply its size.
pub fn process_avatar(raw: &[u8]) -> Result<ProcessedImage, MediaError> {
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
    let bounded = if decoded.width() > AVATAR_MAX_EDGE || decoded.height() > AVATAR_MAX_EDGE {
        decoded.thumbnail(AVATAR_MAX_EDGE, AVATAR_MAX_EDGE)
    } else {
        decoded
    };

    let mut bytes = Vec::new();
    bounded
        .write_to(&mut std::io::Cursor::new(&mut bytes), format)
        .map_err(|_| MediaError::Undecodable)?;

    Ok(ProcessedImage { bytes, media_type })
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

/// Where uploaded media rests.
///
/// One variant today. The trait-shaped surface is deliberate: an
/// S3-compatible backend is a second variant behind these three methods,
/// and every row records which backend wrote it, so enabling object
/// storage later cannot orphan what was written while it was local.
#[derive(Clone, Debug)]
pub enum MediaStore {
    Local { root: PathBuf },
}

impl MediaStore {
    /// A store rooted at `root`, creating it if absent.
    pub fn local(root: impl Into<PathBuf>) -> std::io::Result<Self> {
        let root = root.into();
        std::fs::create_dir_all(&root)?;
        Ok(Self::Local { root })
    }

    /// The discriminator stored on every row this store writes.
    pub fn backend(&self) -> &'static str {
        match self {
            Self::Local { .. } => "local",
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
        }
    }
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
}
