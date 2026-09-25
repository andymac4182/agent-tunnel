//! **Capture dimensions from what the pinned server actually sends** (M5-C14).
//!
//! Every pinned 0.3.46 backend's `screenshot` answers
//! `{"success", "image_data", "format"}` (VNC omits `format`), where
//! `image_data` is the base64 of a PNG or JPEG. **It never sends `width`,
//! `height` or a scale**, so the capture identity cannot be built from members
//! of the response; an earlier revision read `width`/`height`/`scale_percent`
//! members that only the Lane A fixture emitted, and so against a released
//! backend it issued no identity at all.
//!
//! What the response *does* carry is the image, and a PNG states its own
//! dimensions in the first chunk: the eight-byte signature, then `IHDR` with
//! width and height as big-endian `u32`s, then that chunk's CRC. This module
//! reads exactly that, from the first [`PNG_HEADER_BASE64_CHARS`] characters of
//! `image_data`, and nothing else. It does not decode the image.
//!
//! # What it deliberately refuses
//!
//! * **JPEG.** A JPEG's dimensions live in a start-of-frame marker at an
//!   arbitrary offset, so reading them means walking the whole stream. The
//!   pinned default format is `png`, and a capture reported as anything else
//!   gets no identity rather than a guess -- the safe direction, because no
//!   identity means no coordinate resolves.
//! * **A header whose CRC does not match.** A truncated or corrupted prefix is
//!   refused rather than read, so a damaged capture cannot mint an identity
//!   with the wrong bounds.
//! * **The scale.** Nothing here can know it, and see [`crate::capture`] for
//!   why a pixel count is not a point count on the one pinned backend (macOS)
//!   that resizes before it encodes.
//!
//! Pure and allocation-light: no dependency, no float, no clock.

/// The PNG file signature.
pub const PNG_SIGNATURE: [u8; 8] = [0x89, b'P', b'N', b'G', b'\r', b'\n', 0x1a, b'\n'];

/// Bytes in the signature plus a complete `IHDR` chunk: 8 + 4 (length) + 4
/// (type) + 13 (data) + 4 (CRC).
pub const PNG_HEADER_BYTES: usize = 33;

/// Base64 characters that cover [`PNG_HEADER_BYTES`]: 33 bytes round up to 11
/// four-character groups.
pub const PNG_HEADER_BASE64_CHARS: usize = 44;

/// The `format` value the pinned handlers report for a PNG capture.
pub const PNG_FORMAT: &str = "png";

/// Why a capture's dimensions could not be read.
///
/// Carries no image bytes: diagnostics name the shape of the failure, never the
/// capture.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ImageHeaderError {
    /// `image_data` is missing, or is not a string.
    Absent,
    /// The backend reported a format other than PNG.
    NotPng,
    /// `image_data` is not valid base64 over the header's span.
    NotBase64,
    /// The decoded bytes are too short to hold a PNG header.
    Truncated,
    /// The first eight bytes are not the PNG signature.
    BadSignature,
    /// The first chunk is not a 13-byte `IHDR`.
    NotIhdr,
    /// The `IHDR` CRC does not match its bytes.
    BadCrc,
    /// A dimension is zero. The PNG specification forbids it.
    ZeroDimension,
}

impl core::fmt::Display for ImageHeaderError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            Self::Absent => "the capture carries no image data",
            Self::NotPng => "the capture is not a PNG",
            Self::NotBase64 => "the capture's image data is not base64",
            Self::Truncated => "the capture's image data is too short for a PNG header",
            Self::BadSignature => "the capture's image data lacks the PNG signature",
            Self::NotIhdr => "the capture's first PNG chunk is not IHDR",
            Self::BadCrc => "the capture's PNG header fails its checksum",
            Self::ZeroDimension => "the capture's PNG header declares a zero dimension",
        })
    }
}

impl std::error::Error for ImageHeaderError {}

/// Read a capture's pixel dimensions from a `screenshot` result object.
///
/// `format` is honoured when present and must be `png`; it is **absent** on
/// the pinned VNC backend, whose `screenshot` always returns PNG bytes, so an
/// absent `format` falls through to the signature check rather than being
/// assumed either way.
///
/// # Errors
/// Any [`ImageHeaderError`].
pub fn capture_dimensions(result: &serde_json::Value) -> Result<(u32, u32), ImageHeaderError> {
    if let Some(format) = result.get("format")
        && format.as_str() != Some(PNG_FORMAT)
    {
        return Err(ImageHeaderError::NotPng);
    }
    let image_data = result
        .get("image_data")
        .and_then(serde_json::Value::as_str)
        .ok_or(ImageHeaderError::Absent)?;
    png_dimensions_from_base64(image_data)
}

/// Read a PNG's width and height from the start of its base64 encoding.
///
/// Decodes only the first [`PNG_HEADER_BASE64_CHARS`] characters.
///
/// # Errors
/// Any [`ImageHeaderError`] other than [`ImageHeaderError::Absent`] and
/// [`ImageHeaderError::NotPng`].
pub fn png_dimensions_from_base64(image_data: &str) -> Result<(u32, u32), ImageHeaderError> {
    let prefix = image_data
        .get(..PNG_HEADER_BASE64_CHARS)
        .ok_or(ImageHeaderError::Truncated)?;
    let bytes = decode_base64(prefix).ok_or(ImageHeaderError::NotBase64)?;
    png_dimensions(&bytes)
}

/// Read a PNG's width and height from its first bytes.
///
/// # Errors
/// [`ImageHeaderError::Truncated`], [`ImageHeaderError::BadSignature`],
/// [`ImageHeaderError::NotIhdr`], [`ImageHeaderError::BadCrc`] or
/// [`ImageHeaderError::ZeroDimension`].
pub fn png_dimensions(bytes: &[u8]) -> Result<(u32, u32), ImageHeaderError> {
    let header = bytes
        .get(..PNG_HEADER_BYTES)
        .ok_or(ImageHeaderError::Truncated)?;
    if header[..8] != PNG_SIGNATURE {
        return Err(ImageHeaderError::BadSignature);
    }
    let length = u32::from_be_bytes([header[8], header[9], header[10], header[11]]);
    if length != 13 || &header[12..16] != b"IHDR" {
        return Err(ImageHeaderError::NotIhdr);
    }
    let recorded = u32::from_be_bytes([header[29], header[30], header[31], header[32]]);
    if crc32(&header[12..29]) != recorded {
        return Err(ImageHeaderError::BadCrc);
    }
    let width = u32::from_be_bytes([header[16], header[17], header[18], header[19]]);
    let height = u32::from_be_bytes([header[20], header[21], header[22], header[23]]);
    if width == 0 || height == 0 {
        return Err(ImageHeaderError::ZeroDimension);
    }
    Ok((width, height))
}

/// The CRC-32 PNG chunks carry (ISO 3309 / ITU-T V.42, reflected, polynomial
/// `0xEDB88320`), over a chunk's type and data.
///
/// Bitwise rather than table-driven: it runs over 17 bytes per capture.
#[must_use]
pub fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in bytes {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// Decode standard base64 (RFC 4648 section 4, `+` and `/`, `=` padding).
///
/// Strict: the length must be a multiple of four, padding may appear only in
/// the last group, and any other character is a refusal. `None` on anything
/// malformed.
#[must_use]
pub fn decode_base64(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    if !bytes.len().is_multiple_of(4) {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    let groups = bytes.len() / 4;
    for (index, group) in bytes.chunks_exact(4).enumerate() {
        let last = index + 1 == groups;
        let padding = group.iter().rev().take_while(|&&byte| byte == b'=').count();
        if padding > 2 || (padding > 0 && !last) {
            return None;
        }
        let mut value = 0u32;
        for (position, &byte) in group.iter().enumerate() {
            let sextet = if position >= 4 - padding {
                0
            } else {
                u32::from(sextet(byte)?)
            };
            value = (value << 6) | sextet;
        }
        let [_, first, second, third] = value.to_be_bytes();
        out.push(first);
        if padding < 2 {
            out.push(second);
        }
        if padding < 1 {
            out.push(third);
        }
    }
    Some(out)
}

const fn sextet(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

#[cfg(test)]
mod tests;
