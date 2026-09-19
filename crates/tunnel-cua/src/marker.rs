//! Synthetic capture images, verified by **decoding markers** — never by byte
//! count.
//!
//! This is the fourth of the four host-untouched proofs, and the one that is
//! easiest to fake. `<scratchpad>/m5-scoping-and-decisions.md` names the
//! defect directly: *a screenshot verified by byte count rather than by
//! decoding markers*. A length check passes for any blob of the right size,
//! including a real capture of somebody's actual desktop, so a test built on
//! one would go green on precisely the run that should fail loudest.
//!
//! The format here is therefore **deliberately not an image format**. It is a
//! tiny container with a magic string, dimensions, a seed, and a body every
//! byte of which is a pure function of `(seed, x, y)`. Consequences:
//!
//! * A real PNG, JPEG or raw framebuffer fails [`decode`] at the magic, with
//!   [`MarkerError::NotSynthetic`]. It cannot be mistaken for a fixture image
//!   no matter how large it is.
//! * Two images of **identical length** and different seeds differ in every
//!   marker, so a byte-count comparison cannot distinguish them and
//!   [`verify`] can. `tests::a_byte_count_cannot_tell_two_captures_apart_and_the_markers_can`
//!   is that control, written as a test rather than as a sentence.
//! * Nothing here can produce a real capture: there is no code path in this
//!   crate that reads a screen, and no dependency that could.

/// The container magic. Eight bytes, chosen to be absent from every real image
/// format's header.
pub const MAGIC: &[u8; 8] = b"CUAFIX01";

/// Header length: magic, width, height, seed.
pub const HEADER_LEN: usize = 8 + 2 + 2 + 4;

/// The largest synthetic image this module will build or accept, in pixels.
/// 4096x4096 keeps a whole image inside the profile's response limit.
pub const MAX_DIMENSION: u16 = 4096;

/// A decoded synthetic image.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyntheticImage {
    pub width: u16,
    pub height: u16,
    pub seed: u32,
    markers: Vec<u8>,
}

impl SyntheticImage {
    /// The marker byte at `(x, y)`, or `None` outside the image.
    #[must_use]
    pub fn marker_at(&self, x: u16, y: u16) -> Option<u8> {
        if x >= self.width || y >= self.height {
            return None;
        }
        self.markers
            .get(usize::from(y) * usize::from(self.width) + usize::from(x))
            .copied()
    }

    /// Every marker, row-major.
    #[must_use]
    pub fn markers(&self) -> &[u8] {
        &self.markers
    }
}

/// Why a blob is not a synthetic fixture image.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum MarkerError {
    /// The magic is absent. **A real capture lands here**, which is the whole
    /// point: it fails rather than passing silently.
    NotSynthetic,
    /// The header is present but the blob is shorter than its own dimensions
    /// claim, or longer.
    LengthMismatch,
    /// A dimension is zero or past [`MAX_DIMENSION`].
    BadDimensions,
    /// A marker byte is not the value `(seed, x, y)` requires.
    MarkerMismatch { x: u16, y: u16 },
}

impl core::fmt::Display for MarkerError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotSynthetic => formatter.write_str(
                "the capture is not a synthetic fixture image (a real capture reaches here)",
            ),
            Self::LengthMismatch => {
                formatter.write_str("the capture length contradicts its header")
            }
            Self::BadDimensions => {
                formatter.write_str("the capture declares impossible dimensions")
            }
            Self::MarkerMismatch { x, y } => {
                write!(
                    formatter,
                    "the marker at ({x}, {y}) is not the expected value"
                )
            }
        }
    }
}

impl std::error::Error for MarkerError {}

/// The marker byte for one pixel. A pure function, so a verifier recomputes it
/// rather than trusting a copy that travelled with the image.
#[must_use]
pub const fn marker(seed: u32, x: u16, y: u16) -> u8 {
    // A cheap avalanche: every input bit reaches the output byte, so two
    // images differing only in their seed differ in essentially every marker.
    let mut value = seed
        .wrapping_mul(0x9E37_79B9)
        .wrapping_add((x as u32) << 16)
        .wrapping_add(y as u32);
    value ^= value >> 15;
    value = value.wrapping_mul(0x85EB_CA6B);
    value ^= value >> 13;
    (value & 0xff) as u8
}

/// Build one synthetic image.
///
/// # Errors
/// [`MarkerError::BadDimensions`] for a zero or oversized dimension.
pub fn encode(width: u16, height: u16, seed: u32) -> Result<Vec<u8>, MarkerError> {
    if width == 0 || height == 0 || width > MAX_DIMENSION || height > MAX_DIMENSION {
        return Err(MarkerError::BadDimensions);
    }
    let mut out = Vec::with_capacity(HEADER_LEN + usize::from(width) * usize::from(height));
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&width.to_be_bytes());
    out.extend_from_slice(&height.to_be_bytes());
    out.extend_from_slice(&seed.to_be_bytes());
    for y in 0..height {
        for x in 0..width {
            out.push(marker(seed, x, y));
        }
    }
    Ok(out)
}

/// Decode a blob as a synthetic image, **without** checking the markers.
///
/// Separate from [`verify`] on purpose: decoding says "this is shaped like a
/// fixture image", verifying says "and every marker is the one the seed
/// requires". A test that only decoded would be a length check wearing a
/// better name.
///
/// # Errors
/// [`MarkerError::NotSynthetic`], [`MarkerError::BadDimensions`] or
/// [`MarkerError::LengthMismatch`].
pub fn decode(blob: &[u8]) -> Result<SyntheticImage, MarkerError> {
    if blob.len() < HEADER_LEN || &blob[..8] != MAGIC {
        return Err(MarkerError::NotSynthetic);
    }
    let width = u16::from_be_bytes([blob[8], blob[9]]);
    let height = u16::from_be_bytes([blob[10], blob[11]]);
    let seed = u32::from_be_bytes([blob[12], blob[13], blob[14], blob[15]]);
    if width == 0 || height == 0 || width > MAX_DIMENSION || height > MAX_DIMENSION {
        return Err(MarkerError::BadDimensions);
    }
    let expected = HEADER_LEN + usize::from(width) * usize::from(height);
    if blob.len() != expected {
        return Err(MarkerError::LengthMismatch);
    }
    Ok(SyntheticImage {
        width,
        height,
        seed,
        markers: blob[HEADER_LEN..].to_vec(),
    })
}

/// Decode `blob` and check **every** marker against what its seed requires.
///
/// This is the function a test must call. It is what makes "the fixture served
/// this image" a checkable claim and "a real capture happened" an impossible
/// one.
///
/// # Errors
/// Anything [`decode`] returns, plus [`MarkerError::MarkerMismatch`] naming
/// the first pixel that disagrees.
pub fn verify(
    blob: &[u8],
    width: u16,
    height: u16,
    seed: u32,
) -> Result<SyntheticImage, MarkerError> {
    let image = decode(blob)?;
    if image.width != width || image.height != height {
        return Err(MarkerError::BadDimensions);
    }
    // **There is deliberately no `image.seed != seed` early return.** One was
    // written here and `scripts/m5-guard-deletion.py` reported it as the one
    // case in the suite that stayed green when deleted — because the loop
    // below recomputes every marker from the **caller's** `seed`, so a
    // mismatched image already fails at its first pixel. The early return
    // therefore added no checking, and it actively lied about where: it
    // reported `MarkerMismatch { x: 0, y: 0 }` for a whole-image seed
    // disagreement. It was removed rather than exempted from the harness.
    //
    // The seed recorded inside the blob is not consulted by this function at
    // all, which is the property that matters: a seed that travelled with the
    // image is not evidence about the image.
    for y in 0..height {
        for x in 0..width {
            let found = image.marker_at(x, y).ok_or(MarkerError::LengthMismatch)?;
            if found != marker(seed, x, y) {
                return Err(MarkerError::MarkerMismatch { x, y });
            }
        }
    }
    Ok(image)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_encoded_image_verifies_against_its_own_dimensions_and_seed() {
        let blob = encode(64, 48, 0xA5A5_1234).unwrap();
        let image = verify(&blob, 64, 48, 0xA5A5_1234).unwrap();
        assert_eq!(image.width, 64);
        assert_eq!(image.height, 48);
        assert_eq!(image.markers().len(), 64 * 48);
    }

    /// **The control that makes the marker check load-bearing.**
    ///
    /// Two images of exactly the same length, differing only in seed. A test
    /// that compared `blob.len()` — or even compared against a recorded byte
    /// count — cannot tell them apart. `verify` can, and says where.
    #[test]
    fn a_byte_count_cannot_tell_two_captures_apart_and_the_markers_can() {
        let first = encode(32, 32, 1).unwrap();
        let second = encode(32, 32, 2).unwrap();

        // The byte-count check that must never be used as evidence: it passes.
        assert_eq!(first.len(), second.len());

        // The marker check: it fails, and names a pixel.
        assert!(verify(&first, 32, 32, 1).is_ok());
        assert!(matches!(
            verify(&second, 32, 32, 1),
            Err(MarkerError::MarkerMismatch { .. })
        ));

        // And the two really do differ nearly everywhere, so the mismatch is
        // not a lucky single byte.
        let differing = first[HEADER_LEN..]
            .iter()
            .zip(&second[HEADER_LEN..])
            .filter(|(a, b)| a != b)
            .count();
        assert!(
            differing > (32 * 32 * 9) / 10,
            "only {differing} of 1024 markers differ between two seeds"
        );
    }

    /// **A real capture fails rather than passing silently.**
    ///
    /// The headers of the formats a real backend would return. None of them
    /// carries the magic, so none of them can be mistaken for fixture output
    /// however long it is.
    #[test]
    fn a_real_capture_is_refused_at_the_magic() {
        let png = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR-and-so-on".to_vec();
        let jpeg = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01-and-so-on".to_vec();
        let bmp = b"BM\x36\x00\x0c\x00\x00\x00\x00\x00\x36\x00\x00\x00".to_vec();
        for real in [png, jpeg, bmp] {
            assert_eq!(decode(&real), Err(MarkerError::NotSynthetic));
            assert_eq!(
                verify(&real, 32, 32, 1),
                Err(MarkerError::NotSynthetic),
                "a real capture format must never verify"
            );
        }
        // Length is not the discriminator: a blob the exact length of a valid
        // 32x32 fixture image, but without the magic, is still refused.
        let impostor = vec![0u8; HEADER_LEN + 32 * 32];
        assert_eq!(decode(&impostor), Err(MarkerError::NotSynthetic));
    }

    #[test]
    fn a_truncated_or_padded_image_is_refused_by_length_rather_than_accepted_short() {
        let blob = encode(16, 16, 7).unwrap();
        let mut truncated = blob.clone();
        truncated.pop();
        assert_eq!(decode(&truncated), Err(MarkerError::LengthMismatch));

        let mut padded = blob.clone();
        padded.push(0);
        assert_eq!(decode(&padded), Err(MarkerError::LengthMismatch));

        // Only the header: shaped right, no body.
        assert_eq!(
            decode(&blob[..HEADER_LEN]),
            Err(MarkerError::LengthMismatch)
        );
    }

    #[test]
    fn impossible_dimensions_are_refused_on_both_encode_and_decode() {
        assert_eq!(encode(0, 16, 1), Err(MarkerError::BadDimensions));
        assert_eq!(encode(16, 0, 1), Err(MarkerError::BadDimensions));
        assert_eq!(
            encode(MAX_DIMENSION + 1, 16, 1),
            Err(MarkerError::BadDimensions)
        );

        let mut blob = encode(16, 16, 1).unwrap();
        blob[8] = 0;
        blob[9] = 0;
        assert_eq!(decode(&blob), Err(MarkerError::BadDimensions));

        // A correct image verified against the wrong dimensions is refused,
        // so `verify` is not simply trusting the header it was handed.
        let good = encode(16, 16, 1).unwrap();
        assert_eq!(verify(&good, 16, 8, 1), Err(MarkerError::BadDimensions));
    }

    /// A single flipped byte in the middle is caught and located, so the check
    /// really is per-pixel and not a whole-buffer equality in disguise.
    #[test]
    fn one_corrupted_marker_is_located() {
        let mut blob = encode(8, 8, 3).unwrap();
        let index = HEADER_LEN + 5 * 8 + 2;
        blob[index] = blob[index].wrapping_add(1);
        assert_eq!(
            verify(&blob, 8, 8, 3),
            Err(MarkerError::MarkerMismatch { x: 2, y: 5 })
        );
    }
}
