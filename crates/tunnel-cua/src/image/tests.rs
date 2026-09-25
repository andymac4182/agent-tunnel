use serde_json::json;

use super::*;

/// A 1x1 RGBA PNG produced by an ordinary encoder, not by this crate, so the
/// CRC and the IHDR layout are checked against something this module did not
/// write. Its IHDR CRC is `0x1f15c489`.
const ONE_BY_ONE_PNG_BASE64: &str = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==";

#[test]
fn the_crc_is_the_standard_one() {
    // The published CRC-32 check value.
    assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    assert_eq!(crc32(b""), 0);
}

#[test]
fn base64_decodes_the_rfc_vectors_and_refuses_malformed_input() {
    assert_eq!(decode_base64("").unwrap(), b"");
    assert_eq!(decode_base64("TWFu").unwrap(), b"Man");
    assert_eq!(decode_base64("TWE=").unwrap(), b"Ma");
    assert_eq!(decode_base64("TQ==").unwrap(), b"M");
    assert_eq!(decode_base64("Zm9vYmFy").unwrap(), b"foobar");
    for refused in ["TWF", "TW=u", "T===", "TQ==TWFu", "TW!u", "TWFu\n"] {
        assert_eq!(decode_base64(refused), None, "{refused:?}");
    }
}

#[test]
fn a_real_png_header_yields_its_dimensions() {
    assert_eq!(
        png_dimensions_from_base64(ONE_BY_ONE_PNG_BASE64),
        Ok((1, 1))
    );
    // Only the header span is decoded: the rest of the string may be
    // anything, which is what makes this cheap on a 1920-wide capture.
    let mut truncated_body = ONE_BY_ONE_PNG_BASE64[..PNG_HEADER_BASE64_CHARS].to_owned();
    truncated_body.push_str("!!!! not base64 at all");
    assert_eq!(png_dimensions_from_base64(&truncated_body), Ok((1, 1)));
}

#[test]
fn every_malformed_header_is_refused_by_name() {
    let good = decode_base64(ONE_BY_ONE_PNG_BASE64).unwrap();

    assert_eq!(
        png_dimensions(&good[..PNG_HEADER_BYTES - 1]),
        Err(ImageHeaderError::Truncated)
    );

    let mut signature = good.clone();
    signature[1] = b'Q';
    assert_eq!(
        png_dimensions(&signature),
        Err(ImageHeaderError::BadSignature)
    );

    let mut chunk = good.clone();
    chunk[12..16].copy_from_slice(b"IDAT");
    assert_eq!(png_dimensions(&chunk), Err(ImageHeaderError::NotIhdr));

    // **The CRC is load-bearing**: change one dimension byte and leave the
    // checksum, and the header is refused rather than read with the wrong
    // bounds.
    let mut width = good.clone();
    width[19] = 2;
    assert_eq!(png_dimensions(&width), Err(ImageHeaderError::BadCrc));
    // ...and recomputing the checksum makes the same bytes readable, so the
    // refusal above was the CRC and not the edit.
    let crc = crc32(&width[12..29]).to_be_bytes();
    width[29..33].copy_from_slice(&crc);
    assert_eq!(png_dimensions(&width), Ok((2, 1)));

    let mut zero = good;
    zero[16..20].copy_from_slice(&[0, 0, 0, 0]);
    let crc = crc32(&zero[12..29]).to_be_bytes();
    zero[29..33].copy_from_slice(&crc);
    assert_eq!(png_dimensions(&zero), Err(ImageHeaderError::ZeroDimension));

    assert_eq!(
        png_dimensions_from_base64("iVBORw0KGgo"),
        Err(ImageHeaderError::Truncated)
    );
    let mut not_base64 = ONE_BY_ONE_PNG_BASE64.to_owned();
    not_base64.replace_range(4..5, "*");
    assert_eq!(
        png_dimensions_from_base64(&not_base64),
        Err(ImageHeaderError::NotBase64)
    );
}

/// **The released response shape, member for member.** macOS, Linux, Windows
/// and Android answer `{success, image_data, format}`; VNC answers
/// `{success, image_data}`. Neither carries `width`, `height` or a scale.
#[test]
fn the_released_screenshot_shapes_yield_dimensions_and_nothing_else_is_read() {
    for result in [
        json!({"success": true, "image_data": ONE_BY_ONE_PNG_BASE64, "format": "png"}),
        json!({"success": true, "image_data": ONE_BY_ONE_PNG_BASE64}),
    ] {
        assert_eq!(capture_dimensions(&result), Ok((1, 1)), "{result}");
    }
    // Members the released server never sends are not consulted, even when
    // present and wrong.
    let decoy = json!({
        "success": true,
        "image_data": ONE_BY_ONE_PNG_BASE64,
        "format": "png",
        "width": 640,
        "height": 480,
    });
    assert_eq!(capture_dimensions(&decoy), Ok((1, 1)));

    assert_eq!(
        capture_dimensions(
            &json!({"success": true, "image_data": ONE_BY_ONE_PNG_BASE64, "format": "jpeg"})
        ),
        Err(ImageHeaderError::NotPng)
    );
    assert_eq!(
        capture_dimensions(&json!({"success": true, "format": "png"})),
        Err(ImageHeaderError::Absent)
    );
    assert_eq!(
        capture_dimensions(&json!({"success": true, "image_data": 7})),
        Err(ImageHeaderError::Absent)
    );
}
