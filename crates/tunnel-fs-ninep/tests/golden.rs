//! Byte-exact golden fixtures, one per message type in the profile.
//!
//! The files under `fixtures/` are the artefact this gate owes the TypeScript
//! client: hex, one message per file, with a comment header naming the type and
//! tag.  They are checked in and compared **byte for byte** in both directions,
//! so a change to the wire format cannot pass review as an incidental diff.
//!
//! To regenerate after a deliberate format change:
//!
//! ```text
//! cargo test -p tunnel-fs-ninep --test golden -- --ignored regenerate
//! ```
//!
//! and then read the diff.  The regeneration test is `#[ignore]`d precisely so
//! that it cannot rewrite the evidence during an ordinary run.

mod common;

use std::collections::BTreeSet;

use common::{FIXTURE_MSIZE, encode_hex, fixture_dir, fixtures, read_fixture};
use tunnel_fs_ninep::{Frame, MessageType, decode_exact};

#[test]
fn every_fixture_encodes_to_its_checked_in_bytes() {
    for (stem, frame) in fixtures() {
        let encoded = frame
            .to_bytes(FIXTURE_MSIZE)
            .unwrap_or_else(|error| panic!("{stem} encode: {error}"));
        assert_eq!(encoded, read_fixture(stem), "{stem} bytes differ");
    }
}

#[test]
fn every_fixture_decodes_back_to_its_frame() {
    for (stem, frame) in fixtures() {
        let decoded = decode_exact(&read_fixture(stem), FIXTURE_MSIZE)
            .unwrap_or_else(|error| panic!("{stem} decode: {error}"));
        assert_eq!(decoded, frame, "{stem} round trip");
    }
}

#[test]
fn the_declared_size_is_the_file_length_and_the_header_is_seven_bytes() {
    for (stem, _) in fixtures() {
        let bytes = read_fixture(stem);
        let declared = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        assert_eq!(declared as usize, bytes.len(), "{stem} declared size");
        assert!(bytes.len() >= 7, "{stem} shorter than the header");
    }
}

#[test]
fn the_type_byte_and_tag_are_where_the_layout_says() {
    for (stem, frame) in fixtures() {
        let bytes = read_fixture(stem);
        assert_eq!(bytes[4], frame.message_type().code(), "{stem} type byte");
        assert_eq!(
            u16::from_le_bytes([bytes[5], bytes[6]]),
            frame.tag,
            "{stem} tag"
        );
    }
}

#[test]
fn every_message_type_in_the_profile_has_a_fixture() {
    let covered: BTreeSet<MessageType> = fixtures()
        .into_iter()
        .map(|(_, frame)| frame.message_type())
        .collect();
    let missing: Vec<&str> = MessageType::ALL
        .into_iter()
        .filter(|message_type| !covered.contains(message_type))
        .map(MessageType::as_str)
        .collect();
    assert!(missing.is_empty(), "no golden fixture for {missing:?}");
    assert_eq!(
        covered.len(),
        MessageType::ALL.len(),
        "the profile has {} types",
        MessageType::ALL.len()
    );
}

#[test]
fn the_index_lists_exactly_the_fixture_files() {
    let index: BTreeSet<String> = std::fs::read_to_string(fixture_dir().join("index.txt"))
        .expect("fixtures/index.txt")
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(ToOwned::to_owned)
        .collect();
    let present: BTreeSet<String> = std::fs::read_dir(fixture_dir())
        .expect("fixtures/")
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.ends_with(".hex"))
        .collect();
    assert_eq!(index, present, "fixtures/index.txt is out of date");

    let declared: BTreeSet<String> = fixtures()
        .into_iter()
        .map(|(stem, _)| format!("{stem}.hex"))
        .collect();
    assert_eq!(declared, present, "a fixture file has no test fixture");
}

/// Rewrite every fixture file from the encoder.  Run deliberately, never in an
/// ordinary test run.
#[test]
#[ignore = "regenerates checked-in evidence; run deliberately and read the diff"]
fn regenerate() {
    let dir = fixture_dir();
    std::fs::create_dir_all(&dir).expect("fixtures/");
    let mut names = Vec::new();
    for (stem, frame) in fixtures() {
        let bytes = frame.to_bytes(FIXTURE_MSIZE).expect("fixture encodes");
        let body = describe(stem, &frame, &bytes);
        std::fs::write(dir.join(format!("{stem}.hex")), body).expect("write fixture");
        names.push(format!("{stem}.hex"));
    }
    names.sort();
    std::fs::write(dir.join("index.txt"), names.join("\n") + "\n").expect("write index");
}

fn describe(stem: &str, frame: &Frame, bytes: &[u8]) -> String {
    format!(
        "# agent-tunnel 9P2000.L golden fixture\n\
         # name: {stem}\n\
         # type: {} ({})\n\
         # tag: {}\n\
         # size: {} bytes, msize {}\n\
         # Little-endian; string[s] is a 16-bit BYTE count of UTF-8.\n\
         {}",
        frame.message_type().as_str(),
        frame.message_type().code(),
        frame.tag,
        bytes.len(),
        FIXTURE_MSIZE,
        encode_hex(bytes),
    )
}
