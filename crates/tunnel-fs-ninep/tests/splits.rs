//! Split independence, coalescing, and seeded dependency-free fuzzing.
//!
//! The property under test is that the incremental decoder's output depends on
//! the **bytes**, never on how they were chunked: a 9P record may span tunnel
//! DATA frames and several may share one, so a decoder that behaved differently
//! at a chunk boundary would make the relay's framing visible to the protocol.

mod common;

use common::{
    FIXTURE_MSIZE, Rng, decode_chunks, decode_chunks_fin, fixtures, one_byte_chunks, raw_frame,
};
use tunnel_fs_ninep::{
    CodecError, Frame, FrameDecoder, MAX_MESSAGE_BYTES, Message, MessageType, decode_exact,
};

/// Every fixture's bytes, concatenated: one stream carrying all 41 message
/// types plus the two `Rlerror` codes.
fn every_fixture_stream() -> (Vec<u8>, Vec<Frame>) {
    let mut bytes = Vec::new();
    let mut frames = Vec::new();
    for (_, frame) in fixtures() {
        bytes.extend_from_slice(&frame.to_bytes(FIXTURE_MSIZE).expect("fixture encodes"));
        frames.push(frame);
    }
    (bytes, frames)
}

type Run = (Vec<Frame>, Option<CodecError>);

/// Assert the decoder's output is identical for the whole buffer, one-byte
/// chunks, and **every** single split point.
fn assert_split_independent(bytes: &[u8], msize: u32) -> Run {
    let whole = decode_chunks(&[bytes], msize);
    assert_eq!(
        decode_chunks(&one_byte_chunks(bytes), msize),
        whole,
        "one-byte chunking"
    );
    for split in 0..=bytes.len() {
        let (a, b) = bytes.split_at(split);
        assert_eq!(decode_chunks(&[a, b], msize), whole, "split at {split}");
    }
    whole
}

#[test]
fn every_split_of_every_message_type_decodes_identically() {
    let (bytes, frames) = every_fixture_stream();
    let (decoded, error) = assert_split_independent(&bytes, FIXTURE_MSIZE);
    assert_eq!(error, None);
    assert_eq!(decoded, frames);
    assert_eq!(decoded.len(), fixtures().len());
}

#[test]
fn every_three_way_split_of_a_representative_set_decodes_identically() {
    // Exhaustive two-way splits above; this adds every pair of cut points over
    // a shorter stream, so a boundary landing inside the size prefix *and*
    // inside a body in the same run is covered.
    let mut bytes = Vec::new();
    let mut expected = Vec::new();
    for (name, frame) in fixtures() {
        if !matches!(
            name,
            "tversion" | "twalk" | "rwalk" | "rread" | "rgetattr" | "rclunk"
        ) {
            continue;
        }
        bytes.extend_from_slice(&frame.to_bytes(FIXTURE_MSIZE).unwrap());
        expected.push(frame);
    }
    for first in 0..=bytes.len() {
        for second in first..=bytes.len() {
            let (a, rest) = bytes.split_at(first);
            let (b, c) = rest.split_at(second - first);
            assert_eq!(
                decode_chunks(&[a, b, c], FIXTURE_MSIZE),
                (expected.clone(), None),
                "splits at {first} and {second}"
            );
        }
    }
}

#[test]
fn coalesced_frames_decode_as_consecutive_messages() {
    let one = Frame::new(1, Message::Tclunk { fid: 1 })
        .to_bytes(MAX_MESSAGE_BYTES)
        .unwrap();
    let mut stream = Vec::new();
    for _ in 0..64 {
        stream.extend_from_slice(&one);
    }
    let (frames, error) = decode_chunks(&[&stream], MAX_MESSAGE_BYTES);
    assert_eq!(error, None);
    assert_eq!(frames.len(), 64);
    // The consumer-WebSocket decoder refuses the same bytes, because there its
    // rule is one message per binary message.
    assert_eq!(
        decode_exact(&stream, MAX_MESSAGE_BYTES),
        Err(CodecError::TrailingBytes)
    );
}

#[test]
fn every_split_of_a_malformed_stream_reports_the_same_error() {
    let (mut bytes, _) = every_fixture_stream();
    // Corrupt the type byte of the third message.
    let mut at = 0usize;
    for (index, (_, frame)) in fixtures().into_iter().enumerate() {
        let len = frame.to_bytes(FIXTURE_MSIZE).unwrap().len();
        if index == 2 {
            bytes[at + 4] = 0xFE;
            break;
        }
        at += len;
    }
    let (frames, error) = assert_split_independent(&bytes, FIXTURE_MSIZE);
    assert_eq!(error, Some(CodecError::UnknownMessageType(0xFE)));
    assert_eq!(frames.len(), 2, "the two frames before the corruption");
}

#[test]
fn an_error_is_sticky_and_the_decoder_never_resynchronises() {
    let good = Frame::new(1, Message::Tclunk { fid: 1 })
        .to_bytes(MAX_MESSAGE_BYTES)
        .unwrap();
    let bad = raw_frame(0xFE, 1, &[]);
    let mut stream = bad.clone();
    stream.extend_from_slice(&good);

    let mut decoder = FrameDecoder::new();
    let mut input = &stream[..];
    assert_eq!(
        decoder.decode(&mut input),
        Err(CodecError::UnknownMessageType(0xFE))
    );
    assert_eq!(
        decoder.failure(),
        Some(CodecError::UnknownMessageType(0xFE))
    );
    // A well-formed frame after the violation is not decoded: there is no
    // trustworthy boundary left to resynchronise on.
    let mut more = &good[..];
    assert_eq!(
        decoder.decode(&mut more),
        Err(CodecError::UnknownMessageType(0xFE))
    );
}

#[test]
fn a_stream_that_ends_inside_a_frame_is_reported_at_fin() {
    let bytes = Frame::new(1, Message::Tclunk { fid: 1 })
        .to_bytes(MAX_MESSAGE_BYTES)
        .unwrap();
    for cut in 1..bytes.len() {
        let mut decoder = FrameDecoder::new();
        let mut input = &bytes[..cut];
        assert_eq!(decoder.decode(&mut input), Ok(None));
        assert!(!decoder.is_idle(), "a partial frame is not idle at {cut}");
        assert_eq!(
            decoder.fin(),
            Err(CodecError::TruncatedBody),
            "cut at {cut}"
        );
    }
    let mut decoder = FrameDecoder::new();
    let mut input = &bytes[..];
    assert!(decoder.decode(&mut input).unwrap().is_some());
    assert!(decoder.is_idle());
    assert_eq!(decoder.fin(), Ok(()));
}

#[test]
fn the_decoder_bound_can_only_be_reduced_and_only_at_a_boundary() {
    let mut decoder = FrameDecoder::new();
    assert_eq!(decoder.msize(), MAX_MESSAGE_BYTES);
    assert!(decoder.apply_msize(4_096).is_ok());
    assert_eq!(decoder.msize(), 4_096);
    assert!(
        decoder.apply_msize(8_192).is_err(),
        "raising the bound would let a peer re-frame what it already sent"
    );
    assert!(decoder.apply_msize(255).is_err(), "below the floor");

    // Mid-frame it is refused whatever the value.
    let bytes = Frame::new(1, Message::Tclunk { fid: 1 })
        .to_bytes(MAX_MESSAGE_BYTES)
        .unwrap();
    let mut input = &bytes[..5];
    assert_eq!(decoder.decode(&mut input), Ok(None));
    assert!(decoder.apply_msize(1_024).is_err());
}

#[test]
fn seeded_random_chunking_matches_whole_decoding() {
    let (bytes, frames) = every_fixture_stream();
    let mut rng = Rng::new(0x9e37_79b9_7f4a_7c15);
    for round in 0..200 {
        let mut chunks = Vec::new();
        let mut rest = &bytes[..];
        while !rest.is_empty() {
            let take = (rng.below(97) + 1).min(rest.len());
            let (a, b) = rest.split_at(take);
            chunks.push(a);
            rest = b;
        }
        assert_eq!(
            decode_chunks(&chunks, FIXTURE_MSIZE),
            (frames.clone(), None),
            "round {round}"
        );
    }
}

#[test]
fn seeded_garbage_never_panics_and_never_over_allocates() {
    let mut rng = Rng::new(0xbad_5eed);
    let mut accepted = 0u32;
    let mut refused = 0u32;
    for msize in [tunnel_fs_ninep::MIN_MSIZE, 4_096, MAX_MESSAGE_BYTES] {
        for _ in 0..3_000 {
            let len = rng.below(600);
            let garbage = rng.bytes(len);

            let mut decoder = FrameDecoder::with_msize(msize);
            let mut input = &garbage[..];
            loop {
                match decoder.decode(&mut input) {
                    Ok(Some(_)) => accepted += 1,
                    Ok(None) => break,
                    Err(_) => {
                        refused += 1;
                        break;
                    }
                }
                // The decoder never retains more than the negotiated maximum,
                // whatever a frame declares.
                assert!(decoder.retained_len() <= msize as usize);
            }
            assert!(decoder.retained_len() <= msize as usize);

            // One-byte chunking must reach the same verdict.
            let whole = decode_chunks(&[&garbage], msize);
            assert_eq!(decode_chunks(&one_byte_chunks(&garbage), msize), whole);

            let _ = decode_exact(&garbage, msize);
        }
    }
    assert!(
        refused > 5_000,
        "only {refused} garbage inputs were refused"
    );
    let _ = accepted;
}

#[test]
fn seeded_single_byte_mutations_are_refused_or_still_well_formed() {
    let (bytes, frames) = every_fixture_stream();
    let mut rng = Rng::new(0x1234_5678);
    let mut refused = 0u32;
    let mut accepted = 0u32;
    for _ in 0..4_000 {
        let mut mutated = bytes.clone();
        let index = rng.below(mutated.len());
        let value = rng.next_u64() as u8;
        if mutated[index] == value {
            continue;
        }
        mutated[index] = value;
        let whole = decode_chunks_fin(&[&mutated], FIXTURE_MSIZE);
        assert_eq!(
            decode_chunks_fin(&one_byte_chunks(&mutated), FIXTURE_MSIZE),
            whole,
            "chunking changed the verdict for a mutation at {index}"
        );
        if whole.1.is_some() {
            refused += 1;
        } else {
            // An accepted mutation may only have changed a payload byte or a
            // numeric field; the message grammar is intact.
            assert_eq!(whole.0.len(), frames.len());
            accepted += 1;
        }
    }
    assert!(refused > 500, "only {refused} mutations were refused");
    assert!(accepted > 500, "only {accepted} mutations were accepted");
}

#[test]
fn a_declared_size_never_drives_an_allocation_above_msize() {
    // The pathological case: a tiny buffer declaring a huge frame.  The bound
    // is applied to the declared size before a byte of body is reserved.
    for declared in [MAX_MESSAGE_BYTES, MAX_MESSAGE_BYTES + 1, u32::MAX] {
        let mut bytes = declared.to_le_bytes().to_vec();
        bytes.push(MessageType::Twrite.code());
        bytes.extend_from_slice(&1u16.to_le_bytes());
        let mut decoder = FrameDecoder::with_msize(512);
        let mut input = &bytes[..];
        let result = decoder.decode(&mut input);
        assert!(result.is_err(), "declared {declared} was accepted");
        assert_eq!(decoder.retained_len(), 0);
    }
}
