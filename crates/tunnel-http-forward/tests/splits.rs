//! Split independence, coalescing, binary bodies, and seeded random input.

mod common;

use common::*;
use tunnel_http_forward::{
    CodecError, END_RECORD, MAX_BODY_PAYLOAD_LEN, Method, RecordDecoder, RecordHeader, RecordKind,
    RequestReader, ResponseReader, encode_body, encode_record, encode_request_head,
    encode_response_head,
};

fn request_exchange(body: &[u8]) -> Vec<u8> {
    let mut head = doc_request_head();
    head.body_length = Some(body.len() as u64);
    let mut out = Vec::new();
    encode_request_head(&head, &request_policy(), &mut out).unwrap();
    encode_body(body, &mut out);
    out.extend_from_slice(&END_RECORD);
    out
}

fn all_bytes_body() -> Vec<u8> {
    (0..=255u8).collect()
}

/// Assert decoder and reader output is identical for whole, one-byte, and
/// every single split point.
fn assert_split_independent(bytes: &[u8]) {
    let (whole_events, whole_error) = decode_chunks(&[bytes]);
    let mut reader = RequestReader::new(request_policy());
    let (whole_flow, whole_flow_error) = run_request(&mut reader, &[bytes], true);

    let ones = one_byte_chunks(bytes);
    assert_eq!(decode_chunks(&ones), (whole_events.clone(), whole_error));
    let mut reader = RequestReader::new(request_policy());
    assert_eq!(
        run_request(&mut reader, &ones, true),
        (whole_flow.clone(), whole_flow_error)
    );

    for split in 0..=bytes.len() {
        let (a, b) = bytes.split_at(split);
        assert_eq!(
            decode_chunks(&[a, b]),
            (whole_events.clone(), whole_error),
            "decoder split at {split}"
        );
        let mut reader = RequestReader::new(request_policy());
        assert_eq!(
            run_request(&mut reader, &[a, b], true),
            (whole_flow.clone(), whole_flow_error),
            "reader split at {split}"
        );
    }
}

#[test]
fn every_split_of_a_binary_request_is_identical() {
    let body = all_bytes_body();
    let bytes = request_exchange(&body);
    assert_split_independent(&bytes);
    let mut reader = RequestReader::new(request_policy());
    let (flow, error) = run_request(&mut reader, &[&bytes], true);
    assert_eq!(error, None);
    let mut head = doc_request_head();
    head.body_length = Some(256);
    assert_eq!(
        flow,
        vec![Flow::Head(head), Flow::Body(body), Flow::End, Flow::Fin]
    );
}

#[test]
fn every_split_of_an_empty_body_request_is_identical() {
    for declared in [Some(0), None] {
        let mut head = doc_request_head();
        head.body_length = declared;
        let mut bytes = Vec::new();
        encode_request_head(&head, &request_policy(), &mut bytes).unwrap();
        bytes.extend_from_slice(&END_RECORD);
        assert_split_independent(&bytes);
        let mut reader = RequestReader::new(request_policy());
        let (flow, error) = run_request(&mut reader, &[&bytes], true);
        assert_eq!(error, None);
        assert_eq!(flow, vec![Flow::Head(head), Flow::End, Flow::Fin]);
    }
}

#[test]
fn every_split_of_many_small_body_records_is_identical() {
    let mut head = doc_request_head();
    head.body_length = None;
    let mut bytes = Vec::new();
    encode_request_head(&head, &request_policy(), &mut bytes).unwrap();
    let mut expected_body = Vec::new();
    for value in 0..=255u8 {
        // Records of 1, 2, 3 bytes cycling, covering every byte value.
        let len = usize::from(value % 3) + 1;
        let chunk = vec![value; len];
        encode_record(RecordKind::Body, &chunk, &mut bytes).unwrap();
        expected_body.extend_from_slice(&chunk);
    }
    bytes.extend_from_slice(&END_RECORD);
    assert_split_independent(&bytes);

    let mut reader = RequestReader::new(request_policy());
    let (flow, error) = run_request(&mut reader, &[&bytes], true);
    assert_eq!(error, None);
    assert_eq!(flow[1], Flow::Body(expected_body));
    let (events, error) = decode_chunks(&[&bytes]);
    assert_eq!(error, None);
    // Header+Head, then 256 × (Header+BodyRecord), then END header.
    assert_eq!(events.len(), 2 + 256 * 2 + 1);
}

#[test]
fn every_split_of_a_malformed_stream_reports_the_same_error() {
    let mut bytes = request_exchange(b"abc");
    // Corrupt END's flags byte.
    let end = bytes.len() - 8;
    bytes[end + 1] = 1;
    let (_, error) = decode_chunks(&[&bytes]);
    assert_eq!(error, Some(CodecError::NonzeroFlags));
    assert_split_independent(&bytes);
}

#[test]
fn response_with_maximum_records_every_split_via_three_way_cuts() {
    let body: Vec<u8> = (0..MAX_BODY_PAYLOAD_LEN + 300)
        .map(|i| (i * 7 % 256) as u8)
        .collect();
    let mut head = doc_response_head();
    head.body_length = Some(body.len() as u64);
    let mut bytes = Vec::new();
    encode_response_head(&head, &response_policy(), Method::Get, &mut bytes).unwrap();
    encode_body(&body, &mut bytes);
    bytes.extend_from_slice(&END_RECORD);
    let expected = vec![
        Flow::Head(head),
        Flow::Body(body.clone()),
        Flow::End,
        Flow::Fin,
    ];
    // Exhaustive single splits across the head and both record boundaries.
    let second_header = bytes.len() - 8 - 300 - 8;
    let interesting: Vec<usize> = (0..140)
        .chain(second_header - 40..=second_header + 40)
        .chain(bytes.len() - 20..=bytes.len())
        .collect();
    for split in interesting {
        let (a, b) = bytes.split_at(split);
        let mut reader = ResponseReader::new(response_policy(), Method::Get);
        assert_eq!(
            run_response(&mut reader, &[a, b], true),
            (expected.clone(), None),
            "split {split}"
        );
    }
    let mut reader = ResponseReader::new(response_policy(), Method::Get);
    assert_eq!(
        run_response(&mut reader, &one_byte_chunks(&bytes), true),
        (expected, None)
    );
}

#[test]
fn coalesced_exchanges_decode_as_consecutive_records() {
    let mut bytes = Vec::new();
    encode_record(RecordKind::Body, b"a", &mut bytes).unwrap();
    encode_record(RecordKind::Body, b"bc", &mut bytes).unwrap();
    bytes.extend_from_slice(&END_RECORD);
    bytes.extend_from_slice(&END_RECORD);
    let (events, error) = decode_chunks(&[&bytes]);
    assert_eq!(error, None);
    let end = Normal::Header(RecordHeader::new(RecordKind::End, 0).unwrap());
    assert_eq!(
        events,
        vec![
            Normal::Header(RecordHeader::new(RecordKind::Body, 1).unwrap()),
            Normal::BodyRecord(b"a".to_vec()),
            Normal::Header(RecordHeader::new(RecordKind::Body, 2).unwrap()),
            Normal::BodyRecord(b"bc".to_vec()),
            end.clone(),
            end,
        ]
    );
}

#[test]
fn seeded_random_chunking_matches_whole_decoding() {
    let mut rng = Rng::new(0x5eed_0001);
    for round in 0..200 {
        let len = rng.below(3 * 1024);
        let body = rng.bytes(len);
        let bytes = request_exchange(&body);
        let mut chunks = Vec::new();
        let mut rest = &bytes[..];
        while !rest.is_empty() {
            let take = (rng.below(40) + 1).min(rest.len());
            let (a, b) = rest.split_at(take);
            chunks.push(a);
            rest = b;
        }
        let mut reader = RequestReader::new(request_policy());
        let (flow, error) = run_request(&mut reader, &chunks, true);
        assert_eq!(error, None, "round {round}");
        let mut head = doc_request_head();
        head.body_length = Some(body.len() as u64);
        let mut expected = vec![Flow::Head(head)];
        if !body.is_empty() {
            expected.push(Flow::Body(body));
        }
        expected.extend([Flow::End, Flow::Fin]);
        assert_eq!(flow, expected, "round {round}");
    }
}

#[test]
fn seeded_random_garbage_never_panics_and_stays_bounded() {
    let mut rng = Rng::new(0xbad_5eed);
    for _ in 0..2_000 {
        let len = rng.below(256);
        let garbage = rng.bytes(len);
        let mut decoder = RecordDecoder::new();
        let mut input = &garbage[..];
        while let Ok(Some(_)) = decoder.decode(&mut input) {
            assert!(decoder.retained_len() <= tunnel_http_forward::MAX_HEAD_PAYLOAD_LEN);
        }
        let mut reader = RequestReader::new(request_policy());
        let _ = run_request(&mut reader, &one_byte_chunks(&garbage), true);
        let mut reader = ResponseReader::new(response_policy(), Method::Post);
        let _ = run_response(&mut reader, &[&garbage], true);
    }
}

#[test]
fn seeded_single_byte_mutations_are_rejected_or_well_formed() {
    let bytes = request_exchange(b"payload bytes");
    let (baseline, _) = {
        let mut reader = RequestReader::new(request_policy());
        run_request(&mut reader, &[&bytes], true)
    };
    let mut rng = Rng::new(42);
    let mut rejected = 0;
    for _ in 0..3_000 {
        let mut mutated = bytes.clone();
        let index = rng.below(mutated.len());
        let value = rng.next_u64() as u8;
        if mutated[index] == value {
            continue;
        }
        mutated[index] = value;
        let mut whole = RequestReader::new(request_policy());
        let whole_result = run_request(&mut whole, &[&mutated], true);
        let mut ones = RequestReader::new(request_policy());
        assert_eq!(
            run_request(&mut ones, &one_byte_chunks(&mutated), true),
            whole_result
        );
        if whole_result.1.is_some() {
            rejected += 1;
        } else {
            // Accepted mutations may only alter body bytes or insignificant
            // head bytes that still validate; the grammar is preserved.
            assert_eq!(whole_result.0.len(), baseline.len());
        }
    }
    assert!(rejected > 1_000, "only {rejected} mutations rejected");
}
