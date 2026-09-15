//! Golden record fixtures and fixed-header validation.

mod common;

use common::*;
use tunnel_http_forward::{
    CodecError, END_RECORD, HttpErrorCode, MAX_BODY_PAYLOAD_LEN, MAX_HEAD_PAYLOAD_LEN,
    MAX_RECORD_LEN, Method, RECORD_HEADER_LEN, RecordDecoder, RecordEvent, RecordHeader,
    RecordKind, encode_body, encode_record, encode_request_head, encode_response_head,
};

#[test]
fn limits_are_pinned() {
    assert_eq!(RECORD_HEADER_LEN, 8);
    assert_eq!(MAX_RECORD_LEN, 65_536);
    assert_eq!(MAX_BODY_PAYLOAD_LEN, 65_528);
    assert_eq!(MAX_HEAD_PAYLOAD_LEN, 16_384);
    assert_eq!(RecordKind::RequestHead.code(), 0x01);
    assert_eq!(RecordKind::ResponseHead.code(), 0x02);
    assert_eq!(RecordKind::Body.code(), 0x03);
    assert_eq!(RecordKind::End.code(), 0x04);
}

#[test]
fn golden_document_body_hello() {
    let expected = [
        0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x68, 0x65, 0x6c, 0x6c, 0x6f,
    ];
    let mut out = Vec::new();
    encode_record(RecordKind::Body, b"hello", &mut out).unwrap();
    assert_eq!(out, expected);
    let mut via_body = Vec::new();
    encode_body(b"hello", &mut via_body);
    assert_eq!(via_body, expected);
    let (events, error) = decode_chunks(&[&expected]);
    assert_eq!(error, None);
    assert_eq!(
        events,
        vec![
            Normal::Header(RecordHeader::new(RecordKind::Body, 5).unwrap()),
            Normal::BodyRecord(b"hello".to_vec()),
        ]
    );
}

#[test]
fn golden_document_end() {
    let expected = [0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    assert_eq!(END_RECORD, expected);
    let mut out = Vec::new();
    encode_record(RecordKind::End, b"", &mut out).unwrap();
    assert_eq!(out, expected);
    assert_eq!(
        RecordHeader::new(RecordKind::End, 0).unwrap().encode(),
        expected
    );
    let (events, error) = decode_chunks(&[&expected]);
    assert_eq!(error, None);
    assert_eq!(
        events,
        vec![Normal::Header(
            RecordHeader::new(RecordKind::End, 0).unwrap()
        )]
    );
}

#[test]
fn golden_request_head_matches_document_example() {
    let json = concat!(
        r#"{"method":"POST","path":"/acp","query":"","http_version":"2","#,
        r#""headers":[["content-type","application/json"],"#,
        r#"["accept","application/json, text/event-stream"],"#,
        r#"["acp-connection-id","connection-demo"],["acp-session-id","session-demo"]],"#,
        r#""body_length":null}"#
    );
    assert_eq!(json.len(), 251);
    let mut expected = vec![0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfb];
    expected.extend_from_slice(json.as_bytes());
    let mut out = Vec::new();
    encode_request_head(&doc_request_head(), &request_policy(), &mut out).unwrap();
    assert_eq!(out, expected);
}

#[test]
fn golden_response_heads() {
    let json = concat!(
        r#"{"status":200,"headers":[["content-type","text/event-stream"],"#,
        r#"["cache-control","no-store"]],"body_length":null}"#
    );
    assert_eq!(json.len(), 111);
    let mut expected = vec![0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x6f];
    expected.extend_from_slice(json.as_bytes());
    let mut out = Vec::new();
    encode_response_head(
        &doc_response_head(),
        &response_policy(),
        Method::Post,
        &mut out,
    )
    .unwrap();
    assert_eq!(out, expected);

    let mut no_content = Vec::new();
    let head = tunnel_http_forward::ResponseHead {
        status: 204,
        headers: vec![],
        body_length: Some(0),
    };
    encode_response_head(&head, &response_policy(), Method::Post, &mut no_content).unwrap();
    let mut expected = vec![0x02, 0, 0, 0, 0, 0, 0, 0x2d];
    expected.extend_from_slice(br#"{"status":204,"headers":[],"body_length":"0"}"#);
    assert_eq!(no_content, expected);
}

#[test]
fn length_is_big_endian_at_every_byte_position() {
    assert_eq!(
        RecordHeader::new(RecordKind::Body, 0x0102)
            .unwrap()
            .encode(),
        [0x03, 0, 0, 0, 0x00, 0x00, 0x01, 0x02]
    );
    assert_eq!(
        RecordHeader::new(RecordKind::Body, 65_528)
            .unwrap()
            .encode(),
        [0x03, 0, 0, 0, 0x00, 0x00, 0xff, 0xf8]
    );
    assert_eq!(
        RecordHeader::new(RecordKind::RequestHead, 16_384)
            .unwrap()
            .encode(),
        [0x01, 0, 0, 0, 0x00, 0x00, 0x40, 0x00]
    );
    // A little-endian reading of 0x0102 would be 0x0201 = 513.
    let header = RecordHeader::decode([0x03, 0, 0, 0, 0, 0, 0x01, 0x02]).unwrap();
    assert_eq!(header.payload_len(), 258);
    let header = RecordHeader::decode([0x03, 0, 0, 0, 0, 0, 0x02, 0x01]).unwrap();
    assert_eq!(header.payload_len(), 513);
}

#[test]
fn max_body_record_is_exactly_65536_bytes() {
    let payload: Vec<u8> = (0..MAX_BODY_PAYLOAD_LEN).map(|i| (i % 251) as u8).collect();
    let mut out = Vec::new();
    encode_record(RecordKind::Body, &payload, &mut out).unwrap();
    assert_eq!(out.len(), MAX_RECORD_LEN);
    let (events, error) = decode_chunks(&[&out]);
    assert_eq!(error, None);
    assert_eq!(events[1], Normal::BodyRecord(payload));
}

#[test]
fn encode_body_splits_into_maximal_records() {
    let body = vec![0xa5; MAX_BODY_PAYLOAD_LEN * 2 + 3];
    let mut out = Vec::new();
    encode_body(&body, &mut out);
    assert_eq!(out.len(), body.len() + 3 * RECORD_HEADER_LEN);
    assert_eq!(&out[..8], &[0x03, 0, 0, 0, 0, 0, 0xff, 0xf8]);
    let third = 2 * MAX_RECORD_LEN;
    assert_eq!(&out[third..third + 8], &[0x03, 0, 0, 0, 0, 0, 0, 3]);
    let mut empty = Vec::new();
    encode_body(b"", &mut empty);
    assert!(empty.is_empty());
}

fn header_error(bytes: [u8; 8]) -> Option<CodecError> {
    // The error must be reported with only the eight header bytes present,
    // i.e. before any payload is read or allocated.
    let mut decoder = RecordDecoder::new();
    let mut input = &bytes[..];
    let result = decoder.decode(&mut input);
    match result {
        Err(error) => {
            assert!(input.is_empty());
            assert_eq!(decoder.retained_len(), 0);
            Some(error)
        }
        Ok(Some(RecordEvent::Header(_))) => None,
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn unknown_kinds_rejected_at_header() {
    for kind in 0..=u8::MAX {
        let result = header_error([kind, 0, 0, 0, 0, 0, 0, 1]);
        match kind {
            0x01..=0x03 => assert_eq!(result, None, "kind {kind:#x}"),
            0x04 => assert_eq!(result, Some(CodecError::EndWithPayload)),
            other => assert_eq!(result, Some(CodecError::UnknownKind(other))),
        }
    }
}

#[test]
fn every_nonzero_flag_and_reserved_value_rejected() {
    for value in 1..=u8::MAX {
        assert_eq!(
            header_error([0x03, value, 0, 0, 0, 0, 0, 1]),
            Some(CodecError::NonzeroFlags)
        );
        assert_eq!(
            header_error([0x03, 0, value, 0, 0, 0, 0, 1]),
            Some(CodecError::NonzeroReserved)
        );
        assert_eq!(
            header_error([0x03, 0, 0, value, 0, 0, 0, 1]),
            Some(CodecError::NonzeroReserved)
        );
    }
    // Precedence: kind, then flags, then reserved, then length.
    assert_eq!(
        header_error([0x09, 1, 1, 1, 0xff, 0xff, 0xff, 0xff]),
        Some(CodecError::UnknownKind(9))
    );
    assert_eq!(
        header_error([0x03, 1, 1, 1, 0xff, 0xff, 0xff, 0xff]),
        Some(CodecError::NonzeroFlags)
    );
    assert_eq!(
        header_error([0x03, 0, 0, 1, 0xff, 0xff, 0xff, 0xff]),
        Some(CodecError::NonzeroReserved)
    );
}

fn with_len(kind: u8, len: u32) -> [u8; 8] {
    let l = len.to_be_bytes();
    [kind, 0, 0, 0, l[0], l[1], l[2], l[3]]
}

#[test]
fn body_lengths_at_boundaries() {
    assert_eq!(header_error(with_len(0x03, 0)), Some(CodecError::EmptyBody));
    assert_eq!(header_error(with_len(0x03, 1)), None);
    assert_eq!(header_error(with_len(0x03, 65_528)), None);
    assert_eq!(
        header_error(with_len(0x03, 65_529)),
        Some(CodecError::RecordTooLarge)
    );
    for len in [
        65_536,
        0x0001_0000_u32 + 8,
        0x7fff_ffff,
        0xffff_fff8,
        u32::MAX,
    ] {
        assert_eq!(
            header_error(with_len(0x03, len)),
            Some(CodecError::RecordTooLarge),
            "{len}"
        );
    }
}

#[test]
fn head_lengths_at_boundaries() {
    for kind in [0x01, 0x02] {
        assert_eq!(header_error(with_len(kind, 0)), Some(CodecError::EmptyHead));
        assert_eq!(header_error(with_len(kind, 1)), None);
        assert_eq!(header_error(with_len(kind, 16_384)), None);
        assert_eq!(
            header_error(with_len(kind, 16_385)),
            Some(CodecError::HeadTooLarge)
        );
        assert_eq!(
            header_error(with_len(kind, 65_528)),
            Some(CodecError::HeadTooLarge)
        );
        assert_eq!(
            header_error(with_len(kind, u32::MAX)),
            Some(CodecError::HeadTooLarge)
        );
    }
}

#[test]
fn end_lengths() {
    assert_eq!(header_error(with_len(0x04, 0)), None);
    for len in [1, 8, 65_528, u32::MAX] {
        assert_eq!(
            header_error(with_len(0x04, len)),
            Some(CodecError::EndWithPayload)
        );
    }
}

#[test]
fn encoder_rejects_invalid_lengths() {
    let mut out = Vec::new();
    assert_eq!(
        encode_record(RecordKind::Body, b"", &mut out),
        Err(CodecError::EmptyBody)
    );
    assert_eq!(
        encode_record(RecordKind::Body, &vec![0; 65_529], &mut out),
        Err(CodecError::RecordTooLarge)
    );
    assert_eq!(
        encode_record(RecordKind::RequestHead, &vec![b' '; 16_385], &mut out),
        Err(CodecError::HeadTooLarge)
    );
    assert_eq!(
        encode_record(RecordKind::End, b"x", &mut out),
        Err(CodecError::EndWithPayload)
    );
    assert!(out.is_empty(), "failed encodes must not append");
}

#[test]
fn head_payload_at_16_kib_decodes_and_16_kib_plus_one_does_not() {
    let payload = vec![b' '; 16_384];
    let mut record = Vec::new();
    encode_record(RecordKind::ResponseHead, &payload, &mut record).unwrap();
    let (events, error) = decode_chunks(&[&record]);
    assert_eq!(error, None);
    assert_eq!(events[1], Normal::Head(payload));

    let mut oversized = with_len(0x02, 16_385).to_vec();
    oversized.extend(vec![b' '; 16_385]);
    let (events, error) = decode_chunks(&[&oversized]);
    assert!(events.is_empty());
    assert_eq!(error, Some(CodecError::HeadTooLarge));
}

#[test]
fn errors_are_sticky_and_payload_free() {
    let mut decoder = RecordDecoder::new();
    let mut input = &[0x07u8, 0, 0, 0, 0, 0, 0, 0, 0x04][..];
    assert_eq!(decoder.decode(&mut input), Err(CodecError::UnknownKind(7)));
    let mut more = &END_RECORD[..];
    assert_eq!(decoder.decode(&mut more), Err(CodecError::UnknownKind(7)));

    assert_eq!(CodecError::RecordTooLarge.code(), HttpErrorCode::BadRecord);
    assert_eq!(
        CodecError::RecordTooLarge.code().as_str(),
        "HTTP_BAD_RECORD"
    );
    let text = CodecError::RecordTooLarge.to_string();
    assert!(text.starts_with("HTTP_BAD_RECORD"));
    assert!(text.len() < 128);
}

#[test]
fn partial_state_tracks_header_head_and_body() {
    let mut decoder = RecordDecoder::new();
    assert_eq!(decoder.partial(), None);
    let mut record = Vec::new();
    encode_record(RecordKind::Body, &[1, 2, 3, 4], &mut record).unwrap();
    let mut input = &record[..3];
    assert_eq!(decoder.decode(&mut input), Ok(None));
    let partial = decoder.partial().unwrap();
    assert_eq!(
        (
            partial.ordinal,
            partial.kind,
            partial.received,
            partial.total
        ),
        (1, None, 3, None)
    );
    let mut input = &record[3..9];
    assert!(matches!(
        decoder.decode(&mut input),
        Ok(Some(RecordEvent::Header(_)))
    ));
    let partial = decoder.partial().unwrap();
    assert_eq!(partial.received, 8);
    assert_eq!(partial.total, Some(12));
    assert!(matches!(
        decoder.decode(&mut input),
        Ok(Some(RecordEvent::Body {
            data: [1],
            record_done: false
        }))
    ));
    assert_eq!(decoder.partial().unwrap().received, 9);
    let mut rest = &record[9..];
    assert!(matches!(
        decoder.decode(&mut rest),
        Ok(Some(RecordEvent::Body {
            data: [2, 3, 4],
            record_done: true
        }))
    ));
    assert_eq!(decoder.partial(), None);
    assert!(decoder.is_idle());
    let mut next = &END_RECORD[..1];
    assert_eq!(decoder.decode(&mut next), Ok(None));
    assert_eq!(decoder.partial().unwrap().ordinal, 2);
}

#[test]
fn body_fragments_are_not_retained() {
    let mut decoder = RecordDecoder::new();
    let mut record = Vec::new();
    encode_record(RecordKind::Body, &vec![9; 65_528], &mut record).unwrap();
    for chunk in record.chunks(1000) {
        let mut input = chunk;
        while let Some(event) = decoder.decode(&mut input).unwrap() {
            let _ = event;
        }
        // Only an unfinished header is ever retained for BODY records.
        assert!(decoder.retained_len() < RECORD_HEADER_LEN);
    }
}

#[test]
fn head_retention_is_bounded_by_the_declared_payload() {
    let mut decoder = RecordDecoder::new();
    let mut input = &with_len(0x01, 16_384)[..];
    assert!(matches!(
        decoder.decode(&mut input),
        Ok(Some(RecordEvent::Header(_)))
    ));
    let filler = vec![b' '; 20_000];
    let mut input = &filler[..];
    assert!(
        matches!(decoder.decode(&mut input), Ok(Some(RecordEvent::Head(p))) if p.len() == 16_384)
    );
    assert_eq!(
        input.len(),
        20_000 - 16_384,
        "must not consume past the record"
    );
}
