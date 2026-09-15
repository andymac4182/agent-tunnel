//! Directional grammar, FIN/END ordering, declared lengths, zero-body
//! responses, limits, reset, and caller-observed record deadlines.

mod common;

use common::*;
use tunnel_http_forward::{
    CodecError, END_RECORD, HttpErrorCode, MAX_BODY_LIMIT, Method, Phase, PolicyError,
    RecordDeadline, RecordKind, RequestPolicy, RequestReader, ResetOutcome, ResponseHead,
    ResponsePolicy, ResponseReader, encode_record, encode_request_head, encode_response_head,
    request_head_json, response_head_json,
};

fn req_head_record(body_length: Option<u64>) -> Vec<u8> {
    let mut out = Vec::new();
    encode_request_head(
        &request_head(Method::Post, body_length),
        &request_policy(),
        &mut out,
    )
    .unwrap();
    out
}

fn resp_head_record(status: u16, body_length: Option<u64>) -> Vec<u8> {
    // Encode without the zero-body check so tests can build invalid heads.
    let head = response_head(status, body_length);
    let mut out = Vec::new();
    encode_record(
        RecordKind::ResponseHead,
        response_head_json(&head).as_bytes(),
        &mut out,
    )
    .unwrap();
    out
}

fn body(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    encode_record(RecordKind::Body, data, &mut out).unwrap();
    out
}

fn cat(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

fn request_result(
    bytes: &[u8],
    fin: bool,
) -> (
    Vec<Flow<tunnel_http_forward::RequestHead>>,
    Option<CodecError>,
    Phase,
) {
    let mut reader = RequestReader::new(request_policy());
    let (flow, error) = run_request(&mut reader, &[bytes], fin);
    // The same outcome must hold one byte at a time.
    let mut ones = RequestReader::new(request_policy());
    assert_eq!(
        run_request(&mut ones, &one_byte_chunks(bytes), fin),
        (flow.clone(), error)
    );
    assert_eq!(ones.phase(), reader.phase());
    (flow, error, reader.phase())
}

fn response_result(
    bytes: &[u8],
    method: Method,
    fin: bool,
) -> (Vec<Flow<ResponseHead>>, Option<CodecError>, Phase) {
    let mut reader = ResponseReader::new(response_policy(), method);
    let (flow, error) = run_response(&mut reader, &[bytes], fin);
    let mut ones = ResponseReader::new(response_policy(), method);
    assert_eq!(
        run_response(&mut ones, &one_byte_chunks(bytes), fin),
        (flow.clone(), error)
    );
    (flow, error, reader.phase())
}

#[test]
fn successful_request_phases() {
    let mut reader = RequestReader::new(request_policy());
    assert_eq!(reader.phase(), Phase::AwaitHead);
    let head = req_head_record(Some(3));
    let mut input = &head[..];
    assert!(matches!(
        reader.read(&mut input),
        Ok(Some(tunnel_http_forward::RequestEvent::Head(_)))
    ));
    assert_eq!(reader.phase(), Phase::Body);
    let b = body(b"abc");
    let mut input = &b[..];
    assert_eq!(
        reader.read(&mut input),
        Ok(Some(tunnel_http_forward::RequestEvent::Body(b"abc")))
    );
    assert_eq!(reader.body_received(), 3);
    let mut input = &END_RECORD[..];
    assert_eq!(
        reader.read(&mut input),
        Ok(Some(tunnel_http_forward::RequestEvent::End))
    );
    assert_eq!(reader.phase(), Phase::AwaitFin);
    assert_eq!(reader.fin(), Ok(()));
    assert_eq!(reader.phase(), Phase::Complete);
    assert_eq!(reader.reset(), ResetOutcome::AlreadyComplete);
    assert_eq!(reader.phase(), Phase::Complete);
}

#[test]
fn grammar_errors_before_head() {
    let cases: [(Vec<u8>, CodecError); 3] = [
        (body(b"x"), CodecError::BodyBeforeHead),
        (END_RECORD.to_vec(), CodecError::EndBeforeHead),
        (resp_head_record(200, None), CodecError::WrongDirectionHead),
    ];
    for (bytes, expected) in cases {
        let (flow, error, phase) = request_result(&bytes, false);
        assert!(flow.is_empty());
        assert_eq!(error, Some(expected));
        assert_eq!(phase, Phase::Failed(expected));
        assert_eq!(expected.code(), HttpErrorCode::BadRecord);
    }
    let request_head_to_response = req_head_record(None);
    let (_, error, _) = response_result(&request_head_to_response, Method::Post, false);
    assert_eq!(error, Some(CodecError::WrongDirectionHead));
}

#[test]
fn wrong_head_is_rejected_before_its_payload_arrives() {
    // Only the eight header bytes of a wrong-direction head are supplied.
    let wrong = resp_head_record(200, None);
    let mut reader = RequestReader::new(request_policy());
    let mut input = &wrong[..8];
    assert_eq!(reader.read(&mut input), Err(CodecError::WrongDirectionHead));
    // Same for a BODY before HEAD with a maximal declared payload.
    let mut reader = RequestReader::new(request_policy());
    let mut input = &[0x03u8, 0, 0, 0, 0, 0, 0xff, 0xf8][..];
    assert_eq!(reader.read(&mut input), Err(CodecError::BodyBeforeHead));
}

#[test]
fn second_head_during_body() {
    let bytes = cat(&[&req_head_record(None), &body(b"a"), &req_head_record(None)]);
    let (flow, error, _) = request_result(&bytes, false);
    assert_eq!(flow.len(), 2);
    assert_eq!(error, Some(CodecError::SecondHead));
    let bytes = cat(&[&req_head_record(None), &req_head_record(None)]);
    assert_eq!(
        request_result(&bytes, false).1,
        Some(CodecError::SecondHead)
    );
    let bytes = cat(&[&req_head_record(None), &resp_head_record(200, None)]);
    assert_eq!(
        request_result(&bytes, false).1,
        Some(CodecError::WrongDirectionHead)
    );
}

#[test]
fn records_after_end() {
    let done = cat(&[&req_head_record(None), &END_RECORD]);
    let cases: [(Vec<u8>, CodecError); 5] = [
        (END_RECORD.to_vec(), CodecError::RepeatedEnd),
        (body(b"x"), CodecError::BodyAfterEnd),
        (req_head_record(None), CodecError::SecondHead),
        (resp_head_record(200, None), CodecError::WrongDirectionHead),
        (vec![0x00], CodecError::DataAfterEnd),
    ];
    for (extra, expected) in cases {
        let bytes = cat(&[&done, &extra]);
        let (flow, error, _) = request_result(&bytes, true);
        assert_eq!(flow.last(), Some(&Flow::End));
        assert_eq!(error, Some(expected));
        // Even the first byte alone is enough to fail.
        let mut reader = RequestReader::new(request_policy());
        let _ = run_request(&mut reader, &[&done], false);
        let mut first = &extra[..1];
        assert_eq!(reader.read(&mut first), Err(expected));
        assert_eq!(reader.fin(), Err(expected), "errors are sticky");
    }
}

#[test]
fn fin_before_end_and_eof_inside_record() {
    let (_, error, _) = request_result(b"", true);
    assert_eq!(error, Some(CodecError::FinBeforeEnd));
    let (_, error, _) = request_result(&req_head_record(None), true);
    assert_eq!(error, Some(CodecError::FinBeforeEnd));
    let (_, error, _) = request_result(&cat(&[&req_head_record(None), &body(b"ab")]), true);
    assert_eq!(error, Some(CodecError::FinBeforeEnd));

    let head = req_head_record(None);
    for cut in 1..head.len() {
        let mut reader = RequestReader::new(request_policy());
        let (_, error) = run_request(&mut reader, &[&head[..cut]], true);
        assert_eq!(error, Some(CodecError::EofInsideRecord), "cut {cut}");
    }
    let full = cat(&[&head, &body(b"abcd"), &END_RECORD]);
    for cut in head.len() + 1..full.len() {
        if cut == head.len() + 12 {
            // Exactly at the BODY/END boundary: no partial record.
            let mut reader = RequestReader::new(request_policy());
            let (_, error) = run_request(&mut reader, &[&full[..cut]], true);
            assert_eq!(error, Some(CodecError::FinBeforeEnd));
            continue;
        }
        let mut reader = RequestReader::new(request_policy());
        let (_, error) = run_request(&mut reader, &[&full[..cut]], true);
        assert_eq!(error, Some(CodecError::EofInsideRecord), "cut {cut}");
    }
}

#[test]
fn fin_after_end_then_no_more_data() {
    let bytes = cat(&[&req_head_record(Some(0)), &END_RECORD]);
    let mut reader = RequestReader::new(request_policy());
    let (flow, error) = run_request(&mut reader, &[&bytes], true);
    assert_eq!(error, None);
    assert_eq!(flow.last(), Some(&Flow::Fin));
    let mut late = &END_RECORD[..];
    assert_eq!(reader.read(&mut late), Err(CodecError::AfterTerminal));
    assert_eq!(reader.fin(), Err(CodecError::AfterTerminal));
    let mut empty: &[u8] = &[];
    assert_eq!(reader.read(&mut empty), Ok(None));
}

#[test]
fn declared_length_mismatch_both_directions() {
    // Shorter than declared, detected at END.
    let bytes = cat(&[&req_head_record(Some(5)), &body(b"abcd"), &END_RECORD]);
    let (flow, error, _) = request_result(&bytes, true);
    assert_eq!(error, Some(CodecError::BodyShorterThanDeclared));
    assert_eq!(flow.last(), Some(&Flow::Body(b"abcd".to_vec())));
    assert_eq!(
        CodecError::BodyShorterThanDeclared.code(),
        HttpErrorCode::LengthMismatch
    );
    // Declared nonzero, no body at all.
    let bytes = cat(&[&req_head_record(Some(1)), &END_RECORD]);
    assert_eq!(
        request_result(&bytes, true).1,
        Some(CodecError::BodyShorterThanDeclared)
    );
    // Longer than declared, detected at the offending BODY header before any
    // of its bytes are emitted.
    let bytes = cat(&[
        &req_head_record(Some(5)),
        &body(b"abc"),
        &body(b"def"),
        &END_RECORD,
    ]);
    let (flow, error, _) = request_result(&bytes, true);
    assert_eq!(error, Some(CodecError::BodyLongerThanDeclared));
    assert_eq!(flow.last(), Some(&Flow::Body(b"abc".to_vec())));
    let bytes = cat(&[&req_head_record(Some(0)), &body(b"x")]);
    assert_eq!(
        request_result(&bytes, false).1,
        Some(CodecError::BodyLongerThanDeclared)
    );
    // Exact match succeeds, including across records.
    let bytes = cat(&[
        &req_head_record(Some(6)),
        &body(b"abc"),
        &body(b"def"),
        &END_RECORD,
    ]);
    assert_eq!(request_result(&bytes, true).1, None);
    // Response direction.
    let bytes = cat(&[&resp_head_record(200, Some(2)), &body(b"a"), &END_RECORD]);
    assert_eq!(
        response_result(&bytes, Method::Post, true).1,
        Some(CodecError::BodyShorterThanDeclared)
    );
    let bytes = cat(&[&resp_head_record(200, Some(2)), &body(b"abc")]);
    assert_eq!(
        response_result(&bytes, Method::Post, true).1,
        Some(CodecError::BodyLongerThanDeclared)
    );
}

#[test]
fn unknown_length_is_bounded_by_the_body_limit() {
    let mut policy = RequestPolicy::new(10).unwrap();
    policy.allow_route(Method::Post, "/acp").unwrap();
    policy.allow_http_version(tunnel_http_forward::HttpVersion::Http2);
    policy
        .headers
        .allow("content-type", tunnel_http_forward::Occurrence::Singleton)
        .unwrap();
    let mut head = Vec::new();
    encode_request_head(&request_head(Method::Post, None), &policy, &mut head).unwrap();

    let exact = cat(&[&head, &body(b"12345"), &body(b"67890"), &END_RECORD]);
    let mut reader = RequestReader::new(policy.clone());
    assert_eq!(run_request(&mut reader, &[&exact], true).1, None);

    let over = cat(&[&head, &body(b"12345"), &body(b"678901")]);
    let mut reader = RequestReader::new(policy.clone());
    let (flow, error) = run_request(&mut reader, &[&over], false);
    assert_eq!(error, Some(CodecError::BodyLimitExceeded));
    assert_eq!(flow.last(), Some(&Flow::Body(b"12345".to_vec())));
    assert_eq!(error.unwrap().code(), HttpErrorCode::BodyLimit);

    // A known length above the limit fails at the head, before any BODY.
    let mut big = Vec::new();
    encode_record(
        RecordKind::RequestHead,
        request_head_json(&request_head(Method::Post, Some(11))).as_bytes(),
        &mut big,
    )
    .unwrap();
    let mut reader = RequestReader::new(policy.clone());
    let (flow, error) = run_request(&mut reader, &[&big], false);
    assert!(flow.is_empty());
    assert_eq!(error, Some(CodecError::DeclaredLengthExceedsLimit));

    // The largest finite limit: counters stay exact near it, and a declared
    // length one past it is rejected at the head.
    let mut ceiling = RequestPolicy::new(MAX_BODY_LIMIT).unwrap();
    ceiling.allow_route(Method::Post, "/acp").unwrap();
    ceiling.allow_http_version(tunnel_http_forward::HttpVersion::Http2);
    ceiling
        .headers
        .allow("content-type", tunnel_http_forward::Occurrence::Singleton)
        .unwrap();
    let head_with = |declared: u64| {
        let mut out = Vec::new();
        encode_record(
            RecordKind::RequestHead,
            request_head_json(&request_head(Method::Post, Some(declared))).as_bytes(),
            &mut out,
        )
        .unwrap();
        out
    };
    let bytes = cat(&[&head_with(MAX_BODY_LIMIT), &body(b"x"), &END_RECORD]);
    let mut reader = RequestReader::new(ceiling.clone());
    assert_eq!(
        run_request(&mut reader, &[&bytes], true).1,
        Some(CodecError::BodyShorterThanDeclared)
    );
    for declared in [MAX_BODY_LIMIT + 1, u64::MAX] {
        let mut reader = RequestReader::new(ceiling.clone());
        assert_eq!(
            run_request(&mut reader, &[&head_with(declared)], false).1,
            Some(CodecError::DeclaredLengthExceedsLimit)
        );
    }
}

#[test]
fn body_limits_have_a_finite_ceiling() {
    assert_eq!(MAX_BODY_LIMIT, 1 << 40);
    assert!(RequestPolicy::new(MAX_BODY_LIMIT).is_ok());
    assert!(ResponsePolicy::new(MAX_BODY_LIMIT).is_ok());
    for limit in [MAX_BODY_LIMIT + 1, u64::MAX] {
        assert_eq!(
            RequestPolicy::new(limit),
            Err(PolicyError::BodyLimitAboveCeiling)
        );
        assert_eq!(
            ResponsePolicy::new(limit),
            Err(PolicyError::BodyLimitAboveCeiling)
        );
    }
}

#[test]
fn zero_body_responses() {
    for (method, status) in [
        (Method::Head, 200),
        (Method::Head, 404),
        (Method::Post, 204),
        (Method::Get, 205),
        (Method::Get, 304),
    ] {
        // "0", no BODY, END: accepted.
        let ok = cat(&[&resp_head_record(status, Some(0)), &END_RECORD]);
        let (flow, error, phase) = response_result(&ok, method, true);
        assert_eq!(error, None, "{method:?} {status}");
        assert_eq!(phase, Phase::Complete);
        assert_eq!(flow.len(), 3);

        // null or nonzero declared length: rejected at the head.
        for declared in [None, Some(1), Some(10)] {
            let bad = resp_head_record(status, declared);
            let (flow, error, _) = response_result(&bad, method, false);
            assert!(flow.is_empty());
            assert_eq!(error, Some(CodecError::ZeroBodyRequired), "{declared:?}");
        }

        // Any BODY record: rejected before its bytes are emitted.
        let with_body = cat(&[&resp_head_record(status, Some(0)), &body(b"x"), &END_RECORD]);
        let (flow, error, _) = response_result(&with_body, method, true);
        assert_eq!(error, Some(CodecError::BodyForbidden));
        assert!(!flow.iter().any(|item| matches!(item, Flow::Body(_))));

        // The encoder refuses to produce an invalid zero-body head.
        let mut out = Vec::new();
        assert_eq!(
            encode_response_head(
                &response_head(status, None),
                &response_policy(),
                method,
                &mut out
            ),
            Err(CodecError::ZeroBodyRequired)
        );
    }
    // The same statuses allow bodies only where the rule does not apply.
    let normal = cat(&[&resp_head_record(200, None), &body(b"data"), &END_RECORD]);
    assert_eq!(response_result(&normal, Method::Get, true).1, None);
    // The rule depends on the request method: 200 to GET with a body is fine,
    // the same bytes answering HEAD are not.
    let (_, error, _) = response_result(
        &cat(&[&resp_head_record(200, None), &END_RECORD]),
        Method::Head,
        true,
    );
    assert_eq!(error, Some(CodecError::ZeroBodyRequired));
}

#[test]
fn reset_interrupts_unfinished_directions_only() {
    let mut reader = RequestReader::new(request_policy());
    assert_eq!(reader.reset(), ResetOutcome::Interrupted);
    assert_eq!(reader.phase(), Phase::Interrupted);
    assert_eq!(reader.reset(), ResetOutcome::AlreadyTerminal);
    assert_eq!(reader.fin(), Err(CodecError::AfterTerminal));

    for prefix in [
        req_head_record(None),
        cat(&[&req_head_record(None), &body(b"a")]),
        cat(&[&req_head_record(None), &END_RECORD]),
    ] {
        let mut reader = RequestReader::new(request_policy());
        let _ = run_request(&mut reader, &[&prefix], false);
        assert_eq!(reader.reset(), ResetOutcome::Interrupted);
        let mut more = &END_RECORD[..];
        assert_eq!(reader.read(&mut more), Err(CodecError::AfterTerminal));
    }

    let mut failed = RequestReader::new(request_policy());
    let _ = run_request(&mut failed, &[&END_RECORD], false);
    assert_eq!(failed.reset(), ResetOutcome::AlreadyTerminal);
    assert_eq!(failed.phase(), Phase::Failed(CodecError::EndBeforeHead));
}

#[test]
fn invalid_head_payload_fails_the_direction() {
    let mut record = Vec::new();
    encode_record(
        RecordKind::RequestHead,
        br#"{"method":"POST","method":"GET"}"#,
        &mut record,
    )
    .unwrap();
    let (_, error, phase) = request_result(&record, false);
    assert_eq!(error, Some(CodecError::DuplicateKey));
    assert_eq!(phase, Phase::Failed(CodecError::DuplicateKey));
}

#[test]
fn record_deadline_is_caller_observed_and_not_extended_by_trickling() {
    let bytes = cat(&[&req_head_record(None), &body(b"abcdef"), &END_RECORD]);
    let mut reader = RequestReader::new(request_policy());
    let mut deadline = RecordDeadline::new(10);

    // First byte of the head arrives at t=100.
    let (_, error) = run_request(&mut reader, &[&bytes[..1]], false);
    assert_eq!(error, None);
    assert_eq!(deadline.observe(reader.partial_record(), 100), Ok(()));
    assert_eq!(deadline.started_at(), Some(100));
    // Trickled bytes of the same record keep the original start.
    for (offset, now) in (1..8).zip(101..) {
        let _ = run_request(&mut reader, &[&bytes[offset..=offset]], false);
        assert_eq!(deadline.observe(reader.partial_record(), now), Ok(()));
        assert_eq!(deadline.started_at(), Some(100));
    }
    assert_eq!(deadline.observe(reader.partial_record(), 110), Ok(()));
    assert_eq!(
        deadline.observe(reader.partial_record(), 111),
        Err(CodecError::RecordDeadlineExceeded)
    );
    reader.abort(CodecError::RecordDeadlineExceeded);
    assert_eq!(
        reader.phase(),
        Phase::Failed(CodecError::RecordDeadlineExceeded)
    );
    assert_eq!(
        CodecError::RecordDeadlineExceeded.code(),
        HttpErrorCode::DeadlineExceeded
    );

    // Completing a record clears the clock; the next record restarts it.
    let mut reader = RequestReader::new(request_policy());
    let mut deadline = RecordDeadline::new(10);
    let head_len = bytes.len() - 14 - 8;
    let _ = run_request(&mut reader, &[&bytes[..head_len - 1]], false);
    assert_eq!(deadline.observe(reader.partial_record(), 0), Ok(()));
    let _ = run_request(&mut reader, &[&bytes[head_len - 1..head_len + 2]], false);
    // A new record (the BODY) began: its budget starts now, not at 0.
    assert_eq!(deadline.observe(reader.partial_record(), 9), Ok(()));
    assert_eq!(deadline.started_at(), Some(9));
    assert_eq!(deadline.observe(reader.partial_record(), 19), Ok(()));
    let _ = run_request(&mut reader, &[&bytes[head_len + 2..]], false);
    assert_eq!(deadline.observe(reader.partial_record(), 1000), Ok(()));
    assert_eq!(deadline.started_at(), None);
    assert_eq!(reader.fin(), Ok(()));
}

#[test]
fn abort_does_not_overwrite_a_completed_direction() {
    let bytes = cat(&[&req_head_record(Some(0)), &END_RECORD]);
    let mut reader = RequestReader::new(request_policy());
    let _ = run_request(&mut reader, &[&bytes], true);
    reader.abort(CodecError::RecordDeadlineExceeded);
    assert_eq!(reader.phase(), Phase::Complete);
}
