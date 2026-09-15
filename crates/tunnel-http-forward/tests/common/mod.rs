//! Shared synthetic fixtures for the http-forward codec tests.
#![allow(dead_code)]

use tunnel_http_forward::{
    CodecError, HeaderField, HttpVersion, Method, Occurrence, RecordDecoder, RecordEvent,
    RecordHeader, RequestEvent, RequestHead, RequestPolicy, RequestReader, ResponseEvent,
    ResponseHead, ResponsePolicy, ResponseReader,
};

/// A JSON backslash-u escape prefix built without writing it literally.
pub fn uesc(hex: &str) -> String {
    let mut out = String::from('\\');
    out.push('u');
    out.push_str(hex);
    out
}

pub const REQUEST_BODY_LIMIT: u64 = 1024 * 1024;
pub const RESPONSE_BODY_LIMIT: u64 = 4 * 1024 * 1024;

pub fn request_policy() -> RequestPolicy {
    let mut policy = RequestPolicy::new(REQUEST_BODY_LIMIT).unwrap();
    for (method, path) in [
        (Method::Post, "/acp"),
        (Method::Get, "/acp"),
        (Method::Head, "/acp"),
        (Method::Delete, "/acp"),
        (Method::Get, "/v1/events.stream"),
    ] {
        policy.allow_route(method, path).unwrap();
    }
    policy.allow_http_version(HttpVersion::Http11);
    policy.allow_http_version(HttpVersion::Http2);
    policy.query.allow("cursor", Occurrence::Singleton).unwrap();
    policy.query.allow("tag", Occurrence::Repeatable).unwrap();
    for name in [
        "content-type",
        "accept",
        "acp-connection-id",
        "acp-session-id",
    ] {
        policy.headers.allow(name, Occurrence::Singleton).unwrap();
    }
    policy
        .headers
        .allow("cache-control", Occurrence::Repeatable)
        .unwrap();
    policy
}

pub fn response_policy() -> ResponsePolicy {
    let mut policy = ResponsePolicy::new(RESPONSE_BODY_LIMIT).unwrap();
    policy
        .headers
        .allow("content-type", Occurrence::Singleton)
        .unwrap();
    policy
        .headers
        .allow("cache-control", Occurrence::Repeatable)
        .unwrap();
    policy
}

/// The request head example from docs/http-forwarding.md.
pub fn doc_request_head() -> RequestHead {
    RequestHead {
        method: Method::Post,
        path: "/acp".into(),
        query: String::new(),
        http_version: HttpVersion::Http2,
        headers: vec![
            HeaderField::new("content-type", "application/json"),
            HeaderField::new("accept", "application/json, text/event-stream"),
            HeaderField::new("acp-connection-id", "connection-demo"),
            HeaderField::new("acp-session-id", "session-demo"),
        ],
        body_length: None,
    }
}

pub fn doc_response_head() -> ResponseHead {
    ResponseHead {
        status: 200,
        headers: vec![
            HeaderField::new("content-type", "text/event-stream"),
            HeaderField::new("cache-control", "no-store"),
        ],
        body_length: None,
    }
}

pub fn request_head(method: Method, body_length: Option<u64>) -> RequestHead {
    RequestHead {
        method,
        path: "/acp".into(),
        query: String::new(),
        http_version: HttpVersion::Http2,
        headers: vec![HeaderField::new("content-type", "application/json")],
        body_length,
    }
}

pub fn response_head(status: u16, body_length: Option<u64>) -> ResponseHead {
    ResponseHead {
        status,
        headers: vec![HeaderField::new("content-type", "application/json")],
        body_length,
    }
}

/// A request JSON object with one field replaced by raw JSON text.
pub fn request_json_with(field: &str, raw: &str) -> String {
    let mut fields = vec![
        ("method", "\"POST\"".to_owned()),
        ("path", "\"/acp\"".to_owned()),
        ("query", "\"\"".to_owned()),
        ("http_version", "\"2\"".to_owned()),
        (
            "headers",
            "[[\"content-type\",\"application/json\"]]".to_owned(),
        ),
        ("body_length", "null".to_owned()),
    ];
    for entry in &mut fields {
        if entry.0 == field {
            entry.1 = raw.to_owned();
        }
    }
    object(&fields)
}

pub fn response_json_with(field: &str, raw: &str) -> String {
    let mut fields = vec![
        ("status", "200".to_owned()),
        (
            "headers",
            "[[\"content-type\",\"application/json\"]]".to_owned(),
        ),
        ("body_length", "null".to_owned()),
    ];
    for entry in &mut fields {
        if entry.0 == field {
            entry.1 = raw.to_owned();
        }
    }
    object(&fields)
}

fn object(fields: &[(&str, String)]) -> String {
    let body: Vec<String> = fields
        .iter()
        .map(|(key, value)| format!("\"{key}\":{value}"))
        .collect();
    format!("{{{}}}", body.join(","))
}

/// A deterministic xorshift64* generator; no external dependency.
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Self(seed.max(1))
    }

    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    pub fn below(&mut self, bound: usize) -> usize {
        (self.next_u64() % bound.max(1) as u64) as usize
    }

    pub fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.next_u64() as u8).collect()
    }
}

/// A split-independent view of decoder output: BODY fragments are joined
/// per record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Normal {
    Header(RecordHeader),
    Head(Vec<u8>),
    BodyRecord(Vec<u8>),
}

/// Decode `chunks` in order.  Returns normalized events and the first error.
pub fn decode_chunks(chunks: &[&[u8]]) -> (Vec<Normal>, Option<CodecError>) {
    let mut decoder = RecordDecoder::new();
    let mut events = Vec::new();
    let mut body = Vec::new();
    for chunk in chunks {
        let mut input = *chunk;
        loop {
            match decoder.decode(&mut input) {
                Ok(Some(RecordEvent::Header(header))) => events.push(Normal::Header(header)),
                Ok(Some(RecordEvent::Head(payload))) => events.push(Normal::Head(payload)),
                Ok(Some(RecordEvent::Body { data, record_done })) => {
                    assert!(!data.is_empty(), "empty BODY fragment emitted");
                    body.extend_from_slice(data);
                    if record_done {
                        events.push(Normal::BodyRecord(std::mem::take(&mut body)));
                    }
                }
                Ok(None) => {
                    assert!(input.is_empty(), "decoder stopped with unread input");
                    break;
                }
                Err(error) => return (events, Some(error)),
            }
        }
    }
    (events, None)
}

/// Reader output with adjacent body fragments joined.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Flow<H> {
    Head(H),
    Body(Vec<u8>),
    End,
    Fin,
}

fn push_body<H>(flow: &mut Vec<Flow<H>>, data: &[u8]) {
    if let Some(Flow::Body(existing)) = flow.last_mut() {
        existing.extend_from_slice(data);
    } else {
        flow.push(Flow::Body(data.to_vec()));
    }
}

/// Feed chunks to a request reader, then FIN if `fin`.  Returns flow and the
/// first error.
pub fn run_request(
    reader: &mut RequestReader,
    chunks: &[&[u8]],
    fin: bool,
) -> (Vec<Flow<RequestHead>>, Option<CodecError>) {
    let mut flow = Vec::new();
    for chunk in chunks {
        let mut input = *chunk;
        loop {
            match reader.read(&mut input) {
                Ok(Some(RequestEvent::Head(head))) => flow.push(Flow::Head(head)),
                Ok(Some(RequestEvent::Body(data))) => push_body(&mut flow, data),
                Ok(Some(RequestEvent::End)) => flow.push(Flow::End),
                Ok(None) => break,
                Err(error) => return (flow, Some(error)),
            }
        }
    }
    if fin {
        match reader.fin() {
            Ok(()) => flow.push(Flow::Fin),
            Err(error) => return (flow, Some(error)),
        }
    }
    (flow, None)
}

pub fn run_response(
    reader: &mut ResponseReader,
    chunks: &[&[u8]],
    fin: bool,
) -> (Vec<Flow<ResponseHead>>, Option<CodecError>) {
    let mut flow = Vec::new();
    for chunk in chunks {
        let mut input = *chunk;
        loop {
            match reader.read(&mut input) {
                Ok(Some(ResponseEvent::Head(head))) => flow.push(Flow::Head(head)),
                Ok(Some(ResponseEvent::Body(data))) => push_body(&mut flow, data),
                Ok(Some(ResponseEvent::End)) => flow.push(Flow::End),
                Ok(None) => break,
                Err(error) => return (flow, Some(error)),
            }
        }
    }
    if fin {
        match reader.fin() {
            Ok(()) => flow.push(Flow::Fin),
            Err(error) => return (flow, Some(error)),
        }
    }
    (flow, None)
}

pub fn one_byte_chunks(bytes: &[u8]) -> Vec<&[u8]> {
    bytes.chunks(1).collect()
}
