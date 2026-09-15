#![forbid(unsafe_code)]
//! The pure `http-forward/1` codec defined by `docs/http-forwarding.md`.
//!
//! This crate implements implementation gate 1 only: the bounded record
//! encoder and incremental decoder, strict head JSON, path/query/header
//! validation against caller-supplied policy, and the directional receive
//! state machine.  It is independent of Axum, HTTP servers, ACP/MCP JSON-RPC
//! types, child supervision, and clocks.

pub mod decoder;
pub mod error;
pub mod head;
mod json;
pub mod progress;
pub mod reader;
pub mod record;
pub mod tracker;
pub mod validate;

pub use decoder::{PartialRecord, RecordDecoder, RecordEvent};
pub use error::{CodecError, HeaderRule, HttpErrorCode, PathRule, PolicyError, QueryRule};
pub use head::{
    HeaderField, HttpVersion, Method, RequestHead, ResponseHead, encode_request_head,
    encode_response_head, parse_request_head, parse_response_head, request_head_json,
    requires_zero_body, response_head_json,
};
pub use progress::RecordDeadline;
pub use reader::{
    Direction, Phase, RequestEvent, RequestReader, ResetOutcome, ResponseEvent, ResponseReader,
};
pub use record::{
    END_RECORD, MAX_BODY_PAYLOAD_LEN, MAX_HEAD_PAYLOAD_LEN, MAX_RECORD_LEN, RECORD_HEADER_LEN,
    RecordHeader, RecordKind, encode_body, encode_record,
};
pub use tracker::{RecordPosition, RecordTracker, TrackerSnapshot};
pub use validate::{
    CREDENTIAL_QUERY_PARAMETERS, FORBIDDEN_HEADER_PREFIXES, FORBIDDEN_HEADERS, HeaderPolicy,
    MAX_BODY_LIMIT, MAX_HEADER_FIELDS, MAX_HEADER_NAME_LEN, MAX_HEADER_TOTAL_BYTES,
    MAX_HEADER_VALUE_LEN, MAX_PATH_LEN, MAX_QUERY_LEN, MAX_QUERY_PAIRS, Occurrence, QueryPolicy,
    RequestPolicy, ResponsePolicy, Route, UNSUPPORTED_HEADERS, validate_headers, validate_path,
    validate_query,
};
