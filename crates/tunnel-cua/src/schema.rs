//! The `computer.v1` request and response schema, and the validation that
//! runs **before** anything is dispatched.
//!
//! `docs/http-forwarding.md` is explicit about the boundary: "the initial
//! JSON-command profiles for ACP, MCP, and typed CUA additionally wait for
//! their complete bounded request body and schema/policy validation before
//! invocation; generic HTTP framing alone cannot authorize a partially parsed
//! command." Every function in this module runs on that side of the line, and
//! every failure it produces is an [`crate::outcome::NotDispatched`].
//!
//! # The request
//!
//! ```json
//! {"version": "computer.v1", "operation": "capture", "params": {"display": 0}}
//! ```
//!
//! Exactly three members, all required, no others accepted. `params` must be
//! an object — possibly empty — and its accepted members depend on the
//! operation. An unknown member anywhere is a refusal, not an ignored extra:
//! a parameter this profile has not reasoned about must never reach a backend
//! that might act on it.
//!
//! # The response
//!
//! ```json
//! {"version": "computer.v1", "operation": "capture", "outcome": "ok", "result": {...}}
//! ```
//!
//! `outcome` is one of `ok`, `failed`, `unknown`, `not_dispatched` or
//! `answered_locally` — a closed set mirroring [`crate::outcome::Dispatch`],
//! with no absent-means-success rule. See [`crate::outcome`] for why the
//! not-dispatched/unknown split matters, and [`ResponseOutcome`] for why the
//! wire format has to carry it rather than collapsing it into `failed`.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::json::{self, JsonError};
use crate::operation::{Operation, Refusal, refusal};

/// A validated `computer.v1` request. Nothing has been dispatched.
///
/// It cannot be constructed except through [`validate_request`], so a value of
/// this type is the evidence that validation happened.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Request {
    operation: Operation,
    params: Params,
}

impl Request {
    #[must_use]
    pub const fn operation(&self) -> Operation {
        self.operation
    }

    #[must_use]
    pub const fn params(&self) -> &Params {
        &self.params
    }
}

/// The validated parameters of one operation.
///
/// One variant per operation, so a parameter that belongs to `capture` is not
/// reachable from `screen_info` by construction rather than by a check
/// somebody remembers to write.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Params {
    /// `describe` takes nothing.
    Describe,
    /// `capture` takes an optional display index.
    Capture { display: u32 },
    /// `screen_info` takes an optional display index.
    ScreenInfo { display: u32 },
    /// `cursor_position` takes nothing.
    CursorPosition,
}

/// The display index used when `params` does not name one.
pub const DEFAULT_DISPLAY: u32 = 0;

/// The largest display index this profile accepts.
///
/// A bound rather than the full `u32` range because the index is forwarded to
/// a backend that will index a list with it, and because an unbounded integer
/// in a request that is otherwise all small integers is a fault worth naming.
pub const MAX_DISPLAY: u32 = 63;

/// Why a request body is not a valid `computer.v1` request.
///
/// **Every variant means nothing was dispatched.** Carries no payload bytes:
/// the rejected value's *shape* is nameable, its contents are not.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SchemaError {
    /// The body is not one strict JSON object.
    Json(JsonError),
    /// The body is longer than the configured request limit. Checked before
    /// parsing, so an oversized body is never scanned.
    TooLarge { limit: u64 },
    /// A required member is missing.
    MissingMember { name: &'static str },
    /// A member has the wrong JSON type.
    WrongType { name: &'static str },
    /// A member this profile does not define. Never ignored.
    UnknownMember,
    /// `version` is present but is not [`crate::SCHEMA_VERSION`].
    UnsupportedVersion,
    /// `operation` names something this chunk does not carry.
    Operation(Refusal),
    /// A parameter is out of range.
    OutOfRange { name: &'static str },
}

impl core::fmt::Display for SchemaError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Json(error) => write!(formatter, "{error}"),
            Self::TooLarge { limit } => {
                write!(formatter, "the request body exceeds the {limit}-byte limit")
            }
            Self::MissingMember { name } => write!(formatter, "the {name} member is required"),
            Self::WrongType { name } => write!(formatter, "the {name} member has the wrong type"),
            Self::UnknownMember => formatter.write_str("the request carries an unknown member"),
            Self::UnsupportedVersion => formatter.write_str("unsupported computer.v1 version"),
            Self::Operation(Refusal::Unknown) => formatter.write_str("unknown operation"),
            Self::Operation(Refusal::Deferred(_)) => {
                formatter.write_str("the operation is defined but not carried by this build")
            }
            Self::OutOfRange { name } => write!(formatter, "the {name} parameter is out of range"),
        }
    }
}

impl std::error::Error for SchemaError {}

/// The top-level members a `computer.v1` request may carry, and no others.
pub const REQUEST_MEMBERS: &[&str] = &["version", "operation", "params"];

/// Validate one complete request body.
///
/// The body must be **complete**: this function takes a slice, never a stream,
/// because a partially parsed command cannot be authorized. The caller has
/// already buffered it under the profile's bounded request limit.
///
/// # Errors
/// Any [`SchemaError`]. Every one of them means nothing was dispatched.
pub fn validate_request(body: &[u8], limit: u64) -> Result<Request, SchemaError> {
    // Length first, so an oversized body is refused without being scanned.
    if body.len() as u64 > limit {
        return Err(SchemaError::TooLarge { limit });
    }
    let map = json::strict_object(body).map_err(SchemaError::Json)?;

    for name in map.keys() {
        if !REQUEST_MEMBERS.contains(&name.as_str()) {
            return Err(SchemaError::UnknownMember);
        }
    }

    let version = map
        .get("version")
        .ok_or(SchemaError::MissingMember { name: "version" })?
        .as_str()
        .ok_or(SchemaError::WrongType { name: "version" })?;
    if version != crate::SCHEMA_VERSION {
        return Err(SchemaError::UnsupportedVersion);
    }

    let name = map
        .get("operation")
        .ok_or(SchemaError::MissingMember { name: "operation" })?
        .as_str()
        .ok_or(SchemaError::WrongType { name: "operation" })?;
    let operation = Operation::parse(name).ok_or(SchemaError::Operation(refusal(name)))?;

    let params = map
        .get("params")
        .ok_or(SchemaError::MissingMember { name: "params" })?
        .as_object()
        .ok_or(SchemaError::WrongType { name: "params" })?;

    Ok(Request {
        operation,
        params: validate_params(operation, params)?,
    })
}

fn validate_params(
    operation: Operation,
    params: &serde_json::Map<String, Value>,
) -> Result<Params, SchemaError> {
    let accepted: &[&str] = match operation {
        Operation::Describe | Operation::CursorPosition => &[],
        Operation::Capture | Operation::ScreenInfo => &["display"],
    };
    for name in params.keys() {
        if !accepted.contains(&name.as_str()) {
            return Err(SchemaError::UnknownMember);
        }
    }
    let display = match params.get("display") {
        None => DEFAULT_DISPLAY,
        Some(value) => {
            let number = value
                .as_u64()
                .ok_or(SchemaError::WrongType { name: "display" })?;
            let index =
                u32::try_from(number).map_err(|_| SchemaError::OutOfRange { name: "display" })?;
            if index > MAX_DISPLAY {
                return Err(SchemaError::OutOfRange { name: "display" });
            }
            index
        }
    };
    Ok(match operation {
        Operation::Describe => Params::Describe,
        Operation::Capture => Params::Capture { display },
        Operation::ScreenInfo => Params::ScreenInfo { display },
        Operation::CursorPosition => Params::CursorPosition,
    })
}

/// The `outcome` member of a `computer.v1` response.
///
/// **Five arms, closed**, mirroring [`crate::outcome::Dispatch`] on the wire.
/// Serialized in lowercase, and **never** omitted: a response with no
/// `outcome` is not a success, and this enum has no default so that no
/// `#[serde(default)]` can quietly make it one.
///
/// # Why there is a fourth arm
///
/// The first review of this chunk found the three-arm version rendering a
/// pre-dispatch refusal as `Failed` — whose own contract is "dispatched and
/// failed". That collapsed, at the boundary a consumer actually sees, the
/// exact distinction this crate exists to keep: whether the backend saw the
/// command. `retryable: true` kept it safe, so it was a contract defect rather
/// than a double-click risk, but a consumer reading `failed` had no way to
/// learn that nothing had been sent.
///
/// `not_dispatched` is therefore its own value. Retryability remains an
/// explicit field rather than something a consumer derives from the outcome:
/// `failed` and `not_dispatched` are both retryable for **different reasons**,
/// and a consumer that wants to log which one happened can.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseOutcome {
    /// The operation was dispatched and succeeded.
    Ok,
    /// The operation was dispatched and failed. Its effect did not happen.
    Failed,
    /// The operation was dispatched and its effect is **not known**. Not
    /// retryable. See [`crate::outcome::Completion::Unknown`].
    Unknown,
    /// The operation never reached the backend: it was refused by validation,
    /// by the allowlist, by the capability set, or by the backend before
    /// dispatch. Nothing happened anywhere, so a retry is safe.
    NotDispatched,
    /// The device answered without contacting the backend, and the answer is
    /// correct. See [`crate::outcome::Dispatch::AnsweredLocally`].
    AnsweredLocally,
}

/// A `computer.v1` response, as the device-side facade renders it.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Response {
    /// Always [`crate::SCHEMA_VERSION`].
    pub version: String,
    /// The operation this answers, echoed so a consumer never has to infer it.
    pub operation: String,
    pub outcome: ResponseOutcome,
    /// Present exactly when `outcome` is `ok`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    /// Present exactly when `outcome` is `failed` or `unknown`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ResponseError>,
}

/// A machine-readable failure. Identifiers and phases only — never a payload,
/// a screenshot or a credential.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ResponseError {
    /// A stable identifier a consumer can branch on.
    pub code: String,
    /// A short human-readable phrase. Written by this repository, never
    /// forwarded verbatim from a backend, because a backend's message may
    /// quote a path or a window title.
    pub message: String,
    /// Whether the consumer may safely send the request again.
    ///
    /// `false` for every `unknown`, which is the rule this whole profile turns
    /// on: a retry after an unknown outcome is how a click lands twice.
    pub retryable: bool,
}

impl Response {
    /// A success.
    #[must_use]
    pub fn ok(operation: Operation, result: Value) -> Self {
        Self {
            version: crate::SCHEMA_VERSION.to_owned(),
            operation: operation.name().to_owned(),
            outcome: ResponseOutcome::Ok,
            result: Some(result),
            error: None,
        }
    }

    /// A dispatched operation that failed. Its effect did not happen, so the
    /// consumer may retry.
    #[must_use]
    pub fn failed(operation: Operation, code: &str, message: &str) -> Self {
        Self {
            version: crate::SCHEMA_VERSION.to_owned(),
            operation: operation.name().to_owned(),
            outcome: ResponseOutcome::Failed,
            result: None,
            error: Some(ResponseError {
                code: code.to_owned(),
                message: message.to_owned(),
                retryable: true,
            }),
        }
    }

    /// A dispatched operation whose effect is unknown. **Never retryable**,
    /// and there is no constructor that lets a caller say otherwise.
    #[must_use]
    pub fn unknown(operation: Operation, code: &str, message: &str) -> Self {
        Self {
            version: crate::SCHEMA_VERSION.to_owned(),
            operation: operation.name().to_owned(),
            outcome: ResponseOutcome::Unknown,
            result: None,
            error: Some(ResponseError {
                code: code.to_owned(),
                message: message.to_owned(),
                retryable: false,
            }),
        }
    }

    /// A refusal that happened before dispatch. The operation name is the one
    /// the consumer sent, which may not be an [`Operation`] at all.
    ///
    /// Renders as `outcome: "not_dispatched"`, **not** as `failed`: the
    /// backend never saw this, and a consumer must be able to learn that from
    /// the wire rather than infer it from a retryability flag.
    #[must_use]
    pub fn not_dispatched(operation: &str, code: &str, message: &str) -> Self {
        Self {
            version: crate::SCHEMA_VERSION.to_owned(),
            operation: operation.to_owned(),
            outcome: ResponseOutcome::NotDispatched,
            result: None,
            error: Some(ResponseError {
                code: code.to_owned(),
                message: message.to_owned(),
                retryable: true,
            }),
        }
    }

    /// An operation the device answered without contacting the backend.
    ///
    /// Carries a result, like [`Response::ok`], because the answer is a real
    /// answer -- and a distinct outcome, because the backend was not involved.
    #[must_use]
    pub fn answered_locally(operation: Operation, result: Value) -> Self {
        Self {
            version: crate::SCHEMA_VERSION.to_owned(),
            operation: operation.name().to_owned(),
            outcome: ResponseOutcome::AnsweredLocally,
            result: Some(result),
            error: None,
        }
    }
}

#[cfg(test)]
mod tests;
