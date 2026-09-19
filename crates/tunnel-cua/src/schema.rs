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

use crate::capture::{CaptureId, Point};
use crate::json::{self, JsonError};
use crate::operation::{Button, Operation, Refusal, refusal};

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
    /// `click` takes a capture reference, a point in that capture's pixel
    /// space, and an optional button.
    Click {
        capture: CaptureId,
        point: Point,
        button: Button,
    },
    /// `double_click` takes a capture reference and a point.
    DoubleClick { capture: CaptureId, point: Point },
    /// `move` takes a capture reference and a point.
    Move { capture: CaptureId, point: Point },
    /// `drag` takes a capture reference and two points in it.
    Drag {
        capture: CaptureId,
        from: Point,
        to: Point,
    },
    /// `scroll` takes a capture reference, a point, and a bounded delta.
    Scroll {
        capture: CaptureId,
        point: Point,
        dx: i32,
        dy: i32,
    },
    /// `type_text` takes the text. **The text is never rendered by `Debug`;**
    /// see [`Keystrokes`].
    TypeText { text: Keystrokes },
    /// `press_key` takes one key name.
    PressKey { key: Keystrokes },
    /// `hotkey` takes a chord of key names.
    Hotkey { keys: Vec<Keystrokes> },
}

/// A string of keystrokes, which **must never appear in a diagnostic**.
///
/// `AGENTS.md`: diagnostics carry identifiers, phases and counters, never
/// payloads, keystrokes, screenshots or credentials. [`Params`] derives
/// `Debug`, [`Request`] derives `Debug`, and every refusal in this module is
/// formatted somewhere — so a plain `String` here would put a password into a
/// log the first time anyone wrote `{request:?}` while debugging. This type is
/// the enforcement rather than the reminder: its `Debug` renders a length and
/// nothing else, and there is no `Display`.
///
/// ```
/// use tunnel_cua::schema::Keystrokes;
/// let secret = Keystrokes::new("hunter2");
/// let rendered = format!("{secret:?}");
/// assert!(!rendered.contains("hunter2"));
/// assert!(rendered.contains("redacted"));
/// assert!(rendered.contains('7'), "the length is still legible: {rendered}");
/// ```
///
/// The value does of course reach the backend: that is what typing is. What it
/// must not reach is a log line, and the only way out of this type is
/// [`Keystrokes::as_str`], which is called in exactly one place —
/// [`crate::plan::command_payload`], building the `/cmd` body.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Keystrokes(String);

impl Keystrokes {
    #[must_use]
    pub fn new(text: &str) -> Self {
        Self(text.to_owned())
    }

    /// The only way out. Used to build the upstream request body.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Character count. Safe to log: it is a counter.
    #[must_use]
    pub fn characters(&self) -> usize {
        self.0.chars().count()
    }
}

impl core::fmt::Debug for Keystrokes {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            formatter,
            "Keystrokes(<redacted, {} chars>)",
            self.characters()
        )
    }
}

/// The display index used when `params` does not name one.
pub const DEFAULT_DISPLAY: u32 = 0;

/// The largest coordinate this profile accepts in a request, before the
/// capture's own dimensions narrow it further.
///
/// A first bound at the schema, so an absurd integer is refused without a
/// capture lookup; the real bound is [`crate::capture::CaptureIdentity::contains`].
pub const MAX_COORDINATE: u32 = 65_535;

/// The largest `type_text` payload, in bytes of UTF-8.
///
/// Small on purpose: a consumer typing 4 KiB into a desktop in one operation
/// is not a case this profile is for, and the request limit
/// ([`crate::DEFAULT_REQUEST_BODY_LIMIT`]) is sixteen times larger, so without
/// this bound the limit that actually applied to keystrokes would be an
/// accident of the body limit.
pub const MAX_TEXT_BYTES: usize = 4_096;

/// The longest key name.
pub const MAX_KEY_BYTES: usize = 32;

/// The most keys in one chord.
pub const MAX_HOTKEY_KEYS: usize = 8;

/// The largest scroll delta in either direction.
pub const MAX_SCROLL_DELTA: i32 = 1_024;

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
        Operation::Click => &["capture", "x", "y", "button"],
        Operation::DoubleClick | Operation::Move => &["capture", "x", "y"],
        Operation::Drag => &["capture", "x", "y", "to_x", "to_y"],
        Operation::Scroll => &["capture", "x", "y", "dx", "dy"],
        Operation::TypeText => &["text"],
        Operation::PressKey => &["key"],
        Operation::Hotkey => &["keys"],
    };
    for name in params.keys() {
        if !accepted.contains(&name.as_str()) {
            return Err(SchemaError::UnknownMember);
        }
    }
    Ok(match operation {
        Operation::Describe => Params::Describe,
        Operation::Capture => Params::Capture {
            display: display_of(params)?,
        },
        Operation::ScreenInfo => Params::ScreenInfo {
            display: display_of(params)?,
        },
        Operation::CursorPosition => Params::CursorPosition,
        Operation::Click => Params::Click {
            capture: capture_of(params)?,
            point: point_of(params, "x", "y")?,
            // Absent is the default button, which is the one place in this
            // module an absent member is not a refusal -- and it is safe for
            // the same reason `display` is: the default is the narrower
            // behaviour, not a wider one.
            button: match params.get("button") {
                None => Button::DEFAULT,
                Some(value) => {
                    let name = value
                        .as_str()
                        .ok_or(SchemaError::WrongType { name: "button" })?;
                    Button::parse(name).ok_or(SchemaError::OutOfRange { name: "button" })?
                }
            },
        },
        Operation::DoubleClick => Params::DoubleClick {
            capture: capture_of(params)?,
            point: point_of(params, "x", "y")?,
        },
        Operation::Move => Params::Move {
            capture: capture_of(params)?,
            point: point_of(params, "x", "y")?,
        },
        Operation::Drag => Params::Drag {
            capture: capture_of(params)?,
            from: point_of(params, "x", "y")?,
            to: point_of(params, "to_x", "to_y")?,
        },
        Operation::Scroll => Params::Scroll {
            capture: capture_of(params)?,
            point: point_of(params, "x", "y")?,
            dx: delta_of(params, "dx")?,
            dy: delta_of(params, "dy")?,
        },
        Operation::TypeText => {
            let text = params
                .get("text")
                .ok_or(SchemaError::MissingMember { name: "text" })?
                .as_str()
                .ok_or(SchemaError::WrongType { name: "text" })?;
            if text.is_empty() || text.len() > MAX_TEXT_BYTES {
                return Err(SchemaError::OutOfRange { name: "text" });
            }
            Params::TypeText {
                text: Keystrokes::new(text),
            }
        }
        Operation::PressKey => Params::PressKey {
            key: key_of(params.get("key"), "key")?,
        },
        Operation::Hotkey => {
            let keys = params
                .get("keys")
                .ok_or(SchemaError::MissingMember { name: "keys" })?
                .as_array()
                .ok_or(SchemaError::WrongType { name: "keys" })?;
            if keys.is_empty() || keys.len() > MAX_HOTKEY_KEYS {
                return Err(SchemaError::OutOfRange { name: "keys" });
            }
            Params::Hotkey {
                keys: keys
                    .iter()
                    .map(|value| key_of(Some(value), "keys"))
                    .collect::<Result<Vec<_>, _>>()?,
            }
        }
    })
}

fn display_of(params: &serde_json::Map<String, Value>) -> Result<u32, SchemaError> {
    let Some(value) = params.get("display") else {
        return Ok(DEFAULT_DISPLAY);
    };
    let number = value
        .as_u64()
        .ok_or(SchemaError::WrongType { name: "display" })?;
    let index = u32::try_from(number).map_err(|_| SchemaError::OutOfRange { name: "display" })?;
    if index > MAX_DISPLAY {
        return Err(SchemaError::OutOfRange { name: "display" });
    }
    Ok(index)
}

/// The capture identity an action carries forward. **Required, never
/// defaulted**: an action with no capture is an action whose coordinates mean
/// nothing, and defaulting to "the current capture" would silently act on an
/// image the consumer never saw.
fn capture_of(params: &serde_json::Map<String, Value>) -> Result<CaptureId, SchemaError> {
    let value = params
        .get("capture")
        .ok_or(SchemaError::MissingMember { name: "capture" })?
        .as_u64()
        .ok_or(SchemaError::WrongType { name: "capture" })?;
    Ok(CaptureId::new(value))
}

fn coordinate_of(
    params: &serde_json::Map<String, Value>,
    name: &'static str,
) -> Result<u32, SchemaError> {
    let number = params
        .get(name)
        .ok_or(SchemaError::MissingMember { name })?
        .as_u64()
        .ok_or(SchemaError::WrongType { name })?;
    let value = u32::try_from(number).map_err(|_| SchemaError::OutOfRange { name })?;
    if value > MAX_COORDINATE {
        return Err(SchemaError::OutOfRange { name });
    }
    Ok(value)
}

fn point_of(
    params: &serde_json::Map<String, Value>,
    x: &'static str,
    y: &'static str,
) -> Result<Point, SchemaError> {
    Ok(Point::new(
        coordinate_of(params, x)?,
        coordinate_of(params, y)?,
    ))
}

fn delta_of(
    params: &serde_json::Map<String, Value>,
    name: &'static str,
) -> Result<i32, SchemaError> {
    let number = params
        .get(name)
        .ok_or(SchemaError::MissingMember { name })?
        .as_i64()
        .ok_or(SchemaError::WrongType { name })?;
    let value = i32::try_from(number).map_err(|_| SchemaError::OutOfRange { name })?;
    if value.unsigned_abs() > MAX_SCROLL_DELTA.unsigned_abs() {
        return Err(SchemaError::OutOfRange { name });
    }
    Ok(value)
}

/// Validate one key name.
///
/// **Fail closed on the characters, not only the length.** A key name is
/// forwarded to a backend that maps it onto a keyboard layout; a name carrying
/// a separator, a control character or whitespace is a name this profile has
/// not reasoned about, and the cost of guessing is a keystroke nobody asked
/// for. ASCII letters, digits, `_` and `-`, and nothing else.
fn key_of(value: Option<&Value>, name: &'static str) -> Result<Keystrokes, SchemaError> {
    let text = value
        .ok_or(SchemaError::MissingMember { name })?
        .as_str()
        .ok_or(SchemaError::WrongType { name })?;
    if text.is_empty() || text.len() > MAX_KEY_BYTES {
        return Err(SchemaError::OutOfRange { name });
    }
    if !text
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    {
        return Err(SchemaError::OutOfRange { name });
    }
    Ok(Keystrokes::new(text))
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

    /// A dispatched operation that failed.
    ///
    /// **Retryable only when the operation does not mutate the target**, and
    /// chunk 3 is why that clause exists. For a read, a backend-reported
    /// failure means the effect did not happen and a retry costs a round trip.
    /// For a click it means the *backend* believes the effect did not happen,
    /// on a code path where the backend has already been handed the command —
    /// and this profile does not stake a duplicated click on the backend's
    /// self-report. The rule is [`Operation::mutates_target`], the same
    /// predicate the lease and
    /// [`crate::outcome::Dispatch::retry_is_safe_for`] read.
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
                retryable: !operation.mutates_target(),
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
    /// **Only for an operation name this build cannot parse.** That is the
    /// case the `&str` exists for, and it is the one case where `retryable:
    /// true` is unconditionally right: a name the allowlist rejects was never
    /// dispatched and can never have been an input operation, so no side
    /// effect can have happened. For anything that *is* an [`Operation`], use
    /// [`Response::not_dispatched_for`], which derives retryability instead of
    /// assuming it.
    #[must_use]
    pub fn not_dispatched(operation: &str, code: &str, message: &str) -> Self {
        Self::not_dispatched_retryable(operation, code, message, true)
    }

    /// A pre-dispatch refusal of a known operation, with retryability
    /// **derived** from the refusal and the operation.
    ///
    /// **This exists because the default was the thing a future facade would
    /// get wrong.** The M3-15 rule — a `PeerUnavailable` refusal is never
    /// auto-retried for an operation that synthesises input — reached the wire
    /// only if a caller remembered to compute it and pass it to
    /// [`Response::not_dispatched_retryable`]. Nothing enforced that, and
    /// [`Response::not_dispatched`]'s hardcoded `true` was the easy path.
    /// Here the rule is read from
    /// [`crate::outcome::Dispatch::retry_is_safe_for`], which is the single
    /// place it is decided.
    #[must_use]
    pub fn not_dispatched_for(
        operation: Operation,
        refusal: crate::outcome::NotDispatched,
        code: &str,
        message: &str,
    ) -> Self {
        let retryable =
            crate::outcome::Dispatch::NotDispatched(refusal).retry_is_safe_for(operation);
        Self::not_dispatched_retryable(operation.name(), code, message, retryable)
    }

    /// A pre-dispatch refusal whose retryability the caller decides.
    ///
    /// Needed because not every not-dispatched refusal is safe to retry once
    /// input operations exist. **M3-15 is the case**: a rotation freeze
    /// refuses a new request with the same retryable `503 PEER_UNAVAILABLE`
    /// body that the relay uses for every other owner-not-ready condition, so
    /// a consumer cannot tell a scheduled freeze from a fault state — and a
    /// click retried through a fault state is a click that may land twice. The
    /// decision lives in [`crate::outcome::Dispatch::retry_is_safe_for`]; this
    /// is how it reaches the wire.
    #[must_use]
    pub fn not_dispatched_retryable(
        operation: &str,
        code: &str,
        message: &str,
        retryable: bool,
    ) -> Self {
        Self {
            version: crate::SCHEMA_VERSION.to_owned(),
            operation: operation.to_owned(),
            outcome: ResponseOutcome::NotDispatched,
            result: None,
            error: Some(ResponseError {
                code: code.to_owned(),
                message: message.to_owned(),
                retryable,
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
