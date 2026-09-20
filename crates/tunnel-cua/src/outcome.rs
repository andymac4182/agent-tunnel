//! Was it dispatched, and if so, what happened?
//!
//! This module exists for one distinction, and the distinction is the reason
//! `docs/tasks.md` M5-04 exists: **"unknown outcome" and "not dispatched" are
//! different facts, and only one of them is safe to retry.**
//!
//! ```text
//!   NotDispatched  -> the backend never saw the command -> retry is safe
//!   Dispatched(Ok)      -> it happened, and we know what it returned
//!   Dispatched(Failed)  -> it did not happen, and the backend said so
//!   Dispatched(Unknown) -> it may or may not have happened -> retry is NOT safe
//! ```
//!
//! For this chunk's four read-only operations nothing is lost by guessing
//! wrong. That is exactly why the machinery is built here rather than in
//! chunk 3: a `click` classified as `NotDispatched` when it was really
//! `Unknown` is a double click on someone's desktop, and the place to get the
//! classifier right is where the stakes are still zero.
//!
//! # The four shapes the pinned backend actually produces
//!
//! All four are recorded in `tunnel_http_forward::cua_pin`, read from the
//! released 0.3.46 source, and **none has been observed on a socket**.
//!
//! 1. **HTTP 200 with `data: <JSON>\n\n` framing and `success: true`.**
//! 2. **HTTP 200 with the same framing and `success: false`.** This is the
//!    trap. The success and error payloads are both yielded from one generator
//!    inside a `StreamingResponse`, so the status is committed *before* the
//!    outcome is known. A classifier that reads the status is wrong on every
//!    backend failure. Worse, the envelope is `{"success": True, **result}`,
//!    so a handler result carrying its own `success` key **overrides** the
//!    envelope — what is on the wire is the merged value, and the merged value
//!    is the only thing that may be read.
//! 3. **A real 400 or 401 with no `data:` framing at all.** Pre-dispatch
//!    failures are `HTTPException`s: a malformed body, a missing or unknown
//!    command, cloud auth. A parser that assumes the framing faults
//!    *specifically on the error path*, which is the path least likely to be
//!    exercised. These are [`NotDispatched`].
//! 4. **A 503 from `UNAVAILABLE_WITHOUT_CONTAINER_NAME`.** Deliberately
//!    unavailable, not a transient fault to retry through.
//!
//! # The direction this classifier fails in
//!
//! Every status it does not recognise becomes [`Completion::Unknown`], never
//! [`NotDispatched`]. That is the safe direction and the expensive one: a
//! consumer told `unknown` must not retry, so a misclassification costs an
//! operation rather than a duplicated effect. The reverse default would trade
//! a duplicated click for a saved round trip.

use serde_json::Value;

use tunnel_http_forward::cua_pin;

use crate::Operation;
use crate::capture::CaptureRefusal;
use crate::lease::LeaseRefusal;
use crate::operation::Refusal;
use crate::schema::SchemaError;

/// What happened to one `computer.v1` operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Dispatch {
    /// The backend never saw it. Safe to retry.
    NotDispatched(NotDispatched),
    /// The backend saw it. Whether it succeeded is [`Completion`].
    Dispatched(Completion),
    /// **The device answered without contacting the backend, and the answer is
    /// correct.** Not a refusal and not a dispatch.
    ///
    /// This third arm exists because the first review of this chunk found the
    /// two-arm version telling a lie: `describe` is answered entirely from the
    /// negotiated capability set, and reporting it as
    /// [`Dispatch::Dispatched`] made [`Dispatch::reached_the_backend`] return
    /// `true` for an operation that never sent a byte — falsifying the very
    /// invariant this module exists to state, in the one case the fault table
    /// did not cover.
    ///
    /// Collapsing it into [`Dispatch::NotDispatched`] would have been the
    /// other lie: nothing was refused, and the consumer has its answer.
    ///
    /// **This matters well beyond `describe`.** Chunk 3's lease query is
    /// answered the same way — from device-side state, with no backend
    /// exchange — and would have inherited exactly this defect.
    AnsweredLocally(Value),
}

impl Dispatch {
    /// Whether a consumer may send this request again.
    ///
    /// The single most load-bearing method in the crate. It is `true` only for
    /// [`Dispatch::NotDispatched`], for [`Completion::Failed`] and for
    /// [`Dispatch::AnsweredLocally`], and there is deliberately no way for a
    /// caller to override it.
    ///
    /// A locally-answered operation is safe to repeat because **no effect
    /// happened anywhere** — not on the backend, and not on the device. That
    /// is a different reason from a `Failed`, whose effect provably did not
    /// happen, and both are different from an `Unknown`.
    ///
    /// # This is the transport-level fact, and for an input operation it is
    /// not the whole answer
    ///
    /// It knows nothing about *what* was dispatched, so it cannot express the
    /// rule chunk 3 needs: an operation that synthesises input and reached the
    /// backend is never retryable. Use [`Dispatch::retry_is_safe_for`] for any
    /// decision an operation is available at, and read this one only as "the
    /// transport permits it". `retry_is_safe_for` is never wider than this,
    /// and a test asserts that over the full cross-product.
    #[must_use]
    pub const fn retry_is_safe(&self) -> bool {
        match self {
            Self::NotDispatched(_) | Self::AnsweredLocally(_) => true,
            Self::Dispatched(Completion::Failed { .. }) => true,
            Self::Dispatched(Completion::Ok(_) | Completion::Unknown(_)) => false,
        }
    }

    /// Whether a consumer may send **this operation** again.
    ///
    /// The narrower of the two, and the one a facade must call. It starts from
    /// [`Dispatch::retry_is_safe`] and then applies two rules that exist only
    /// because input operations do:
    ///
    /// 1. **An input operation that reached the backend is never retryable**,
    ///    whatever the backend said afterwards. `Unknown` was already
    ///    non-retryable; this extends it to `Failed`, where the backend
    ///    reports that the effect did not happen. For a read that report is
    ///    worth acting on. For a click it is a backend's opinion about its own
    ///    side effect, on a path where it has already been handed the command,
    ///    and this profile does not stake a duplicated click on it.
    /// 2. **A [`NotDispatched::PeerUnavailable`] refusal is never auto-retried
    ///    for an input operation** (M3-15). Nothing was dispatched *on this
    ///    attempt*, which is why [`Dispatch::retry_is_safe`] says `true` — but
    ///    the relay's answer cannot distinguish a scheduled rotation freeze
    ///    from a fault state in which an earlier operation is still in flight
    ///    at the device.
    ///
    /// A consumer that has its own evidence may still choose to resend; what
    /// this returns is whether *this profile* will call a resend safe, and
    /// there is deliberately no argument that overrides it.
    #[must_use]
    pub const fn retry_is_safe_for(&self, operation: Operation) -> bool {
        if !self.retry_is_safe() {
            return false;
        }
        if !operation.mutates_target() {
            return true;
        }
        match self {
            Self::Dispatched(_) => false,
            Self::NotDispatched(NotDispatched::PeerUnavailable) => false,
            Self::NotDispatched(_) | Self::AnsweredLocally(_) => true,
        }
    }

    /// Whether the backend saw the command. Distinct from success.
    ///
    /// **The invariant this method carries:** for any exchange, this is `true`
    /// exactly when the backend recorded one ledger entry for it.
    /// `crates/tunnel-cua-fixture/tests/unknown_versus_not_dispatched.rs`
    /// asserts it row by row, `describe` included.
    #[must_use]
    pub const fn reached_the_backend(&self) -> bool {
        matches!(self, Self::Dispatched(_))
    }

    /// Whether the device answered this without a backend exchange.
    #[must_use]
    pub const fn answered_locally(&self) -> bool {
        matches!(self, Self::AnsweredLocally(_))
    }
}

/// Why nothing was dispatched.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum NotDispatched {
    /// The request body failed schema validation. The device refused it; the
    /// backend was never contacted.
    Schema(SchemaError),
    /// The operation name is not carried by this build.
    Operation(Refusal),
    /// The configured endpoint is not loopback, or is otherwise unusable.
    EndpointRefused,
    /// The operation is not in the negotiated capability set — the
    /// intersection of local configuration, upstream backend support and the
    /// caller's grant. See [`crate::capability`].
    NotPermitted,
    /// The connection to the backend was never established, or was lost
    /// **before** the request was fully written. Nothing reached it.
    NotReached,
    /// The backend answered a pre-dispatch `HTTPException` — shape 3 above.
    BackendRejected { status: u16 },
    /// The backend answered 503: deliberately unavailable, not a transient
    /// fault. A supervisor must not retry through this.
    BackendUnavailable,
    /// The input lease or the capture identity refused the operation. Checked
    /// above the dispatch boundary; nothing was sent. See [`crate::plan`].
    InputAuthority(InputRefusal),
    /// The relay refused the request because the device-side peer was not
    /// ready: a rotation freeze, no active carrier, an unfenced owner.
    ///
    /// **Its own variant because of M3-15.** The relay answers all of those
    /// with one retryable `503 PEER_UNAVAILABLE` `not_dispatched` body, so a
    /// consumer cannot tell a *scheduled* freeze — during which nothing was
    /// dispatched and a retry is genuinely free — from a fault state, during
    /// which an earlier operation may still be in flight at the device. For a
    /// read the distinction costs a round trip. For a click it is the
    /// difference between one click and two, so
    /// [`Dispatch::retry_is_safe_for`] refuses to auto-retry this for a
    /// mutating operation. M3-15's remaining work is to make the two
    /// distinguishable at the relay; until then this profile takes the safe
    /// side.
    PeerUnavailable,
}

/// Why an input operation was refused before anything was sent.
///
/// The two halves of the input contract, kept as separate types so that
/// "you do not hold the lease" and "that capture is stale" cannot be confused
/// for one another in a diagnostic — they have entirely different remedies.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum InputRefusal {
    /// The exclusive input lease refused. See [`crate::lease`].
    Lease(LeaseRefusal),
    /// The capture identity or its coordinates refused. See
    /// [`crate::capture`].
    Capture(CaptureRefusal),
}

impl core::fmt::Display for InputRefusal {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Lease(refusal) => write!(formatter, "{refusal}"),
            Self::Capture(refusal) => write!(formatter, "{refusal}"),
        }
    }
}

impl std::error::Error for InputRefusal {}

/// What a dispatched operation did.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Completion {
    /// Succeeded, with the backend's result payload.
    Ok(Value),
    /// The backend reported a failure. The effect did not happen.
    Failed { code: FailureCode },
    /// **The effect may or may not have happened.** Not retryable.
    Unknown(UnknownReason),
}

/// A backend-reported failure, reduced to a code this repository owns.
///
/// The backend's own message is deliberately **not** carried: it may quote a
/// path, a window title or a clipboard fragment, and `AGENTS.md` keeps
/// payloads out of diagnostics.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum FailureCode {
    /// `success: false` with an error the backend named.
    BackendReported,
    /// The backend reported the operation as unsupported on this backend.
    Unsupported,
    /// The backend reported an OS permission refusal (macOS accessibility or
    /// screen recording, for instance). Preserved as a permission denial
    /// rather than escalated or retried under another backend.
    PermissionDenied,
}

/// Why the outcome of a dispatched operation is not known.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum UnknownReason {
    /// The response began but ended before its framing terminated.
    Truncated,
    /// The response body carried no `data: ` event at all where one was due.
    FramingAbsent,
    /// The framed event is not JSON, or is not an object.
    Unparseable,
    /// The framed payload has **no `success` member**.
    ///
    /// Absent is not `true`. The released envelope always writes one, so a
    /// payload without it is a backend this profile does not understand, and
    /// guessing would be the "config echo standing in for a probe" defect in
    /// its response-parsing costume.
    SuccessAbsent,
    /// The transport was lost after the request was fully written.
    TransportLost,
    /// **The supervisor restarted the backend while this operation was in
    /// flight past the dispatch boundary.**
    ///
    /// The whole reason `docs/tasks.md` M5-C08 exists. A supervisor that
    /// restarts a hung backend has destroyed the only witness to what the
    /// backend had already done, so an operation that had reached it has an
    /// outcome nobody can now establish. Reporting that as
    /// [`NotDispatched`] would be the "unknown outcome read as not
    /// dispatched" trap arriving through the *supervisor* rather than
    /// through the response parser: the caller would retry, and the click
    /// would land twice.
    ///
    /// An operation that had **not** reached the backend when the restart
    /// happened is [`NotDispatched::NotReached`] and is genuinely retryable.
    /// The two are separated by
    /// [`crate::supervision::restart_outcome`], never guessed.
    BackendRestarted,
    /// The exchange deadline expired after the request was fully written.
    DeadlineExpired,
    /// An HTTP status this profile has not reasoned about. Fails towards
    /// unknown on purpose.
    UnexpectedStatus { status: u16 },
}

/// Classify a complete backend response.
///
/// `status` is the HTTP status; `body` is the complete response body, already
/// bounded by the caller. A response that never completed must not be passed
/// here — the caller reports [`UnknownReason::Truncated`],
/// [`UnknownReason::TransportLost`] or [`NotDispatched::NotReached`] itself,
/// because only the caller knows how much of the request it managed to write.
#[must_use]
pub fn classify_backend_response(status: u16, body: &[u8]) -> Dispatch {
    if cua_pin::PRE_DISPATCH_ERROR_STATUSES.contains(&status) {
        return Dispatch::NotDispatched(NotDispatched::BackendRejected { status });
    }
    if status == UNAVAILABLE_STATUS {
        return Dispatch::NotDispatched(NotDispatched::BackendUnavailable);
    }
    if status != 200 {
        return Dispatch::Dispatched(Completion::Unknown(UnknownReason::UnexpectedStatus {
            status,
        }));
    }
    match parse_framed_event(body) {
        Err(reason) => Dispatch::Dispatched(Completion::Unknown(reason)),
        Ok(payload) => Dispatch::Dispatched(classify_payload(&payload)),
    }
}

/// The status `UNAVAILABLE_WITHOUT_CONTAINER_NAME` makes the released server
/// answer when `CONTAINER_NAME` is unset.
pub const UNAVAILABLE_STATUS: u16 = 503;

/// Pull the JSON out of one `data: <JSON>\n\n` event.
///
/// # Errors
/// An [`UnknownReason`] describing what the body was instead. Note that every
/// one of these is *dispatched*: the body stage was reached, which on this
/// backend means the command had already been handed to the registry.
pub fn parse_framed_event(body: &[u8]) -> Result<serde_json::Map<String, Value>, UnknownReason> {
    let text = core::str::from_utf8(body).map_err(|_| UnknownReason::Unparseable)?;
    let Some(rest) = text.strip_prefix(cua_pin::CMD_EVENT_PREFIX) else {
        return Err(UnknownReason::FramingAbsent);
    };
    let Some(json) = rest.strip_suffix(cua_pin::CMD_EVENT_TERMINATOR) else {
        // The prefix arrived and the terminator did not: the response began
        // and stopped. Truncated, not absent, and the difference is whether
        // the backend got as far as producing an answer.
        return Err(UnknownReason::Truncated);
    };
    match serde_json::from_str::<Value>(json) {
        Ok(Value::Object(map)) => Ok(map),
        _ => Err(UnknownReason::Unparseable),
    }
}

/// Decide what a framed payload says, reading **`success` and nothing else**.
///
/// The status played no part in reaching here, and must not: shape 2 above.
#[must_use]
pub fn classify_payload(payload: &serde_json::Map<String, Value>) -> Completion {
    match payload.get(SUCCESS_MEMBER) {
        // Absent is not true.
        None => Completion::Unknown(UnknownReason::SuccessAbsent),
        Some(Value::Bool(true)) => {
            let mut result = payload.clone();
            result.remove(SUCCESS_MEMBER);
            Completion::Ok(Value::Object(result))
        }
        Some(Value::Bool(false)) => Completion::Failed {
            code: failure_code(payload),
        },
        // A non-boolean `success` is a backend this profile does not
        // understand. Truthiness is not a thing here.
        Some(_) => Completion::Unknown(UnknownReason::Unparseable),
    }
}

/// The member the released envelope writes, and which a handler result may
/// override: `{"success": True, **result}`.
pub const SUCCESS_MEMBER: &str = "success";

/// Reduce a backend error to a code this repository owns.
///
/// Matching is on lowercase substrings of the backend's own `error` string.
/// That is a heuristic, it is labelled as one, and its default is the
/// non-committal [`FailureCode::BackendReported`] — a permission denial that
/// this misses is reported as a plain failure, never as a success and never as
/// something to escalate scope for.
fn failure_code(payload: &serde_json::Map<String, Value>) -> FailureCode {
    let message = payload
        .get("error")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_lowercase();
    if message.contains("not supported")
        || message.contains("unsupported")
        || message.contains("unknown command")
    {
        return FailureCode::Unsupported;
    }
    if message.contains("permission")
        || message.contains("not authorized")
        || message.contains("accessibility")
        || message.contains("screen recording")
    {
        return FailureCode::PermissionDenied;
    }
    FailureCode::BackendReported
}

#[cfg(test)]
mod tests;
