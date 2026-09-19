//! The Lane A dispatch path: validate, negotiate, check the endpoint, then —
//! and only then — send one `/cmd` exchange and classify the answer.
//!
//! **Where this lives, and why.** The device-side facade — supervision, the
//! exclusive input lease, the capture-identity carry-forward, the tunnel
//! session state that all three hang off — is a later chunk, and none of it is
//! needed to dispatch a read-only operation. What *is* needed is the thing
//! this module is: the ordering of the checks, the boundary they sit on, and
//! the classification of what comes back. It lives beside the fixture because
//! the fixture is the only backend it is allowed to talk to.
//!
//! **The ordering is the contract.** Every check below the comment marked
//! `dispatch boundary` may produce a [`Completion`]; every check above it may
//! only produce a [`NotDispatched`]. A test reads the fixture's ledger to
//! check that claim rather than taking this module's word for it.

use std::collections::BTreeSet;
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use tunnel_cua::capability::{CallerGrant, LocalConfiguration, UpstreamSupport};
use tunnel_cua::endpoint::BackendEndpoint;
use tunnel_cua::operation::Operation;
use tunnel_cua::outcome::{
    Completion, Dispatch, NotDispatched, UnknownReason, classify_backend_response,
};
use tunnel_cua::plan::{Planned, discovery_payload, plan};
use tunnel_cua::schema::Request;

use crate::CMD_PATH;

/// Everything the dispatcher needs that is not the request.
pub struct Dispatcher {
    endpoint: BackendEndpoint,
    permitted: BTreeSet<Operation>,
    deadline: Duration,
}

/// The default per-exchange deadline. Finite; there is no unlimited value.
pub const DEFAULT_DEADLINE: Duration = Duration::from_secs(10);

impl Dispatcher {
    /// Build a dispatcher for a negotiated capability set.
    ///
    /// The capability set is computed by the caller through
    /// [`tunnel_cua::capability::negotiate`], so the dispatcher cannot widen
    /// it: it has no access to the three inputs, only to their intersection.
    #[must_use]
    pub fn new(endpoint: BackendEndpoint, permitted: BTreeSet<Operation>) -> Self {
        Self {
            endpoint,
            permitted,
            deadline: DEFAULT_DEADLINE,
        }
    }

    /// Build one from the three negotiation inputs.
    #[must_use]
    pub fn negotiated(
        endpoint: BackendEndpoint,
        local: &LocalConfiguration,
        upstream: &UpstreamSupport,
        grant: &CallerGrant,
    ) -> Self {
        Self::new(
            endpoint,
            tunnel_cua::capability::negotiate(local, upstream, grant),
        )
    }

    #[must_use]
    pub fn with_deadline(mut self, deadline: Duration) -> Self {
        self.deadline = deadline;
        self
    }

    #[must_use]
    pub fn permits(&self, operation: Operation) -> bool {
        self.permitted.contains(&operation)
    }

    /// Validate a consumer request body and dispatch it if everything allows.
    ///
    /// **The ordering is not written here.** It lives in
    /// [`tunnel_cua::plan::plan`], in the production crate, so a future
    /// device-side facade inherits it rather than re-deriving it. This
    /// function is the part that is genuinely transport: take the plan, and
    /// either send it or answer it locally.
    pub async fn handle(&self, body: &[u8], limit: u64) -> Dispatch {
        // ---- above the dispatch boundary: nothing has been sent -------------
        let planned = match plan(body, limit, &self.permitted) {
            Ok(planned) => planned,
            Err(refused) => return refused,
        };
        let payload = match planned {
            // `describe` is answered from the negotiated set -- the only
            // honest thing it could be answered from, since a config echo
            // would be the trap. It is **not** a dispatch, and reporting it as
            // one made `reached_the_backend()` true for an operation that sent
            // no bytes.
            Planned::AnswerLocally { .. } => {
                return Dispatch::AnsweredLocally(self.describe());
            }
            Planned::Dispatch { payload, .. } => payload,
        };

        // ---- the dispatch boundary -----------------------------------------
        // Past this line the backend may have seen the command, so no failure
        // may be reported as `NotDispatched` unless we know the request was
        // never fully written.
        self.send(&payload).await
    }

    /// Read the backend's `version` response, which is where
    /// `desktop_capture_authorized` lives.
    ///
    /// Separate from [`Dispatcher::handle`] because `version` is not a
    /// `computer.v1` operation: it is issued during capability discovery, on
    /// nobody's behalf, and it goes through
    /// [`tunnel_cua::plan::discovery_payload`] which admits only the commands
    /// `describe` reads.
    pub async fn read_version(&self) -> Dispatch {
        match discovery_payload(tunnel_cua::capability::CAPTURE_AUTHORITY_COMMAND) {
            Err(refusal) => Dispatch::NotDispatched(refusal),
            Ok(payload) => self.send(&payload).await,
        }
    }

    /// The `describe` answer: the negotiated set, and facts this dispatcher
    /// can actually observe.
    ///
    /// `endpoint_is_loopback` is **derived from the endpoint**, not written as
    /// a literal. It is tautologically true given that
    /// [`BackendEndpoint`] cannot hold anything else -- but a hardcoded `true`
    /// asserting a safety property is the config-echo shape this chunk spends
    /// its length policing, and a derived one costs nothing.
    fn describe(&self) -> Value {
        json!({
            "operations": self
                .permitted
                .iter()
                .map(|operation| operation.name())
                .collect::<Vec<_>>(),
            "endpoint_is_loopback": self.endpoint.address().ip().is_loopback(),
        })
    }

    async fn send(&self, payload: &Value) -> Dispatch {
        match tokio::time::timeout(self.deadline, self.exchange(payload)).await {
            // The deadline expired. We had already begun writing, so the
            // outcome is unknown rather than not dispatched.
            Err(_) => Dispatch::Dispatched(Completion::Unknown(UnknownReason::DeadlineExpired)),
            Ok(Err(stage)) => stage.into_dispatch(),
            Ok(Ok((status, body))) => classify_backend_response(status, &body),
        }
    }

    /// One HTTP/1.1 exchange against the fixture.
    ///
    /// The error type is the **stage** the failure happened at, because that
    /// is precisely what decides `NotDispatched` versus `Unknown`. An error
    /// that merely said "I/O error" would have thrown the distinction away at
    /// the only point where it is recoverable.
    async fn exchange(&self, payload: &Value) -> Result<(u16, Vec<u8>), FailureStage> {
        let mut stream = TcpStream::connect(self.endpoint.address())
            .await
            .map_err(|_| FailureStage::Connecting)?;
        let body = payload.to_string();
        let request = format!(
            "POST {CMD_PATH} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            self.endpoint.address(),
            body.len()
        );
        // Written and flushed as one unit. Until this returns Ok, nothing was
        // fully delivered and the request is safely `NotReached`.
        //
        // **The assumption this rests on, stated rather than left implicit.**
        // Treating a partial write as `NotDispatched` is only sound because
        // the backend will not act on a truncated request: the pinned server
        // reads a `Content-Length`-framed body and dispatches to the command
        // registry **after** the body is complete, so bytes that never arrived
        // cannot have been parsed into a command. A backend that dispatched
        // incrementally -- a chunked or streaming command surface -- would
        // break this, and `/ws` is exactly such a surface. It is deferred
        // (`cua_pin::WEBSOCKET_DEFERRAL_RECORDED_AS`), and a chunk that takes
        // it up must revisit this mapping rather than inherit it.
        stream
            .write_all(request.as_bytes())
            .await
            .map_err(|_| FailureStage::Writing)?;
        stream.flush().await.map_err(|_| FailureStage::Writing)?;

        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .await
            .map_err(|_| FailureStage::Reading)?;
        if response.is_empty() {
            // The connection closed with no answer at all, after we had
            // written the whole request. Dispatched; outcome unknown.
            return Err(FailureStage::Reading);
        }
        parse_response(&response).ok_or(FailureStage::Reading)
    }
}

/// Where in the exchange a failure happened.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FailureStage {
    /// The connection was never established. Nothing was sent.
    Connecting,
    /// The request was not fully written. Partial HTTP is not a command: the
    /// backend cannot have parsed a body it did not receive.
    Writing,
    /// The request was fully written and the answer was lost.
    Reading,
}

impl FailureStage {
    const fn into_dispatch(self) -> Dispatch {
        match self {
            Self::Connecting | Self::Writing => Dispatch::NotDispatched(NotDispatched::NotReached),
            Self::Reading => {
                Dispatch::Dispatched(Completion::Unknown(UnknownReason::TransportLost))
            }
        }
    }
}

/// Split an HTTP/1.1 response into its status and body.
fn parse_response(bytes: &[u8]) -> Option<(u16, Vec<u8>)> {
    let separator = bytes.windows(4).position(|window| window == b"\r\n\r\n")?;
    let head = core::str::from_utf8(&bytes[..separator]).ok()?;
    let status = head
        .split("\r\n")
        .next()?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()?;
    Some((status, bytes[separator + 4..].to_vec()))
}

/// Read the backend's `/commands` listing.
///
/// Separate from [`Dispatcher`] because it is part of building an
/// [`UpstreamSupport`], not part of dispatching an operation — and because a
/// `/commands` reading is **not** on its own evidence that a backend can act.
///
/// # Errors
/// Any I/O failure, or a response this function cannot parse.
pub async fn read_commands(endpoint: BackendEndpoint) -> std::io::Result<Vec<String>> {
    let mut stream = TcpStream::connect(endpoint.address()).await?;
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        crate::COMMANDS_PATH,
        endpoint.address()
    );
    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await?;
    let (_, body) = parse_response(&response).ok_or(std::io::ErrorKind::InvalidData)?;
    let value: Value =
        serde_json::from_slice(&body).map_err(|_| std::io::ErrorKind::InvalidData)?;
    Ok(value
        .get("commands")
        .and_then(Value::as_array)
        .map(|list| {
            list.iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default())
}

/// Build a `computer.v1` request body, the way a consumer would.
#[must_use]
pub fn request_body(operation: &str, params: Value) -> Vec<u8> {
    json!({
        "version": tunnel_cua::SCHEMA_VERSION,
        "operation": operation,
        "params": params,
    })
    .to_string()
    .into_bytes()
}

/// A convenience for a validated request's operation, for tests that need to
/// name what they sent.
#[must_use]
pub fn operation_of(request: &Request) -> Operation {
    request.operation()
}
