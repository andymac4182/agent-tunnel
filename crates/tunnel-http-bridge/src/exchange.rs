//! The explicit shared terminal state of one exchange at one endpoint.
//!
//! The lock guards a few plain fields and is never held across an await.

use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Mutex, MutexGuard};

use tokio_util::sync::CancellationToken;
use tunnel_http_forward::HttpErrorCode;

use crate::status::{ExchangeReport, Execution, Outcome, ResetDetail};
use crate::stream::FrameSender;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Dir {
    Request,
    Response,
}

#[derive(Debug)]
struct State {
    request: Outcome,
    response: Outcome,
    error: Option<HttpErrorCode>,
}

pub(crate) struct Exchange {
    /// Cancelled on the first failure: every pump stops promptly.
    pub stop: CancellationToken,
    pub request_terminal: CancellationToken,
    pub response_terminal: CancellationToken,
    state: Mutex<State>,
    execution: AtomicU8,
    /// This endpoint's sending direction.
    pub peer: FrameSender,
}

impl Exchange {
    pub fn new(peer: FrameSender, execution: Execution) -> Self {
        Self {
            stop: CancellationToken::new(),
            request_terminal: CancellationToken::new(),
            response_terminal: CancellationToken::new(),
            state: Mutex::new(State {
                request: Outcome::Pending,
                response: Outcome::Pending,
                error: None,
            }),
            execution: AtomicU8::new(execution.to_u8()),
            peer,
        }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub fn execution(&self) -> Execution {
        Execution::from_u8(self.execution.load(Ordering::SeqCst))
    }

    pub fn set_execution(&self, execution: Execution) {
        self.execution.store(execution.to_u8(), Ordering::SeqCst);
    }

    const fn token(&self, dir: Dir) -> &CancellationToken {
        match dir {
            Dir::Request => &self.request_terminal,
            Dir::Response => &self.response_terminal,
        }
    }

    /// Mark a direction complete unless it already aborted.
    pub fn complete(&self, dir: Dir) {
        {
            let mut state = self.lock();
            let slot = match dir {
                Dir::Request => &mut state.request,
                Dir::Response => &mut state.response,
            };
            if *slot == Outcome::Pending {
                *slot = Outcome::Complete;
            }
        }
        self.token(dir).cancel();
    }

    pub fn is_complete(&self, dir: Dir) -> bool {
        let state = self.lock();
        match dir {
            Dir::Request => state.request == Outcome::Complete,
            Dir::Response => state.response == Outcome::Complete,
        }
    }

    /// Atomically claim handler invocation: fails if the exchange already
    /// failed, so a RESET can never claim `not_dispatched` for a handler that
    /// is then started.
    pub fn begin_dispatch(&self) -> bool {
        let state = self.lock();
        if state.error.is_some() {
            return false;
        }
        self.set_execution(Execution::Dispatched);
        true
    }

    /// Record the first failure, abort unfinished directions, stop every
    /// pump and emit RESET once.  Completed directions stay complete.
    /// Returns the reset detail if this call recorded the first failure.
    pub fn abort(&self, code: HttpErrorCode) -> Option<ResetDetail> {
        let (detail, first) = {
            let mut state = self.lock();
            if state.request == Outcome::Complete && state.response == Outcome::Complete {
                return None;
            }
            let State {
                request,
                response,
                error,
            } = &mut *state;
            let first = error.is_none();
            let code = *error.get_or_insert(code);
            for slot in [request, response] {
                if *slot == Outcome::Pending {
                    *slot = Outcome::Aborted;
                }
            }
            // Read under the lock that `begin_dispatch` takes.
            let detail = ResetDetail {
                code,
                execution: self.execution(),
            };
            (detail, first)
        };
        self.stop.cancel();
        self.request_terminal.cancel();
        self.response_terminal.cancel();
        self.peer.reset(detail);
        first.then_some(detail)
    }

    pub fn error_code(&self) -> HttpErrorCode {
        self.lock()
            .error
            .unwrap_or(HttpErrorCode::StreamInterrupted)
    }

    pub fn report(&self) -> ExchangeReport {
        let state = self.lock();
        ExchangeReport {
            request: state.request,
            response: state.response,
            execution: self.execution(),
            error: state.error,
        }
    }
}
