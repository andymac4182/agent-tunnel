//! Directional receive state machines.
//!
//! ```text
//! owner → device: REQUEST_HEAD, BODY*, END, outer FIN
//! device → owner: RESPONSE_HEAD, BODY*, END, outer FIN
//! ```
//!
//! Grammar violations are decided from the fixed record header, before a
//! wrong HEAD or BODY payload is read or allocated.  Errors are sticky.

use crate::decoder::{PartialRecord, RecordDecoder, RecordEvent};
use crate::error::CodecError;
use crate::head::{
    Method, RequestHead, ResponseHead, parse_request_head, parse_response_head, requires_zero_body,
};
use crate::record::{RecordHeader, RecordKind};
use crate::validate::{RequestPolicy, ResponsePolicy};

/// Which direction a reader decodes.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Direction {
    /// Owner → device, carrying the request.
    Request,
    /// Device → owner, carrying the response.
    Response,
}

impl Direction {
    const fn head_kind(self) -> RecordKind {
        match self {
            Self::Request => RecordKind::RequestHead,
            Self::Response => RecordKind::ResponseHead,
        }
    }
}

/// Directional phase.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Phase {
    AwaitHead,
    Body,
    AwaitFin,
    Complete,
    Interrupted,
    Failed(CodecError),
}

/// Result of applying an outer RESET or carrier failure.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ResetOutcome {
    /// An unfinished direction is now interrupted.
    Interrupted,
    /// The direction had already completed; that result is preserved.
    AlreadyComplete,
    /// The direction had already failed or been interrupted.
    AlreadyTerminal,
}

/// A decoded request-direction event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RequestEvent<'input> {
    Head(RequestHead),
    Body(&'input [u8]),
    End,
}

/// A decoded response-direction event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResponseEvent<'input> {
    Head(ResponseHead),
    Body(&'input [u8]),
    End,
}

enum Raw<'input> {
    Head(Vec<u8>),
    Body(&'input [u8]),
    End,
}

#[derive(Debug)]
struct Core {
    direction: Direction,
    decoder: RecordDecoder,
    phase: Phase,
    declared: Option<u64>,
    received: u64,
    limit: u64,
    zero_body: bool,
}

impl Core {
    const fn new(direction: Direction, limit: u64) -> Self {
        Self {
            direction,
            decoder: RecordDecoder::new(),
            phase: Phase::AwaitHead,
            declared: None,
            received: 0,
            limit,
            zero_body: false,
        }
    }

    fn fail(&mut self, error: CodecError) -> CodecError {
        self.phase = Phase::Failed(error);
        self.decoder.fail(error);
        error
    }

    fn next<'input>(
        &mut self,
        input: &mut &'input [u8],
    ) -> Result<Option<Raw<'input>>, CodecError> {
        match self.phase {
            Phase::Failed(error) => return Err(error),
            Phase::Complete | Phase::Interrupted => {
                return if input.is_empty() {
                    Ok(None)
                } else {
                    Err(CodecError::AfterTerminal)
                };
            }
            Phase::AwaitFin => {
                // Any record byte after END fails immediately; classify by the
                // kind byte alone so the result is independent of splits.
                let Some(&first) = input.first() else {
                    return Ok(None);
                };
                let error = match RecordKind::from_code(first) {
                    Ok(RecordKind::End) => CodecError::RepeatedEnd,
                    Ok(RecordKind::Body) => CodecError::BodyAfterEnd,
                    Ok(kind) if kind == self.direction.head_kind() => CodecError::SecondHead,
                    Ok(_) => CodecError::WrongDirectionHead,
                    Err(_) => CodecError::DataAfterEnd,
                };
                return Err(self.fail(error));
            }
            Phase::AwaitHead | Phase::Body => {}
        }
        loop {
            let event = match self.decoder.decode(input) {
                Ok(Some(event)) => event,
                Ok(None) => return Ok(None),
                Err(error) => return Err(self.fail(error)),
            };
            match event {
                RecordEvent::Header(header) => {
                    if let Some(raw) = self.on_header(header)? {
                        return Ok(Some(raw));
                    }
                }
                RecordEvent::Head(payload) => return Ok(Some(Raw::Head(payload))),
                RecordEvent::Body { data, .. } => {
                    // Header-time checks already bound the whole record; this
                    // checked add keeps the counter exact per fragment.
                    let Some(received) = self.received.checked_add(data.len() as u64) else {
                        return Err(self.fail(CodecError::BodyLimitExceeded));
                    };
                    self.received = received;
                    return Ok(Some(Raw::Body(data)));
                }
            }
        }
    }

    fn on_header(&mut self, header: RecordHeader) -> Result<Option<Raw<'static>>, CodecError> {
        let kind = header.kind();
        let head_kind = self.direction.head_kind();
        let error = match (self.phase, kind) {
            (_, RecordKind::RequestHead | RecordKind::ResponseHead) if kind != head_kind => {
                CodecError::WrongDirectionHead
            }
            (Phase::AwaitHead, RecordKind::Body) => CodecError::BodyBeforeHead,
            (Phase::AwaitHead, RecordKind::End) => CodecError::EndBeforeHead,
            (Phase::AwaitHead, _) => return Ok(None),
            (Phase::Body, RecordKind::RequestHead | RecordKind::ResponseHead) => {
                CodecError::SecondHead
            }
            (Phase::Body, RecordKind::Body) => match self.check_body_record(header) {
                Ok(()) => return Ok(None),
                Err(error) => error,
            },
            (Phase::Body, RecordKind::End) => match self.check_end() {
                Ok(()) => {
                    self.phase = Phase::AwaitFin;
                    return Ok(Some(Raw::End));
                }
                Err(error) => error,
            },
            // Other phases never reach the decoder.
            _ => CodecError::AfterTerminal,
        };
        Err(self.fail(error))
    }

    fn check_body_record(&self, header: RecordHeader) -> Result<(), CodecError> {
        if self.zero_body {
            return Err(CodecError::BodyForbidden);
        }
        let after = self
            .received
            .checked_add(u64::from(header.payload_len()))
            .ok_or(CodecError::BodyLimitExceeded)?;
        if let Some(declared) = self.declared
            && after > declared
        {
            return Err(CodecError::BodyLongerThanDeclared);
        }
        if after > self.limit {
            return Err(CodecError::BodyLimitExceeded);
        }
        Ok(())
    }

    fn check_end(&self) -> Result<(), CodecError> {
        match self.declared {
            Some(declared) if self.received < declared => Err(CodecError::BodyShorterThanDeclared),
            Some(declared) if self.received > declared => Err(CodecError::BodyLongerThanDeclared),
            _ => Ok(()),
        }
    }

    fn accept_head(&mut self, declared: Option<u64>, zero_body: bool) -> Result<(), CodecError> {
        if let Some(length) = declared
            && length > self.limit
        {
            return Err(self.fail(CodecError::DeclaredLengthExceedsLimit));
        }
        self.declared = declared;
        self.zero_body = zero_body;
        self.phase = Phase::Body;
        Ok(())
    }

    fn fin(&mut self) -> Result<(), CodecError> {
        match self.phase {
            Phase::AwaitFin => {
                self.phase = Phase::Complete;
                Ok(())
            }
            Phase::AwaitHead | Phase::Body => {
                let error = if self.decoder.is_idle() {
                    CodecError::FinBeforeEnd
                } else {
                    CodecError::EofInsideRecord
                };
                Err(self.fail(error))
            }
            Phase::Complete | Phase::Interrupted => Err(CodecError::AfterTerminal),
            Phase::Failed(error) => Err(error),
        }
    }

    fn reset(&mut self) -> ResetOutcome {
        match self.phase {
            Phase::AwaitHead | Phase::Body | Phase::AwaitFin => {
                self.phase = Phase::Interrupted;
                ResetOutcome::Interrupted
            }
            Phase::Complete => ResetOutcome::AlreadyComplete,
            Phase::Interrupted | Phase::Failed(_) => ResetOutcome::AlreadyTerminal,
        }
    }
}

macro_rules! common_reader_methods {
    () => {
        /// Current phase.
        #[must_use]
        pub const fn phase(&self) -> Phase {
            self.core.phase
        }

        /// Body octets accepted so far.
        #[must_use]
        pub const fn body_received(&self) -> u64 {
            self.core.received
        }

        /// The partly received record, for the caller's completion deadline.
        #[must_use]
        pub fn partial_record(&self) -> Option<PartialRecord> {
            self.core.decoder.partial()
        }

        /// Apply the outer ordered FIN.  The caller must have passed every
        /// preceding DATA byte to `read` until it returned `Ok(None)`.
        ///
        /// # Errors
        /// [`CodecError::FinBeforeEnd`] or [`CodecError::EofInsideRecord`].
        pub fn fin(&mut self) -> Result<(), CodecError> {
            self.core.fin()
        }

        /// Apply an outer RESET or unrecoverable carrier failure.
        pub fn reset(&mut self) -> ResetOutcome {
            self.core.reset()
        }

        /// Latch a caller-detected failure such as an expired deadline.
        pub fn abort(&mut self, error: CodecError) {
            if matches!(
                self.core.phase,
                Phase::AwaitHead | Phase::Body | Phase::AwaitFin
            ) {
                self.core.fail(error);
            }
        }
    };
}

/// The owner→device request receiver.
#[derive(Debug)]
pub struct RequestReader {
    core: Core,
    policy: RequestPolicy,
}

impl RequestReader {
    #[must_use]
    pub fn new(policy: RequestPolicy) -> Self {
        Self {
            core: Core::new(Direction::Request, policy.body_limit()),
            policy,
        }
    }

    common_reader_methods!();

    /// Decode the next event from `input`, advancing it.  Returns `Ok(None)`
    /// once `input` is exhausted.
    ///
    /// # Errors
    /// Any record, grammar, head, or length error; errors are sticky.
    pub fn read<'input>(
        &mut self,
        input: &mut &'input [u8],
    ) -> Result<Option<RequestEvent<'input>>, CodecError> {
        Ok(match self.core.next(input)? {
            None => None,
            Some(Raw::Head(payload)) => {
                let head = match parse_request_head(&payload, &self.policy) {
                    Ok(head) => head,
                    Err(error) => return Err(self.core.fail(error)),
                };
                self.core.accept_head(head.body_length, false)?;
                Some(RequestEvent::Head(head))
            }
            Some(Raw::Body(data)) => Some(RequestEvent::Body(data)),
            Some(Raw::End) => Some(RequestEvent::End),
        })
    }
}

/// The device→owner response receiver.  The request method is explicit
/// because a response to HEAD must have no body.
#[derive(Debug)]
pub struct ResponseReader {
    core: Core,
    policy: ResponsePolicy,
    request_method: Method,
}

impl ResponseReader {
    #[must_use]
    pub fn new(policy: ResponsePolicy, request_method: Method) -> Self {
        Self {
            core: Core::new(Direction::Response, policy.body_limit()),
            policy,
            request_method,
        }
    }

    common_reader_methods!();

    /// Decode the next event from `input`, advancing it.
    ///
    /// # Errors
    /// Any record, grammar, head, or length error; errors are sticky.
    pub fn read<'input>(
        &mut self,
        input: &mut &'input [u8],
    ) -> Result<Option<ResponseEvent<'input>>, CodecError> {
        Ok(match self.core.next(input)? {
            None => None,
            Some(Raw::Head(payload)) => {
                let head = match parse_response_head(&payload, &self.policy, self.request_method) {
                    Ok(head) => head,
                    Err(error) => return Err(self.core.fail(error)),
                };
                let zero = requires_zero_body(self.request_method, head.status);
                self.core.accept_head(head.body_length, zero)?;
                Some(ResponseEvent::Head(head))
            }
            Some(Raw::Body(data)) => Some(ResponseEvent::Body(data)),
            Some(Raw::End) => Some(ResponseEvent::End),
        })
    }
}
