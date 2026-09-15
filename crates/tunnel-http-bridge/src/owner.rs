//! The owner-side ingress adapter.

use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Request, Response, StatusCode, header};
use http_body::Body;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use tunnel_http_forward::{
    HttpErrorCode, Method, ResponseEvent, ResponseHead, ResponseReader, requires_zero_body,
};

use crate::body::{BodySender, ChannelBody};
use crate::exchange::{Dir, Exchange};
use crate::normalize;
use crate::pump::{self, PumpError};
use crate::status::{
    ExchangeReport, Execution, Origin, Outcome, ResetDetail, gateway_response, gateway_status,
};
use crate::stream::{Frame, FrameReceiver, FrameSender};
use crate::{BridgeConfig, Profile};

/// Observes and controls a forwarded exchange after `forward` returns.
pub struct ExchangeHandle {
    task: JoinHandle<ExchangeReport>,
    consumer: CancellationToken,
}

impl ExchangeHandle {
    /// Cancel the exchange as a consumer disconnect would.
    pub fn cancel(&self) {
        self.consumer.cancel();
    }

    /// Wait for both directions to reach a terminal state.
    pub async fn report(self) -> ExchangeReport {
        self.task.await.unwrap_or(ExchangeReport {
            request: Outcome::Pending,
            response: Outcome::Pending,
            execution: Execution::Unknown,
            error: Some(HttpErrorCode::StreamInterrupted),
        })
    }
}

enum HeadOutcome {
    Committed(Response<ChannelBody>),
    Failed(Origin, ResetDetail),
}

struct Owner {
    exchange: Exchange,
    head: Mutex<Option<oneshot::Sender<HeadOutcome>>>,
    consumer: CancellationToken,
}

impl Owner {
    fn take_head(&self) -> Option<oneshot::Sender<HeadOutcome>> {
        self.head
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
    }

    /// Abort the exchange; before headers commit, answer with a gateway
    /// response carrying the first failure.
    fn fail(&self, origin: Origin, code: HttpErrorCode) {
        if let Some(detail) = self.exchange.abort(code)
            && let Some(head) = self.take_head()
        {
            let _ = head.send(HeadOutcome::Failed(origin, detail));
        }
    }

    /// The device reset: its dispatch record is authoritative.
    fn peer_reset(&self, detail: ResetDetail) {
        if !self.exchange.is_complete(Dir::Response) {
            self.exchange.set_execution(detail.execution);
        }
        self.fail(Origin::Upstream, detail.code);
    }

    fn pump_failed(&self, error: PumpError) {
        match error {
            PumpError::Stopped => {}
            PumpError::Source(code) => self.fail(Origin::Consumer, code),
            PumpError::Sink(code) => self.fail(Origin::Upstream, code),
        }
    }

    fn commit(&self, response: Response<ChannelBody>) -> bool {
        match self.take_head() {
            Some(head) => {
                let _ = head.send(HeadOutcome::Committed(response));
                true
            }
            None => false,
        }
    }
}

fn rejected(
    status: StatusCode,
    code: HttpErrorCode,
    execution: Execution,
) -> (Response<ChannelBody>, ExchangeHandle) {
    let report = ExchangeReport {
        request: Outcome::Aborted,
        response: Outcome::Aborted,
        execution,
        error: Some(code),
    };
    (
        gateway_response(status, code, execution),
        ExchangeHandle {
            task: tokio::spawn(async move { report }),
            consumer: CancellationToken::new(),
        },
    )
}

/// Forward one consumer request over one logical stream.
///
/// Returns once the device's response head arrives (early responses are
/// returned while the upload continues) or a failure is decided before
/// headers.  Nothing is written to `to_device` unless the request passes
/// normalization and policy validation.  Dropping the returned future, or
/// the response body before it ends, cancels the exchange with RESET.
pub async fn forward<B>(
    request: Request<B>,
    profile: Arc<Profile>,
    config: BridgeConfig,
    to_device: FrameSender,
    from_device: FrameReceiver,
) -> (Response<ChannelBody>, ExchangeHandle)
where
    B: Body<Data = Bytes> + Send + 'static,
{
    let (parts, body) = request.into_parts();
    let ingress = match normalize::request_head(&parts, &profile.request) {
        Ok(ingress) => ingress,
        Err(error) => return rejected(error.status(), error.code(), Execution::NotDispatched),
    };
    let method = ingress.head.method;
    let declared = ingress.head.body_length;
    let (head_tx, head_rx) = oneshot::channel();
    let consumer = CancellationToken::new();
    let owner = Arc::new(Owner {
        exchange: Exchange::new(to_device, Execution::NotDispatched),
        head: Mutex::new(Some(head_tx)),
        consumer: consumer.clone(),
    });
    let task = tokio::spawn(run(
        Arc::clone(&owner),
        ingress.record,
        body,
        declared,
        method,
        profile,
        config,
        from_device,
    ));
    let handle = ExchangeHandle {
        task,
        consumer: consumer.clone(),
    };
    let guard = consumer.drop_guard();
    let outcome = head_rx.await;
    drop(guard.disarm());
    let response = match outcome {
        Ok(HeadOutcome::Committed(response)) => response,
        Ok(HeadOutcome::Failed(origin, detail)) => gateway_response(
            gateway_status(origin, detail.code, detail.execution),
            detail.code,
            detail.execution,
        ),
        Err(_) => {
            let execution = owner.exchange.execution();
            gateway_response(
                gateway_status(
                    Origin::Upstream,
                    HttpErrorCode::StreamInterrupted,
                    execution,
                ),
                HttpErrorCode::StreamInterrupted,
                execution,
            )
        }
    };
    (response, handle)
}

#[allow(clippy::too_many_arguments)]
async fn run<B>(
    owner: Arc<Owner>,
    head_record: Bytes,
    body: B,
    declared: Option<u64>,
    method: Method,
    profile: Arc<Profile>,
    config: BridgeConfig,
    from_device: FrameReceiver,
) -> ExchangeReport
where
    B: Body<Data = Bytes> + Send + 'static,
{
    let exchange = &owner.exchange;
    let started = Instant::now();
    let deadline_at = started + config.deadline();
    let discard_until = started + config.discard_bound();
    let request = async {
        // A head no larger than the credit capacity is one queue item: it is
        // either wholly queued or not queued at all.  Only once it is queued
        // can the request reach the device.  A larger head could be partly
        // queued before a failure, so it is `unknown` from the start.
        if head_record.len() > exchange.peer.capacity() {
            exchange.set_execution(Execution::Unknown);
        }
        if let Err(error) = pump::send(exchange, head_record).await {
            owner.pump_failed(error);
            return;
        }
        exchange.set_execution(Execution::Unknown);
        let body = std::pin::pin!(body);
        match pump::pump_body(exchange, body, declared, profile.request.body_limit()).await {
            Ok(()) => exchange.complete(Dir::Request),
            Err(error) => owner.pump_failed(error),
        }
    };
    let response = response_pump(
        &owner,
        from_device,
        ResponseReader::new(profile.response.clone(), method),
        method,
        config.body_queue(),
        discard_until,
    );
    let pumps = async {
        tokio::join!(request, response);
    };
    let watchdog = async {
        let deadline = tokio::time::sleep_until(deadline_at);
        let finished = async {
            exchange.request_terminal.cancelled().await;
            exchange.response_terminal.cancelled().await;
        };
        tokio::select! {
            biased;
            () = finished => {}
            () = owner.consumer.cancelled() => owner.fail(Origin::Consumer, HttpErrorCode::Cancelled),
            () = deadline => owner.fail(Origin::Upstream, HttpErrorCode::DeadlineExceeded),
        }
    };
    tokio::join!(pumps, watchdog);
    exchange.report()
}

fn build_response(
    head: ResponseHead,
    method: Method,
    queue: usize,
    consumer: &CancellationToken,
) -> Result<(Response<ChannelBody>, BodySender), HttpErrorCode> {
    let status = StatusCode::from_u16(head.status).map_err(|_| HttpErrorCode::InvalidHead)?;
    let mut headers = HeaderMap::new();
    for field in &head.headers {
        let name = HeaderName::from_bytes(field.name.as_bytes())
            .map_err(|_| HttpErrorCode::InvalidHead)?;
        let value = HeaderValue::from_str(&field.value).map_err(|_| HttpErrorCode::InvalidHead)?;
        headers.append(name, value);
    }
    let zero_body = requires_zero_body(method, head.status);
    if !zero_body && let Some(length) = head.body_length {
        // Generated from the checked typed length, never copied framing.
        headers.insert(header::CONTENT_LENGTH, HeaderValue::from(length));
    }
    let (sender, body) = ChannelBody::channel(queue, head.body_length, Some(consumer.clone()));
    let mut response = Response::new(body);
    *response.status_mut() = status;
    *response.headers_mut() = headers;
    Ok((response, sender))
}

async fn response_pump(
    owner: &Owner,
    mut from_device: FrameReceiver,
    mut reader: ResponseReader,
    method: Method,
    queue: usize,
    discard_until: Instant,
) {
    let exchange = &owner.exchange;
    let mut signal = from_device.reset_signal();
    let mut body: Option<BodySender> = None;
    let mut peer_terminated = false;
    'frames: loop {
        let listen_only = exchange.is_complete(Dir::Response);
        let frame = tokio::select! {
            biased;
            () = exchange.stop.cancelled() => break,
            () = exchange.request_terminal.cancelled(), if listen_only => return,
            frame = from_device.recv() => frame,
        };
        if matches!(frame, None | Some(Frame::Reset(_))) {
            peer_terminated = true;
        }
        match frame {
            None => {
                if !listen_only {
                    owner.fail(Origin::Upstream, HttpErrorCode::StreamInterrupted);
                }
                break;
            }
            Some(Frame::Reset(detail)) => {
                owner.peer_reset(detail);
                break;
            }
            Some(Frame::Fin) => match reader.fin() {
                Ok(()) => {
                    if let Some(sender) = body.take() {
                        sender.finish();
                    }
                    exchange.complete(Dir::Response);
                }
                Err(error) => {
                    owner.fail(Origin::Upstream, error.code());
                    break;
                }
            },
            Some(Frame::Data(bytes)) => {
                let mut input: &[u8] = &bytes;
                loop {
                    let event = match reader.read(&mut input) {
                        Ok(Some(event)) => event,
                        Ok(None) => break,
                        Err(error) => {
                            owner.fail(Origin::Upstream, error.code());
                            break 'frames;
                        }
                    };
                    match event {
                        ResponseEvent::Head(head) => {
                            match build_response(head, method, queue, &owner.consumer) {
                                Ok((response, sender)) => {
                                    // A response head is only sent after the
                                    // handler returned.
                                    exchange.set_execution(Execution::Dispatched);
                                    body = Some(sender);
                                    if !owner.commit(response) {
                                        break 'frames;
                                    }
                                }
                                Err(code) => {
                                    owner.fail(Origin::Upstream, code);
                                    break 'frames;
                                }
                            }
                        }
                        ResponseEvent::Body(slice) => {
                            let Some(sender) = body.as_ref() else {
                                continue;
                            };
                            let chunk = bytes.slice_ref(slice);
                            tokio::select! {
                                biased;
                                () = exchange.stop.cancelled() => break 'frames,
                                sent = sender.send(chunk) => if sent.is_err() {
                                    owner.fail(Origin::Consumer, HttpErrorCode::Cancelled);
                                    break 'frames;
                                },
                                // Only a RESET before the device's FIN: bytes
                                // of a response the device completed are
                                // delivered, and a later RESET is seen in
                                // order (it then aborts only the upload).
                                detail = signal.wait_before_fin() => {
                                    owner.peer_reset(detail);
                                    break 'frames;
                                }
                            }
                        }
                        ResponseEvent::End => {}
                    }
                }
            }
        }
    }
    if let Some(sender) = body.take() {
        sender.fail(exchange.error_code());
    }
    if !peer_terminated {
        // Bounded by the deadline plus a short grace: a peer that never
        // finishes cannot hold the exchange open, but a deadline abort still
        // gives the peer time to see the RESET instead of a lost receiver.
        let _ = tokio::time::timeout_at(discard_until, from_device.discard_until_terminal()).await;
    }
}
