//! Owner re-validation of relayed `http-forward/1` records (review finding B
//! of implementation gate 3) and the fixture hold positions of gate 4.
//!
//! The owner's peer relay no longer trusts the ingress (or the device) to
//! have validated the record stream.  Each direction runs the codec's
//! directional reader against the owner's own copy of the export profile
//! *before* forwarding a chunk:
//!
//! * owner→device: [`OwnerRequestWriter`] wraps the actor writer and runs a
//!   [`RequestReader`], so an invalid head, record grammar or length never
//!   reaches the device; a head the owner rejects was never forwarded, so
//!   the owner reports `not_dispatched`;
//! * device→owner: [`OwnerResponseWriter`] wraps the peer-hop writer and runs
//!   a [`ResponseReader`] for the request method the owner validated.
//!
//! Only a HEAD payload (at most 16 KiB) is retained while it is incomplete;
//! BODY octets pass through as slices of the chunk being forwarded, never
//! collected.  On a failure the owner resets both directions with the same
//! sanitized detail: the device through the ordered actor RESET, the ingress
//! through the peer-hop RESET record.

use std::future::Future;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use tokio::sync::watch;
use tunnel_http_bridge::{CarrierClosed, CarrierWriter, Execution, FrameSender, ResetDetail};
use tunnel_http_forward::{
    CodecError, HttpErrorCode, Method, RecordKind, RecordPosition, RecordTracker, RequestEvent,
    RequestPolicy, RequestReader, ResponsePolicy, ResponseReader,
};

use super::hold::{HttpRelayHoldPoint, HttpRelayInterposer};

/// The first owner-side validation failure of one relayed exchange.
#[derive(Debug, Default)]
pub(crate) struct OwnerVerdict {
    detail: Mutex<Option<ResetDetail>>,
}

impl OwnerVerdict {
    /// Record the first failure; returns whether this call recorded it.
    fn set(&self, detail: ResetDetail) -> bool {
        let mut slot = self
            .detail
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if slot.is_some() {
            return false;
        }
        *slot = Some(detail);
        true
    }

    pub(crate) fn get(&self) -> Option<ResetDetail> {
        *self
            .detail
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// Owner→device: validate, then forward to the actor stream.
pub(crate) struct OwnerRequestWriter<W> {
    inner: W,
    reader: RequestReader,
    method: watch::Sender<Option<Method>>,
    tracker: RecordTracker,
    hold: Option<Arc<dyn HttpRelayInterposer>>,
    verdict: Arc<OwnerVerdict>,
    /// The owner→ingress direction, reset with the owner's detail.
    other: FrameSender,
}

impl<W: CarrierWriter> OwnerRequestWriter<W> {
    pub(crate) fn new(
        inner: W,
        policy: RequestPolicy,
        method: watch::Sender<Option<Method>>,
        hold: Option<Arc<dyn HttpRelayInterposer>>,
        verdict: Arc<OwnerVerdict>,
        other: FrameSender,
    ) -> Self {
        Self {
            inner,
            reader: RequestReader::new(policy),
            method,
            tracker: RecordTracker::new(),
            hold,
            verdict,
            other,
        }
    }

    fn validate(&mut self, chunk: &[u8]) -> Result<(), CodecError> {
        let mut input = chunk;
        loop {
            match self.reader.read(&mut input)? {
                Some(RequestEvent::Head(head)) => {
                    self.method.send_replace(Some(head.method));
                }
                Some(_) => {}
                None => return Ok(()),
            }
        }
    }

    /// The prefix length to forward before holding this chunk, if an armed
    /// hold names the position this chunk starts at.
    fn hold_split(&self, chunk: &[u8]) -> Option<(usize, HttpRelayHoldPoint)> {
        let point = self.hold.as_ref()?.armed_point()?;
        let snapshot = self.tracker.snapshot();
        match point {
            HttpRelayHoldPoint::InsideBodyHeader { bytes }
                if snapshot.heads > 0
                    && snapshot.position == RecordPosition::Boundary
                    && chunk.first() == Some(&RecordKind::Body.code())
                    && chunk.len() > usize::from(bytes) =>
            {
                Some((usize::from(bytes), point))
            }
            HttpRelayHoldPoint::InsideBodyPayload
                if matches!(
                    snapshot.position,
                    RecordPosition::Payload {
                        kind: RecordKind::Body,
                        received: 0,
                        ..
                    }
                ) && chunk.len() >= 2 =>
            {
                Some((chunk.len() / 2, point))
            }
            _ => None,
        }
    }

    async fn fail(&mut self, code: HttpErrorCode) {
        let execution = if self.tracker.snapshot().heads > 0 {
            Execution::Unknown
        } else {
            Execution::NotDispatched
        };
        let detail = ResetDetail { code, execution };
        if self.verdict.set(detail) {
            tracing::debug!(
                code = code.as_str(),
                execution = execution.as_str(),
                phase = "http_forward_owner_request_rejected"
            );
        }
        self.other.reset(detail);
        self.inner.reset(detail).await;
    }
}

#[allow(clippy::manual_async_fn)]
impl<W: CarrierWriter> CarrierWriter for OwnerRequestWriter<W> {
    fn data(&mut self, data: Bytes) -> impl Future<Output = Result<(), CarrierClosed>> + Send {
        async move {
            if let Err(error) = self.validate(&data) {
                self.fail(error.code()).await;
                return Err(CarrierClosed);
            }
            let mut chunk = data;
            if let Some((prefix_len, point)) = self.hold_split(&chunk) {
                let prefix = chunk.split_to(prefix_len);
                let observed = prefix.clone();
                self.inner.data(prefix).await?;
                self.tracker.observe(&observed);
                if let Some(hold) = self.hold.clone() {
                    hold.hold_at(point).await;
                }
            }
            let observed = chunk.clone();
            self.inner.data(chunk).await?;
            self.tracker.observe(&observed);
            Ok(())
        }
    }

    fn finish(&mut self) -> impl Future<Output = Result<(), CarrierClosed>> + Send {
        async move {
            if let Err(error) = self.reader.fin() {
                self.fail(error.code()).await;
                return Err(CarrierClosed);
            }
            if let Some(hold) = self.hold.clone()
                && self.tracker.snapshot().ends > 0
            {
                hold.hold_at(HttpRelayHoldPoint::BeforeRequestFin).await;
            }
            self.inner.finish().await
        }
    }

    fn reset(&mut self, detail: ResetDetail) -> impl Future<Output = ()> + Send {
        self.inner.reset(detail)
    }
}

/// Device→owner: validate, then forward to the peer hop.
pub(crate) struct OwnerResponseWriter<W> {
    inner: W,
    reader: Option<ResponseReader>,
    policy: ResponsePolicy,
    method: watch::Receiver<Option<Method>>,
    verdict: Arc<OwnerVerdict>,
    /// The owner→device direction, reset with the owner's detail.
    other: FrameSender,
}

impl<W: CarrierWriter> OwnerResponseWriter<W> {
    pub(crate) fn new(
        inner: W,
        policy: ResponsePolicy,
        method: watch::Receiver<Option<Method>>,
        verdict: Arc<OwnerVerdict>,
        other: FrameSender,
    ) -> Self {
        Self {
            inner,
            reader: None,
            policy,
            method,
            verdict,
            other,
        }
    }

    fn validate(&mut self, chunk: &[u8]) -> Result<(), HttpErrorCode> {
        if self.reader.is_none() {
            // A response can only answer a request head the owner validated.
            let method = (*self.method.borrow()).ok_or(HttpErrorCode::BadRecord)?;
            self.reader = Some(ResponseReader::new(self.policy.clone(), method));
        }
        let Some(reader) = self.reader.as_mut() else {
            return Err(HttpErrorCode::BadRecord);
        };
        let mut input = chunk;
        loop {
            match reader.read(&mut input) {
                Ok(Some(_)) => {}
                Ok(None) => return Ok(()),
                Err(error) => return Err(error.code()),
            }
        }
    }

    async fn fail(&mut self, code: HttpErrorCode) {
        let detail = ResetDetail {
            code,
            execution: Execution::Unknown,
        };
        if self.verdict.set(detail) {
            tracing::debug!(
                code = code.as_str(),
                phase = "http_forward_owner_response_rejected"
            );
        }
        self.other.reset(detail);
        self.inner.reset(detail).await;
    }
}

#[allow(clippy::manual_async_fn)]
impl<W: CarrierWriter> CarrierWriter for OwnerResponseWriter<W> {
    fn data(&mut self, data: Bytes) -> impl Future<Output = Result<(), CarrierClosed>> + Send {
        async move {
            if let Err(code) = self.validate(&data) {
                self.fail(code).await;
                return Err(CarrierClosed);
            }
            self.inner.data(data).await
        }
    }

    fn finish(&mut self) -> impl Future<Output = Result<(), CarrierClosed>> + Send {
        async move {
            let result = match self.reader.as_mut() {
                Some(reader) => reader.fin().map_err(|error| error.code()),
                None => Err(HttpErrorCode::BadRecord),
            };
            if let Err(code) = result {
                self.fail(code).await;
                return Err(CarrierClosed);
            }
            self.inner.finish().await
        }
    }

    fn reset(&mut self, detail: ResetDetail) -> impl Future<Output = ()> + Send {
        self.inner.reset(detail)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tunnel_http_bridge::{Frame, channel};
    use tunnel_http_forward::{
        END_RECORD, HeaderField, HttpVersion, Occurrence, RequestHead, ResponseHead, encode_body,
        encode_record, encode_request_head, encode_response_head,
    };

    /// A carrier writer that records what reached it.
    #[derive(Clone, Default)]
    struct Recorder {
        events: Arc<Mutex<Vec<String>>>,
        bytes: Arc<Mutex<Vec<u8>>>,
    }

    impl Recorder {
        fn events(&self) -> Vec<String> {
            self.events.lock().unwrap().clone()
        }
        fn bytes(&self) -> Vec<u8> {
            self.bytes.lock().unwrap().clone()
        }
    }

    impl CarrierWriter for Recorder {
        fn data(&mut self, data: Bytes) -> impl Future<Output = Result<(), CarrierClosed>> + Send {
            self.events
                .lock()
                .unwrap()
                .push(format!("data:{}", data.len()));
            self.bytes.lock().unwrap().extend_from_slice(&data);
            async { Ok(()) }
        }
        fn finish(&mut self) -> impl Future<Output = Result<(), CarrierClosed>> + Send {
            self.events.lock().unwrap().push("fin".into());
            async { Ok(()) }
        }
        fn reset(&mut self, detail: ResetDetail) -> impl Future<Output = ()> + Send {
            self.events.lock().unwrap().push(format!(
                "reset:{}:{}",
                detail.code.as_str(),
                detail.execution.as_str()
            ));
            async {}
        }
    }

    fn policies() -> (RequestPolicy, ResponsePolicy) {
        let mut request = RequestPolicy::new(1 << 20).unwrap();
        request.allow_route(Method::Post, "/echo").unwrap();
        request.allow_http_version(HttpVersion::Http11);
        request
            .headers
            .allow("content-type", Occurrence::Singleton)
            .unwrap();
        let mut response = ResponsePolicy::new(1 << 20).unwrap();
        response
            .headers
            .allow("content-type", Occurrence::Singleton)
            .unwrap();
        (request, response)
    }

    fn valid_head(policy: &RequestPolicy) -> Vec<u8> {
        let head = RequestHead {
            method: Method::Post,
            path: "/echo".into(),
            query: String::new(),
            http_version: HttpVersion::Http11,
            headers: vec![HeaderField::new("content-type", "text/plain")],
            body_length: None,
        };
        let mut out = Vec::new();
        encode_request_head(&head, policy, &mut out).unwrap();
        out
    }

    /// A head that the codec's JSON would carry from a compromised peer:
    /// syntactically valid, but naming a forbidden internal header.
    fn forged_head() -> Vec<u8> {
        let json = br#"{"method":"POST","path":"/echo","query":"","http_version":"1.1","headers":[["x-agent-tunnel-owner","relay-a"]],"body_length":null}"#;
        let mut out = Vec::new();
        encode_record(RecordKind::RequestHead, json, &mut out).unwrap();
        out
    }

    #[tokio::test]
    async fn a_forged_head_injected_past_ingress_never_reaches_the_device() {
        let (request_policy, _) = policies();
        let actor = Recorder::default();
        let (method_tx, _method_rx) = watch::channel(None);
        let verdict = Arc::new(OwnerVerdict::default());
        let (to_ingress, mut from_owner, _) = channel(1 << 16);
        let mut writer = OwnerRequestWriter::new(
            actor.clone(),
            request_policy,
            method_tx,
            None,
            Arc::clone(&verdict),
            to_ingress,
        );
        let result = writer.data(Bytes::from(forged_head())).await;
        assert_eq!(result, Err(CarrierClosed));
        // Nothing was forwarded; the actor stream is reset instead.
        assert!(actor.bytes().is_empty());
        assert_eq!(
            actor.events(),
            vec!["reset:HTTP_INVALID_HEAD:not_dispatched".to_owned()]
        );
        assert_eq!(
            verdict.get(),
            Some(ResetDetail {
                code: HttpErrorCode::InvalidHead,
                execution: Execution::NotDispatched
            })
        );
        // The ingress learns the same detail.
        assert_eq!(
            from_owner.recv().await,
            Some(Frame::Reset(ResetDetail {
                code: HttpErrorCode::InvalidHead,
                execution: Execution::NotDispatched
            }))
        );
    }

    #[tokio::test]
    async fn grammar_and_fin_violations_are_rejected_at_the_owner() {
        let (request_policy, _) = policies();
        // BODY before HEAD.
        let actor = Recorder::default();
        let (to_ingress, _rx, _) = channel(1 << 16);
        let mut writer = OwnerRequestWriter::new(
            actor.clone(),
            request_policy.clone(),
            watch::channel(None).0,
            None,
            Arc::new(OwnerVerdict::default()),
            to_ingress,
        );
        let mut body = Vec::new();
        encode_body(b"synthetic", &mut body);
        assert_eq!(writer.data(Bytes::from(body)).await, Err(CarrierClosed));
        assert!(actor.bytes().is_empty());
        // FIN before END, after a forwarded head: execution is unknown.
        let actor = Recorder::default();
        let (to_ingress, _rx, _) = channel(1 << 16);
        let verdict = Arc::new(OwnerVerdict::default());
        let mut writer = OwnerRequestWriter::new(
            actor.clone(),
            request_policy.clone(),
            watch::channel(None).0,
            None,
            Arc::clone(&verdict),
            to_ingress,
        );
        assert!(
            writer
                .data(Bytes::from(valid_head(&request_policy)))
                .await
                .is_ok()
        );
        assert_eq!(writer.finish().await, Err(CarrierClosed));
        assert_eq!(
            verdict.get().map(|detail| detail.execution),
            Some(Execution::Unknown)
        );
        assert!(!actor.events().contains(&"fin".to_owned()));
    }

    #[tokio::test]
    async fn valid_records_pass_through_byte_for_byte_and_unbuffered() {
        let (request_policy, response_policy) = policies();
        let actor = Recorder::default();
        let (method_tx, method_rx) = watch::channel(None);
        let (to_ingress, _rx, _) = channel(1 << 16);
        let verdict = Arc::new(OwnerVerdict::default());
        let mut writer = OwnerRequestWriter::new(
            actor.clone(),
            request_policy.clone(),
            method_tx,
            None,
            Arc::clone(&verdict),
            to_ingress,
        );
        let mut stream = valid_head(&request_policy);
        encode_body(&[3u8; 1000], &mut stream);
        stream.extend_from_slice(&END_RECORD);
        // Arbitrary splits, including inside headers.
        for piece in stream.chunks(7) {
            writer.data(Bytes::copy_from_slice(piece)).await.unwrap();
        }
        writer.finish().await.unwrap();
        assert_eq!(actor.bytes(), stream);
        assert!(verdict.get().is_none());

        // The response is validated against the method the owner saw.
        let hop = Recorder::default();
        let (to_device, _rx, _) = channel(1 << 16);
        let mut response = OwnerResponseWriter::new(
            hop.clone(),
            response_policy.clone(),
            method_rx,
            Arc::clone(&verdict),
            to_device,
        );
        let head = ResponseHead {
            status: 200,
            headers: vec![HeaderField::new("content-type", "text/plain")],
            body_length: Some(3),
        };
        let mut bytes = Vec::new();
        encode_response_head(&head, &response_policy, Method::Post, &mut bytes).unwrap();
        encode_body(b"abc", &mut bytes);
        bytes.extend_from_slice(&END_RECORD);
        response.data(Bytes::from(bytes.clone())).await.unwrap();
        response.finish().await.unwrap();
        assert_eq!(hop.bytes(), bytes);
    }

    #[tokio::test]
    async fn a_response_length_violation_resets_both_directions_at_the_owner() {
        let (_, response_policy) = policies();
        let hop = Recorder::default();
        let (to_device, mut device_rx, _) = channel(1 << 16);
        let verdict = Arc::new(OwnerVerdict::default());
        let mut response = OwnerResponseWriter::new(
            hop.clone(),
            response_policy.clone(),
            watch::channel(Some(Method::Post)).1,
            Arc::clone(&verdict),
            to_device,
        );
        let head = ResponseHead {
            status: 200,
            headers: vec![],
            body_length: Some(2),
        };
        let mut bytes = Vec::new();
        encode_response_head(&head, &response_policy, Method::Post, &mut bytes).unwrap();
        encode_body(b"toolong", &mut bytes);
        assert_eq!(response.data(Bytes::from(bytes)).await, Err(CarrierClosed));
        assert!(
            hop.bytes().is_empty(),
            "nothing invalid reaches the ingress"
        );
        assert_eq!(
            hop.events(),
            vec!["reset:HTTP_LENGTH_MISMATCH:unknown".to_owned()]
        );
        assert!(matches!(device_rx.recv().await, Some(Frame::Reset(_))));
        // A response before any validated request head is a bad record.
        let hop = Recorder::default();
        let (to_device, _rx, _) = channel(1 << 16);
        let mut early = OwnerResponseWriter::new(
            hop.clone(),
            response_policy,
            watch::channel(None).1,
            Arc::new(OwnerVerdict::default()),
            to_device,
        );
        assert_eq!(
            early.data(Bytes::from_static(&END_RECORD)).await,
            Err(CarrierClosed)
        );
        assert_eq!(
            hop.events(),
            vec!["reset:HTTP_BAD_RECORD:unknown".to_owned()]
        );
    }

    /// A minimal interposer for this unit test.  The gate's one-shot hold
    /// with its self-release ceiling lives in `tunnel-test-harness`.
    #[derive(Default)]
    struct TestHold {
        state: Mutex<(Option<HttpRelayHoldPoint>, bool)>,
        reached: tokio::sync::Notify,
        release: tokio::sync::Notify,
    }

    impl TestHold {
        fn arm(&self, point: HttpRelayHoldPoint) -> bool {
            let mut state = self.state.lock().unwrap();
            if state.0.is_some() || state.1 {
                return false;
            }
            state.0 = Some(point);
            true
        }

        async fn reached(&self) {
            loop {
                let notified = self.reached.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                if self.state.lock().unwrap().1 {
                    return;
                }
                notified.await;
            }
        }

        fn release(&self) {
            self.state.lock().unwrap().1 = false;
            self.release.notify_waiters();
        }
    }

    impl HttpRelayInterposer for TestHold {
        fn armed_point(&self) -> Option<HttpRelayHoldPoint> {
            self.state.lock().unwrap().0
        }

        fn hold_at(
            &self,
            point: HttpRelayHoldPoint,
        ) -> std::pin::Pin<Box<dyn Future<Output = ()> + Send + '_>> {
            Box::pin(async move {
                let released = self.release.notified();
                tokio::pin!(released);
                released.as_mut().enable();
                {
                    let mut state = self.state.lock().unwrap();
                    if state.0 != Some(point) {
                        return;
                    }
                    *state = (None, true);
                }
                self.reached.notify_waiters();
                released.await;
            })
        }
    }

    #[tokio::test]
    async fn an_armed_hold_stops_the_relay_inside_a_body_header_and_before_fin() {
        let (request_policy, _) = policies();
        let actor = Recorder::default();
        let hold = Arc::new(TestHold::default());
        let (to_ingress, _rx, _) = channel(1 << 16);
        let mut writer = OwnerRequestWriter::new(
            actor.clone(),
            request_policy.clone(),
            watch::channel(None).0,
            Some(Arc::clone(&hold) as Arc<dyn HttpRelayInterposer>),
            Arc::new(OwnerVerdict::default()),
            to_ingress,
        );
        writer
            .data(Bytes::from(valid_head(&request_policy)))
            .await
            .unwrap();
        let head_len = actor.bytes().len();
        let mut body = Vec::new();
        encode_body(&[9u8; 32], &mut body);
        assert!(hold.arm(HttpRelayHoldPoint::InsideBodyHeader { bytes: 3 }));
        let task = tokio::spawn(async move {
            // The real ingress writes the header and payload as two chunks.
            writer
                .data(Bytes::copy_from_slice(&body[..8]))
                .await
                .unwrap();
            writer
                .data(Bytes::copy_from_slice(&body[8..]))
                .await
                .unwrap();
            writer.data(Bytes::from_static(&END_RECORD)).await.unwrap();
            writer.finish().await.unwrap();
        });
        hold.reached().await;
        assert_eq!(actor.bytes().len(), head_len + 3, "three header bytes only");
        assert!(
            !hold.arm(HttpRelayHoldPoint::BeforeRequestFin),
            "still held"
        );
        hold.release();
        // Re-arm for FIN once the first hold is released.
        loop {
            if hold.arm(HttpRelayHoldPoint::BeforeRequestFin) {
                break;
            }
            tokio::task::yield_now().await;
        }
        hold.reached().await;
        assert!(
            actor
                .events()
                .last()
                .is_some_and(|event| event.starts_with("data"))
        );
        assert!(!actor.events().contains(&"fin".to_owned()));
        hold.release();
        task.await.unwrap();
        assert_eq!(actor.events().last().map(String::as_str), Some("fin"));
    }
}
