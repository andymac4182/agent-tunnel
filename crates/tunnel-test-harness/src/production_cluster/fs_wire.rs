//! A minimal 9P2000.L consumer over a real TLS WebSocket, shared by the M4
//! filesystem gates.
//!
//! There is no shipped Rust consumer client — the contract's first certified
//! runtime is Node — so the gate speaks the wire itself.  It is deliberately
//! thin: every byte it sends is produced by gate 3's own [`Frame::encode`] and
//! every byte it receives is decoded by gate 3's own [`decode_exact`], so this
//! module cannot accidentally prove a framing rule that the product does not
//! implement.  Its only original content is tag allocation and the
//! request/reply correlation a client has to do.
//!
//! One binary WebSocket message carries exactly one complete 9P message, which
//! is the consumer rule the relay enforces; the byte-stream rule is the
//! device's and is not modelled here.
//!
//! All fixture data is synthetic.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt as _, StreamExt as _};
use rustls::pki_types::CertificateDer;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::{HeaderName, HeaderValue};
use tokio_tungstenite::{
    Connector, MaybeTlsStream, WebSocketStream, connect_async_tls_with_config,
    tungstenite::Message as WsMessage,
};
use uuid::Uuid;

use tunnel_fs_ninep::{
    DIALECT, Frame, MAX_MESSAGE_BYTES, Message, NOFID, NONUNAME, NOTAG, Qid, decode_exact,
};

use crate::{HarnessError, Result};

/// The header a Node client sends the descriptor's `grantRevision` in.
pub(crate) const GRANT_REVISION_HEADER: &str = "x-agent-tunnel-grant-revision";
/// How long one handshake, send or receive may take.
const IO_TIMEOUT: Duration = Duration::from_secs(20);

/// Why an upgrade did not produce a 9P socket.
pub(crate) enum UpgradeFailure {
    /// The relay answered an HTTP status instead of `101`.
    Status {
        /// The status code.
        status: u16,
        /// The response body, which is the contract's JSON error envelope.
        body: Option<Vec<u8>>,
    },
    /// The harness itself could not complete the attempt.
    Harness(HarnessError),
}

impl UpgradeFailure {
    /// The status, or a harness failure turned into one.
    pub(crate) fn into_status(self) -> Result<(u16, Option<Vec<u8>>)> {
        match self {
            Self::Status { status, body } => Ok((status, body)),
            Self::Harness(error) => Err(error),
        }
    }
}

/// One event read off the consumer socket.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Event {
    /// A complete 9P message.
    Frame(Frame),
    /// The server closed, with the close code it named.
    Close(Option<u16>),
    /// The socket ended without a close frame.
    Ended,
}

/// A 9P2000.L client over one consumer WebSocket.
pub(crate) struct NinepClient {
    socket: WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>,
    /// The bound in force: the profile ceiling until `Rversion` reduces it.
    msize: u32,
    next_tag: u16,
    /// The subprotocol the server selected, for the evidence.
    selected: String,
}

/// Where one upgrade is aimed.
pub(crate) struct Target {
    /// The relay's public consumer address.
    pub consumer_addr: SocketAddr,
    /// The device the export belongs to.
    pub device_id: Uuid,
    /// The service path segment.
    pub service: String,
}

impl NinepClient {
    /// Open a consumer WebSocket and, on `101`, hand back a 9P client.
    ///
    /// `subprotocol` is a parameter rather than the constant because one case
    /// this gate has to prove is an upgrade that offers the wrong one.
    pub(crate) async fn connect(
        target: &Target,
        server_ca_der: &[u8],
        token: &str,
        subprotocol: Option<&str>,
    ) -> std::result::Result<Self, UpgradeFailure> {
        Self::connect_with(target, server_ca_der, token, subprotocol, &[]).await
    }

    /// The same upgrade with caller-supplied extra request headers.
    ///
    /// The grant-revision cases need this: what the contract calls a cached
    /// descriptor is a revision a consumer carries into its upgrade, so the
    /// header has to be settable on the upgrade and not only on the
    /// descriptor read.
    pub(crate) async fn connect_with(
        target: &Target,
        server_ca_der: &[u8],
        token: &str,
        subprotocol: Option<&str>,
        extra: &[(&str, &str)],
    ) -> std::result::Result<Self, UpgradeFailure> {
        let tls = tls_config(server_ca_der).map_err(UpgradeFailure::Harness)?;
        let url = format!(
            "wss://localhost:{}/v1/devices/{}/services/{}/fs",
            target.consumer_addr.port(),
            target.device_id,
            target.service
        );
        let mut request = url.into_client_request().map_err(|error| {
            UpgradeFailure::Harness(HarnessError::Http(format!("fs upgrade request: {error}")))
        })?;
        request.headers_mut().insert(
            "authorization",
            HeaderValue::from_str(&format!("Bearer {token}")).map_err(|error| {
                UpgradeFailure::Harness(HarnessError::Http(format!("fs upgrade auth: {error}")))
            })?,
        );
        if let Some(subprotocol) = subprotocol {
            request.headers_mut().insert(
                "sec-websocket-protocol",
                HeaderValue::from_str(subprotocol).map_err(|error| {
                    UpgradeFailure::Harness(HarnessError::Http(format!(
                        "fs upgrade subprotocol: {error}"
                    )))
                })?,
            );
        }
        for (name, value) in extra {
            let name = HeaderName::from_bytes(name.as_bytes()).map_err(|error| {
                UpgradeFailure::Harness(HarnessError::Http(format!("fs upgrade header: {error}")))
            })?;
            let value = HeaderValue::from_str(value).map_err(|error| {
                UpgradeFailure::Harness(HarnessError::Http(format!("fs upgrade header: {error}")))
            })?;
            request.headers_mut().insert(name, value);
        }
        let connected = timeout(
            IO_TIMEOUT,
            connect_async_tls_with_config(
                request,
                None,
                true,
                Some(Connector::Rustls(Arc::new(tls))),
            ),
        )
        .await
        .map_err(|_| {
            UpgradeFailure::Harness(HarnessError::Timeout("fs upgrade timed out".into()))
        })?;
        match connected {
            Ok((socket, response)) => {
                let selected = response
                    .headers()
                    .get("sec-websocket-protocol")
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or_default()
                    .to_owned();
                Ok(Self {
                    socket,
                    msize: MAX_MESSAGE_BYTES,
                    next_tag: 0,
                    selected,
                })
            }
            Err(tokio_tungstenite::tungstenite::Error::Http(response)) => {
                Err(UpgradeFailure::Status {
                    status: response.status().as_u16(),
                    body: response.body().clone(),
                })
            }
            Err(error) => Err(UpgradeFailure::Harness(HarnessError::Http(format!(
                "fs upgrade failed: {error}"
            )))),
        }
    }

    /// The subprotocol the server selected.
    pub(crate) fn selected_subprotocol(&self) -> &str {
        &self.selected
    }

    /// The next tag, never [`NOTAG`].
    fn take_tag(&mut self) -> u16 {
        // Wrapping deliberately: a session here never has more than a handful
        // of tags outstanding, and skipping `NOTAG` is the only rule.
        self.next_tag = self.next_tag.wrapping_add(1);
        if self.next_tag == NOTAG {
            self.next_tag = 0;
        }
        self.next_tag
    }

    /// Send one frame as exactly one binary message.
    pub(crate) async fn send_frame(&mut self, frame: &Frame) -> Result<()> {
        let bytes = frame
            .to_bytes(self.msize)
            .map_err(|error| HarnessError::Http(format!("9P encode refused: {error:?}")))?;
        timeout(
            IO_TIMEOUT,
            self.socket.send(WsMessage::Binary(bytes.into())),
        )
        .await
        .map_err(|_| HarnessError::Timeout("9P send timed out".into()))?
        .map_err(|error| HarnessError::Http(format!("9P send failed: {error}")))
    }

    /// Read the next event, ignoring ping/pong and refusing text.
    pub(crate) async fn recv_event(&mut self) -> Result<Event> {
        loop {
            let message = timeout(IO_TIMEOUT, self.socket.next())
                .await
                .map_err(|_| HarnessError::Timeout("9P receive timed out".into()))?;
            match message {
                Some(Ok(WsMessage::Binary(bytes))) => {
                    let frame = decode_exact(&bytes, MAX_MESSAGE_BYTES).map_err(|error| {
                        HarnessError::Http(format!("9P decode refused: {error:?}"))
                    })?;
                    return Ok(Event::Frame(frame));
                }
                Some(Ok(WsMessage::Close(frame))) => {
                    return Ok(Event::Close(frame.map(|frame| u16::from(frame.code))));
                }
                Some(Ok(WsMessage::Ping(_) | WsMessage::Pong(_) | WsMessage::Frame(_))) => {}
                Some(Ok(WsMessage::Text(_))) => {
                    return Err(HarnessError::Process(
                        "the filesystem endpoint sent a text message".into(),
                    ));
                }
                Some(Err(error)) => {
                    // A server that closes with a code sometimes surfaces as a
                    // protocol error on the next poll; the close frame the gate
                    // already read is the authoritative one, so this is the
                    // end-of-socket case rather than a failure.
                    return Err(HarnessError::Http(format!("9P socket failed: {error}")));
                }
                None => return Ok(Event::Ended),
            }
        }
    }

    /// Read the next frame, treating a close as a failure.
    pub(crate) async fn recv_frame(&mut self) -> Result<Frame> {
        match self.recv_event().await? {
            Event::Frame(frame) => Ok(frame),
            Event::Close(code) => Err(HarnessError::Process(format!(
                "the filesystem session closed with {code:?} where a reply was expected"
            ))),
            Event::Ended => Err(HarnessError::Process(
                "the filesystem session ended where a reply was expected".into(),
            )),
        }
    }

    /// Send one request and read the reply that carries its tag.
    ///
    /// Replies for other tags are not expected on a serial caller and are
    /// refused rather than skipped: silently dropping one would hide an
    /// interleaving the gate did not ask for.
    pub(crate) async fn call(&mut self, message: Message) -> Result<Message> {
        let tag = self.take_tag();
        self.send_frame(&Frame::new(tag, message)).await?;
        let reply = self.recv_frame().await?;
        if reply.tag != tag {
            return Err(HarnessError::Process(format!(
                "9P reply carried tag {} where {tag} was outstanding",
                reply.tag
            )));
        }
        Ok(reply.message)
    }

    /// `Tversion`, which occupies [`NOTAG`] and reduces the bound in force.
    pub(crate) async fn version(&mut self, offered: u32) -> Result<(u32, String)> {
        self.send_frame(&Frame::new(
            NOTAG,
            Message::Tversion {
                msize: offered,
                version: DIALECT.to_owned(),
            },
        ))
        .await?;
        let reply = self.recv_frame().await?;
        match reply.message {
            Message::Rversion { msize, version } => {
                self.msize = msize;
                Ok((msize, version))
            }
            other => Err(unexpected("Rversion", &other)),
        }
    }

    /// `Tattach` with the only field values this profile permits.
    pub(crate) async fn attach(&mut self, fid: u32) -> Result<Qid> {
        match self.attach_with(fid, NOFID, "", "").await? {
            Message::Rattach { qid } => Ok(qid),
            other => Err(unexpected("Rattach", &other)),
        }
    }

    /// `Tattach` with caller-chosen `afid` and `uname`, for the forged cases.
    pub(crate) async fn attach_with(
        &mut self,
        fid: u32,
        afid: u32,
        uname: &str,
        aname: &str,
    ) -> Result<Message> {
        self.call(Message::Tattach {
            fid,
            afid,
            uname: uname.to_owned(),
            aname: aname.to_owned(),
            n_uname: NONUNAME,
        })
        .await
    }

    /// `Twalk`.
    pub(crate) async fn walk(&mut self, fid: u32, newfid: u32, names: &[&str]) -> Result<Message> {
        self.call(Message::Twalk {
            fid,
            newfid,
            names: names.iter().map(|name| (*name).to_owned()).collect(),
        })
        .await
    }

    /// `Tlopen`.
    pub(crate) async fn lopen(&mut self, fid: u32, flags: u32) -> Result<Message> {
        self.call(Message::Tlopen { fid, flags }).await
    }

    /// `Tread`.
    pub(crate) async fn read(&mut self, fid: u32, offset: u64, count: u32) -> Result<Message> {
        self.call(Message::Tread { fid, offset, count }).await
    }

    /// `Treaddir`.
    pub(crate) async fn readdir(&mut self, fid: u32, offset: u64, count: u32) -> Result<Message> {
        self.call(Message::Treaddir { fid, offset, count }).await
    }

    /// `Tgetattr`.
    pub(crate) async fn getattr(&mut self, fid: u32, request_mask: u64) -> Result<Message> {
        self.call(Message::Tgetattr { fid, request_mask }).await
    }

    /// `Tclunk`.
    pub(crate) async fn clunk(&mut self, fid: u32) -> Result<Message> {
        self.call(Message::Tclunk { fid }).await
    }

    /// `Tflush` of `oldtag`.
    pub(crate) async fn flush(&mut self, oldtag: u16) -> Result<Message> {
        self.call(Message::Tflush { oldtag }).await
    }

    /// Send a request without waiting, returning the tag it took.
    ///
    /// The pipelining the flush case needs: two requests have to be in flight
    /// before either reply is read.
    pub(crate) async fn send(&mut self, message: Message) -> Result<u16> {
        let tag = self.take_tag();
        self.send_frame(&Frame::new(tag, message)).await?;
        Ok(tag)
    }

    /// Drop the socket without a close frame and without draining it.
    ///
    /// The other half of [`NinepClient::close`], and it exists for exactly one
    /// case: a consumer that goes away **while a mutation is in flight**. A
    /// polite close would let the device finish and deliver every outstanding
    /// reply, which is the case where nothing is ambiguous; dropping the
    /// transport mid-stream is what leaves a write that may or may not have
    /// been applied and whose reply the consumer will never see, and that is
    /// the state the contract calls `unknown`.
    pub(crate) fn abandon(self) {
        drop(self);
    }

    /// Close the socket politely and drain what the server sends back.
    pub(crate) async fn close(mut self) {
        let _ = timeout(IO_TIMEOUT, self.socket.send(WsMessage::Close(None))).await;
        let _ = timeout(Duration::from_secs(5), async {
            while let Some(message) = self.socket.next().await {
                if matches!(message, Ok(WsMessage::Close(_)) | Err(_)) {
                    break;
                }
            }
        })
        .await;
    }
}

/// The errno an `Rlerror` carries, or `None` for any other reply.
pub(crate) fn errno_of(message: &Message) -> Option<u32> {
    match message {
        Message::Rlerror { code } => Some(code.errno()),
        _ => None,
    }
}

/// A payload-free "wrong reply" failure: the message *type* and nothing else.
pub(crate) fn unexpected(expected: &str, got: &Message) -> HarnessError {
    HarnessError::Process(format!(
        "expected {expected}, received {}",
        got.message_type()
    ))
}

/// A TLS client configuration trusting only the fixture CA.
pub(crate) fn tls_config(server_ca_der: &[u8]) -> Result<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from(server_ca_der.to_vec()))
        .map_err(|error| HarnessError::Http(format!("consumer CA: {error}")))?;
    rustls::ClientConfig::builder_with_provider(rustls::crypto::ring::default_provider().into())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|error| HarnessError::Http(format!("consumer TLS: {error}")))
        .map(|builder| builder.with_root_certificates(roots).with_no_client_auth())
}
