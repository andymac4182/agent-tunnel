//! Bounded peer records and their shared resource accounting.
//!
//! Peer request and response bodies are made up of complete records.  The
//! record prefix is deliberately small and fixed width so an HTTP/3 body can
//! be split at any byte boundary without making the receiver buffer an
//! unbounded amount of input.  A [`PeerRecordDecoder`] reserves the complete
//! encoded record before it allocates the record body.  The resulting
//! reservation travels with the owned record and is released when the record
//! is dropped.

use bytes::{BufMut, Bytes, BytesMut};
use core::fmt;
use std::ops::Deref;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

/// The size of the fixed peer-record prefix.
pub const PREFIX_LEN: usize = 8;
/// Alias for [`PREFIX_LEN`] used by transport code.
pub const PEER_RECORD_PREFIX_LEN: usize = PREFIX_LEN;

/// Maximum body size for a complete device-data WebSocket message.
pub const MAX_DEVICE_DATA_BODY: usize = 65_600;
/// Maximum body size for a complete device-control text message.
pub const MAX_CONTROL_TEXT_BODY: usize = 32_768;
/// Maximum body size for an ordinary consumer byte chunk.
pub const MAX_CONSUMER_CHUNK_BODY: usize = 65_536;
/// Maximum body size for a close message, including its code and reason.
pub const MAX_CLOSE_BODY: usize = 125;

/// Maximum charged bytes retained by one peer stream.
pub const STREAM_BYTE_BUDGET: usize = 256 * 1024;
/// Maximum charged bytes retained by one peer connection.
pub const CONNECTION_BYTE_BUDGET: usize = 8 * 1024 * 1024;
/// Maximum simultaneously open request streams on a peer connection.
pub const MAX_CONCURRENT_STREAMS: usize = 128;
/// Maximum complete records retained by one stream.
pub const MAX_RECORDS_PER_STREAM: usize = 128;
/// Maximum complete or in-progress records retained by one connection.
///
/// This is separate from [`MAX_CONCURRENT_STREAMS`].  It prevents a large
/// number of zero-body records from exhausting task metadata while still
/// leaving room for streams whose records are larger than a single byte.
pub const MAX_RECORDS_PER_CONNECTION: usize = 4_096;
/// Maximum number of maximum-sized device-data records that fit in one stream
/// byte budget.  This is an accounting consequence, not an independent
/// record-count limit; smaller records may exceed this count while remaining
/// within the byte budget.
pub const MAX_DATA_RECORDS_PER_STREAM: usize = 3;
/// Maximum number of maximum-sized device-data records that fit in one
/// connection byte budget.  This is an accounting consequence, not an
/// independent record-count limit.
pub const MAX_DATA_RECORDS_PER_CONNECTION: usize = 127;
/// Maximum records in the connection-wide control forwarding class.
pub const MAX_CONTROL_RECORDS: usize = 16;
/// Maximum charged bytes in the connection-wide control forwarding class.
pub const MAX_CONTROL_BYTES: usize = 64 * 1024;

/// Maximum number of records returned from one decoder call.
///
/// Callers should pass bounded HTTP/3 chunks.  This limit is an additional
/// guard for a caller that accidentally supplies a very large chunk: the
/// decoder never allocates an output vector with an input-derived capacity.
pub const MAX_RECORDS_PER_PUSH: usize = MAX_RECORDS_PER_STREAM;

/// The largest encoded peer record for each record class.
pub const MAX_DEVICE_DATA_RECORD: usize = PREFIX_LEN + MAX_DEVICE_DATA_BODY;
/// The largest encoded control text record.
pub const MAX_CONTROL_TEXT_RECORD: usize = PREFIX_LEN + MAX_CONTROL_TEXT_BODY;
/// The largest encoded consumer chunk record.
pub const MAX_CONSUMER_CHUNK_RECORD: usize = PREFIX_LEN + MAX_CONSUMER_CHUNK_BODY;
/// The largest encoded close record.
pub const MAX_CLOSE_RECORD: usize = PREFIX_LEN + MAX_CLOSE_BODY;

/// Kinds in the peer-record registry.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum PeerRecordKind {
    /// A complete binary device WebSocket message.
    CompleteDeviceData = 1,
    /// A complete UTF-8 device control WebSocket message.
    CompleteControlText = 2,
    /// A bounded ordinary consumer byte chunk.
    ConsumerChunk = 3,
    /// A WebSocket close body: two-byte code followed by a UTF-8 reason.
    Close = 4,
}

impl PeerRecordKind {
    /// Return the wire value of this kind.
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// Return the maximum body length accepted for this kind.
    #[must_use]
    pub const fn max_body(self) -> usize {
        match self {
            Self::CompleteDeviceData => MAX_DEVICE_DATA_BODY,
            Self::CompleteControlText => MAX_CONTROL_TEXT_BODY,
            Self::ConsumerChunk => MAX_CONSUMER_CHUNK_BODY,
            Self::Close => MAX_CLOSE_BODY,
        }
    }

    /// Return the maximum encoded record length accepted for this kind.
    #[must_use]
    pub const fn max_record(self) -> usize {
        PREFIX_LEN + self.max_body()
    }

    /// Whether this kind's body is text (or contains a text reason).
    #[must_use]
    pub const fn validates_utf8(self) -> bool {
        matches!(self, Self::CompleteControlText | Self::Close)
    }

    fn is_control(self) -> bool {
        matches!(self, Self::CompleteControlText | Self::Close)
    }
}

impl TryFrom<u8> for PeerRecordKind {
    type Error = PeerFrameError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::CompleteDeviceData),
            2 => Ok(Self::CompleteControlText),
            3 => Ok(Self::ConsumerChunk),
            4 => Ok(Self::Close),
            other => Err(Self::Error::UnknownKind(other)),
        }
    }
}

/// The accounting category that caused a reservation to be charged.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResourceLimit {
    /// Per-stream encoded bytes.
    StreamBytes,
    /// Per-connection encoded bytes.
    ConnectionBytes,
    /// Per-stream record metadata entries.
    StreamRecords,
    /// Per-connection record metadata entries.
    ConnectionRecords,
    /// Per-stream complete device-data records.
    StreamDataRecords,
    /// Per-connection complete device-data records.
    ConnectionDataRecords,
    /// Connection-wide control queue record count.
    ControlRecords,
    /// Connection-wide control queue encoded bytes.
    ControlBytes,
    /// Concurrent peer request streams.
    ConcurrentStreams,
}

impl fmt::Display for ResourceLimit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::StreamBytes => "stream bytes",
            Self::ConnectionBytes => "connection bytes",
            Self::StreamRecords => "stream records",
            Self::ConnectionRecords => "connection records",
            Self::StreamDataRecords => "stream data records",
            Self::ConnectionDataRecords => "connection data records",
            Self::ControlRecords => "control records",
            Self::ControlBytes => "control bytes",
            Self::ConcurrentStreams => "concurrent streams",
        };
        formatter.write_str(name)
    }
}

/// A bounded-resource failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResourceError {
    /// A body length is above the selected record kind's wire limit.
    BodyTooLarge {
        /// Record kind whose limit was exceeded.
        kind: PeerRecordKind,
        /// Requested body length.
        length: usize,
        /// Maximum accepted body length.
        maximum: usize,
    },
    /// The requested reservation would exceed one of the declared limits.
    Exhausted {
        /// The limit that would be exceeded.
        limit: ResourceLimit,
        /// The additional amount requested.
        requested: usize,
        /// Amount currently charged to the limit.
        current: usize,
        /// Maximum allowed amount.
        maximum: usize,
    },
    /// A record reservation was used with a different kind or length.
    ReservationMismatch,
}

impl fmt::Display for ResourceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BodyTooLarge {
                kind,
                length,
                maximum,
            } => write!(formatter, "{kind:?} body length {length} exceeds {maximum}"),
            Self::Exhausted {
                limit,
                requested,
                current,
                maximum,
            } => write!(
                formatter,
                "{limit} exhausted: current {current}, requested {requested}, maximum {maximum}"
            ),
            Self::ReservationMismatch => formatter.write_str("reservation does not match record"),
        }
    }
}

impl std::error::Error for ResourceError {}

/// A fixed-size snapshot of resource usage.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ResourceUsage {
    /// Bytes charged on the connection.
    pub bytes: usize,
    /// Record metadata entries charged on the connection.
    pub records: usize,
    /// Complete device-data records charged on the connection.
    pub data_records: usize,
    /// Control records charged on the connection.
    pub control_records: usize,
    /// Control bytes charged on the connection.
    pub control_bytes: usize,
    /// Active stream slots charged on the connection.
    pub active_streams: usize,
}

#[derive(Debug)]
struct ConnectionState {
    bytes: AtomicUsize,
    records: AtomicUsize,
    data_records: AtomicUsize,
    control_records: AtomicUsize,
    control_bytes: AtomicUsize,
    active_streams: AtomicUsize,
}

impl ConnectionState {
    fn new() -> Self {
        Self {
            bytes: AtomicUsize::new(0),
            records: AtomicUsize::new(0),
            data_records: AtomicUsize::new(0),
            control_records: AtomicUsize::new(0),
            control_bytes: AtomicUsize::new(0),
            active_streams: AtomicUsize::new(0),
        }
    }

    fn usage(&self) -> ResourceUsage {
        ResourceUsage {
            bytes: self.bytes.load(Ordering::Acquire),
            records: self.records.load(Ordering::Acquire),
            data_records: self.data_records.load(Ordering::Acquire),
            control_records: self.control_records.load(Ordering::Acquire),
            control_bytes: self.control_bytes.load(Ordering::Acquire),
            active_streams: self.active_streams.load(Ordering::Acquire),
        }
    }
}

#[derive(Debug)]
struct StreamState {
    connection: Arc<ConnectionState>,
    bytes: AtomicUsize,
    records: AtomicUsize,
    data_records: AtomicUsize,
}

impl StreamState {
    fn usage(&self) -> ResourceUsage {
        ResourceUsage {
            bytes: self.bytes.load(Ordering::Acquire),
            records: self.records.load(Ordering::Acquire),
            data_records: self.data_records.load(Ordering::Acquire),
            ..ResourceUsage::default()
        }
    }
}

impl Drop for StreamState {
    fn drop(&mut self) {
        self.connection
            .active_streams
            .fetch_sub(1, Ordering::AcqRel);
    }
}

/// The shared resource budget for one peer connection.
#[derive(Clone, Debug)]
pub struct ConnectionBudget {
    inner: Arc<ConnectionState>,
}

/// The shared resource budget for one peer connection.
pub type ResourceBudget = ConnectionBudget;

impl Default for ConnectionBudget {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnectionBudget {
    /// Construct an empty peer-connection budget.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(ConnectionState::new()),
        }
    }

    /// Open one bounded request-stream slot.
    pub fn open_stream(&self) -> Result<StreamBudget, ResourceError> {
        acquire(
            &self.inner.active_streams,
            MAX_CONCURRENT_STREAMS,
            1,
            ResourceLimit::ConcurrentStreams,
        )?;
        Ok(StreamBudget {
            inner: Arc::new(StreamState {
                connection: Arc::clone(&self.inner),
                bytes: AtomicUsize::new(0),
                records: AtomicUsize::new(0),
                data_records: AtomicUsize::new(0),
            }),
        })
    }

    /// Alias for [`Self::open_stream`].
    pub fn try_open_stream(&self) -> Result<StreamBudget, ResourceError> {
        self.open_stream()
    }

    /// Return the current connection-wide usage.
    #[must_use]
    pub fn usage(&self) -> ResourceUsage {
        self.inner.usage()
    }

    /// Return the currently charged connection bytes.
    #[must_use]
    pub fn reserved_bytes(&self) -> usize {
        self.inner.bytes.load(Ordering::Acquire)
    }

    /// Return the number of active request streams.
    #[must_use]
    pub fn active_streams(&self) -> usize {
        self.inner.active_streams.load(Ordering::Acquire)
    }

    /// Return the remaining connection byte capacity.
    #[must_use]
    pub fn remaining_bytes(&self) -> usize {
        CONNECTION_BYTE_BUDGET.saturating_sub(self.reserved_bytes())
    }
}

/// The shared resource budget for one peer request stream.
#[derive(Clone, Debug)]
pub struct StreamBudget {
    inner: Arc<StreamState>,
}

/// Alias used by transport code that names the peer explicitly.
pub type PeerStreamBudget = StreamBudget;

impl From<&StreamBudget> for StreamBudget {
    fn from(value: &StreamBudget) -> Self {
        value.clone()
    }
}

impl StreamBudget {
    /// Return the connection budget shared by this stream.
    #[must_use]
    pub fn connection_budget(&self) -> ConnectionBudget {
        ConnectionBudget {
            inner: Arc::clone(&self.inner.connection),
        }
    }

    /// Reserve the complete encoded size of one record before allocating its
    /// body.  The returned reservation must be moved into the resulting
    /// [`PeerRecord`] or retained until the body is queued.
    pub fn reserve(
        &self,
        kind: PeerRecordKind,
        body_len: usize,
    ) -> Result<Reservation, ResourceError> {
        if body_len > kind.max_body() {
            return Err(ResourceError::BodyTooLarge {
                kind,
                length: body_len,
                maximum: kind.max_body(),
            });
        }
        let charged = PREFIX_LEN + body_len;
        let connection = Arc::clone(&self.inner.connection);
        let mut held = HeldReservation {
            stream: Arc::clone(&self.inner),
            connection,
            charged,
            stream_bytes: false,
            connection_bytes: false,
            stream_records: false,
            connection_records: false,
            stream_data_records: false,
            connection_data_records: false,
            control_records: false,
            control_bytes: false,
        };

        acquire(
            &held.connection.records,
            MAX_RECORDS_PER_CONNECTION,
            1,
            ResourceLimit::ConnectionRecords,
        )?;
        held.connection_records = true;
        if let Err(error) = acquire(
            &held.stream.records,
            MAX_RECORDS_PER_STREAM,
            1,
            ResourceLimit::StreamRecords,
        ) {
            held.release();
            return Err(error);
        }
        held.stream_records = true;

        // The familiar three-record stream and 127-record connection figures
        // are derived from the byte ceilings for maximum-size data records.
        // Keep the counts for diagnostics, but do not impose a separate count
        // limit: several smaller data records may fit legally.
        if kind == PeerRecordKind::CompleteDeviceData {
            held.connection.data_records.fetch_add(1, Ordering::AcqRel);
            held.connection_data_records = true;
            held.stream.data_records.fetch_add(1, Ordering::AcqRel);
            held.stream_data_records = true;
        }

        if kind.is_control() {
            if let Err(error) = acquire(
                &held.connection.control_records,
                MAX_CONTROL_RECORDS,
                1,
                ResourceLimit::ControlRecords,
            ) {
                held.release();
                return Err(error);
            }
            held.control_records = true;
            if let Err(error) = acquire(
                &held.connection.control_bytes,
                MAX_CONTROL_BYTES,
                charged,
                ResourceLimit::ControlBytes,
            ) {
                held.release();
                return Err(error);
            }
            held.control_bytes = true;
        }

        if let Err(error) = acquire(
            &held.connection.bytes,
            CONNECTION_BYTE_BUDGET,
            charged,
            ResourceLimit::ConnectionBytes,
        ) {
            held.release();
            return Err(error);
        }
        held.connection_bytes = true;
        if let Err(error) = acquire(
            &held.stream.bytes,
            STREAM_BYTE_BUDGET,
            charged,
            ResourceLimit::StreamBytes,
        ) {
            held.release();
            return Err(error);
        }
        held.stream_bytes = true;

        Ok(held.into_reservation(kind, body_len, charged))
    }

    /// Alias for [`Self::reserve`].
    pub fn try_reserve(
        &self,
        kind: PeerRecordKind,
        body_len: usize,
    ) -> Result<Reservation, ResourceError> {
        self.reserve(kind, body_len)
    }

    /// Reserve bytes for an additional copy of a record or body.  Copy
    /// reservations charge bytes only; they do not consume record metadata
    /// slots or data/control record counts.
    #[cfg(test)]
    fn charge_copy(&self, bytes: usize) -> Result<CopyReservation, ResourceError> {
        self.charge_copy_for_kind(None, bytes)
    }

    fn charge_copy_for_kind(
        &self,
        kind: Option<PeerRecordKind>,
        bytes: usize,
    ) -> Result<CopyReservation, ResourceError> {
        if bytes == 0 {
            return Ok(CopyReservation {
                stream: None,
                connection: None,
                bytes: 0,
                control_bytes: 0,
            });
        }
        let connection = Arc::clone(&self.inner.connection);
        acquire(
            &connection.bytes,
            CONNECTION_BYTE_BUDGET,
            bytes,
            ResourceLimit::ConnectionBytes,
        )?;
        let control_bytes = if kind.is_some_and(PeerRecordKind::is_control) {
            if let Err(error) = acquire(
                &connection.control_bytes,
                MAX_CONTROL_BYTES,
                bytes,
                ResourceLimit::ControlBytes,
            ) {
                connection.bytes.fetch_sub(bytes, Ordering::AcqRel);
                return Err(error);
            }
            bytes
        } else {
            0
        };
        if let Err(error) = acquire(
            &self.inner.bytes,
            STREAM_BYTE_BUDGET,
            bytes,
            ResourceLimit::StreamBytes,
        ) {
            connection.bytes.fetch_sub(bytes, Ordering::AcqRel);
            if control_bytes != 0 {
                connection
                    .control_bytes
                    .fetch_sub(control_bytes, Ordering::AcqRel);
            }
            return Err(error);
        }
        Ok(CopyReservation {
            stream: Some(Arc::clone(&self.inner)),
            connection: Some(connection),
            bytes,
            control_bytes,
        })
    }

    /// Reserve and construct a record from bytes that are already owned by
    /// the caller.  Use [`Self::record_from_slice`] when the input is a
    /// borrowed slice and the copy must happen only after validation/reserve.
    pub fn record(&self, kind: PeerRecordKind, body: Bytes) -> Result<PeerRecord, PeerFrameError> {
        let reservation = self.reserve(kind, body.len())?;
        PeerRecord::from_reserved(kind, body, reservation)
    }

    /// Validate, reserve, and copy a borrowed body into a charged record.
    pub fn record_from_slice(
        &self,
        kind: PeerRecordKind,
        body: &[u8],
    ) -> Result<PeerRecord, PeerFrameError> {
        validate_body(kind, body)?;
        let reservation = self.reserve(kind, body.len())?;
        let owned = Bytes::copy_from_slice(body);
        PeerRecord::from_reserved(kind, owned, reservation)
    }

    /// Return the current stream-local usage.
    #[must_use]
    pub fn usage(&self) -> ResourceUsage {
        self.inner.usage()
    }

    /// Return the currently charged stream bytes.
    #[must_use]
    pub fn reserved_bytes(&self) -> usize {
        self.inner.bytes.load(Ordering::Acquire)
    }

    /// Return the remaining stream byte capacity.
    #[must_use]
    pub fn remaining_bytes(&self) -> usize {
        STREAM_BYTE_BUDGET.saturating_sub(self.reserved_bytes())
    }
}

fn acquire(
    counter: &AtomicUsize,
    maximum: usize,
    requested: usize,
    limit: ResourceLimit,
) -> Result<(), ResourceError> {
    let mut current = counter.load(Ordering::Acquire);
    loop {
        let Some(next) = current.checked_add(requested) else {
            return Err(ResourceError::Exhausted {
                limit,
                requested,
                current,
                maximum,
            });
        };
        if next > maximum {
            return Err(ResourceError::Exhausted {
                limit,
                requested,
                current,
                maximum,
            });
        }
        match counter.compare_exchange_weak(current, next, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return Ok(()),
            Err(observed) => current = observed,
        }
    }
}

#[derive(Debug)]
struct HeldReservation {
    stream: Arc<StreamState>,
    connection: Arc<ConnectionState>,
    charged: usize,
    stream_bytes: bool,
    connection_bytes: bool,
    stream_records: bool,
    connection_records: bool,
    stream_data_records: bool,
    connection_data_records: bool,
    control_records: bool,
    control_bytes: bool,
}

impl HeldReservation {
    fn release(self) {
        if self.stream_bytes {
            self.stream.bytes.fetch_sub(self.charged, Ordering::AcqRel);
        }
        if self.connection_bytes {
            self.connection
                .bytes
                .fetch_sub(self.charged, Ordering::AcqRel);
        }
        if self.stream_records {
            self.stream.records.fetch_sub(1, Ordering::AcqRel);
        }
        if self.connection_records {
            self.connection.records.fetch_sub(1, Ordering::AcqRel);
        }
        if self.stream_data_records {
            self.stream.data_records.fetch_sub(1, Ordering::AcqRel);
        }
        if self.connection_data_records {
            self.connection.data_records.fetch_sub(1, Ordering::AcqRel);
        }
        if self.control_records {
            self.connection
                .control_records
                .fetch_sub(1, Ordering::AcqRel);
        }
        if self.control_bytes {
            self.connection
                .control_bytes
                .fetch_sub(self.charged, Ordering::AcqRel);
        }
    }

    fn into_reservation(
        self,
        kind: PeerRecordKind,
        body_len: usize,
        charged: usize,
    ) -> Reservation {
        Reservation {
            stream: self.stream,
            connection: self.connection,
            kind,
            body_len,
            charged,
        }
    }
}

/// A charged complete-record reservation.
///
/// The reservation is intentionally a separate owned value so a transport can
/// transfer it alongside an owned buffer without copying bytes.  Dropping it
/// releases the stream, connection, and class counters.
#[derive(Debug)]
pub struct Reservation {
    stream: Arc<StreamState>,
    connection: Arc<ConnectionState>,
    kind: PeerRecordKind,
    body_len: usize,
    charged: usize,
}

impl Reservation {
    /// Return the record kind covered by this reservation.
    #[must_use]
    pub const fn kind(&self) -> PeerRecordKind {
        self.kind
    }

    /// Return the body length covered by this reservation.
    #[must_use]
    pub const fn body_len(&self) -> usize {
        self.body_len
    }

    /// Return the complete encoded size charged by this reservation.
    #[must_use]
    pub const fn charged_bytes(&self) -> usize {
        self.charged
    }

    /// Charge an additional owned copy while retaining this record's charge.
    pub fn charge_copy(&self, bytes: usize) -> Result<CopyReservation, ResourceError> {
        StreamBudget {
            inner: Arc::clone(&self.stream),
        }
        .charge_copy_for_kind(Some(self.kind), bytes)
    }

    /// Attach an owned body to this reservation without copying it.
    pub fn into_record(
        self,
        kind: PeerRecordKind,
        body: Bytes,
    ) -> Result<PeerRecord, PeerFrameError> {
        PeerRecord::from_reserved(kind, body, self)
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        self.stream.bytes.fetch_sub(self.charged, Ordering::AcqRel);
        self.connection
            .bytes
            .fetch_sub(self.charged, Ordering::AcqRel);
        self.stream.records.fetch_sub(1, Ordering::AcqRel);
        self.connection.records.fetch_sub(1, Ordering::AcqRel);
        if self.kind == PeerRecordKind::CompleteDeviceData {
            self.stream.data_records.fetch_sub(1, Ordering::AcqRel);
            self.connection.data_records.fetch_sub(1, Ordering::AcqRel);
        }
        if self.kind.is_control() {
            self.connection
                .control_records
                .fetch_sub(1, Ordering::AcqRel);
            self.connection
                .control_bytes
                .fetch_sub(self.charged, Ordering::AcqRel);
        }
    }
}

/// A charge for an additional copy of bytes already represented by another
/// reservation.  It carries no record metadata slot and drops independently.
#[derive(Debug)]
pub struct CopyReservation {
    stream: Option<Arc<StreamState>>,
    connection: Option<Arc<ConnectionState>>,
    bytes: usize,
    control_bytes: usize,
}

impl CopyReservation {
    /// Return the additional bytes charged by this copy.
    #[must_use]
    pub const fn charged_bytes(&self) -> usize {
        self.bytes
    }
}

impl Drop for CopyReservation {
    fn drop(&mut self) {
        if self.bytes == 0 {
            return;
        }
        self.stream
            .as_ref()
            .expect("nonzero copy has stream")
            .bytes
            .fetch_sub(self.bytes, Ordering::AcqRel);
        self.connection
            .as_ref()
            .expect("nonzero copy has connection")
            .bytes
            .fetch_sub(self.bytes, Ordering::AcqRel);
        if self.control_bytes != 0 {
            self.connection
                .as_ref()
                .expect("control copy has connection")
                .control_bytes
                .fetch_sub(self.control_bytes, Ordering::AcqRel);
        }
    }
}

/// An owned byte buffer carrying the charge for one additional copy.
pub struct ChargedBytes {
    bytes: Bytes,
    _charge: CopyReservation,
}

impl fmt::Debug for ChargedBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ChargedBytes")
            .field("len", &self.bytes.len())
            .field("charged_bytes", &self._charge.charged_bytes())
            .finish()
    }
}

impl ChargedBytes {
    /// Return the length of the charged buffer.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Return whether the charged buffer is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Return the additional encoded bytes retained by this wrapper.
    #[must_use]
    pub fn charged_bytes(&self) -> usize {
        self._charge.charged_bytes()
    }

    /// Borrow the charged bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl AsRef<[u8]> for ChargedBytes {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl Deref for ChargedBytes {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.bytes
    }
}

/// An owned record body carrying its complete-record reservation.
///
/// The body and reservation intentionally remain one value.  A transport can
/// borrow it for a send or move the wrapper into a queue; it cannot obtain an
/// uncharged `Bytes` through this API.
pub struct ChargedBody {
    bytes: Bytes,
    reservation: Reservation,
}

impl fmt::Debug for ChargedBody {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ChargedBody")
            .field("kind", &self.reservation.kind())
            .field("len", &self.bytes.len())
            .field("charged_bytes", &self.reservation.charged_bytes())
            .finish()
    }
}

impl ChargedBody {
    /// Return the body length.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Return whether the body is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Return the kind covered by the attached reservation.
    #[must_use]
    pub fn kind(&self) -> PeerRecordKind {
        self.reservation.kind()
    }

    /// Return the complete encoded charge carried by this body.
    #[must_use]
    pub fn charged_bytes(&self) -> usize {
        self.reservation.charged_bytes()
    }
}

impl AsRef<[u8]> for ChargedBody {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl Deref for ChargedBody {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.bytes
    }
}

/// One complete peer record.
pub struct PeerRecord {
    /// The validated record kind.
    kind: PeerRecordKind,
    /// The exact body bytes, without the eight-byte prefix.
    body: Bytes,
    reservation: Option<Reservation>,
}

impl fmt::Debug for PeerRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PeerRecord")
            .field("kind", &self.kind)
            .field("body_len", &self.body.len())
            .field(
                "charged_bytes",
                &self.reservation.as_ref().map(Reservation::charged_bytes),
            )
            .finish()
    }
}

impl PartialEq for PeerRecord {
    fn eq(&self, other: &Self) -> bool {
        self.kind == other.kind && self.body == other.body
    }
}

impl Eq for PeerRecord {}

impl PeerRecord {
    /// Construct an uncharged record from already-owned bytes.
    ///
    /// Transport receive paths should use [`StreamBudget::record`] or the
    /// incremental decoder so the encoded size is charged before allocation.
    pub fn new(kind: PeerRecordKind, body: Bytes) -> Result<Self, PeerFrameError> {
        validate_body(kind, &body)?;
        Ok(Self {
            kind,
            body,
            reservation: None,
        })
    }

    /// Construct an uncharged record from a borrowed body, validating before
    /// making the copy.
    pub fn from_slice(kind: PeerRecordKind, body: &[u8]) -> Result<Self, PeerFrameError> {
        validate_body(kind, body)?;
        Self::new(kind, Bytes::copy_from_slice(body))
    }

    /// Construct a UTF-8 control-text record.
    pub fn control_text(text: &str) -> Result<Self, PeerFrameError> {
        Self::from_slice(PeerRecordKind::CompleteControlText, text.as_bytes())
    }

    /// Construct a bounded close record.
    pub fn close(body: &[u8]) -> Result<Self, PeerFrameError> {
        Self::from_slice(PeerRecordKind::Close, body)
    }

    /// Return the body as UTF-8 for a text-bearing record.
    pub fn as_text(&self) -> Result<&str, PeerFrameError> {
        match self.kind {
            PeerRecordKind::CompleteControlText => {
                str::from_utf8(&self.body).map_err(|_| PeerFrameError::InvalidUtf8)
            }
            PeerRecordKind::Close => {
                if self.body.is_empty() {
                    return Ok("");
                }
                str::from_utf8(&self.body[2..]).map_err(|_| PeerFrameError::InvalidUtf8)
            }
            _ => Err(PeerFrameError::TextNotSupported(self.kind)),
        }
    }

    /// Return the body length.
    #[must_use]
    pub fn body_len(&self) -> usize {
        self.body.len()
    }

    /// Return the validated record kind.
    #[must_use]
    pub const fn kind(&self) -> PeerRecordKind {
        self.kind
    }

    /// Borrow the exact body bytes without transferring their reservation.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Return the encoded record length.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        PREFIX_LEN + self.body.len()
    }

    /// Whether this record carries a live resource reservation.
    #[must_use]
    pub fn is_charged(&self) -> bool {
        self.reservation.is_some()
    }

    /// Return the live reservation, if any.
    #[must_use]
    pub fn reservation(&self) -> Option<&Reservation> {
        self.reservation.as_ref()
    }

    /// Encode the prefix and exact body bytes for unit-test fixtures.
    ///
    /// Production transport code must use [`Self::encode_charged`] so the
    /// encoded copy is reserved before allocation and remains charge-bound.
    #[cfg(test)]
    #[must_use]
    pub fn encode(&self) -> Bytes {
        self.encode_unchecked()
    }

    /// Encode to an ordinary `Vec<u8>` for unit-test fixtures.
    #[cfg(test)]
    #[must_use]
    pub fn encode_vec(&self) -> Vec<u8> {
        self.encode_unchecked().to_vec()
    }

    fn encode_unchecked(&self) -> Bytes {
        let mut encoded = BytesMut::with_capacity(self.encoded_len());
        put_prefix(&mut encoded, self.kind, self.body.len());
        encoded.extend_from_slice(&self.body);
        encoded.freeze()
    }

    /// Encode and charge the resulting copy before allocating it.
    pub fn encode_charged(&self, budget: &StreamBudget) -> Result<ChargedBytes, ResourceError> {
        let charge = budget.charge_copy_for_kind(Some(self.kind), self.encoded_len())?;
        Ok(ChargedBytes {
            bytes: self.encode_unchecked(),
            _charge: charge,
        })
    }

    /// Decode exactly one encoded record into a charged owned record.
    pub fn decode<S>(encoded: &[u8], budget: S) -> Result<Self, PeerFrameError>
    where
        S: Into<StreamBudget>,
    {
        decode(encoded, budget)
    }

    /// Move the body and its reservation together.
    #[must_use]
    pub fn into_charged_body(mut self) -> Option<ChargedBody> {
        self.reservation.take().map(|reservation| ChargedBody {
            bytes: self.body,
            reservation,
        })
    }

    /// Attach a reservation to an owned body without copying it.
    fn from_reserved(
        kind: PeerRecordKind,
        body: Bytes,
        reservation: Reservation,
    ) -> Result<Self, PeerFrameError> {
        if reservation.kind != kind || reservation.body_len != body.len() {
            return Err(PeerFrameError::Resource(ResourceError::ReservationMismatch));
        }
        validate_body(kind, &body)?;
        Ok(Self {
            kind,
            body,
            reservation: Some(reservation),
        })
    }
}

/// Encode one complete peer record for unit-test fixtures.
#[cfg(test)]
#[must_use]
pub fn encode(record: &PeerRecord) -> Bytes {
    record.encode_unchecked()
}

/// Decode exactly one complete peer record into a charged owned record.
pub fn decode<S>(encoded: &[u8], budget: S) -> Result<PeerRecord, PeerFrameError>
where
    S: Into<StreamBudget>,
{
    if encoded.is_empty() {
        return Err(PeerFrameError::NoRecord);
    }
    let mut decoder = PeerRecordDecoder::new(budget);
    let records = decoder.push(encoded)?;
    decoder.finish()?;
    match records.len() {
        1 => Ok(records.into_iter().next().expect("one record")),
        0 => Err(PeerFrameError::NoRecord),
        count => Err(PeerFrameError::MultipleRecords { count }),
    }
}

fn put_prefix(output: &mut BytesMut, kind: PeerRecordKind, body_len: usize) {
    output.put_u32(body_len as u32);
    output.put_u8(kind.code());
    output.put_u8(0);
    output.put_u16(0);
}

fn validate_body(kind: PeerRecordKind, body: &[u8]) -> Result<(), PeerFrameError> {
    if body.len() > kind.max_body() {
        return Err(PeerFrameError::BodyTooLarge {
            kind,
            length: body.len(),
            maximum: kind.max_body(),
        });
    }
    match kind {
        PeerRecordKind::CompleteControlText => {
            str::from_utf8(body).map_err(|_| PeerFrameError::InvalidUtf8)?;
        }
        PeerRecordKind::Close => {
            if !body.is_empty() && body.len() < 2 {
                return Err(PeerFrameError::InvalidCloseLength(body.len()));
            }
            if body.len() >= 2 {
                str::from_utf8(&body[2..]).map_err(|_| PeerFrameError::InvalidUtf8)?;
            }
        }
        PeerRecordKind::CompleteDeviceData | PeerRecordKind::ConsumerChunk => {}
    }
    Ok(())
}

fn parse_prefix(prefix: &[u8; PREFIX_LEN]) -> Result<(PeerRecordKind, usize), PeerFrameError> {
    let body_len = u32::from_be_bytes([prefix[0], prefix[1], prefix[2], prefix[3]]) as usize;
    let kind = PeerRecordKind::try_from(prefix[4])?;
    if prefix[5] != 0 {
        return Err(PeerFrameError::InvalidFlags(prefix[5]));
    }
    let reserved = u16::from_be_bytes([prefix[6], prefix[7]]);
    if reserved != 0 {
        return Err(PeerFrameError::NonZeroReserved(reserved));
    }
    if body_len > kind.max_body() {
        return Err(PeerFrameError::BodyTooLarge {
            kind,
            length: body_len,
            maximum: kind.max_body(),
        });
    }
    Ok((kind, body_len))
}

/// An incremental bounded peer-record decoder.
pub struct PeerRecordDecoder {
    stream: StreamBudget,
    prefix: [u8; PREFIX_LEN],
    prefix_len: usize,
    pending: Option<PendingRecord>,
}

struct PendingRecord {
    kind: PeerRecordKind,
    body_len: usize,
    body: BytesMut,
    reservation: Reservation,
}

impl fmt::Debug for PeerRecordDecoder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PeerRecordDecoder")
            .field("prefix_len", &self.prefix_len)
            .field(
                "pending_body_len",
                &self.pending.as_ref().map(|p| p.body.len()),
            )
            .field(
                "pending_body_expected",
                &self.pending.as_ref().map(|p| p.body_len),
            )
            .finish()
    }
}

impl PeerRecordDecoder {
    /// Construct a decoder for one bounded peer stream.
    pub fn new<S>(stream: S) -> Self
    where
        S: Into<StreamBudget>,
    {
        Self {
            stream: stream.into(),
            prefix: [0; PREFIX_LEN],
            prefix_len: 0,
            pending: None,
        }
    }

    /// Return the stream budget used by this decoder.
    #[must_use]
    pub fn stream_budget(&self) -> &StreamBudget {
        &self.stream
    }

    /// Feed a non-empty body fragment and return all complete records made
    /// available by it.  Prefixes and bodies may be split at every byte.
    /// Empty relay chunks fail closed with [`PeerFrameError::EmptyChunk`].
    pub fn push(&mut self, input: &[u8]) -> Result<Vec<PeerRecord>, PeerFrameError> {
        if input.is_empty() {
            // An empty HTTP/3 relay chunk is not a record boundary.  Treat it
            // as a terminal protocol error so a peer cannot keep a stream
            // alive with an unbounded sequence of no-op chunks.  Clear first
            // to release any reservation held by a partial record.
            self.clear();
            return Err(PeerFrameError::EmptyChunk);
        }
        let plan = self.plan_input(input)?;

        // Reserve every new record before changing parser state or allocating
        // a new body.  This makes resource exhaustion atomic for one push and
        // keeps the output vector bounded by the same preflight pass.
        let mut reservations = Vec::with_capacity(plan.new_records.len());
        for record in &plan.new_records {
            reservations.push(self.stream.reserve(record.kind, record.body_len)?);
        }

        let mut next_reservation = reservations.into_iter();
        let mut output = Vec::with_capacity(plan.complete_records);
        let mut index = 0;

        if self.pending.is_some() {
            let pending_len = self
                .pending
                .as_ref()
                .map_or(0, |pending| pending.body.len());
            let pending_capacity = self.pending.as_ref().map_or(0, |pending| pending.body_len);
            let remaining = pending_capacity.saturating_sub(pending_len);
            let take = remaining.min(input.len());
            if take != 0 {
                if let Some(pending) = self.pending.as_mut() {
                    pending.body.extend_from_slice(&input[..take]);
                }
                index = take;
            }
            if take < remaining {
                return Ok(output);
            }
            let pending = self.pending.take().expect("pending record exists");
            if let Err(error) = validate_body(pending.kind, &pending.body) {
                self.clear();
                drop(pending);
                return Err(error);
            }
            let body = pending.body.freeze();
            output.push(PeerRecord::from_reserved(
                pending.kind,
                body,
                pending.reservation,
            )?);
        }

        while index < input.len() {
            while self.prefix_len < PREFIX_LEN && index < input.len() {
                self.prefix[self.prefix_len] = input[index];
                self.prefix_len += 1;
                index += 1;
            }
            if self.prefix_len < PREFIX_LEN {
                break;
            }
            let prefix = self.prefix;
            self.prefix = [0; PREFIX_LEN];
            self.prefix_len = 0;
            let (kind, body_len) = parse_prefix(&prefix)?;
            let reservation = next_reservation
                .next()
                .expect("preflight and parser reservation counts match");

            if body_len == 0 {
                output.push(PeerRecord::from_reserved(kind, Bytes::new(), reservation)?);
                continue;
            }

            let remaining = input.len() - index;
            let take = body_len.min(remaining);
            let mut body = BytesMut::with_capacity(body_len);
            body.extend_from_slice(&input[index..index + take]);
            index += take;
            if take < body_len {
                self.pending = Some(PendingRecord {
                    kind,
                    body_len,
                    body,
                    reservation,
                });
                break;
            }
            let body = body.freeze();
            output.push(PeerRecord::from_reserved(kind, body, reservation)?);
        }

        debug_assert!(next_reservation.next().is_none());
        Ok(output)
    }

    /// Indicate that no more input will arrive.  A partial prefix or body is
    /// reported and dropped, releasing its reservation.
    pub fn finish(&mut self) -> Result<(), PeerFrameError> {
        if self.prefix_len != 0 {
            let received = self.prefix_len;
            self.clear();
            return Err(PeerFrameError::Truncated {
                expected: PREFIX_LEN,
                received,
            });
        }
        if let Some(pending) = self.pending.take() {
            let received = pending.body.len();
            let expected = pending.body_len;
            drop(pending);
            return Err(PeerFrameError::Truncated { expected, received });
        }
        Ok(())
    }

    /// Drop any partial record and release its reservation.
    pub fn clear(&mut self) {
        self.prefix = [0; PREFIX_LEN];
        self.prefix_len = 0;
        self.pending = None;
    }

    /// Whether no prefix or body is currently buffered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.prefix_len == 0 && self.pending.is_none()
    }

    fn plan_input(&self, input: &[u8]) -> Result<PushPlan, PeerFrameError> {
        let mut prefix = self.prefix;
        let mut prefix_len = self.prefix_len;
        let mut index = 0;
        let mut complete_records = 0;
        let mut new_records = Vec::new();

        if let Some(pending) = &self.pending {
            let remaining = pending.body_len.saturating_sub(pending.body.len());
            let take = remaining.min(input.len());
            index = take;
            if take < remaining {
                return Ok(PushPlan {
                    complete_records: 0,
                    new_records,
                });
            }
            complete_records += 1;
        }

        while index < input.len() {
            if complete_records >= MAX_RECORDS_PER_PUSH {
                return Err(PeerFrameError::OutputLimit {
                    maximum: MAX_RECORDS_PER_PUSH,
                });
            }
            while prefix_len < PREFIX_LEN && index < input.len() {
                prefix[prefix_len] = input[index];
                prefix_len += 1;
                index += 1;
            }
            if prefix_len < PREFIX_LEN {
                break;
            }
            let parsed_prefix = prefix;
            prefix = [0; PREFIX_LEN];
            prefix_len = 0;
            let (kind, body_len) = parse_prefix(&parsed_prefix)?;
            if body_len == 0 {
                validate_body(kind, &[])?;
                if new_records.len() >= MAX_RECORDS_PER_PUSH {
                    return Err(PeerFrameError::OutputLimit {
                        maximum: MAX_RECORDS_PER_PUSH,
                    });
                }
                new_records.push(PlannedRecord { kind, body_len });
                complete_records += 1;
                continue;
            }
            let remaining = input.len() - index;
            if remaining < body_len {
                // This is the final record in this input fragment: its body
                // consumes all remaining bytes, so no later prefix exists.
                if new_records.len() >= MAX_RECORDS_PER_PUSH {
                    return Err(PeerFrameError::OutputLimit {
                        maximum: MAX_RECORDS_PER_PUSH,
                    });
                }
                new_records.push(PlannedRecord { kind, body_len });
                return Ok(PushPlan {
                    complete_records,
                    new_records,
                });
            }
            validate_body(kind, &input[index..index + body_len])?;
            if new_records.len() >= MAX_RECORDS_PER_PUSH {
                return Err(PeerFrameError::OutputLimit {
                    maximum: MAX_RECORDS_PER_PUSH,
                });
            }
            new_records.push(PlannedRecord { kind, body_len });
            index += body_len;
            complete_records += 1;
        }

        Ok(PushPlan {
            complete_records,
            new_records,
        })
    }
}

struct PlannedRecord {
    kind: PeerRecordKind,
    body_len: usize,
}

struct PushPlan {
    complete_records: usize,
    new_records: Vec<PlannedRecord>,
}

/// Errors raised while parsing or validating a peer record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PeerFrameError {
    /// An empty relay chunk was received.
    EmptyChunk,
    /// An unassigned record-kind byte was received.
    UnknownKind(u8),
    /// A nonzero flags byte was received.
    InvalidFlags(u8),
    /// A reserved prefix field was nonzero.
    NonZeroReserved(u16),
    /// A body exceeded the limit for its kind.
    BodyTooLarge {
        /// Record kind in the prefix.
        kind: PeerRecordKind,
        /// Declared or supplied body length.
        length: usize,
        /// Maximum accepted body length.
        maximum: usize,
    },
    /// Text or close reason was not valid UTF-8.
    InvalidUtf8,
    /// A one-byte close body cannot contain a close code.
    InvalidCloseLength(usize),
    /// A text accessor was requested for a binary record.
    TextNotSupported(PeerRecordKind),
    /// Input ended in a prefix or body.
    Truncated {
        /// Expected bytes for the current component.
        expected: usize,
        /// Bytes received for the current component.
        received: usize,
    },
    /// A decoder call would produce an unbounded output vector.
    OutputLimit {
        /// Maximum records returned by one call.
        maximum: usize,
    },
    /// No complete record was present in a single-record decode operation.
    NoRecord,
    /// More than one complete record was present in a single-record decode
    /// operation.
    MultipleRecords {
        /// Number of complete records decoded.
        count: usize,
    },
    /// Resource reservation failed.
    Resource(ResourceError),
}

impl fmt::Display for PeerFrameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyChunk => formatter.write_str("empty peer relay chunk"),
            Self::UnknownKind(kind) => write!(formatter, "unknown peer record kind {kind}"),
            Self::InvalidFlags(flags) => {
                write!(formatter, "unsupported peer record flags {flags:#x}")
            }
            Self::NonZeroReserved(value) => {
                write!(formatter, "peer record reserved field is {value:#x}")
            }
            Self::BodyTooLarge {
                kind,
                length,
                maximum,
            } => write!(formatter, "{kind:?} body length {length} exceeds {maximum}"),
            Self::InvalidUtf8 => formatter.write_str("peer text body is not valid UTF-8"),
            Self::InvalidCloseLength(length) => {
                write!(formatter, "close body has invalid length {length}")
            }
            Self::TextNotSupported(kind) => write!(formatter, "{kind:?} does not carry text"),
            Self::Truncated { expected, received } => {
                write!(
                    formatter,
                    "truncated peer record: expected {expected}, received {received}"
                )
            }
            Self::OutputLimit { maximum } => {
                write!(formatter, "decoder output exceeds {maximum} records")
            }
            Self::NoRecord => formatter.write_str("encoded peer input contained no record"),
            Self::MultipleRecords { count } => {
                write!(formatter, "single-record decode received {count} records")
            }
            Self::Resource(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for PeerFrameError {}

impl From<ResourceError> for PeerFrameError {
    fn from(value: ResourceError) -> Self {
        Self::Resource(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encoded(kind: PeerRecordKind, body: &[u8]) -> Vec<u8> {
        let record = PeerRecord::from_slice(kind, body).expect("valid record");
        record.encode_vec()
    }

    #[test]
    fn exact_boundaries_and_plus_one() {
        for (kind, maximum) in [
            (PeerRecordKind::CompleteDeviceData, MAX_DEVICE_DATA_BODY),
            (PeerRecordKind::CompleteControlText, MAX_CONTROL_TEXT_BODY),
            (PeerRecordKind::ConsumerChunk, MAX_CONSUMER_CHUNK_BODY),
            (PeerRecordKind::Close, MAX_CLOSE_BODY),
        ] {
            let body = if kind == PeerRecordKind::CompleteControlText {
                vec![b'x'; maximum]
            } else if kind == PeerRecordKind::Close {
                vec![0; maximum]
            } else {
                vec![0x5a; maximum]
            };
            let wire = encoded(kind, &body);
            assert_eq!(wire.len(), PREFIX_LEN + maximum);
            let budget = ConnectionBudget::new();
            let stream = budget.open_stream().expect("stream");
            let mut decoder = PeerRecordDecoder::new(stream);
            let records = decoder.push(&wire).expect("decode maximum");
            assert_eq!(records.len(), 1);
            assert_eq!(records[0].body(), body.as_slice());
            drop(records);
            assert_eq!(budget.reserved_bytes(), 0);

            let mut too_large = wire;
            let declared = (maximum + 1).to_be_bytes();
            too_large[0..4].copy_from_slice(&declared[4..]);
            let stream = budget.open_stream().expect("stream");
            let mut decoder = PeerRecordDecoder::new(stream);
            assert!(matches!(
                decoder.push(&too_large),
                Err(PeerFrameError::BodyTooLarge { .. })
            ));
            assert_eq!(budget.reserved_bytes(), 0);
        }
    }

    #[test]
    fn every_prefix_split_and_body_split_preserves_bytes() {
        let body = vec![0xa5; MAX_DEVICE_DATA_BODY];
        let wire = encoded(PeerRecordKind::CompleteDeviceData, &body);
        // Exercise every split of the fixed prefix, then representative body
        // fragments without turning the unit test into several gigabytes of
        // repeated copying.
        let mut splits: Vec<usize> = (0..=PREFIX_LEN).collect();
        splits.extend([
            PREFIX_LEN + 1,
            PREFIX_LEN + 17,
            PREFIX_LEN + 4_096,
            wire.len() - 1,
        ]);
        for split in splits {
            let budget = ConnectionBudget::new();
            let stream = budget.open_stream().expect("stream");
            let mut decoder = PeerRecordDecoder::new(stream);
            let mut records = if split == 0 {
                Vec::new()
            } else {
                decoder.push(&wire[..split]).expect("first split")
            };
            records.extend(decoder.push(&wire[split..]).expect("second split"));
            assert_eq!(records.len(), 1, "split {split}");
            assert_eq!(records[0].body(), body.as_slice(), "split {split}");
            drop(records);
            assert_eq!(budget.reserved_bytes(), 0, "split {split}");
        }
    }

    #[test]
    fn fragmented_prefix_then_coalesced_records_preserves_order_and_charges() {
        let budget = ConnectionBudget::new();
        let stream = budget.open_stream().expect("stream");
        let first = encoded(PeerRecordKind::ConsumerChunk, b"abc");
        let second = encoded(PeerRecordKind::CompleteControlText, b"ok");
        let third = encoded(PeerRecordKind::Close, &[0, 0]);
        let fourth = encoded(PeerRecordKind::CompleteDeviceData, &[0x5a, 0x5b]);
        let mut wire = Vec::new();
        wire.extend_from_slice(&first);
        wire.extend_from_slice(&second);
        wire.extend_from_slice(&third);
        wire.extend_from_slice(&fourth);

        let mut decoder = PeerRecordDecoder::new(stream.clone());
        assert!(
            decoder
                .push(&wire[..1])
                .expect("fragmented prefix")
                .is_empty()
        );
        assert_eq!(stream.reserved_bytes(), 0);

        // The second fragment completes the prefix and supplies only the
        // first body byte.  The full record is charged while its body waits
        // for the coalesced continuation.
        assert!(
            decoder
                .push(&wire[1..PREFIX_LEN + 1])
                .expect("fragmented body")
                .is_empty()
        );
        assert_eq!(stream.reserved_bytes(), first.len());
        assert_eq!(stream.usage().records, 1);

        let records = decoder
            .push(&wire[PREFIX_LEN + 1..])
            .expect("coalesced records");
        assert_eq!(records.len(), 4);
        assert_eq!(records[0].kind(), PeerRecordKind::ConsumerChunk);
        assert_eq!(records[0].body(), b"abc");
        assert_eq!(records[1].kind(), PeerRecordKind::CompleteControlText);
        assert_eq!(records[1].body(), b"ok");
        assert_eq!(records[2].kind(), PeerRecordKind::Close);
        assert_eq!(records[2].body(), &[0, 0]);
        assert_eq!(records[3].kind(), PeerRecordKind::CompleteDeviceData);
        assert_eq!(records[3].body(), &[0x5a, 0x5b]);
        assert_eq!(
            stream.reserved_bytes(),
            first.len() + second.len() + third.len() + fourth.len()
        );

        drop(records);
        assert_eq!(stream.reserved_bytes(), 0);
        assert_eq!(budget.reserved_bytes(), 0);
    }

    #[test]
    fn empty_chunk_fails_closed_without_allocating() {
        let budget = ConnectionBudget::new();
        let stream = budget.open_stream().expect("stream");
        let mut decoder = PeerRecordDecoder::new(stream.clone());

        assert_eq!(decoder.push(&[]), Err(PeerFrameError::EmptyChunk));
        assert!(decoder.is_empty());
        assert_eq!(stream.usage(), ResourceUsage::default());
        assert_eq!(decode(&[], stream.clone()), Err(PeerFrameError::NoRecord));

        let wire = encoded(PeerRecordKind::ConsumerChunk, &[]);
        let records = decoder.push(&wire).expect("empty record");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].kind(), PeerRecordKind::ConsumerChunk);
        assert!(records[0].body().is_empty());
        assert_eq!(stream.reserved_bytes(), PREFIX_LEN);

        drop(records);
        decoder.finish().expect("no partial record");
        assert_eq!(stream.reserved_bytes(), 0);
    }

    #[test]
    fn empty_chunk_drops_partial_record_before_failing_closed() {
        let budget = ConnectionBudget::new();
        let stream = budget.open_stream().expect("stream");
        let wire = encoded(PeerRecordKind::ConsumerChunk, b"abc");
        let mut decoder = PeerRecordDecoder::new(stream.clone());

        assert!(
            decoder
                .push(&wire[..PREFIX_LEN + 1])
                .expect("partial body")
                .is_empty()
        );
        assert_eq!(stream.reserved_bytes(), wire.len());

        assert_eq!(decoder.push(&[]), Err(PeerFrameError::EmptyChunk));
        assert!(decoder.is_empty());
        assert_eq!(stream.usage(), ResourceUsage::default());
    }

    #[test]
    fn oversized_declared_length_is_rejected_before_reservation() {
        let budget = ConnectionBudget::new();
        let stream = budget.open_stream().expect("stream");
        let mut prefix = vec![0; PREFIX_LEN];
        prefix[..4].copy_from_slice(&u32::MAX.to_be_bytes());
        prefix[4] = PeerRecordKind::ConsumerChunk.code();

        assert!(matches!(
            PeerRecordDecoder::new(stream.clone()).push(&prefix),
            Err(PeerFrameError::BodyTooLarge {
                kind: PeerRecordKind::ConsumerChunk,
                length,
                maximum: MAX_CONSUMER_CHUNK_BODY,
            }) if length == u32::MAX as usize
        ));
        assert_eq!(stream.usage(), ResourceUsage::default());
    }

    #[test]
    fn truncated_record_finish_releases_pending_reservation() {
        let budget = ConnectionBudget::new();
        let stream = budget.open_stream().expect("stream");
        let wire = encoded(PeerRecordKind::ConsumerChunk, b"abcde");
        let mut decoder = PeerRecordDecoder::new(stream.clone());

        assert!(
            decoder
                .push(&wire[..PREFIX_LEN + 2])
                .expect("partial body")
                .is_empty()
        );
        assert_eq!(stream.reserved_bytes(), wire.len());
        assert_eq!(stream.usage().records, 1);

        assert_eq!(
            decoder.finish(),
            Err(PeerFrameError::Truncated {
                expected: 5,
                received: 2,
            })
        );
        assert!(decoder.is_empty());
        assert_eq!(stream.usage(), ResourceUsage::default());
    }

    #[test]
    fn malformed_pending_body_releases_reservation_and_allows_reuse() {
        let budget = ConnectionBudget::new();
        let stream = budget.open_stream().expect("stream");
        let mut malformed = encoded(PeerRecordKind::CompleteControlText, b"abc");
        malformed[PREFIX_LEN + 2] = 0xff;
        let mut decoder = PeerRecordDecoder::new(stream.clone());

        assert!(
            decoder
                .push(&malformed[..PREFIX_LEN + 1])
                .expect("partial text")
                .is_empty()
        );
        assert_eq!(stream.reserved_bytes(), malformed.len());
        assert_eq!(stream.usage().records, 1);
        assert_eq!(budget.usage().control_records, 1);
        assert_eq!(budget.usage().control_bytes, malformed.len());

        assert_eq!(
            decoder.push(&malformed[PREFIX_LEN + 1..]),
            Err(PeerFrameError::InvalidUtf8)
        );
        assert!(decoder.is_empty());
        assert_eq!(stream.usage(), ResourceUsage::default());

        let valid = encoded(PeerRecordKind::ConsumerChunk, b"reused");
        let records = decoder.push(&valid).expect("decoder remains usable");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].body(), b"reused");
        drop(records);
        assert_eq!(stream.usage(), ResourceUsage::default());
    }

    #[test]
    fn dropping_decoder_releases_pending_reservation() {
        let budget = ConnectionBudget::new();
        let stream = budget.open_stream().expect("stream");
        let wire = encoded(PeerRecordKind::CompleteControlText, b"abc");

        {
            let mut decoder = PeerRecordDecoder::new(stream.clone());
            assert!(
                decoder
                    .push(&wire[..PREFIX_LEN + 1])
                    .expect("partial body")
                    .is_empty()
            );
            assert_eq!(stream.reserved_bytes(), wire.len());
            assert_eq!(stream.usage().records, 1);
            assert_eq!(budget.usage().control_records, 1);
        }

        assert_eq!(stream.usage(), ResourceUsage::default());
        drop(stream);
        assert_eq!(budget.active_streams(), 0);
    }

    #[test]
    fn malformed_prefix_does_not_reserve_or_allocate_body() {
        for (offset, value) in [(4, 0xff), (5, 1), (7, 1)] {
            let budget = ConnectionBudget::new();
            let stream = budget.open_stream().expect("stream");
            let mut decoder = PeerRecordDecoder::new(stream);
            let mut wire = vec![0xff; PREFIX_LEN + MAX_DEVICE_DATA_BODY];
            wire[0..4].copy_from_slice(&(MAX_DEVICE_DATA_BODY as u32).to_be_bytes());
            wire[4] = PeerRecordKind::CompleteDeviceData.code();
            wire[offset] = value;
            assert!(decoder.push(&wire).is_err());
            assert_eq!(budget.reserved_bytes(), 0);
            assert!(decoder.is_empty());
        }
    }

    #[test]
    fn invalid_utf8_and_close_reason_are_rejected() {
        assert!(matches!(
            PeerRecord::from_slice(PeerRecordKind::CompleteControlText, &[0xff]),
            Err(PeerFrameError::InvalidUtf8)
        ));
        assert!(matches!(
            PeerRecord::from_slice(PeerRecordKind::Close, &[0]),
            Err(PeerFrameError::InvalidCloseLength(1))
        ));
        assert!(matches!(
            PeerRecord::from_slice(PeerRecordKind::Close, &[0, 1, 0xff]),
            Err(PeerFrameError::InvalidUtf8)
        ));
    }

    #[test]
    fn pending_body_uses_declared_length_not_allocator_capacity() {
        let budget = ConnectionBudget::new();
        let stream = budget.open_stream().expect("stream");
        let first = encoded(PeerRecordKind::ConsumerChunk, &[0x7f]);
        let second = encoded(PeerRecordKind::ConsumerChunk, &[]);
        let mut decoder = PeerRecordDecoder::new(stream);

        assert!(
            decoder
                .push(&first[..PREFIX_LEN])
                .expect("prefix")
                .is_empty()
        );
        let mut continuation = Vec::with_capacity(1 + second.len());
        continuation.push(first[PREFIX_LEN]);
        continuation.extend_from_slice(&second);
        let mut records = decoder
            .push(&continuation)
            .expect("declared body completes before next prefix");
        assert_eq!(records.len(), 2);
        assert_eq!(records.remove(0).body(), &[0x7f]);
        assert!(records[0].body().is_empty());
        drop(records);
        assert_eq!(budget.reserved_bytes(), 0);
    }

    #[test]
    fn stream_and_connection_data_record_limits_release_on_drop() {
        let budget = ConnectionBudget::new();
        let stream = budget.open_stream().expect("stream");
        let mut records = Vec::new();
        for _ in 0..MAX_DATA_RECORDS_PER_STREAM {
            let reservation = stream
                .reserve(PeerRecordKind::CompleteDeviceData, MAX_DEVICE_DATA_BODY)
                .expect("data reservation");
            records.push(
                reservation
                    .into_record(
                        PeerRecordKind::CompleteDeviceData,
                        Bytes::from(vec![0; MAX_DEVICE_DATA_BODY]),
                    )
                    .expect("record"),
            );
        }
        assert!(matches!(
            stream.reserve(PeerRecordKind::CompleteDeviceData, MAX_DEVICE_DATA_BODY),
            Err(ResourceError::Exhausted {
                limit: ResourceLimit::StreamBytes,
                ..
            })
        ));
        // Four small data records are legal because their aggregate encoded
        // bytes remain under the stream budget.
        for _ in 0..4 {
            let reservation = stream
                .reserve(PeerRecordKind::CompleteDeviceData, 1)
                .expect("small data record");
            drop(reservation);
        }
        drop(records);
        assert_eq!(stream.reserved_bytes(), 0);
        assert_eq!(budget.reserved_bytes(), 0);
    }

    #[test]
    fn tiny_records_hit_stream_and_connection_metadata_limits() {
        let budget = ConnectionBudget::new();
        let mut streams = Vec::new();
        for _ in 0..(MAX_RECORDS_PER_CONNECTION / MAX_RECORDS_PER_STREAM) {
            streams.push(budget.open_stream().expect("stream"));
        }

        let mut records = Vec::new();
        let tiny_wire = encoded(PeerRecordKind::ConsumerChunk, &[]);
        let mut decoder = PeerRecordDecoder::new(streams[0].clone());
        for _ in 0..MAX_RECORDS_PER_STREAM {
            records.extend(decoder.push(&tiny_wire).expect("tiny stream record"));
        }
        assert!(matches!(
            decoder.push(&tiny_wire),
            Err(PeerFrameError::Resource(ResourceError::Exhausted {
                limit: ResourceLimit::StreamRecords,
                current: MAX_RECORDS_PER_STREAM,
                maximum: MAX_RECORDS_PER_STREAM,
                ..
            }))
        ));
        assert_eq!(budget.usage().records, MAX_RECORDS_PER_STREAM);
        assert_eq!(budget.usage().bytes, PREFIX_LEN * MAX_RECORDS_PER_STREAM);

        for stream in streams.iter().skip(1) {
            for _ in 0..MAX_RECORDS_PER_STREAM {
                records.push(
                    stream
                        .record_from_slice(PeerRecordKind::ConsumerChunk, &[])
                        .expect("tiny connection record"),
                );
            }
        }
        assert_eq!(budget.usage().records, MAX_RECORDS_PER_CONNECTION);
        assert!(matches!(
            streams[1].record_from_slice(PeerRecordKind::ConsumerChunk, &[]),
            Err(PeerFrameError::Resource(ResourceError::Exhausted {
                limit: ResourceLimit::ConnectionRecords,
                current: MAX_RECORDS_PER_CONNECTION,
                maximum: MAX_RECORDS_PER_CONNECTION,
                ..
            }))
        ));
        assert!(budget.usage().bytes < CONNECTION_BYTE_BUDGET / 2);

        drop(records);
        assert_eq!(budget.reserved_bytes(), 0);
        assert_eq!(budget.usage().records, 0);
        drop(decoder);
        drop(streams);
        assert_eq!(budget.active_streams(), 0);
    }

    #[test]
    fn control_queue_has_independent_record_and_byte_limits() {
        let budget = ConnectionBudget::new();
        let stream = budget.open_stream().expect("stream");
        let records = vec![
            stream
                .record_from_slice(PeerRecordKind::CompleteControlText, &[b'x'; 32_768])
                .expect("control record"),
        ];
        assert!(matches!(
            stream.record_from_slice(PeerRecordKind::CompleteControlText, &[b'x'; 32_768]),
            Err(PeerFrameError::Resource(ResourceError::Exhausted {
                limit: ResourceLimit::ControlBytes,
                ..
            }))
        ));
        drop(records);

        let mut close_records = Vec::new();
        for _ in 0..MAX_CONTROL_RECORDS {
            close_records.push(
                stream
                    .record_from_slice(PeerRecordKind::Close, &[])
                    .expect("close control record"),
            );
        }
        assert_eq!(budget.usage().control_records, MAX_CONTROL_RECORDS);
        assert_eq!(
            budget.usage().control_bytes,
            PREFIX_LEN * MAX_CONTROL_RECORDS
        );
        assert!(budget.usage().control_bytes < MAX_CONTROL_BYTES);
        assert!(matches!(
            stream.record_from_slice(PeerRecordKind::Close, &[]),
            Err(PeerFrameError::Resource(ResourceError::Exhausted {
                limit: ResourceLimit::ControlRecords,
                ..
            }))
        ));
        assert_eq!(budget.usage().control_records, MAX_CONTROL_RECORDS);
        drop(close_records);
        assert_eq!(budget.usage().control_bytes, 0);
        assert_eq!(budget.usage().control_records, 0);
    }

    #[test]
    fn stream_holds_three_maximum_data_records_and_connection_holds_127() {
        let budget = ConnectionBudget::new();
        let stream = budget.open_stream().expect("stream");
        let record_len = PREFIX_LEN + MAX_DEVICE_DATA_BODY;
        let mut records = Vec::new();
        for _ in 0..MAX_DATA_RECORDS_PER_STREAM {
            records.push(
                stream
                    .reserve(PeerRecordKind::CompleteDeviceData, MAX_DEVICE_DATA_BODY)
                    .expect("three records"),
            );
        }
        assert_eq!(stream.reserved_bytes(), record_len * 3);
        drop(records);

        let mut streams = Vec::new();
        let mut reservations = Vec::new();
        for _ in 0..MAX_CONCURRENT_STREAMS {
            if let Ok(next) = budget.open_stream() {
                streams.push(next);
            }
        }
        // Fill the connection byte budget with maximum-sized records.  The
        // 128th record is rejected by the shared connection bytes, even
        // though each individual stream still has room.
        reservations.push(
            stream
                .reserve(PeerRecordKind::CompleteDeviceData, MAX_DEVICE_DATA_BODY)
                .expect("first connection record"),
        );
        'fill: for item in &streams {
            for _ in 0..MAX_DATA_RECORDS_PER_STREAM {
                match item.reserve(PeerRecordKind::CompleteDeviceData, MAX_DEVICE_DATA_BODY) {
                    Ok(reservation) => reservations.push(reservation),
                    Err(_) => break 'fill,
                }
            }
        }
        assert_eq!(reservations.len(), MAX_DATA_RECORDS_PER_CONNECTION);
        assert!(matches!(
            stream.reserve(PeerRecordKind::CompleteDeviceData, MAX_DEVICE_DATA_BODY),
            Err(ResourceError::Exhausted {
                limit: ResourceLimit::ConnectionBytes,
                ..
            })
        ));
        drop(reservations);
        drop(streams);
        assert_eq!(budget.reserved_bytes(), 0);
    }

    #[test]
    fn copy_charge_is_separate_and_raii_releases_it() {
        let budget = ConnectionBudget::new();
        let stream = budget.open_stream().expect("stream");
        let record = stream
            .record_from_slice(PeerRecordKind::ConsumerChunk, b"hello")
            .expect("record");
        let before = budget.reserved_bytes();
        let encoded = record.encode_charged(&stream).expect("charged copy");
        assert_eq!(encoded.as_ref(), record.encode().as_ref());
        assert_eq!(budget.reserved_bytes(), before + record.encoded_len());
        drop(encoded);
        assert_eq!(budget.reserved_bytes(), before);
        drop(record);
        assert_eq!(budget.reserved_bytes(), 0);
    }

    #[test]
    fn control_encoded_copy_uses_control_byte_budget() {
        let budget = ConnectionBudget::new();
        let stream = budget.open_stream().expect("stream");
        let outbound =
            PeerRecord::control_text(&"x".repeat(MAX_CONTROL_TEXT_BODY)).expect("control text");
        let encoded = outbound
            .encode_charged(&stream)
            .expect("first control copy");
        assert_eq!(budget.usage().control_bytes, outbound.encoded_len());
        drop(encoded);
        assert_eq!(budget.usage().control_bytes, 0);

        let queued = stream
            .record_from_slice(
                PeerRecordKind::CompleteControlText,
                &vec![b'x'; MAX_CONTROL_TEXT_BODY],
            )
            .expect("queued control");
        assert!(matches!(
            queued.encode_charged(&stream),
            Err(ResourceError::Exhausted {
                limit: ResourceLimit::ControlBytes,
                ..
            })
        ));
        drop(queued);
        assert_eq!(budget.usage().control_bytes, 0);
    }

    #[test]
    fn zero_copy_charge_does_not_pin_stream_slot() {
        let budget = ConnectionBudget::new();
        let stream = budget.open_stream().expect("stream");
        let zero = stream.charge_copy(0).expect("zero copy charge");
        assert_eq!(zero.charged_bytes(), 0);
        drop(stream);
        assert_eq!(budget.active_streams(), 0);
        drop(zero);
        assert_eq!(budget.active_streams(), 0);
    }

    #[test]
    fn bounded_push_output_rejects_many_zero_body_records() {
        let budget = ConnectionBudget::new();
        let stream = budget.open_stream().expect("stream");
        let wire = PeerRecord::from_slice(PeerRecordKind::ConsumerChunk, &[])
            .expect("empty chunk")
            .encode();
        let mut input = Vec::new();
        for _ in 0..=MAX_RECORDS_PER_PUSH {
            input.extend_from_slice(&wire);
        }
        let mut decoder = PeerRecordDecoder::new(stream);
        assert!(matches!(
            decoder.push(&input),
            Err(PeerFrameError::OutputLimit { .. })
        ));
        assert_eq!(budget.reserved_bytes(), 0);
    }
}
