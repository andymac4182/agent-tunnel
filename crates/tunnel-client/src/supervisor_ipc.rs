//! Local, read-only supervisor status IPC (task row M6-06).
//!
//! `tunnel-client connect` is the supervisor. It listens on one Unix socket
//! per profile and answers exactly one request, `status`, with a redacted
//! snapshot; `tunnel-client status` and `tunnel-client doctor` read it. There
//! is no mutating request: `disconnect` and `credentials renew` remain
//! unimplemented, so nothing on this socket can change the supervisor.
//!
//! **Authorization is the same user, checked three ways.** The socket is
//! created in a directory that must be owned by this user and writable by no
//! one else, and is set to `0600`; the server compares every accepted peer's
//! kernel-reported UID (`SO_PEERCRED` / `getpeereid`, through
//! `tokio::net::UnixStream::peer_cred`) with its own effective UID and closes
//! any other peer without a byte; and the reader refuses a socket that is not
//! owned by it, is readable or writable by anyone else, or whose listening
//! peer is another UID -- so a planted socket cannot impersonate the
//! supervisor either. No unsafe code: the UID comes from `rustix`'s safe
//! `geteuid`, and the peer credential from `tokio`.
//!
//! **The endpoint** is `[supervisor] ipc_path` when set, else
//! `supervisor.sock` beside the client key. That is the recommendation task
//! row M0-03 recorded (options (c) with (a)), applied by default pending owner
//! confirmation (2026-09-25).
//!
//! **The bind is the profile lock.** A supervisor that finds a live listener
//! on its path refuses to start (`SUPERVISOR_RUNNING`); a socket file nobody
//! listens on is a stale leftover of a killed supervisor and is replaced.
//!
//! **Redaction is by construction.** [`SupervisorStatus`] holds identifiers,
//! phases, counters, deadlines, a certificate expiry and export names and
//! kinds. It has no field that can hold a path, an endpoint, certificate or
//! key material, a ticket, a token, a canary or payload bytes, and its error
//! field is a closed diagnostic code rather than a message.

use std::{
    io,
    path::{Path, PathBuf},
    time::Duration,
};

use serde::{Deserialize, Serialize};

/// The status request, one line.
pub const STATUS_REQUEST: &str = "status";
/// A request longer than this is refused unread.
pub const MAX_REQUEST_BYTES: usize = 64;
/// A response longer than this is refused by the reader.
pub const MAX_RESPONSE_BYTES: usize = 64 * 1024;
/// Every read, write and connect on the socket is bounded by this.
pub const IPC_IO_TIMEOUT: Duration = Duration::from_secs(2);
/// `sun_path` holds 104 bytes on macOS and 108 on Linux, both including the
/// terminating NUL; the smaller bound is enforced everywhere so a profile
/// behaves the same on both.
pub const MAX_SOCKET_PATH_BYTES: usize = 103;
/// Schema version of [`SupervisorStatus`] and its response envelope.
pub const IPC_SCHEMA_VERSION: u8 = 1;

/// Why a supervisor IPC operation failed. Every variant maps to one closed
/// diagnostic code and carries no path, peer data or OS error text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IpcError {
    /// No supervisor is listening: no socket file, or a stale one.
    Absent,
    /// Another supervisor for this profile is already listening.
    Busy,
    /// The socket, its directory or its peer failed the same-user check.
    Unauthorized(&'static str),
    /// The socket path is longer than `sun_path` allows.
    PathTooLong,
    /// The supervisor did not answer within [`IPC_IO_TIMEOUT`].
    Timeout,
    /// The answer was not a bounded, well-formed status response.
    Malformed,
    /// A local I/O failure other than the above.
    Io(&'static str),
    /// This platform has no supervisor IPC (not Unix).
    Unsupported,
}

impl IpcError {
    /// The stable diagnostic code.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::Absent => "SUPERVISOR_ABSENT",
            Self::Busy => "SUPERVISOR_RUNNING",
            Self::Unauthorized(_) => "IPC_UNAUTHORIZED",
            Self::PathTooLong => "IPC_PATH_TOO_LONG",
            Self::Timeout => "IPC_TIMEOUT",
            Self::Malformed => "IPC_MALFORMED",
            Self::Io(_) => "IPC_IO_ERROR",
            Self::Unsupported => "IPC_UNSUPPORTED",
        }
    }
}

impl std::fmt::Display for IpcError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Absent => formatter.write_str(
                "no supervisor is running for this profile (start `tunnel-client connect`)",
            ),
            Self::Busy => formatter
                .write_str("another tunnel-client connect is already supervising this profile"),
            Self::Unauthorized(reason) => {
                write!(formatter, "local supervisor IPC refused: {reason}")
            }
            Self::PathTooLong => write!(
                formatter,
                "the supervisor socket path is longer than {MAX_SOCKET_PATH_BYTES} bytes; \
                 set a shorter [supervisor] ipc_path"
            ),
            Self::Timeout => write!(
                formatter,
                "the supervisor did not answer within {} s",
                IPC_IO_TIMEOUT.as_secs()
            ),
            Self::Malformed => formatter.write_str("the supervisor's answer was malformed"),
            Self::Io(reason) => write!(formatter, "local supervisor IPC failed: {reason}"),
            Self::Unsupported => {
                formatter.write_str("supervisor IPC is not supported on this platform")
            }
        }
    }
}

impl std::error::Error for IpcError {}

/// The negotiated-by-configuration rotation policy the supervisor runs with.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct RotationPolicyStatus {
    pub interval_seconds: u64,
    pub handshake_timeout_seconds: u64,
    pub overlap_seconds: u64,
}

/// One configured export: its name and kind, nothing else.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExportStatus {
    pub name: String,
    pub kind: String,
}

/// The live session, copied from the connector actor's bounded snapshot.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct SessionStatus {
    pub phase: String,
    pub session_id: Option<String>,
    pub epoch: Option<u64>,
    pub active_generation: Option<u64>,
    pub active_connection_id: Option<String>,
    pub candidate_generation: Option<u64>,
    pub candidate_connection_id: Option<String>,
    pub rotation_id: Option<String>,
    pub rotations_completed: u64,
    pub streams: usize,
    pub open_journal_entries: usize,
    pub emitted_sequences: u64,
    pub received_sequences: u64,
    pub drain_fences: usize,
    pub drain_acks: usize,
    pub queue_frames: usize,
    pub queue_bytes: usize,
    pub replay_frames: usize,
    pub replay_bytes: usize,
    pub recovery_attempt: Option<u64>,
    pub recovery_attempt_deadline_ms: Option<u64>,
    pub recovery_episode_deadline_ms: Option<u64>,
}

impl From<&crate::ConnectionStatus> for SessionStatus {
    fn from(status: &crate::ConnectionStatus) -> Self {
        Self {
            phase: status.phase.clone(),
            session_id: status.session_id.clone(),
            epoch: status.epoch,
            active_generation: status.active_generation,
            active_connection_id: status.active_connection_id.clone(),
            candidate_generation: status.candidate_generation,
            candidate_connection_id: status.candidate_connection_id.clone(),
            rotation_id: status.rotation_id.clone(),
            rotations_completed: status.rotations_completed,
            streams: status.streams,
            open_journal_entries: status.open_journal_entries,
            emitted_sequences: status.emitted_sequences,
            received_sequences: status.received_sequences,
            drain_fences: status.drain_fences,
            drain_acks: status.drain_acks,
            queue_frames: status.queue_frames,
            queue_bytes: status.queue_bytes,
            replay_frames: status.replay_frames,
            replay_bytes: status.replay_bytes,
            recovery_attempt: status.recovery_attempt,
            recovery_attempt_deadline_ms: status.recovery_attempt_deadline_ms,
            recovery_episode_deadline_ms: status.recovery_episode_deadline_ms,
        }
    }
}

/// Counters the IPC server itself keeps.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct IpcCounters {
    /// Status requests answered.
    pub requests_served: u64,
    /// Connections closed unanswered because the peer was another UID.
    pub peers_refused: u64,
    /// Connections answered with `IPC_BAD_REQUEST`, or that timed out.
    pub bad_requests: u64,
}

/// The supervisor's redacted status snapshot.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct SupervisorStatus {
    /// The supervisor process.
    pub pid: u32,
    /// `starting`, `connecting`, `ready`, `backoff` or `stopping`.
    pub state: String,
    /// The profile's device label.
    pub device_id: String,
    /// Sessions that became ready in this process.
    pub sessions: u64,
    /// The reconnect attempt in progress or awaited, if any.
    pub attempt: Option<u32>,
    /// The backoff delay being waited, while `state` is `backoff`.
    pub retry_delay_ms: Option<u64>,
    /// The diagnostic code of the last session end, if any.
    pub last_error_code: Option<String>,
    /// The client certificate's `notAfter`, unix seconds.
    pub certificate_expires_at_unix: Option<i64>,
    pub rotation_policy: RotationPolicyStatus,
    pub exports: Vec<ExportStatus>,
    /// The live session, while one exists.
    pub session: Option<SessionStatus>,
    /// The IPC server's own counters, filled in when the answer is sent.
    pub ipc: IpcCounters,
}

/// The one-line answer on the socket.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IpcResponse {
    pub schema_version: u8,
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<SupervisorStatus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

fn check_path_length(path: &Path) -> Result<(), IpcError> {
    if path.as_os_str().len() > MAX_SOCKET_PATH_BYTES {
        return Err(IpcError::PathTooLong);
    }
    Ok(())
}

/// Whether a peer UID may read the supervisor's status. Kept as a function so
/// the rule has one definition, used by the server and by its tests.
#[must_use]
pub fn peer_is_authorized(peer_uid: u32, own_uid: u32) -> bool {
    peer_uid == own_uid
}

#[cfg(unix)]
mod unix {
    use super::*;
    use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{UnixListener, UnixStream},
        sync::watch,
    };
    use tokio_util::sync::CancellationToken;

    /// This process's effective UID.
    #[must_use]
    pub fn effective_uid() -> u32 {
        rustix::process::geteuid().as_raw()
    }

    fn check_directory(path: &Path, uid: u32) -> Result<(), IpcError> {
        let parent = match path.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent,
            _ => Path::new("."),
        };
        let metadata = std::fs::metadata(parent).map_err(|error| match error.kind() {
            io::ErrorKind::NotFound => IpcError::Io("the supervisor socket directory is missing"),
            _ => IpcError::Io("the supervisor socket directory is unreadable"),
        })?;
        if !metadata.is_dir() {
            return Err(IpcError::Io(
                "the supervisor socket directory is not a directory",
            ));
        }
        if metadata.uid() != uid {
            return Err(IpcError::Unauthorized(
                "the supervisor socket directory is owned by another user",
            ));
        }
        if metadata.permissions().mode() & 0o022 != 0 {
            return Err(IpcError::Unauthorized(
                "the supervisor socket directory is writable by other users",
            ));
        }
        Ok(())
    }

    /// Check a socket file before trusting it, as the reader does.
    fn check_socket_file(path: &Path, uid: u32) -> Result<(), IpcError> {
        let metadata = std::fs::symlink_metadata(path).map_err(|error| match error.kind() {
            io::ErrorKind::NotFound => IpcError::Absent,
            _ => IpcError::Io("the supervisor socket is unreadable"),
        })?;
        if !metadata.file_type().is_socket() {
            return Err(IpcError::Unauthorized(
                "the supervisor socket path is not a socket",
            ));
        }
        if metadata.uid() != uid {
            return Err(IpcError::Unauthorized(
                "the supervisor socket is owned by another user",
            ));
        }
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(IpcError::Unauthorized(
                "the supervisor socket is accessible to other users",
            ));
        }
        Ok(())
    }

    /// A bound supervisor socket. Dropping it removes the socket file, if
    /// the path still names the socket this process created.
    #[derive(Debug)]
    pub struct SupervisorIpc {
        listener: UnixListener,
        path: PathBuf,
        identity: (u64, u64),
        expected_uid: u32,
    }

    impl SupervisorIpc {
        /// Bind the profile's supervisor socket, taking the profile lock.
        pub fn bind(path: &Path) -> Result<Self, IpcError> {
            Self::bind_for_uid(path, effective_uid())
        }

        /// Bind, authorizing peers whose UID is `expected_uid`. Only tests
        /// pass anything but [`effective_uid`], to exercise the refusal.
        #[doc(hidden)]
        pub fn bind_for_uid(path: &Path, expected_uid: u32) -> Result<Self, IpcError> {
            check_path_length(path)?;
            let own_uid = effective_uid();
            check_directory(path, own_uid)?;
            match std::fs::symlink_metadata(path) {
                Ok(metadata) => {
                    if !metadata.file_type().is_socket() {
                        return Err(IpcError::Io(
                            "the supervisor socket path exists and is not a socket",
                        ));
                    }
                    // A live listener is another supervisor; refused is a
                    // stale file left by a killed one.
                    match std::os::unix::net::UnixStream::connect(path) {
                        Ok(_) => return Err(IpcError::Busy),
                        Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {
                            std::fs::remove_file(path).map_err(|_| {
                                IpcError::Io("a stale supervisor socket could not be removed")
                            })?;
                        }
                        Err(_) => {
                            return Err(IpcError::Io(
                                "an existing supervisor socket could not be probed",
                            ));
                        }
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(_) => return Err(IpcError::Io("the supervisor socket path is unreadable")),
            }
            let listener = UnixListener::bind(path).map_err(|error| match error.kind() {
                io::ErrorKind::AddrInUse => IpcError::Busy,
                _ => IpcError::Io("the supervisor socket could not be bound"),
            })?;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                .map_err(|_| IpcError::Io("the supervisor socket mode could not be set"))?;
            let metadata = std::fs::symlink_metadata(path)
                .map_err(|_| IpcError::Io("the bound supervisor socket vanished"))?;
            Ok(Self {
                listener,
                path: path.to_owned(),
                identity: (metadata.dev(), metadata.ino()),
                expected_uid,
            })
        }

        /// Serve status requests until `cancel` fires. One connection at a
        /// time, each bounded by [`IPC_IO_TIMEOUT`], so the server's memory
        /// and time are bounded whatever a local peer does.
        pub async fn serve(
            self,
            status: watch::Receiver<SupervisorStatus>,
            cancel: CancellationToken,
        ) {
            let mut counters = IpcCounters::default();
            loop {
                let accepted = tokio::select! {
                    biased;
                    () = cancel.cancelled() => break,
                    accepted = self.listener.accept() => accepted,
                };
                let Ok((stream, _)) = accepted else {
                    // A transient accept failure (EMFILE, say) must not spin.
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                };
                // A peer whose credentials cannot be read -- a same-user
                // probe that already closed, as a second `connect` checking
                // the lock does -- is not a refused user; it is counted with
                // the malformed requests, so `peers_refused` counts only
                // peers the kernel reported as another UID.
                match stream.peer_cred() {
                    Ok(credential) if peer_is_authorized(credential.uid(), self.expected_uid) => {}
                    Ok(_) => {
                        counters.peers_refused = counters.peers_refused.saturating_add(1);
                        drop(stream);
                        continue;
                    }
                    Err(_) => {
                        counters.bad_requests = counters.bad_requests.saturating_add(1);
                        drop(stream);
                        continue;
                    }
                }
                match tokio::time::timeout(IPC_IO_TIMEOUT, answer(stream, &status, &mut counters))
                    .await
                {
                    Ok(Ok(())) => {}
                    Ok(Err(())) | Err(_) => {
                        counters.bad_requests = counters.bad_requests.saturating_add(1);
                    }
                }
            }
        }
    }

    impl Drop for SupervisorIpc {
        fn drop(&mut self) {
            if let Ok(metadata) = std::fs::symlink_metadata(&self.path)
                && (metadata.dev(), metadata.ino()) == self.identity
            {
                let _ = std::fs::remove_file(&self.path);
            }
        }
    }

    async fn answer(
        mut stream: UnixStream,
        status: &watch::Receiver<SupervisorStatus>,
        counters: &mut IpcCounters,
    ) -> Result<(), ()> {
        let mut request = Vec::with_capacity(MAX_REQUEST_BYTES);
        let mut byte = [0_u8; 1];
        loop {
            match stream.read(&mut byte).await {
                Ok(0) => break,
                Ok(_) if byte[0] == b'\n' => break,
                Ok(_) if request.len() < MAX_REQUEST_BYTES => request.push(byte[0]),
                Ok(_) | Err(_) => return Err(()),
            }
        }
        let response = if request == STATUS_REQUEST.as_bytes() {
            counters.requests_served = counters.requests_served.saturating_add(1);
            let mut snapshot = status.borrow().clone();
            snapshot.ipc = *counters;
            IpcResponse {
                schema_version: IPC_SCHEMA_VERSION,
                ok: true,
                result: Some(snapshot),
                error: None,
            }
        } else {
            counters.bad_requests = counters.bad_requests.saturating_add(1);
            IpcResponse {
                schema_version: IPC_SCHEMA_VERSION,
                ok: false,
                result: None,
                error: Some("IPC_BAD_REQUEST".to_owned()),
            }
        };
        let mut line = serde_json::to_vec(&response).map_err(|_| ())?;
        line.push(b'\n');
        stream.write_all(&line).await.map_err(|_| ())?;
        let _ = stream.shutdown().await;
        Ok(())
    }

    /// Read the supervisor's status for the socket at `path`.
    pub async fn query_status(path: &Path) -> Result<SupervisorStatus, IpcError> {
        query_status_for_uid(path, effective_uid()).await
    }

    /// Read the status, authorizing a listening peer whose UID is
    /// `expected_peer_uid`. The socket file is always checked against this
    /// process's own UID; only tests pass anything but [`effective_uid`]
    /// here, to exercise the peer check on its own -- a file check against
    /// the shifted UID would refuse first and leave the peer check untested
    /// (measured: the first version of that test stayed green with the peer
    /// check deleted).
    #[doc(hidden)]
    pub async fn query_status_for_uid(
        path: &Path,
        expected_peer_uid: u32,
    ) -> Result<SupervisorStatus, IpcError> {
        check_path_length(path)?;
        check_socket_file(path, effective_uid())?;
        let mut stream = match tokio::time::timeout(IPC_IO_TIMEOUT, UnixStream::connect(path)).await
        {
            Err(_) => return Err(IpcError::Timeout),
            Ok(Ok(stream)) => stream,
            Ok(Err(error)) => {
                return Err(match error.kind() {
                    io::ErrorKind::ConnectionRefused | io::ErrorKind::NotFound => IpcError::Absent,
                    io::ErrorKind::PermissionDenied => {
                        IpcError::Unauthorized("the supervisor socket refused this user")
                    }
                    _ => IpcError::Io("could not connect to the supervisor socket"),
                });
            }
        };
        let peer = stream
            .peer_cred()
            .map_err(|_| IpcError::Io("the supervisor's credentials could not be read"))?;
        if !peer_is_authorized(peer.uid(), expected_peer_uid) {
            return Err(IpcError::Unauthorized(
                "the process listening on the supervisor socket is another user",
            ));
        }
        let exchange = async {
            stream
                .write_all(format!("{STATUS_REQUEST}\n").as_bytes())
                .await
                .map_err(|_| IpcError::Io("could not send the status request"))?;
            let mut response = Vec::new();
            let mut limited = (&mut stream).take(MAX_RESPONSE_BYTES as u64 + 1);
            limited
                .read_to_end(&mut response)
                .await
                .map_err(|_| IpcError::Io("could not read the status answer"))?;
            if response.len() > MAX_RESPONSE_BYTES {
                return Err(IpcError::Malformed);
            }
            Ok(response)
        };
        let response = tokio::time::timeout(IPC_IO_TIMEOUT, exchange)
            .await
            .map_err(|_| IpcError::Timeout)??;
        // An authorized peer closing without an answer is a supervisor that
        // refused this reader (another UID from its point of view).
        if response.is_empty() {
            return Err(IpcError::Unauthorized(
                "the supervisor closed the connection without answering",
            ));
        }
        let response: IpcResponse =
            serde_json::from_slice(&response).map_err(|_| IpcError::Malformed)?;
        match (response.schema_version, response.ok, response.result) {
            (IPC_SCHEMA_VERSION, true, Some(status)) => Ok(status),
            _ => Err(IpcError::Malformed),
        }
    }
}

#[cfg(unix)]
pub use unix::{SupervisorIpc, effective_uid, query_status, query_status_for_uid};

/// Read the supervisor's status; this platform has no supervisor IPC.
#[cfg(not(unix))]
pub async fn query_status(_path: &Path) -> Result<SupervisorStatus, IpcError> {
    Err(IpcError::Unsupported)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use tokio::sync::watch;
    use tokio_util::sync::CancellationToken;

    fn private_dir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))
            .expect("chmod");
        dir
    }

    fn snapshot() -> SupervisorStatus {
        SupervisorStatus {
            pid: 7,
            state: "ready".to_owned(),
            device_id: "device-a".to_owned(),
            ..SupervisorStatus::default()
        }
    }

    #[tokio::test]
    async fn a_same_user_reader_gets_the_snapshot_and_the_socket_is_owner_only() {
        let dir = private_dir();
        let path = dir.path().join("s.sock");
        let ipc = SupervisorIpc::bind(&path).expect("bind");
        let mode = std::fs::metadata(&path)
            .expect("socket")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "the socket must be owner-only");
        let (_tx, rx) = watch::channel(snapshot());
        let cancel = CancellationToken::new();
        let server = tokio::spawn(ipc.serve(rx, cancel.clone()));
        let status = query_status(&path).await.expect("status");
        assert_eq!(status.state, "ready");
        assert_eq!(status.ipc.requests_served, 1);
        cancel.cancel();
        server.await.expect("server joins");
        assert!(
            !path.exists(),
            "the socket file is removed when the server ends"
        );
    }

    #[tokio::test]
    async fn a_peer_with_another_uid_is_closed_unanswered() {
        let dir = private_dir();
        let path = dir.path().join("s.sock");
        // The server authorizes a UID that is not this process's, so this
        // process is, to it, another user: the real peer_cred path refuses.
        let other = effective_uid().wrapping_add(1);
        let ipc = SupervisorIpc::bind_for_uid(&path, other).expect("bind");
        let (_tx, rx) = watch::channel(snapshot());
        let cancel = CancellationToken::new();
        let server = tokio::spawn(ipc.serve(rx, cancel.clone()));
        let error = query_status(&path).await.expect_err("refused");
        assert_eq!(error.code(), "IPC_UNAUTHORIZED", "{error}");
        cancel.cancel();
        server.await.expect("server joins");
    }

    #[tokio::test]
    async fn a_reader_refuses_a_supervisor_running_as_another_uid() {
        let dir = private_dir();
        let path = dir.path().join("s.sock");
        let ipc = SupervisorIpc::bind(&path).expect("bind");
        let (_tx, rx) = watch::channel(snapshot());
        let cancel = CancellationToken::new();
        let server = tokio::spawn(ipc.serve(rx, cancel.clone()));
        let other = effective_uid().wrapping_add(1);
        let error = query_status_for_uid(&path, other)
            .await
            .expect_err("refused");
        assert_eq!(
            error,
            IpcError::Unauthorized(
                "the process listening on the supervisor socket is another user"
            )
        );
        cancel.cancel();
        server.await.expect("server joins");
    }

    #[tokio::test]
    async fn a_socket_readable_by_others_is_refused_before_connecting() {
        let dir = private_dir();
        let path = dir.path().join("s.sock");
        let ipc = SupervisorIpc::bind(&path).expect("bind");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).expect("chmod");
        let (_tx, rx) = watch::channel(snapshot());
        let cancel = CancellationToken::new();
        let server = tokio::spawn(ipc.serve(rx, cancel.clone()));
        let error = query_status(&path).await.expect_err("refused");
        assert_eq!(
            error,
            IpcError::Unauthorized("the supervisor socket is accessible to other users")
        );
        cancel.cancel();
        server.await.expect("server joins");
    }

    #[tokio::test]
    async fn a_group_writable_directory_is_refused_for_the_socket() {
        let dir = private_dir();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o770))
            .expect("chmod");
        let error = SupervisorIpc::bind(&dir.path().join("s.sock")).expect_err("refused");
        assert!(matches!(error, IpcError::Unauthorized(_)), "{error:?}");
    }

    #[tokio::test]
    async fn a_live_supervisor_holds_the_profile_and_a_stale_socket_is_replaced() {
        let dir = private_dir();
        let path = dir.path().join("s.sock");
        let first = SupervisorIpc::bind(&path).expect("bind");
        assert_eq!(
            SupervisorIpc::bind(&path).expect_err("busy"),
            IpcError::Busy
        );
        // A killed supervisor leaves its file behind with nobody listening.
        let stale = std::os::unix::net::UnixListener::bind(dir.path().join("t.sock"))
            .expect("stale listener");
        drop(stale);
        let replaced = SupervisorIpc::bind(&dir.path().join("t.sock")).expect("stale replaced");
        drop(replaced);
        drop(first);
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn no_socket_is_absent_and_a_long_path_is_refused() {
        let dir = private_dir();
        assert_eq!(
            query_status(&dir.path().join("none.sock"))
                .await
                .expect_err("absent"),
            IpcError::Absent
        );
        let long = dir.path().join("x".repeat(MAX_SOCKET_PATH_BYTES));
        assert_eq!(
            SupervisorIpc::bind(&long).expect_err("long"),
            IpcError::PathTooLong
        );
    }

    #[tokio::test]
    async fn an_unknown_request_is_answered_bad_request_and_counted() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let dir = private_dir();
        let path = dir.path().join("s.sock");
        let ipc = SupervisorIpc::bind(&path).expect("bind");
        let (_tx, rx) = watch::channel(snapshot());
        let cancel = CancellationToken::new();
        let server = tokio::spawn(ipc.serve(rx, cancel.clone()));
        let mut stream = tokio::net::UnixStream::connect(&path)
            .await
            .expect("connect");
        stream.write_all(b"disconnect\n").await.expect("write");
        let mut answer = String::new();
        stream.read_to_string(&mut answer).await.expect("read");
        assert!(answer.contains("IPC_BAD_REQUEST"), "{answer}");
        let status = query_status(&path).await.expect("status");
        assert_eq!(status.ipc.bad_requests, 1);
        assert_eq!(status.ipc.requests_served, 1);
        cancel.cancel();
        server.await.expect("server joins");
    }
}
