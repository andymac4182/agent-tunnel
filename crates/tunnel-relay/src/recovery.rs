//! Explicit operator-controlled cluster recovery workflow.
//!
//! This module is a separate authority
//! boundary from membership version persistence: the file below remembers
//! only the highest externally signed recovery approval version accepted for
//! one `(deployment_id, redis_namespace)` trust domain.  It deliberately does
//! not bind to a deployment incarnation, so an approved replacement can be
//! activated after a normal deployment restart.
//!
//! The production command wiring is documented in
//! The relay CLI must open an existing
//! fence, verify the supplied nonce and operator signature, durably advance
//! the approval version, and only then call the catalog activation API.  A
//! missing or corrupt fence is an error.  Only the explicit
//! `recovery-initialize` command may create a new fence.

use std::{
    collections::BTreeSet,
    error::Error,
    fmt,
    fs::{self, File, Metadata, OpenOptions, TryLockError},
    io::{self, Read, Write},
    path::{Component, Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use tunnel_catalog::{
    CatalogConnectionError, CatalogConnectionStage, CatalogError, DurableCatalogObservation,
    RecoveryApprovalVerifier, RecoveryPolicy, RedisCatalog, TrustedRecoveryKey,
};

use crate::redis_connection::{
    RedisConnectionError, RedisTlsMaterialPaths, map_catalog_connection_error,
};

use tokio::task::JoinHandle;

/// Schema version for the external recovery approval-version fence.
pub const RECOVERY_FENCE_SCHEMA_VERSION: u16 = 1;
/// Maximum encoded recovery fence size.
pub const MAX_RECOVERY_FENCE_BYTES: usize = 16 * 1024;
/// Maximum size of an approval, trust document, or quiescence declaration.
pub const MAX_RECOVERY_INPUT_BYTES: usize = 16 * 1024;
/// Maximum size of each stable identity, nonce, and key identifier.
pub const MAX_RECOVERY_IDENTIFIER_BYTES: usize = 128;
/// Exact mode required for the fence, lock, and local control files on Unix.
pub const RECOVERY_CONTROL_FILE_MODE: u32 = 0o600;

/// Maximum time allowed for one bounded local recovery-file operation before
/// the workflow reports a timeout.  The timeout path still awaits the join
/// handle, so a blocking rename cannot outlive that recovery attempt and race
/// a later activation.
pub const MAX_RECOVERY_BLOCKING_TIMEOUT: Duration = Duration::from_secs(2);

const MAX_RECOVERY_PATH_BYTES: usize = 4 * 1024;
const MAX_TEMP_FILE_ATTEMPTS: usize = 8;
#[cfg(unix)]
const FILE_MODE_MASK: u32 = 0o7777;

/// Stable identity for a recovery version fence.
///
/// The deployment incarnation is intentionally absent.  Incarnation is a
/// signed approval claim and a Redis activation target; including it in this
/// file would make a normal restart look like a new authority and would allow
/// an old approval version to be replayed against a replacement incarnation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryFenceIdentity {
    pub deployment_id: String,
    pub redis_namespace: String,
}

impl RecoveryFenceIdentity {
    /// Construct and validate the stable trust-domain identity.
    pub fn new(
        deployment_id: impl Into<String>,
        redis_namespace: impl Into<String>,
    ) -> Result<Self, RecoveryFenceStoreError> {
        let identity = Self {
            deployment_id: deployment_id.into(),
            redis_namespace: redis_namespace.into(),
        };
        validate_identifier(&identity.deployment_id)?;
        validate_identifier(&identity.redis_namespace)?;
        Ok(identity)
    }
}

/// The version remembered by [`RecoveryApprovalVersionStore`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryFenceState {
    /// `None` means that the explicitly bootstrapped fence has accepted no
    /// approval yet.  Approval version zero is never valid.
    pub highest_approval_version: Option<u64>,
}

impl RecoveryFenceState {
    #[cfg(test)]
    fn empty() -> Self {
        Self {
            highest_approval_version: None,
        }
    }
}

/// Redacted failures at the local recovery-fence boundary.
///
/// Variants intentionally contain no path, file content, nonce, approval,
/// public-key bytes, or operating-system error text.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecoveryFenceStoreError {
    InvalidIdentity,
    InvalidPath,
    Missing,
    AlreadyExists,
    Busy,
    SymlinkRejected,
    PathChanged,
    NotRegularFile,
    ParentDirectoryNotPrivate,
    InsecurePermissions,
    UnsupportedSchema(u16),
    IdentityMismatch,
    Oversized { size: usize, max: usize },
    Corrupt,
    InvalidState,
    EqualVersionConflict { version: u64 },
    VersionRollback { highest: u64, received: u64 },
    Serialization,
    Io,
    DurableSync,
}

impl fmt::Display for RecoveryFenceStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidIdentity => formatter.write_str("invalid recovery fence identity"),
            Self::InvalidPath => formatter.write_str("invalid recovery fence path"),
            Self::Missing => formatter.write_str("recovery approval fence is missing"),
            Self::AlreadyExists => formatter.write_str("recovery approval fence already exists"),
            Self::Busy => formatter.write_str("recovery approval fence is already open"),
            Self::SymlinkRejected => formatter.write_str("recovery fence symlink is rejected"),
            Self::PathChanged => formatter.write_str("recovery fence path changed during access"),
            Self::NotRegularFile => formatter.write_str("recovery fence is not a regular file"),
            Self::ParentDirectoryNotPrivate => {
                formatter.write_str("recovery fence parent directory is not private")
            }
            Self::InsecurePermissions => {
                formatter.write_str("recovery fence permissions are too broad")
            }
            Self::UnsupportedSchema(version) => {
                write!(formatter, "unsupported recovery fence schema {version}")
            }
            Self::IdentityMismatch => formatter.write_str("recovery fence identity mismatch"),
            Self::Oversized { size, max } => {
                write!(
                    formatter,
                    "recovery fence exceeds {max} bytes (received {size})"
                )
            }
            Self::Corrupt => formatter.write_str("recovery fence is corrupt"),
            Self::InvalidState => formatter.write_str("recovery fence state is invalid"),
            Self::EqualVersionConflict { version } => {
                write!(
                    formatter,
                    "recovery approval version {version} was already accepted"
                )
            }
            Self::VersionRollback { highest, received } => write!(
                formatter,
                "recovery approval version {received} is below accepted version {highest}"
            ),
            Self::Serialization => formatter.write_str("recovery fence serialization failed"),
            Self::Io => formatter.write_str("recovery fence I/O failed"),
            Self::DurableSync => formatter.write_str("recovery fence durable sync failed"),
        }
    }
}

impl Error for RecoveryFenceStoreError {}

/// A durable, identity-bound high-water mark for signed recovery approvals.
///
/// `open` is the serving/recovery path and requires an existing valid file.
/// `bootstrap` is the only creation path.  Clones share both the process-local
/// writer mutex and the stable sidecar lock held for this instance's lifetime;
/// a second process opening the same fence receives [`Busy`].
#[derive(Clone, Debug)]
pub struct RecoveryApprovalVersionStore {
    path: PathBuf,
    identity: RecoveryFenceIdentity,
    _lock: Arc<File>,
    writer: Arc<Mutex<()>>,
}

impl RecoveryApprovalVersionStore {
    /// Open an existing fence.  Missing, malformed, mismatched, or insecure
    /// state is always an error; this method never creates empty state.
    pub fn open(
        path: impl Into<PathBuf>,
        identity: RecoveryFenceIdentity,
    ) -> Result<Self, RecoveryFenceStoreError> {
        let store = Self::new(path, identity)?;
        store.load()?;
        Ok(store)
    }

    /// Explicitly create an empty fence for a newly provisioned deployment.
    ///
    /// This is intentionally a separate operation from `open` and is not
    /// called by `observe` or `recover`.
    pub fn bootstrap(
        path: impl Into<PathBuf>,
        identity: RecoveryFenceIdentity,
    ) -> Result<Self, RecoveryFenceStoreError> {
        let store = Self::new(path, identity)?;
        let bytes = encode_envelope(&PersistedRecoveryFence::empty(&store.identity))?;
        store.create_initial(&bytes)?;
        Ok(store)
    }

    /// Return the configured fence path for operator diagnostics.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Load and validate the current high-water state.
    pub fn load(&self) -> Result<RecoveryFenceState, RecoveryFenceStoreError> {
        let _writer = self
            .writer
            .lock()
            .map_err(|_| RecoveryFenceStoreError::Io)?;
        self.load_unlocked()
    }

    /// Durably advance the fence before a catalog activation.
    ///
    /// Equal or lower versions are rejected.  The temp file is opened
    /// exclusively with mode `0600`, synced, renamed atomically, and followed
    /// by a parent-directory sync.  A failure leaves activation to the caller
    /// (which must remain unavailable) and never silently accepts the record.
    pub fn record(&self, approval_version: u64) -> Result<(), RecoveryFenceStoreError> {
        if approval_version == 0 {
            return Err(RecoveryFenceStoreError::InvalidState);
        }
        let _writer = self
            .writer
            .lock()
            .map_err(|_| RecoveryFenceStoreError::Io)?;
        let current = self.load_unlocked()?;
        if let Some(highest) = current.highest_approval_version {
            if approval_version < highest {
                return Err(RecoveryFenceStoreError::VersionRollback {
                    highest,
                    received: approval_version,
                });
            }
            if approval_version == highest {
                return Err(RecoveryFenceStoreError::EqualVersionConflict {
                    version: approval_version,
                });
            }
        }
        let next = PersistedRecoveryFence {
            schema_version: RECOVERY_FENCE_SCHEMA_VERSION,
            deployment_id: self.identity.deployment_id.clone(),
            redis_namespace: self.identity.redis_namespace.clone(),
            highest_approval_version: Some(approval_version),
        };
        let bytes = encode_envelope(&next)?;
        self.replace_atomically(&bytes)
    }

    fn new(
        path: impl Into<PathBuf>,
        identity: RecoveryFenceIdentity,
    ) -> Result<Self, RecoveryFenceStoreError> {
        let path = path.into();
        validate_path(&path)?;
        let lock = Arc::new(open_lock_file(&lock_path(&path)?)?);
        Ok(Self {
            path,
            identity,
            _lock: lock,
            writer: Arc::new(Mutex::new(())),
        })
    }

    fn load_unlocked(&self) -> Result<RecoveryFenceState, RecoveryFenceStoreError> {
        let bytes = read_bounded_control_file(&self.path, MAX_RECOVERY_FENCE_BYTES)
            .map_err(map_control_file_error)?;
        let envelope = decode_envelope(&bytes)?;
        if envelope.schema_version != RECOVERY_FENCE_SCHEMA_VERSION {
            return Err(RecoveryFenceStoreError::UnsupportedSchema(
                envelope.schema_version,
            ));
        }
        if envelope.deployment_id != self.identity.deployment_id
            || envelope.redis_namespace != self.identity.redis_namespace
        {
            return Err(RecoveryFenceStoreError::IdentityMismatch);
        }
        validate_identifier(&envelope.deployment_id)?;
        validate_identifier(&envelope.redis_namespace)?;
        validate_state(&RecoveryFenceState {
            highest_approval_version: envelope.highest_approval_version,
        })?;
        Ok(RecoveryFenceState {
            highest_approval_version: envelope.highest_approval_version,
        })
    }

    fn create_initial(&self, bytes: &[u8]) -> Result<(), RecoveryFenceStoreError> {
        let parent = parent_directory(&self.path);
        let parent_metadata = ensure_parent_directory(parent)?;
        match fs::symlink_metadata(&self.path) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    return Err(RecoveryFenceStoreError::SymlinkRejected);
                }
                return Err(RecoveryFenceStoreError::AlreadyExists);
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(_) => return Err(RecoveryFenceStoreError::Io),
        }
        let temp = self.write_temporary(bytes)?;
        let result = match fs::hard_link(&temp, &self.path) {
            Ok(()) => sync_parent_directory(parent, &parent_metadata),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                Err(RecoveryFenceStoreError::AlreadyExists)
            }
            Err(_) => Err(RecoveryFenceStoreError::Io),
        };
        let _ = fs::remove_file(&temp);
        result
    }

    fn replace_atomically(&self, bytes: &[u8]) -> Result<(), RecoveryFenceStoreError> {
        let parent = parent_directory(&self.path);
        let parent_metadata = ensure_parent_directory(parent)?;
        let temp = self.write_temporary(bytes)?;
        let result = match fs::rename(&temp, &self.path) {
            Ok(()) => sync_parent_directory(parent, &parent_metadata),
            Err(_) => Err(RecoveryFenceStoreError::Io),
        };
        if result.is_err() {
            let _ = fs::remove_file(&temp);
        }
        result
    }

    fn write_temporary(&self, bytes: &[u8]) -> Result<PathBuf, RecoveryFenceStoreError> {
        let parent = parent_directory(&self.path);
        ensure_parent_directory(parent)?;
        let file_name = self
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(RecoveryFenceStoreError::InvalidPath)?;
        for _ in 0..MAX_TEMP_FILE_ATTEMPTS {
            let temp = parent.join(format!(
                ".{file_name}.tmp-{}",
                uuid::Uuid::new_v4().simple()
            ));
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(RECOVERY_CONTROL_FILE_MODE);
                options.custom_flags(libc::O_NOFOLLOW);
            }
            let mut file = match options.open(&temp) {
                Ok(file) => file,
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(_) => return Err(RecoveryFenceStoreError::Io),
            };
            let result = (|| {
                file.write_all(bytes)
                    .map_err(|_| RecoveryFenceStoreError::Io)?;
                file.sync_all()
                    .map_err(|_| RecoveryFenceStoreError::DurableSync)
            })();
            drop(file);
            if let Err(error) = result {
                let _ = fs::remove_file(&temp);
                return Err(error);
            }
            return Ok(temp);
        }
        Err(RecoveryFenceStoreError::Io)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedRecoveryFence {
    schema_version: u16,
    deployment_id: String,
    redis_namespace: String,
    highest_approval_version: Option<u64>,
}

impl PersistedRecoveryFence {
    fn empty(identity: &RecoveryFenceIdentity) -> Self {
        Self {
            schema_version: RECOVERY_FENCE_SCHEMA_VERSION,
            deployment_id: identity.deployment_id.clone(),
            redis_namespace: identity.redis_namespace.clone(),
            highest_approval_version: None,
        }
    }
}

fn validate_identifier(value: &str) -> Result<(), RecoveryFenceStoreError> {
    if value.trim().is_empty()
        || value.len() > MAX_RECOVERY_IDENTIFIER_BYTES
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err(RecoveryFenceStoreError::InvalidIdentity);
    }
    Ok(())
}

fn validate_path(path: &Path) -> Result<(), RecoveryFenceStoreError> {
    let value = path.to_str().ok_or(RecoveryFenceStoreError::InvalidPath)?;
    if value.is_empty()
        || value.len() > MAX_RECOVERY_PATH_BYTES
        || value.bytes().any(|byte| byte.is_ascii_control())
        || path.file_name().is_none()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(RecoveryFenceStoreError::InvalidPath);
    }
    Ok(())
}

fn validate_state(state: &RecoveryFenceState) -> Result<(), RecoveryFenceStoreError> {
    if state.highest_approval_version == Some(0) {
        return Err(RecoveryFenceStoreError::InvalidState);
    }
    Ok(())
}

fn encode_envelope(envelope: &PersistedRecoveryFence) -> Result<Vec<u8>, RecoveryFenceStoreError> {
    let bytes = serde_json::to_vec(envelope).map_err(|_| RecoveryFenceStoreError::Serialization)?;
    if bytes.len() > MAX_RECOVERY_FENCE_BYTES {
        return Err(RecoveryFenceStoreError::Oversized {
            size: bytes.len(),
            max: MAX_RECOVERY_FENCE_BYTES,
        });
    }
    Ok(bytes)
}

fn decode_envelope(bytes: &[u8]) -> Result<PersistedRecoveryFence, RecoveryFenceStoreError> {
    if bytes.len() > MAX_RECOVERY_FENCE_BYTES {
        return Err(RecoveryFenceStoreError::Oversized {
            size: bytes.len(),
            max: MAX_RECOVERY_FENCE_BYTES,
        });
    }
    let envelope = serde_json::from_slice::<PersistedRecoveryFence>(bytes)
        .map_err(|_| RecoveryFenceStoreError::Corrupt)?;
    let canonical = encode_envelope(&envelope)?;
    if canonical != bytes {
        return Err(RecoveryFenceStoreError::Corrupt);
    }
    Ok(envelope)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ControlFileError {
    Missing,
    SymlinkRejected,
    PathChanged,
    NotRegularFile,
    ParentDirectoryNotPrivate,
    InsecurePermissions,
    Oversized { size: usize, max: usize },
    Io,
}

fn map_control_file_error(error: ControlFileError) -> RecoveryFenceStoreError {
    match error {
        ControlFileError::Missing => RecoveryFenceStoreError::Missing,
        ControlFileError::SymlinkRejected => RecoveryFenceStoreError::SymlinkRejected,
        ControlFileError::PathChanged => RecoveryFenceStoreError::PathChanged,
        ControlFileError::NotRegularFile => RecoveryFenceStoreError::NotRegularFile,
        ControlFileError::ParentDirectoryNotPrivate => {
            RecoveryFenceStoreError::ParentDirectoryNotPrivate
        }
        ControlFileError::InsecurePermissions => RecoveryFenceStoreError::InsecurePermissions,
        ControlFileError::Oversized { size, max } => {
            RecoveryFenceStoreError::Oversized { size, max }
        }
        ControlFileError::Io => RecoveryFenceStoreError::Io,
    }
}

fn read_bounded_control_file(path: &Path, max_bytes: usize) -> Result<Vec<u8>, ControlFileError> {
    validate_path(path).map_err(|_| ControlFileError::Io)?;
    let parent = parent_directory(path);
    let parent_metadata = ensure_parent_directory(parent).map_err(map_fence_path_error)?;
    let path_metadata = fs::symlink_metadata(path).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            ControlFileError::Missing
        } else {
            ControlFileError::Io
        }
    })?;
    validate_control_file_metadata(&path_metadata)?;
    if path_metadata.len() > max_bytes as u64 {
        return Err(ControlFileError::Oversized {
            size: path_metadata.len() as usize,
            max: max_bytes,
        });
    }
    let file = open_readonly_nofollow(path).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            ControlFileError::Missing
        } else if error.kind() == io::ErrorKind::InvalidInput {
            ControlFileError::SymlinkRejected
        } else {
            ControlFileError::Io
        }
    })?;
    let opened_metadata = file.metadata().map_err(|_| ControlFileError::Io)?;
    validate_control_file_metadata(&opened_metadata)?;
    if !same_file_metadata(&path_metadata, &opened_metadata) {
        return Err(ControlFileError::PathChanged);
    }
    let current_path_metadata = fs::symlink_metadata(path).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            ControlFileError::Missing
        } else {
            ControlFileError::Io
        }
    })?;
    if current_path_metadata.file_type().is_symlink()
        || !same_file_metadata(&path_metadata, &current_path_metadata)
    {
        return Err(ControlFileError::PathChanged);
    }
    let current_parent_metadata = ensure_parent_directory(parent).map_err(map_fence_path_error)?;
    if !same_file_metadata(&parent_metadata, &current_parent_metadata) {
        return Err(ControlFileError::PathChanged);
    }
    let mut bytes = Vec::with_capacity(max_bytes.min(4096));
    let mut bounded = file.take((max_bytes + 1) as u64);
    bounded
        .read_to_end(&mut bytes)
        .map_err(|_| ControlFileError::Io)?;
    if bytes.len() > max_bytes {
        return Err(ControlFileError::Oversized {
            size: bytes.len(),
            max: max_bytes,
        });
    }
    Ok(bytes)
}

fn map_fence_path_error(error: RecoveryFenceStoreError) -> ControlFileError {
    match error {
        RecoveryFenceStoreError::SymlinkRejected => ControlFileError::SymlinkRejected,
        RecoveryFenceStoreError::NotRegularFile => ControlFileError::NotRegularFile,
        RecoveryFenceStoreError::ParentDirectoryNotPrivate => {
            ControlFileError::ParentDirectoryNotPrivate
        }
        RecoveryFenceStoreError::InsecurePermissions => ControlFileError::InsecurePermissions,
        _ => ControlFileError::Io,
    }
}

fn open_readonly_nofollow(path: &Path) -> io::Result<File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut options = OpenOptions::new();
        options.read(true).custom_flags(libc::O_NOFOLLOW);
        options.open(path)
    }
    #[cfg(not(unix))]
    {
        File::open(path)
    }
}

fn validate_control_file_metadata(metadata: &Metadata) -> Result<(), ControlFileError> {
    if metadata.file_type().is_symlink() {
        return Err(ControlFileError::SymlinkRejected);
    }
    if !metadata.file_type().is_file() {
        return Err(ControlFileError::NotRegularFile);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode() & FILE_MODE_MASK;
        if mode != RECOVERY_CONTROL_FILE_MODE {
            return Err(ControlFileError::InsecurePermissions);
        }
    }
    Ok(())
}

fn lock_path(path: &Path) -> Result<PathBuf, RecoveryFenceStoreError> {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(RecoveryFenceStoreError::InvalidPath)?;
    let lock_path = parent_directory(path).join(format!(".{file_name}.lock"));
    validate_path(&lock_path)?;
    Ok(lock_path)
}

fn open_lock_file(path: &Path) -> Result<File, RecoveryFenceStoreError> {
    let parent = parent_directory(path);
    let parent_metadata = ensure_parent_directory(parent)?;
    let previous_metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => {
            validate_file_metadata(&metadata)?;
            if metadata.len() != 0 {
                return Err(RecoveryFenceStoreError::Corrupt);
            }
            Some(metadata)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(_) => return Err(RecoveryFenceStoreError::Io),
    };
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
        options.mode(RECOVERY_CONTROL_FILE_MODE);
    }
    let file = options.open(path).map_err(|error| {
        if error.kind() == io::ErrorKind::WouldBlock {
            RecoveryFenceStoreError::Busy
        } else {
            RecoveryFenceStoreError::Io
        }
    })?;
    let opened_metadata = file.metadata().map_err(|_| RecoveryFenceStoreError::Io)?;
    validate_file_metadata(&opened_metadata)?;
    if opened_metadata.len() != 0 {
        return Err(RecoveryFenceStoreError::Corrupt);
    }
    if previous_metadata
        .as_ref()
        .is_some_and(|metadata| !same_file_metadata(metadata, &opened_metadata))
    {
        return Err(RecoveryFenceStoreError::PathChanged);
    }
    let current_metadata = fs::symlink_metadata(path).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            RecoveryFenceStoreError::Missing
        } else {
            RecoveryFenceStoreError::Io
        }
    })?;
    if current_metadata.file_type().is_symlink()
        || !same_file_metadata(&current_metadata, &opened_metadata)
    {
        return Err(RecoveryFenceStoreError::PathChanged);
    }
    let current_parent_metadata = ensure_parent_directory(parent)?;
    if !same_file_metadata(&parent_metadata, &current_parent_metadata) {
        return Err(RecoveryFenceStoreError::PathChanged);
    }
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(TryLockError::WouldBlock) => Err(RecoveryFenceStoreError::Busy),
        Err(TryLockError::Error(_)) => Err(RecoveryFenceStoreError::Io),
    }
}

fn validate_file_metadata(metadata: &Metadata) -> Result<(), RecoveryFenceStoreError> {
    if metadata.file_type().is_symlink() {
        return Err(RecoveryFenceStoreError::SymlinkRejected);
    }
    if !metadata.file_type().is_file() {
        return Err(RecoveryFenceStoreError::NotRegularFile);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode() & FILE_MODE_MASK;
        if mode != RECOVERY_CONTROL_FILE_MODE {
            return Err(RecoveryFenceStoreError::InsecurePermissions);
        }
    }
    Ok(())
}

fn ensure_parent_directory(path: &Path) -> Result<Metadata, RecoveryFenceStoreError> {
    ensure_no_symlink_components(path)?;
    let metadata = fs::symlink_metadata(path).map_err(|_| RecoveryFenceStoreError::Io)?;
    if metadata.file_type().is_symlink() {
        return Err(RecoveryFenceStoreError::SymlinkRejected);
    }
    if !metadata.is_dir() {
        return Err(RecoveryFenceStoreError::NotRegularFile);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & FILE_MODE_MASK != 0o700 {
            return Err(RecoveryFenceStoreError::ParentDirectoryNotPrivate);
        }
    }
    Ok(metadata)
}

fn ensure_no_symlink_components(path: &Path) -> Result<(), RecoveryFenceStoreError> {
    let mut current = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => current.push(prefix.as_os_str()),
            Component::RootDir => current.push(component.as_os_str()),
            Component::CurDir => {
                if current.as_os_str().is_empty() {
                    current.push(component.as_os_str());
                }
            }
            Component::ParentDir => return Err(RecoveryFenceStoreError::InvalidPath),
            Component::Normal(name) => current.push(name),
        }
        let metadata = fs::symlink_metadata(&current).map_err(|_| RecoveryFenceStoreError::Io)?;
        if metadata.file_type().is_symlink() {
            return Err(RecoveryFenceStoreError::SymlinkRejected);
        }
    }
    Ok(())
}

fn same_file_metadata(first: &Metadata, second: &Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        first.dev() == second.dev() && first.ino() == second.ino()
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        first.volume_serial_number() == second.volume_serial_number()
            && first.file_index() == second.file_index()
    }
    #[cfg(not(any(unix, windows)))]
    {
        first.is_file() == second.is_file() && first.len() == second.len()
    }
}

fn parent_directory(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn sync_parent_directory(path: &Path, expected: &Metadata) -> Result<(), RecoveryFenceStoreError> {
    let current = ensure_parent_directory(path)?;
    if !same_file_metadata(expected, &current) {
        return Err(RecoveryFenceStoreError::PathChanged);
    }
    #[cfg(unix)]
    {
        let directory = open_readonly_nofollow(path).map_err(|_| RecoveryFenceStoreError::Io)?;
        let opened = directory
            .metadata()
            .map_err(|_| RecoveryFenceStoreError::Io)?;
        if !same_file_metadata(expected, &opened) {
            return Err(RecoveryFenceStoreError::PathChanged);
        }
        directory
            .sync_all()
            .map_err(|_| RecoveryFenceStoreError::DurableSync)?;
    }
    let after = ensure_parent_directory(path)?;
    if !same_file_metadata(expected, &after) {
        return Err(RecoveryFenceStoreError::PathChanged);
    }
    Ok(())
}

/// The only quiescence value emitted by `recovery-observe`.
///
/// A Redis read cannot prove that an old primary or relay has stopped.  The
/// recover command therefore requires an explicit operator declaration, but
/// keeps this output as `unproven` so diagnostics never turn that declaration
/// into an authority claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QuiescenceStatus {
    Unproven,
}

/// Redacted, read-only output of `recovery-observe`.
///
/// This value contains only identifiers, a durable-catalog digest, and
/// bounded counters.  It never includes catalog records, Redis credentials,
/// signed approval bytes, or a quiescence claim.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryObservation {
    pub schema_version: u16,
    pub deployment_id: String,
    pub redis_namespace: String,
    pub deployment_incarnation: String,
    pub redis_run_id: String,
    pub catalog_digest: String,
    pub catalog_generation: String,
    pub key_count: usize,
    pub byte_count: usize,
    pub quiescence: QuiescenceStatus,
}

impl RecoveryObservation {
    fn from_catalog(
        config: &RecoveryWorkflowConfig,
        observation: DurableCatalogObservation,
    ) -> Self {
        Self {
            schema_version: RECOVERY_FENCE_SCHEMA_VERSION,
            deployment_id: config.deployment_id.clone(),
            redis_namespace: config.redis_namespace.clone(),
            deployment_incarnation: config.deployment_incarnation.clone(),
            redis_run_id: observation.redis_run_id().to_owned(),
            catalog_digest: observation.catalog_digest().to_owned(),
            catalog_generation: observation.catalog_generation().to_owned(),
            key_count: observation.key_count(),
            byte_count: observation.byte_count(),
            quiescence: QuiescenceStatus::Unproven,
        }
    }
}

/// Operator declaration required before catalog activation.
///
/// The booleans are deliberately explicit because the recovery command must
/// stop and ask for a human-controlled fencing decision.  They are not signed
/// by this module and do not prove quiescence; Redis cannot provide that proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuiescenceAcknowledgement {
    pub declaration_id: String,
    pub old_primary_fenced: bool,
    pub old_relays_fenced: bool,
}

impl QuiescenceAcknowledgement {
    /// Construct the operator declaration supplied by CLI or orchestration.
    pub fn new(
        declaration_id: impl Into<String>,
        old_primary_fenced: bool,
        old_relays_fenced: bool,
    ) -> Result<Self, RecoveryWorkflowError> {
        let declaration = Self {
            declaration_id: declaration_id.into(),
            old_primary_fenced,
            old_relays_fenced,
        };
        declaration.validate()?;
        Ok(declaration)
    }

    fn validate(&self) -> Result<(), RecoveryWorkflowError> {
        validate_workflow_identifier(&self.declaration_id)?;
        if !self.old_primary_fenced || !self.old_relays_fenced {
            return Err(RecoveryWorkflowError::QuiescenceRequired);
        }
        Ok(())
    }
}

/// Stable inputs shared by `recovery-observe` and `recover`.
///
/// `deployment_incarnation` selects the candidate owner fence but is not part
/// of the local approval-version fence.  The expected nonce, trusted key
/// document, and deployment identity come from outside Redis and must be
/// supplied by the operator or deployment authority.
#[derive(Clone)]
pub struct RecoveryWorkflowConfig {
    pub redis_url: String,
    pub deployment_id: String,
    pub redis_namespace: String,
    pub deployment_incarnation: String,
    pub fence_path: PathBuf,
    pub trusted_keys_path: PathBuf,
    pub redis_tls_material: RedisTlsMaterialPaths,
}

impl fmt::Debug for RecoveryWorkflowConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecoveryWorkflowConfig")
            .field("has_redis_url", &(!self.redis_url.is_empty()))
            .field("deployment_id", &self.deployment_id)
            .field("redis_namespace", &self.redis_namespace)
            .field("deployment_incarnation", &self.deployment_incarnation)
            .field("fence_path", &"<redacted>")
            .field("trusted_keys_path", &"<redacted>")
            .field("redis_tls_material", &self.redis_tls_material)
            .finish()
    }
}

impl RecoveryWorkflowConfig {
    /// Construct and validate workflow inputs without opening Redis or files.
    pub fn new(
        redis_url: impl Into<String>,
        deployment_id: impl Into<String>,
        redis_namespace: impl Into<String>,
        deployment_incarnation: impl Into<String>,
        fence_path: impl Into<PathBuf>,
        trusted_keys_path: impl Into<PathBuf>,
        redis_tls_material: RedisTlsMaterialPaths,
    ) -> Result<Self, RecoveryWorkflowError> {
        let config = Self {
            redis_url: redis_url.into(),
            deployment_id: deployment_id.into(),
            redis_namespace: redis_namespace.into(),
            deployment_incarnation: deployment_incarnation.into(),
            fence_path: fence_path.into(),
            trusted_keys_path: trusted_keys_path.into(),
            redis_tls_material,
        };
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), RecoveryWorkflowError> {
        validate_workflow_identifier(&self.deployment_id)?;
        validate_workflow_identifier(&self.redis_namespace)?;
        validate_workflow_identifier(&self.deployment_incarnation)?;
        if self.redis_url.trim().is_empty()
            || self.redis_url.len() > MAX_RECOVERY_PATH_BYTES
            || self
                .redis_url
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        {
            return Err(RecoveryWorkflowError::InvalidInput("Redis authority URL"));
        }
        if !self.redis_url.starts_with("redis://") && !self.redis_url.starts_with("rediss://") {
            return Err(RecoveryWorkflowError::InvalidInput(
                "Redis authority URL scheme",
            ));
        }
        validate_workflow_path(&self.fence_path)?;
        validate_workflow_path(&self.trusted_keys_path)?;
        self.redis_tls_material
            .validate_shape()
            .map_err(RecoveryWorkflowError::InvalidInput)
    }

    fn identity(&self) -> Result<RecoveryFenceIdentity, RecoveryWorkflowError> {
        RecoveryFenceIdentity::new(&self.deployment_id, &self.redis_namespace)
            .map_err(RecoveryWorkflowError::Fence)
    }
}

/// Inputs that are deliberately not persisted by the recovery module.
#[derive(Clone)]
pub struct RecoverRequest {
    /// Fresh challenge obtained from an authority outside Redis.  It must not
    /// be copied from the signed approval file.
    pub expected_nonce: String,
    pub approval_path: PathBuf,
    pub quiescence: QuiescenceAcknowledgement,
}

impl fmt::Debug for RecoverRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecoverRequest")
            .field("has_expected_nonce", &(!self.expected_nonce.is_empty()))
            .field("approval_path", &"<redacted>")
            .field("quiescence", &self.quiescence)
            .finish()
    }
}

impl RecoverRequest {
    fn validate(&self) -> Result<(), RecoveryWorkflowError> {
        validate_nonce(&self.expected_nonce)?;
        validate_workflow_path(&self.approval_path)?;
        self.quiescence.validate()
    }
}

/// Redacted result after Redis activation committed.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryOutcome {
    pub schema_version: u16,
    pub approval_version: u64,
    pub deployment_incarnation: String,
    pub redis_run_id: String,
    pub catalog_digest: String,
    pub quiescence_declared: bool,
}

/// Errors returned by the staged recovery workflow.
///
/// The workflow intentionally collapses backend details and all input paths.
/// `ActivationOutcomeUnknown` means an EXEC may have reached Redis; callers
/// must observe/reconcile and obtain a fresh higher approval, never retrying
/// the consumed approval automatically.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RecoveryWorkflowError {
    InvalidInput(&'static str),
    InsecureTransport,
    Fence(RecoveryFenceStoreError),
    ControlFile,
    ApprovalRejected,
    TrustedKeysRejected,
    QuiescenceRequired,
    RedisConnection,
    /// The Redis connection failed; carries only the bounded stage, lane and
    /// failure class (M6-C72), never a URL, credential or server text.
    RedisConnectionStaged(RedisConnectionError),
    CatalogUnavailable,
    CatalogDigestMismatch,
    ActivationFailed,
    ActivationOutcomeUnknown,
    BlockingTimeout,
    BlockingTaskFailed,
}

impl fmt::Display for RecoveryWorkflowError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput(field) => write!(formatter, "invalid recovery input: {field}"),
            Self::InsecureTransport => {
                formatter.write_str("recovery requires a verified Redis authority transport")
            }
            Self::Fence(error) => error.fmt(formatter),
            Self::ControlFile => formatter.write_str("recovery control file could not be read"),
            Self::ApprovalRejected => formatter.write_str("recovery approval was rejected"),
            Self::TrustedKeysRejected => {
                formatter.write_str("trusted recovery key document was rejected")
            }
            Self::QuiescenceRequired => formatter.write_str(
                "explicit operator acknowledgement that the old primary and relays are fenced is required",
            ),
            Self::RedisConnection => formatter.write_str("recovery Redis connection failed"),
            Self::RedisConnectionStaged(error) => match error.stage_detail() {
                Some(detail) => write!(formatter, "recovery Redis connection failed; {detail}"),
                None => formatter.write_str("recovery Redis connection failed"),
            },
            Self::CatalogUnavailable => formatter.write_str("recovery catalog operation failed"),
            Self::CatalogDigestMismatch => {
                formatter.write_str("recovery approval does not match the live catalog observation")
            }
            Self::ActivationFailed => formatter.write_str(
                "recovery activation failed; reconcile the catalog and obtain a fresh higher approval",
            ),
            Self::ActivationOutcomeUnknown => formatter.write_str(
                "recovery activation outcome is unknown; reconcile the catalog and obtain a fresh higher approval",
            ),
            Self::BlockingTimeout => formatter.write_str(
                "recovery local control operation timed out; the outstanding operation was joined and no activation occurred",
            ),
            Self::BlockingTaskFailed => {
                formatter.write_str("recovery local control operation failed")
            }
        }
    }
}

impl Error for RecoveryWorkflowError {}

/// Read a bounded catalog observation without opening the local approval
/// fence or changing Redis authority state.
pub async fn recovery_observe(
    config: &RecoveryWorkflowConfig,
) -> Result<RecoveryObservation, RecoveryWorkflowError> {
    config.validate()?;
    let catalog = connect_for_recovery(config).await?;
    let observation = catalog
        .observe_durable_catalog()
        .await
        .map_err(map_catalog_error)?;
    Ok(RecoveryObservation::from_catalog(config, observation))
}

struct PreparedRecovery {
    store: RecoveryApprovalVersionStore,
    prior: RecoveryFenceState,
    approval_bytes: Vec<u8>,
    trusted_keys: Vec<TrustedRecoveryKey>,
}

async fn prepare_recovery(
    config: &RecoveryWorkflowConfig,
    request: &RecoverRequest,
) -> Result<PreparedRecovery, RecoveryWorkflowError> {
    let identity = config.identity()?;
    let fence_path = config.fence_path.clone();
    let approval_path = request.approval_path.clone();
    let trusted_keys_path = config.trusted_keys_path.clone();
    let task = tokio::task::spawn_blocking(move || {
        let store = RecoveryApprovalVersionStore::open(fence_path, identity)
            .map_err(RecoveryWorkflowError::Fence)?;
        let prior = store.load().map_err(RecoveryWorkflowError::Fence)?;
        let approval_bytes = read_bounded_control_file(&approval_path, MAX_RECOVERY_INPUT_BYTES)
            .map_err(|_| RecoveryWorkflowError::ControlFile)?;
        let trusted_keys = load_trusted_recovery_keys(&trusted_keys_path)?;
        Ok(PreparedRecovery {
            store,
            prior,
            approval_bytes,
            trusted_keys,
        })
    });
    supervise_blocking(task).await
}

async fn persist_approval_version(
    store: &RecoveryApprovalVersionStore,
    approval_version: u64,
) -> Result<(), RecoveryWorkflowError> {
    let store = store.clone();
    let task = tokio::task::spawn_blocking(move || {
        store
            .record(approval_version)
            .map_err(RecoveryWorkflowError::Fence)
    });
    supervise_blocking(task).await
}

/// Await a bounded blocking phase while retaining its join handle on timeout.
///
/// `tokio::time::timeout` only stops waiting; it cannot cancel filesystem I/O.
/// After a deadline, this function joins the outstanding task before returning
/// an error.  That ordering guarantees that a late atomic rename cannot race
/// a subsequent recovery attempt, and the caller cannot proceed to Redis
/// activation after a timed-out persistence phase.  If the *outer* recovery
/// future is dropped, Tokio may detach this join handle; the blocking closure
/// still owns the cloned fence store and therefore retains the stable sidecar
/// lock until its file operation completes.  A production CLI that must wait
/// for cancellation should own this future in a supervisor and run it to
/// completion rather than dropping it.
async fn supervise_blocking<T>(
    task: JoinHandle<Result<T, RecoveryWorkflowError>>,
) -> Result<T, RecoveryWorkflowError>
where
    T: Send + 'static,
{
    supervise_blocking_with_timeout(task, MAX_RECOVERY_BLOCKING_TIMEOUT).await
}

async fn supervise_blocking_with_timeout<T>(
    mut task: JoinHandle<Result<T, RecoveryWorkflowError>>,
    timeout: Duration,
) -> Result<T, RecoveryWorkflowError>
where
    T: Send + 'static,
{
    match tokio::time::timeout(timeout, &mut task).await {
        Ok(Ok(result)) => result,
        Ok(Err(_)) => Err(RecoveryWorkflowError::BlockingTaskFailed),
        Err(_) => {
            let _ = task.await;
            Err(RecoveryWorkflowError::BlockingTimeout)
        }
    }
}

/// Verify, durably consume, and activate one externally approved recovery.
///
/// The order is intentionally strict:
///
/// 1. open the existing identity-bound fence;
/// 2. read a fresh bounded Redis observation;
/// 3. verify the signed approval against the externally supplied nonce,
///    observed Redis run, deployment identity, incarnation, digest, and
///    persisted version;
/// 4. durably advance the local version fence;
/// 5. call the catalog's bounded approval-gated activation.
///
/// If step 4 succeeds and step 5 fails, the version remains consumed.  The
/// caller must observe/reconcile and obtain a higher approval.  This function
/// never retries activation with the same approval.
pub async fn recover(
    config: &RecoveryWorkflowConfig,
    request: &RecoverRequest,
) -> Result<RecoveryOutcome, RecoveryWorkflowError> {
    config.validate()?;
    request.validate()?;

    // Keep the sidecar lock in `prepared.store` while Redis observation and
    // signature verification run.  No second recovery process can race the
    // version check or persistence phase.
    let PreparedRecovery {
        store,
        prior,
        approval_bytes,
        trusted_keys,
    } = prepare_recovery(config, request).await?;
    let catalog = connect_for_recovery(config).await?;
    let observation = catalog
        .observe_durable_catalog()
        .await
        .map_err(map_catalog_error)?;

    let policy = RecoveryPolicy::new(
        &config.deployment_id,
        &config.redis_namespace,
        observation.redis_run_id(),
        &config.deployment_incarnation,
    )
    .map_err(|_| RecoveryWorkflowError::ApprovalRejected)?;
    let verifier = RecoveryApprovalVerifier::new(policy, trusted_keys)
        .map_err(|_| RecoveryWorkflowError::TrustedKeysRejected)?;
    let verified = verifier
        .verify(
            &approval_bytes,
            &request.expected_nonce,
            Utc::now(),
            prior.highest_approval_version,
        )
        .map_err(|_| RecoveryWorkflowError::ApprovalRejected)?;
    if verified.catalog_digest() != observation.catalog_digest() {
        return Err(RecoveryWorkflowError::CatalogDigestMismatch);
    }

    // The blocking persistence phase is supervised and joined on timeout.  It
    // is intentionally completed before any catalog activation.
    persist_approval_version(&store, verified.approval_version()).await?;

    match catalog
        .activate_deployment_incarnation_with_approval(&verified)
        .await
    {
        Ok(()) => Ok(RecoveryOutcome {
            schema_version: RECOVERY_FENCE_SCHEMA_VERSION,
            approval_version: verified.approval_version(),
            deployment_incarnation: config.deployment_incarnation.clone(),
            redis_run_id: observation.redis_run_id().to_owned(),
            catalog_digest: observation.catalog_digest().to_owned(),
            quiescence_declared: true,
        }),
        Err(error) => Err(map_activation_error(error)),
    }
}

async fn connect_for_recovery(
    config: &RecoveryWorkflowConfig,
) -> Result<RedisCatalog, RecoveryWorkflowError> {
    if config.redis_tls_material.is_configured() {
        if !config.redis_url.starts_with("rediss://") {
            return Err(RecoveryWorkflowError::InsecureTransport);
        }
        let tls = config
            .redis_tls_material
            .load()
            .map_err(|_| RecoveryWorkflowError::RedisConnection)?
            .ok_or(RecoveryWorkflowError::RedisConnection)?;
        RedisCatalog::connect_for_recovery_with_tls_staged(
            &config.redis_url,
            &config.redis_namespace,
            &config.deployment_incarnation,
            tls,
        )
        .await
        .map_err(map_connection_error)
    } else {
        RedisCatalog::connect_for_recovery_staged(
            &config.redis_url,
            &config.redis_namespace,
            &config.deployment_incarnation,
        )
        .await
        .map_err(map_connection_error)
    }
}

/// A failure while opening the Redis authority keeps its bounded stage, lane
/// and class (M6-C72).  A refused local profile (namespace or incarnation
/// shape) keeps the classification `map_catalog_error` gives it.
fn map_connection_error(error: CatalogConnectionError) -> RecoveryWorkflowError {
    if error.stage() == CatalogConnectionStage::AuthorityProfile {
        return map_catalog_error(error.into_catalog_error());
    }
    RecoveryWorkflowError::RedisConnectionStaged(map_catalog_connection_error(&error))
}

fn map_catalog_error(error: CatalogError) -> RecoveryWorkflowError {
    match error {
        CatalogError::Database(_) => RecoveryWorkflowError::RedisConnection,
        CatalogError::InvalidInput(_) => RecoveryWorkflowError::InvalidInput("catalog input"),
        CatalogError::Conflict(_) | CatalogError::OwnerBusy => {
            RecoveryWorkflowError::CatalogUnavailable
        }
        _ => RecoveryWorkflowError::CatalogUnavailable,
    }
}

fn map_activation_error(error: CatalogError) -> RecoveryWorkflowError {
    match error {
        CatalogError::Conflict("recovery activation outcome unknown") => {
            RecoveryWorkflowError::ActivationOutcomeUnknown
        }
        _ => RecoveryWorkflowError::ActivationFailed,
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustedRecoveryKeyDocument {
    schema_version: u16,
    keys: Vec<TrustedRecoveryKeyEntry>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustedRecoveryKeyEntry {
    key_id: String,
    public_key: String,
}

/// Load operator-installed public keys.  The accepted schema has no private
/// key field, and unknown fields are rejected before any key is trusted.
pub fn load_trusted_recovery_keys(
    path: &Path,
) -> Result<Vec<TrustedRecoveryKey>, RecoveryWorkflowError> {
    let bytes = read_bounded_control_file(path, MAX_RECOVERY_INPUT_BYTES)
        .map_err(|_| RecoveryWorkflowError::ControlFile)?;
    let document = serde_json::from_slice::<TrustedRecoveryKeyDocument>(&bytes)
        .map_err(|_| RecoveryWorkflowError::TrustedKeysRejected)?;
    if document.schema_version != RECOVERY_FENCE_SCHEMA_VERSION
        || document.keys.is_empty()
        || document.keys.len() > 32
    {
        return Err(RecoveryWorkflowError::TrustedKeysRejected);
    }
    let mut ids = BTreeSet::new();
    let mut keys = Vec::with_capacity(document.keys.len());
    for entry in document.keys {
        if !ids.insert(entry.key_id.clone()) {
            return Err(RecoveryWorkflowError::TrustedKeysRejected);
        }
        let public_key = decode_public_key(&entry.public_key)
            .ok_or(RecoveryWorkflowError::TrustedKeysRejected)?;
        let key = TrustedRecoveryKey::new(entry.key_id, public_key)
            .map_err(|_| RecoveryWorkflowError::TrustedKeysRejected)?;
        keys.push(key);
    }
    Ok(keys)
}

fn decode_public_key(encoded: &str) -> Option<[u8; 32]> {
    let bytes = if encoded.len() == 64 && encoded.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        let mut bytes = [0_u8; 32];
        for (index, chunk) in encoded.as_bytes().chunks_exact(2).enumerate() {
            let high = (chunk[0] as char).to_digit(16)? as u8;
            let low = (chunk[1] as char).to_digit(16)? as u8;
            bytes[index] = high << 4 | low;
        }
        bytes.to_vec()
    } else {
        URL_SAFE_NO_PAD
            .decode(encoded)
            .or_else(|_| STANDARD.decode(encoded))
            .ok()?
    };
    bytes.try_into().ok()
}

fn validate_workflow_identifier(value: &str) -> Result<(), RecoveryWorkflowError> {
    if value.trim().is_empty()
        || value.len() > MAX_RECOVERY_IDENTIFIER_BYTES
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err(RecoveryWorkflowError::InvalidInput("recovery identity"));
    }
    Ok(())
}

fn validate_workflow_path(path: &Path) -> Result<(), RecoveryWorkflowError> {
    let value = path
        .to_str()
        .ok_or(RecoveryWorkflowError::InvalidInput("recovery control path"))?;
    if value.is_empty()
        || value.len() > MAX_RECOVERY_PATH_BYTES
        || value.bytes().any(|byte| byte.is_ascii_control())
        || path.file_name().is_none()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(RecoveryWorkflowError::InvalidInput("recovery control path"));
    }
    Ok(())
}

fn validate_nonce(nonce: &str) -> Result<(), RecoveryWorkflowError> {
    if nonce.len() < 16
        || nonce.len() > MAX_RECOVERY_IDENTIFIER_BYTES
        || !nonce
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(RecoveryWorkflowError::InvalidInput(
            "expected recovery nonce",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let suffix = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "agent-tunnel-recovery-state-{}-{suffix}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("create test directory");
            let path = fs::canonicalize(path).expect("canonicalize test directory");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                    .expect("private test directory");
            }
            Self(path)
        }

        fn fence_path(&self) -> PathBuf {
            self.0.join("recovery-fence.json")
        }

        fn control_path(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn identity() -> RecoveryFenceIdentity {
        RecoveryFenceIdentity::new("deployment-a", "cluster-a").expect("identity")
    }

    #[test]
    fn bootstrap_is_explicit_and_round_trips_stable_identity() {
        let directory = TestDirectory::new();
        let path = directory.fence_path();
        let store = RecoveryApprovalVersionStore::bootstrap(&path, identity()).expect("bootstrap");
        assert_eq!(
            store.load().expect("empty state"),
            RecoveryFenceState::empty()
        );
        drop(store);

        let reopened = RecoveryApprovalVersionStore::open(&path, identity()).expect("reopen");
        assert_eq!(
            reopened.load().expect("reloaded state"),
            RecoveryFenceState::empty()
        );
        drop(reopened);

        // The fence identity intentionally has no deployment-incarnation
        // field: the same file remains valid when the approved candidate
        // changes from incarnation-a to incarnation-b.
        let same_domain =
            RecoveryFenceIdentity::new("deployment-a", "cluster-a").expect("same stable domain");
        let same_domain_store = RecoveryApprovalVersionStore::open(&path, same_domain)
            .expect("incarnation-independent");
        assert_eq!(
            same_domain_store.load().expect("stable domain state"),
            RecoveryFenceState::empty()
        );
    }

    #[test]
    fn missing_state_never_silently_bootstraps() {
        let directory = TestDirectory::new();
        let path = directory.fence_path();
        let error = RecoveryApprovalVersionStore::open(&path, identity())
            .expect_err("missing state must fail closed");
        assert_eq!(error, RecoveryFenceStoreError::Missing);
        assert!(!path.exists(), "open must not create an empty fence");

        let store = RecoveryApprovalVersionStore::bootstrap(&path, identity()).expect("bootstrap");
        drop(store);
        assert_eq!(
            RecoveryApprovalVersionStore::bootstrap(&path, identity())
                .expect_err("bootstrap is create-only"),
            RecoveryFenceStoreError::AlreadyExists
        );
    }

    #[test]
    fn sidecar_lock_blocks_separate_store_until_owner_drops() {
        let directory = TestDirectory::new();
        let path = directory.fence_path();
        let store = RecoveryApprovalVersionStore::bootstrap(&path, identity()).expect("bootstrap");
        assert_eq!(
            RecoveryApprovalVersionStore::open(&path, identity()).expect_err("stable lock"),
            RecoveryFenceStoreError::Busy
        );
        drop(store);
        let reopened = RecoveryApprovalVersionStore::open(&path, identity()).expect("after drop");
        drop(reopened);
    }

    #[test]
    fn identity_is_bound_to_deployment_and_namespace() {
        let directory = TestDirectory::new();
        let path = directory.fence_path();
        let store = RecoveryApprovalVersionStore::bootstrap(&path, identity()).expect("bootstrap");
        drop(store);
        assert_eq!(
            RecoveryApprovalVersionStore::open(
                &path,
                RecoveryFenceIdentity::new("deployment-b", "cluster-a").expect("identity"),
            )
            .expect_err("deployment binding"),
            RecoveryFenceStoreError::IdentityMismatch
        );
        // The lock sidecar remains stable but is released when the failed
        // open's temporary store is dropped, so namespace mismatch can also
        // be observed independently.
        assert_eq!(
            RecoveryApprovalVersionStore::open(
                &path,
                RecoveryFenceIdentity::new("deployment-a", "cluster-b").expect("identity"),
            )
            .expect_err("namespace binding"),
            RecoveryFenceStoreError::IdentityMismatch
        );
    }

    #[test]
    fn approval_versions_are_monotonic_and_durable() {
        let directory = TestDirectory::new();
        let path = directory.fence_path();
        let store = RecoveryApprovalVersionStore::bootstrap(&path, identity()).expect("bootstrap");
        store.record(7).expect("first version");
        assert_eq!(
            store.record(7).expect_err("equal replay"),
            RecoveryFenceStoreError::EqualVersionConflict { version: 7 }
        );
        assert_eq!(
            store.record(6).expect_err("rollback"),
            RecoveryFenceStoreError::VersionRollback {
                highest: 7,
                received: 6,
            }
        );
        store.record(9).expect("advance");
        assert_eq!(
            store.load().expect("durable high water"),
            RecoveryFenceState {
                highest_approval_version: Some(9)
            }
        );
        drop(store);
        let reopened = RecoveryApprovalVersionStore::open(&path, identity()).expect("reopen");
        assert_eq!(
            reopened
                .load()
                .expect("restart fence")
                .highest_approval_version,
            Some(9)
        );
    }

    #[test]
    #[cfg(unix)]
    fn insecure_state_permissions_fail_closed() {
        use std::os::unix::fs::PermissionsExt;

        let directory = TestDirectory::new();
        let path = directory.fence_path();
        let store = RecoveryApprovalVersionStore::bootstrap(&path, identity()).expect("bootstrap");
        drop(store);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).expect("insecure test mode");
        assert_eq!(
            RecoveryApprovalVersionStore::open(&path, identity())
                .expect_err("insecure state must fail closed"),
            RecoveryFenceStoreError::InsecurePermissions
        );
    }

    #[test]
    fn unknown_activation_outcome_requires_reconciliation() {
        assert_eq!(
            map_activation_error(CatalogError::Conflict(
                "recovery activation outcome unknown"
            )),
            RecoveryWorkflowError::ActivationOutcomeUnknown
        );
        assert_eq!(
            map_activation_error(CatalogError::OwnerBusy),
            RecoveryWorkflowError::ActivationFailed
        );
    }

    #[test]
    fn incomplete_quiescence_is_refused_before_local_mutation() {
        let acknowledgement = QuiescenceAcknowledgement {
            declaration_id: "operator-declaration-1".to_owned(),
            old_primary_fenced: true,
            old_relays_fenced: false,
        };
        let request = RecoverRequest {
            expected_nonce: "0123456789abcdef".to_owned(),
            approval_path: PathBuf::from("approval.json"),
            quiescence: acknowledgement,
        };
        assert_eq!(
            request
                .validate()
                .expect_err("fencing acknowledgement required"),
            RecoveryWorkflowError::QuiescenceRequired
        );
    }

    #[test]
    fn trusted_key_document_has_bounded_public_only_schema() {
        let directory = TestDirectory::new();
        let path = directory.control_path("trusted-keys.json");
        let public_key = STANDARD.encode([7_u8; 32]);
        let document = format!(
            "{{\"schema_version\":1,\"keys\":[{{\"key_id\":\"operator-a\",\"public_key\":\"{public_key}\"}}]}}"
        );
        fs::write(&path, document).expect("trusted key document");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
                .expect("trusted key permissions");
        }
        let keys = load_trusted_recovery_keys(&path).expect("public key document");
        assert_eq!(keys.len(), 1);

        fs::write(
            &path,
            format!(
                "{{\"schema_version\":1,\"keys\":[{{\"key_id\":\"operator-a\",\"public_key\":\"{public_key}\",\"private_key\":\"secret\"}}]}}"
            ),
        )
        .expect("unknown field");
        assert_eq!(
            load_trusted_recovery_keys(&path).expect_err("private key field rejected"),
            RecoveryWorkflowError::TrustedKeysRejected
        );
    }

    #[test]
    fn workflow_debug_redacts_authority_credentials_and_control_paths() {
        let config = RecoveryWorkflowConfig {
            redis_url: "rediss://operator:super-secret@redis.example.test/0".to_owned(),
            deployment_id: "deployment-a".to_owned(),
            redis_namespace: "cluster-a".to_owned(),
            deployment_incarnation: "incarnation-b".to_owned(),
            fence_path: PathBuf::from("/owner/private/recovery-fence.json"),
            trusted_keys_path: PathBuf::from("/owner/private/trusted-keys.json"),
            redis_tls_material: RedisTlsMaterialPaths::default(),
        };
        let rendered = format!("{config:?}");
        assert!(!rendered.contains("super-secret"));
        assert!(!rendered.contains("redis.example.test"));
        assert!(!rendered.contains("recovery-fence.json"));
        assert!(!rendered.contains("trusted-keys.json"));

        let request = RecoverRequest {
            expected_nonce: "externally-supplied-secret-challenge".to_owned(),
            approval_path: PathBuf::from("/owner/private/approval.json"),
            quiescence: QuiescenceAcknowledgement {
                declaration_id: "operator-declaration-1".to_owned(),
                old_primary_fenced: true,
                old_relays_fenced: true,
            },
        };
        let rendered = format!("{request:?}");
        assert!(!rendered.contains("externally-supplied-secret-challenge"));
        assert!(!rendered.contains("approval.json"));
    }

    fn write_private_control_file(path: &Path, bytes: &[u8]) {
        fs::write(path, bytes).expect("control file");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))
                .expect("control file permissions");
        }
    }

    #[tokio::test]
    async fn prepare_phase_runs_control_reads_in_supervised_blocking_task() {
        let directory = TestDirectory::new();
        let fence_path = directory.fence_path();
        let store = RecoveryApprovalVersionStore::bootstrap(&fence_path, identity())
            .expect("bootstrap fence");
        drop(store);
        let trusted_path = directory.control_path("trusted-keys.json");
        let public_key = STANDARD.encode([7_u8; 32]);
        write_private_control_file(
            &trusted_path,
            format!(
                "{{\"schema_version\":1,\"keys\":[{{\"key_id\":\"operator-a\",\"public_key\":\"{public_key}\"}}]}}"
            )
            .as_bytes(),
        );
        let approval_path = directory.control_path("approval.json");
        write_private_control_file(&approval_path, b"{}");
        let config = RecoveryWorkflowConfig::new(
            "redis://127.0.0.1:6379/0",
            "deployment-a",
            "cluster-a",
            "incarnation-b",
            &fence_path,
            &trusted_path,
            RedisTlsMaterialPaths::default(),
        )
        .expect("workflow config");
        let request = RecoverRequest {
            expected_nonce: "0123456789abcdef".to_owned(),
            approval_path,
            quiescence: QuiescenceAcknowledgement {
                declaration_id: "operator-declaration-1".to_owned(),
                old_primary_fenced: true,
                old_relays_fenced: true,
            },
        };
        let prepared = prepare_recovery(&config, &request)
            .await
            .expect("prepare local recovery inputs");
        assert_eq!(prepared.prior.highest_approval_version, None);
        assert_eq!(prepared.approval_bytes, b"{}");
        assert_eq!(prepared.trusted_keys.len(), 1);
    }

    #[tokio::test]
    async fn persistence_phase_records_before_activation_boundary() {
        let directory = TestDirectory::new();
        let path = directory.fence_path();
        let store = RecoveryApprovalVersionStore::bootstrap(&path, identity()).expect("bootstrap");
        persist_approval_version(&store, 11)
            .await
            .expect("durable approval version");
        assert_eq!(
            store
                .load()
                .expect("persisted state")
                .highest_approval_version,
            Some(11)
        );
    }

    #[tokio::test]
    async fn blocking_timeout_joins_before_returning() {
        let completed = Arc::new(AtomicBool::new(false));
        let marker = Arc::clone(&completed);
        let task = tokio::task::spawn_blocking(move || {
            std::thread::sleep(Duration::from_millis(20));
            marker.store(true, Ordering::Release);
            Ok::<_, RecoveryWorkflowError>(())
        });
        assert_eq!(
            supervise_blocking_with_timeout(task, Duration::from_millis(1)).await,
            Err(RecoveryWorkflowError::BlockingTimeout)
        );
        assert!(
            completed.load(Ordering::Acquire),
            "a timed-out filesystem task must be joined before the caller continues"
        );
    }

    #[tokio::test]
    async fn cancelled_outer_future_keeps_fence_lock_until_task_finishes() {
        let directory = TestDirectory::new();
        let path = directory.fence_path();
        let store = RecoveryApprovalVersionStore::bootstrap(&path, identity()).expect("bootstrap");
        let task_store = store.clone();
        drop(store);

        let started = Arc::new(tokio::sync::Notify::new());
        let task_started = Arc::clone(&started);
        let completed = Arc::new(AtomicBool::new(false));
        let task_completed = Arc::clone(&completed);
        let (release_writer, wait_for_release) = std::sync::mpsc::sync_channel(0);
        let outer = tokio::spawn(async move {
            let task = tokio::task::spawn_blocking(move || {
                task_started.notify_one();
                wait_for_release.recv().expect("release detached writer");
                let result = task_store.record(11).map_err(RecoveryWorkflowError::Fence);
                task_completed.store(true, Ordering::Release);
                result
            });
            supervise_blocking_with_timeout(task, Duration::from_secs(1)).await
        });
        tokio::time::timeout(Duration::from_secs(1), started.notified())
            .await
            .expect("blocking task started");

        // Dropping the outer future can detach Tokio's JoinHandle.  The
        // closure still owns the cloned store, so a second process cannot
        // open the fence while the pending write is alive.
        outer.abort();
        let _ = outer.await;
        assert_eq!(
            RecoveryApprovalVersionStore::open(&path, identity())
                .expect_err("detached writer retains the stable lock"),
            RecoveryFenceStoreError::Busy
        );

        release_writer.send(()).expect("release detached writer");
        tokio::time::timeout(Duration::from_secs(1), async {
            while !completed.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("detached writer completion");
        let reopened = RecoveryApprovalVersionStore::open(&path, identity())
            .expect("lock released after detached task finished");
        assert_eq!(
            reopened
                .load()
                .expect("completed detached write")
                .highest_approval_version,
            Some(11)
        );
    }
}
