//! Restricted persistence for signed-membership version fences.
//!
//! [`tunnel_cluster::membership::MembershipVersionState`] intentionally
//! contains only high-water versions and leaves I/O to its caller.  This
//! module is the relay-side file boundary for that state.  The file is bound
//! to the stable deployment and relay identity, contains no signed records or
//! credentials, and is never treated as optional when opened in persisted
//! mode.

use std::{
    collections::BTreeMap,
    error::Error,
    fmt,
    fs::{self, File, Metadata, OpenOptions, TryLockError},
    io::{self, Read, Write},
    path::{Component, Path, PathBuf},
    sync::{Arc, Mutex},
};

use serde::{Deserialize, Serialize};
use tunnel_cluster::membership::{MAX_AUTHORIZED_NODES, MembershipVersionState};

/// Schema version for the local membership-fence envelope.
pub const MEMBERSHIP_VERSION_STATE_SCHEMA_VERSION: u16 = 1;
/// Maximum encoded size of a local state file.
pub const MAX_MEMBERSHIP_VERSION_STATE_BYTES: usize = 16 * 1024;
/// Maximum byte length of each identity or node-map key.
pub const MAX_MEMBERSHIP_VERSION_STATE_IDENTIFIER_BYTES: usize = 128;
/// File permissions used for state files on Unix platforms.
pub const MEMBERSHIP_VERSION_STATE_FILE_MODE: u32 = 0o600;

const MAX_STATE_PATH_BYTES: usize = 4 * 1024;
const MAX_TEMP_FILE_ATTEMPTS: usize = 8;
#[cfg(unix)]
const FILE_MODE_MASK: u32 = 0o777;

/// Stable identity to which a persisted version fence belongs.
///
/// `boot_id` is deliberately absent.  It identifies one process incarnation
/// and therefore must not invalidate a high-water fence after a normal relay
/// restart.  The runtime binds boot identity separately when it admits peers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MembershipVersionStateIdentity {
    pub deployment_id: String,
    pub deployment_incarnation: String,
    pub node_id: String,
}

impl MembershipVersionStateIdentity {
    /// Construct and validate a stable identity for a state file.
    pub fn new(
        deployment_id: impl Into<String>,
        deployment_incarnation: impl Into<String>,
        node_id: impl Into<String>,
    ) -> Result<Self, MembershipVersionStateStoreError> {
        let identity = Self {
            deployment_id: deployment_id.into(),
            deployment_incarnation: deployment_incarnation.into(),
            node_id: node_id.into(),
        };
        validate_identifier(&identity.deployment_id)?;
        validate_identifier(&identity.deployment_incarnation)?;
        validate_identifier(&identity.node_id)?;
        Ok(identity)
    }
}

/// Typed failures at the local membership-fence boundary.
///
/// Variants intentionally do not include paths, file contents, or operating
/// system error text.  State paths can be deployment-sensitive and the file
/// contents must never enter diagnostics.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MembershipVersionStateStoreError {
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
    StateRollback,
    Serialization,
    Io,
    DurableSync,
}

impl fmt::Display for MembershipVersionStateStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidIdentity => formatter.write_str("invalid membership state identity"),
            Self::InvalidPath => formatter.write_str("invalid membership state path"),
            Self::Missing => formatter.write_str("membership state is missing"),
            Self::AlreadyExists => formatter.write_str("membership state already exists"),
            Self::Busy => formatter.write_str("membership state is already open"),
            Self::SymlinkRejected => formatter.write_str("membership state symlink is rejected"),
            Self::PathChanged => formatter.write_str("membership state path changed during access"),
            Self::NotRegularFile => formatter.write_str("membership state is not a regular file"),
            Self::ParentDirectoryNotPrivate => {
                formatter.write_str("membership state parent directory is not private")
            }
            Self::InsecurePermissions => {
                formatter.write_str("membership state permissions are too broad")
            }
            Self::UnsupportedSchema(version) => {
                write!(formatter, "unsupported membership state schema {version}")
            }
            Self::IdentityMismatch => formatter.write_str("membership state identity mismatch"),
            Self::Oversized { size, max } => {
                write!(
                    formatter,
                    "membership state exceeds {max} bytes (received {size})"
                )
            }
            Self::Corrupt => formatter.write_str("membership state is corrupt"),
            Self::InvalidState => formatter.write_str("membership state is invalid"),
            Self::StateRollback => formatter.write_str("membership state would roll back a fence"),
            Self::Serialization => formatter.write_str("membership state serialization failed"),
            Self::Io => formatter.write_str("membership state I/O failed"),
            Self::DurableSync => formatter.write_str("membership state durable sync failed"),
        }
    }
}

impl Error for MembershipVersionStateStoreError {}

/// A bounded, identity-bound membership version state file.
///
/// `open` requires an existing valid file.  A new deployment must call
/// `bootstrap` explicitly; it creates an empty fence only when the target did
/// not already exist.  Callers should serialize writes through one store
/// instance (clones share an internal writer lock); each write is still
/// committed with a temporary file, fsync, and atomic rename.  The configured
/// parent directory must be an existing owner-only (`0700`) directory with no
/// symlink components.
#[derive(Clone, Debug)]
pub struct MembershipVersionStateStore {
    path: PathBuf,
    identity: MembershipVersionStateIdentity,
    _lock: Arc<File>,
    writer: Arc<Mutex<()>>,
}

impl MembershipVersionStateStore {
    /// Open an existing state file in persisted mode.
    ///
    /// Missing, malformed, mismatched, or broadly permissioned state is an
    /// error.  This method never creates an empty state implicitly.
    pub fn open(
        path: impl Into<PathBuf>,
        identity: MembershipVersionStateIdentity,
    ) -> Result<Self, MembershipVersionStateStoreError> {
        let store = Self::new(path, identity)?;
        store.load()?;
        Ok(store)
    }

    /// Explicitly create a new empty state file for a new deployment.
    ///
    /// Existing files are never replaced by bootstrap.  Operators must
    /// provide a fresh path (or perform an independently reviewed recovery
    /// procedure) when changing deployment incarnation.
    pub fn bootstrap(
        path: impl Into<PathBuf>,
        identity: MembershipVersionStateIdentity,
    ) -> Result<Self, MembershipVersionStateStoreError> {
        let store = Self::new(path, identity)?;
        let envelope = PersistedMembershipVersionState::empty(&store.identity);
        let bytes = encode_envelope(&envelope)?;
        store.create_initial(&bytes)?;
        Ok(store)
    }

    /// Return the configured state path for operator diagnostics.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Load the current high-water state after revalidating its identity and
    /// file restrictions.
    pub fn load(&self) -> Result<MembershipVersionState, MembershipVersionStateStoreError> {
        let bytes = read_bounded_file(&self.path)?;
        let envelope = decode_envelope(&bytes)?;
        self.validate_envelope(&envelope)?;
        Ok(envelope.state)
    }

    /// Persist a state whose fences are at least as high as the current file.
    ///
    /// A lower checkpoint or node version is rejected rather than replacing a
    /// durable fence.  The state is encoded canonically, written to a
    /// same-directory mode-0600 temporary file, synced, atomically renamed,
    /// and followed by a parent-directory sync on Unix.
    pub fn save(
        &self,
        state: &MembershipVersionState,
    ) -> Result<(), MembershipVersionStateStoreError> {
        let _writer = self
            .writer
            .lock()
            .map_err(|_| MembershipVersionStateStoreError::Io)?;
        validate_state(state)?;
        let current = self.load()?;
        if state_rolls_back(&current, state) {
            return Err(MembershipVersionStateStoreError::StateRollback);
        }
        let envelope = PersistedMembershipVersionState {
            schema_version: MEMBERSHIP_VERSION_STATE_SCHEMA_VERSION,
            deployment_id: self.identity.deployment_id.clone(),
            deployment_incarnation: self.identity.deployment_incarnation.clone(),
            node_id: self.identity.node_id.clone(),
            state: state.clone(),
        };
        let bytes = encode_envelope(&envelope)?;
        self.replace_atomically(&bytes)
    }

    fn new(
        path: impl Into<PathBuf>,
        identity: MembershipVersionStateIdentity,
    ) -> Result<Self, MembershipVersionStateStoreError> {
        let path = path.into();
        validate_path(&path)?;
        validate_identifier(&identity.deployment_id)?;
        validate_identifier(&identity.deployment_incarnation)?;
        validate_identifier(&identity.node_id)?;
        let lock = Arc::new(open_lock_file(&lock_path(&path)?)?);
        Ok(Self {
            path,
            identity,
            _lock: lock,
            writer: Arc::new(Mutex::new(())),
        })
    }

    fn validate_envelope(
        &self,
        envelope: &PersistedMembershipVersionState,
    ) -> Result<(), MembershipVersionStateStoreError> {
        if envelope.schema_version != MEMBERSHIP_VERSION_STATE_SCHEMA_VERSION {
            return Err(MembershipVersionStateStoreError::UnsupportedSchema(
                envelope.schema_version,
            ));
        }
        if envelope.deployment_id != self.identity.deployment_id
            || envelope.deployment_incarnation != self.identity.deployment_incarnation
            || envelope.node_id != self.identity.node_id
        {
            return Err(MembershipVersionStateStoreError::IdentityMismatch);
        }
        validate_identifier(&envelope.deployment_id)?;
        validate_identifier(&envelope.deployment_incarnation)?;
        validate_identifier(&envelope.node_id)?;
        validate_state(&envelope.state)
    }

    fn create_initial(&self, bytes: &[u8]) -> Result<(), MembershipVersionStateStoreError> {
        let parent = parent_directory(&self.path);
        let parent_metadata = ensure_parent_directory(parent)?;
        match fs::symlink_metadata(&self.path) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    return Err(MembershipVersionStateStoreError::SymlinkRejected);
                }
                return Err(MembershipVersionStateStoreError::AlreadyExists);
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(_) => return Err(MembershipVersionStateStoreError::Io),
        }

        let temp = self.write_temporary(bytes)?;
        let result = match fs::hard_link(&temp, &self.path) {
            Ok(()) => sync_parent_directory(parent, &parent_metadata),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                Err(MembershipVersionStateStoreError::AlreadyExists)
            }
            Err(_) => Err(MembershipVersionStateStoreError::Io),
        };
        let _ = fs::remove_file(&temp);
        result
    }

    fn replace_atomically(&self, bytes: &[u8]) -> Result<(), MembershipVersionStateStoreError> {
        let parent = parent_directory(&self.path);
        let parent_metadata = ensure_parent_directory(parent)?;
        let temp = self.write_temporary(bytes)?;
        let result = match fs::rename(&temp, &self.path) {
            Ok(()) => sync_parent_directory(parent, &parent_metadata),
            Err(_) => Err(MembershipVersionStateStoreError::Io),
        };
        if result.is_err() {
            let _ = fs::remove_file(&temp);
        }
        result
    }

    fn write_temporary(&self, bytes: &[u8]) -> Result<PathBuf, MembershipVersionStateStoreError> {
        let parent = parent_directory(&self.path);
        let _parent_metadata = ensure_parent_directory(parent)?;
        for _ in 0..MAX_TEMP_FILE_ATTEMPTS {
            let temp_name = format!(
                ".{}.tmp-{}",
                self.path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .ok_or(MembershipVersionStateStoreError::InvalidPath)?,
                uuid::Uuid::new_v4().simple()
            );
            let temp = parent.join(temp_name);
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(MEMBERSHIP_VERSION_STATE_FILE_MODE);
            }
            let mut file = match options.open(&temp) {
                Ok(file) => file,
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(_) => return Err(MembershipVersionStateStoreError::Io),
            };
            let result = (|| {
                file.write_all(bytes)
                    .map_err(|_| MembershipVersionStateStoreError::Io)?;
                file.sync_all()
                    .map_err(|_| MembershipVersionStateStoreError::DurableSync)
            })();
            drop(file);
            if let Err(error) = result {
                let _ = fs::remove_file(&temp);
                return Err(error);
            }
            return Ok(temp);
        }
        Err(MembershipVersionStateStoreError::Io)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedMembershipVersionState {
    schema_version: u16,
    deployment_id: String,
    deployment_incarnation: String,
    node_id: String,
    state: MembershipVersionState,
}

impl PersistedMembershipVersionState {
    fn empty(identity: &MembershipVersionStateIdentity) -> Self {
        Self {
            schema_version: MEMBERSHIP_VERSION_STATE_SCHEMA_VERSION,
            deployment_id: identity.deployment_id.clone(),
            deployment_incarnation: identity.deployment_incarnation.clone(),
            node_id: identity.node_id.clone(),
            state: MembershipVersionState {
                checkpoint_version: None,
                node_versions: BTreeMap::new(),
            },
        }
    }
}

fn validate_identifier(value: &str) -> Result<(), MembershipVersionStateStoreError> {
    if value.trim().is_empty()
        || value.len() > MAX_MEMBERSHIP_VERSION_STATE_IDENTIFIER_BYTES
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err(MembershipVersionStateStoreError::InvalidIdentity);
    }
    Ok(())
}

fn validate_path(path: &Path) -> Result<(), MembershipVersionStateStoreError> {
    let value = path
        .to_str()
        .ok_or(MembershipVersionStateStoreError::InvalidPath)?;
    if value.is_empty()
        || value.len() > MAX_STATE_PATH_BYTES
        || value.bytes().any(|byte| byte.is_ascii_control())
        || path.file_name().is_none()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(MembershipVersionStateStoreError::InvalidPath);
    }
    Ok(())
}

fn validate_state(state: &MembershipVersionState) -> Result<(), MembershipVersionStateStoreError> {
    if state.node_versions.len() > MAX_AUTHORIZED_NODES
        || state.checkpoint_version == Some(0)
        || state.node_versions.values().any(|version| *version == 0)
    {
        return Err(MembershipVersionStateStoreError::InvalidState);
    }
    for node_id in state.node_versions.keys() {
        validate_identifier(node_id)?;
    }
    Ok(())
}

fn state_rolls_back(current: &MembershipVersionState, next: &MembershipVersionState) -> bool {
    if current
        .checkpoint_version
        .zip(next.checkpoint_version)
        .is_some_and(|(current, next)| next < current)
        || current.checkpoint_version.is_some() && next.checkpoint_version.is_none()
    {
        return true;
    }
    current
        .node_versions
        .iter()
        .any(|(node_id, current_version)| {
            next.node_versions
                .get(node_id)
                .is_none_or(|next_version| next_version < current_version)
        })
}

fn encode_envelope(
    envelope: &PersistedMembershipVersionState,
) -> Result<Vec<u8>, MembershipVersionStateStoreError> {
    let bytes = serde_json::to_vec(envelope)
        .map_err(|_| MembershipVersionStateStoreError::Serialization)?;
    if bytes.len() > MAX_MEMBERSHIP_VERSION_STATE_BYTES {
        return Err(MembershipVersionStateStoreError::Oversized {
            size: bytes.len(),
            max: MAX_MEMBERSHIP_VERSION_STATE_BYTES,
        });
    }
    Ok(bytes)
}

fn decode_envelope(
    bytes: &[u8],
) -> Result<PersistedMembershipVersionState, MembershipVersionStateStoreError> {
    if bytes.len() > MAX_MEMBERSHIP_VERSION_STATE_BYTES {
        return Err(MembershipVersionStateStoreError::Oversized {
            size: bytes.len(),
            max: MAX_MEMBERSHIP_VERSION_STATE_BYTES,
        });
    }
    let envelope = serde_json::from_slice::<PersistedMembershipVersionState>(bytes)
        .map_err(|_| MembershipVersionStateStoreError::Corrupt)?;
    let canonical = encode_envelope(&envelope)?;
    if canonical != bytes {
        return Err(MembershipVersionStateStoreError::Corrupt);
    }
    Ok(envelope)
}

fn read_bounded_file(path: &Path) -> Result<Vec<u8>, MembershipVersionStateStoreError> {
    let parent = parent_directory(path);
    let parent_metadata = ensure_parent_directory(parent)?;
    let path_metadata = fs::symlink_metadata(path).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            MembershipVersionStateStoreError::Missing
        } else {
            MembershipVersionStateStoreError::Io
        }
    })?;
    validate_file_metadata(&path_metadata)?;
    let file = open_readonly_nofollow(path).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            MembershipVersionStateStoreError::Missing
        } else {
            MembershipVersionStateStoreError::Io
        }
    })?;
    let opened_metadata = file
        .metadata()
        .map_err(|_| MembershipVersionStateStoreError::Io)?;
    validate_file_metadata(&opened_metadata)?;
    if !same_file_metadata(&path_metadata, &opened_metadata) {
        return Err(MembershipVersionStateStoreError::PathChanged);
    }
    let current_path_metadata = fs::symlink_metadata(path).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            MembershipVersionStateStoreError::Missing
        } else {
            MembershipVersionStateStoreError::Io
        }
    })?;
    if current_path_metadata.file_type().is_symlink() {
        return Err(MembershipVersionStateStoreError::SymlinkRejected);
    }
    if !same_file_metadata(&path_metadata, &current_path_metadata) {
        return Err(MembershipVersionStateStoreError::PathChanged);
    }
    let current_parent_metadata = ensure_parent_directory(parent)?;
    if !same_file_metadata(&parent_metadata, &current_parent_metadata) {
        return Err(MembershipVersionStateStoreError::PathChanged);
    }
    let mut bytes = Vec::with_capacity(MAX_MEMBERSHIP_VERSION_STATE_BYTES.min(4096));
    let mut bounded = file.take((MAX_MEMBERSHIP_VERSION_STATE_BYTES + 1) as u64);
    bounded
        .read_to_end(&mut bytes)
        .map_err(|_| MembershipVersionStateStoreError::Io)?;
    if bytes.len() > MAX_MEMBERSHIP_VERSION_STATE_BYTES {
        return Err(MembershipVersionStateStoreError::Oversized {
            size: bytes.len(),
            max: MAX_MEMBERSHIP_VERSION_STATE_BYTES,
        });
    }
    Ok(bytes)
}

fn open_readonly_nofollow(path: &Path) -> io::Result<File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut options = OpenOptions::new();
        options.read(true);
        options.custom_flags(libc::O_NOFOLLOW);
        options.open(path)
    }
    #[cfg(not(unix))]
    {
        File::open(path)
    }
}

fn lock_path(path: &Path) -> Result<PathBuf, MembershipVersionStateStoreError> {
    let parent = parent_directory(path);
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(MembershipVersionStateStoreError::InvalidPath)?;
    let lock_path = parent.join(format!(".{file_name}.lock"));
    validate_path(&lock_path)?;
    Ok(lock_path)
}

fn open_lock_file(path: &Path) -> Result<File, MembershipVersionStateStoreError> {
    let parent = parent_directory(path);
    let parent_metadata = ensure_parent_directory(parent)?;
    let previous_metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => {
            validate_file_metadata(&metadata)?;
            if metadata.len() != 0 {
                return Err(MembershipVersionStateStoreError::Corrupt);
            }
            Some(metadata)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(_) => return Err(MembershipVersionStateStoreError::Io),
    };

    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
        options.mode(MEMBERSHIP_VERSION_STATE_FILE_MODE);
    }
    let file = options.open(path).map_err(|error| {
        if error.kind() == io::ErrorKind::WouldBlock {
            MembershipVersionStateStoreError::Busy
        } else {
            MembershipVersionStateStoreError::Io
        }
    })?;
    let opened_metadata = file
        .metadata()
        .map_err(|_| MembershipVersionStateStoreError::Io)?;
    validate_file_metadata(&opened_metadata)?;
    if opened_metadata.len() != 0 {
        return Err(MembershipVersionStateStoreError::Corrupt);
    }
    if previous_metadata
        .as_ref()
        .is_some_and(|metadata| !same_file_metadata(metadata, &opened_metadata))
    {
        return Err(MembershipVersionStateStoreError::PathChanged);
    }
    let current_metadata = fs::symlink_metadata(path).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            MembershipVersionStateStoreError::Missing
        } else {
            MembershipVersionStateStoreError::Io
        }
    })?;
    if current_metadata.file_type().is_symlink()
        || !same_file_metadata(&current_metadata, &opened_metadata)
    {
        return Err(MembershipVersionStateStoreError::PathChanged);
    }
    let current_parent_metadata = ensure_parent_directory(parent)?;
    if !same_file_metadata(&parent_metadata, &current_parent_metadata) {
        return Err(MembershipVersionStateStoreError::PathChanged);
    }

    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(TryLockError::WouldBlock) => Err(MembershipVersionStateStoreError::Busy),
        Err(TryLockError::Error(_)) => Err(MembershipVersionStateStoreError::Io),
    }
}

fn validate_file_metadata(metadata: &Metadata) -> Result<(), MembershipVersionStateStoreError> {
    if metadata.file_type().is_symlink() {
        return Err(MembershipVersionStateStoreError::SymlinkRejected);
    }
    if !metadata.file_type().is_file() {
        return Err(MembershipVersionStateStoreError::NotRegularFile);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode() & FILE_MODE_MASK;
        if mode & 0o600 != MEMBERSHIP_VERSION_STATE_FILE_MODE || mode & 0o077 != 0 {
            return Err(MembershipVersionStateStoreError::InsecurePermissions);
        }
    }
    Ok(())
}

fn ensure_parent_directory(path: &Path) -> Result<Metadata, MembershipVersionStateStoreError> {
    ensure_no_symlink_components(path)?;
    let metadata = fs::symlink_metadata(path).map_err(|_| MembershipVersionStateStoreError::Io)?;
    if metadata.file_type().is_symlink() {
        return Err(MembershipVersionStateStoreError::SymlinkRejected);
    }
    if !metadata.is_dir() {
        return Err(MembershipVersionStateStoreError::NotRegularFile);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode() & 0o7777;
        if mode != 0o700 {
            return Err(MembershipVersionStateStoreError::ParentDirectoryNotPrivate);
        }
    }
    Ok(metadata)
}

fn ensure_no_symlink_components(path: &Path) -> Result<(), MembershipVersionStateStoreError> {
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
            Component::ParentDir => return Err(MembershipVersionStateStoreError::InvalidPath),
            Component::Normal(name) => current.push(name),
        }
        let metadata =
            fs::symlink_metadata(&current).map_err(|_| MembershipVersionStateStoreError::Io)?;
        if metadata.file_type().is_symlink() {
            return Err(MembershipVersionStateStoreError::SymlinkRejected);
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
    // `volume_serial_number` and `file_index` -- the Windows `(dev, ino)` --
    // are unstable (`windows_by_handle`), so the relay did not compile for
    // `x86_64-pc-windows-msvc` at all. On stable Rust a `Metadata` offers only
    // these, which a replacement made between the two reads would have to
    // match exactly, creation time included. That is weaker than a file
    // index, and it is the most `Metadata` can say on this host.
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        first.file_attributes() == second.file_attributes()
            && first.creation_time() == second.creation_time()
            && first.last_write_time() == second.last_write_time()
            && first.file_size() == second.file_size()
    }
    #[cfg(not(any(unix, windows)))]
    {
        first.is_file() == second.is_file()
            && first.is_dir() == second.is_dir()
            && first.len() == second.len()
    }
}

fn parent_directory(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn sync_parent_directory(
    path: &Path,
    expected: &Metadata,
) -> Result<(), MembershipVersionStateStoreError> {
    let current = ensure_parent_directory(path)?;
    if !same_file_metadata(expected, &current) {
        return Err(MembershipVersionStateStoreError::PathChanged);
    }
    #[cfg(unix)]
    {
        let directory =
            open_readonly_nofollow(path).map_err(|_| MembershipVersionStateStoreError::Io)?;
        let opened = directory
            .metadata()
            .map_err(|_| MembershipVersionStateStoreError::Io)?;
        if !same_file_metadata(expected, &opened) {
            return Err(MembershipVersionStateStoreError::PathChanged);
        }
        directory
            .sync_all()
            .map_err(|_| MembershipVersionStateStoreError::DurableSync)?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    let after = ensure_parent_directory(path)?;
    if !same_file_metadata(expected, &after) {
        return Err(MembershipVersionStateStoreError::PathChanged);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        sync::atomic::{AtomicU64, Ordering},
    };

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let counter = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "agent-tunnel-membership-state-{}-{counter}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("create test directory");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                    .expect("private test directory");
            }
            Self(fs::canonicalize(path).expect("canonical test directory"))
        }

        fn state_path(&self) -> PathBuf {
            self.0.join("membership-state.json")
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn identity() -> MembershipVersionStateIdentity {
        MembershipVersionStateIdentity::new("deployment-a", "incarnation-a", "relay-a")
            .expect("identity")
    }

    fn state(checkpoint_version: u64, node_versions: &[(&str, u64)]) -> MembershipVersionState {
        MembershipVersionState {
            checkpoint_version: Some(checkpoint_version),
            node_versions: node_versions
                .iter()
                .map(|(node_id, version)| ((*node_id).to_owned(), *version))
                .collect(),
        }
    }

    #[test]
    fn bootstrap_and_persist_round_trip_only_version_fences() {
        let directory = TestDirectory::new();
        let store = MembershipVersionStateStore::bootstrap(directory.state_path(), identity())
            .expect("bootstrap");
        assert_eq!(
            store.load().expect("empty state"),
            MembershipVersionState {
                checkpoint_version: None,
                node_versions: BTreeMap::new(),
            }
        );
        let next = state(7, &[("relay-a", 4), ("relay-b", 9)]);
        store.save(&next).expect("persist");
        assert_eq!(store.load().expect("saved state"), next);
        let temporary_files = fs::read_dir(directory.0.as_path())
            .expect("state directory")
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".membership-state.json.tmp-")
            })
            .count();
        assert_eq!(temporary_files, 0);
        assert!(
            store
                .path()
                .file_name()
                .is_some_and(|name| name == "membership-state.json")
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(store.path())
                .expect("metadata")
                .permissions()
                .mode()
                & FILE_MODE_MASK;
            assert_eq!(mode, MEMBERSHIP_VERSION_STATE_FILE_MODE);
        }
    }

    #[test]
    fn persisted_open_fails_closed_when_state_is_missing() {
        let directory = TestDirectory::new();
        let error = MembershipVersionStateStore::open(directory.state_path(), identity())
            .expect_err("missing state must not bootstrap");
        assert_eq!(error, MembershipVersionStateStoreError::Missing);
    }

    #[test]
    fn sidecar_lock_blocks_second_open_until_owner_drops() {
        let directory = TestDirectory::new();
        let path = directory.state_path();
        let store =
            MembershipVersionStateStore::bootstrap(path.clone(), identity()).expect("bootstrap");
        let second = MembershipVersionStateStore::open(path.clone(), identity())
            .expect_err("second owner must be fenced");
        assert_eq!(second, MembershipVersionStateStoreError::Busy);
        let lock = path
            .parent()
            .expect("parent")
            .join(".membership-state.json.lock");
        assert!(lock.is_file());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&lock)
                    .expect("lock metadata")
                    .permissions()
                    .mode()
                    & FILE_MODE_MASK,
                MEMBERSHIP_VERSION_STATE_FILE_MODE
            );
        }

        drop(store);
        assert!(lock.is_file(), "sidecar remains after owner drops");
        let reopened = MembershipVersionStateStore::open(path, identity())
            .expect("lock becomes available after owner drops");
        assert_eq!(
            reopened.load().expect("state"),
            MembershipVersionState {
                checkpoint_version: None,
                node_versions: BTreeMap::new(),
            }
        );
    }

    #[test]
    fn bootstrap_never_overwrites_existing_state() {
        let directory = TestDirectory::new();
        let path = directory.state_path();
        let store =
            MembershipVersionStateStore::bootstrap(path.clone(), identity()).expect("bootstrap");
        let next = state(3, &[("relay-a", 2)]);
        store.save(&next).expect("persist");
        drop(store);
        let error = MembershipVersionStateStore::bootstrap(path, identity())
            .expect_err("bootstrap must be create-only");
        assert_eq!(error, MembershipVersionStateStoreError::AlreadyExists);
        let store = MembershipVersionStateStore::open(directory.state_path(), identity())
            .expect("state remains");
        assert_eq!(store.load().expect("state remains"), next);
    }

    #[test]
    fn identity_binding_rejects_deployment_incarnation_and_node_changes() {
        let directory = TestDirectory::new();
        let path = directory.state_path();
        let store =
            MembershipVersionStateStore::bootstrap(path.clone(), identity()).expect("bootstrap");
        store.save(&state(4, &[("relay-a", 2)])).expect("persist");
        drop(store);
        for mismatched in [
            MembershipVersionStateIdentity::new("deployment-b", "incarnation-a", "relay-a"),
            MembershipVersionStateIdentity::new("deployment-a", "incarnation-b", "relay-a"),
            MembershipVersionStateIdentity::new("deployment-a", "incarnation-a", "relay-b"),
        ] {
            let mismatched = mismatched.expect("identity");
            let error = MembershipVersionStateStore::open(path.clone(), mismatched)
                .expect_err("identity must be bound");
            assert_eq!(error, MembershipVersionStateStoreError::IdentityMismatch);
        }
    }

    #[test]
    fn corrupt_unknown_and_noncanonical_files_fail_closed() {
        let directory = TestDirectory::new();
        let path = directory.state_path();
        let store =
            MembershipVersionStateStore::bootstrap(path.clone(), identity()).expect("bootstrap");
        fs::write(&path, br#"{"#).expect("corrupt file");
        assert_eq!(
            store.load().expect_err("corrupt"),
            MembershipVersionStateStoreError::Corrupt
        );

        let envelope = PersistedMembershipVersionState::empty(&identity());
        let mut value = serde_json::to_value(envelope).expect("value");
        value
            .as_object_mut()
            .expect("object")
            .insert("unexpected".into(), serde_json::Value::Null);
        fs::write(&path, serde_json::to_vec(&value).expect("json")).expect("unknown field");
        assert_eq!(
            store.load().expect_err("unknown field"),
            MembershipVersionStateStoreError::Corrupt
        );

        let canonical = serde_json::to_vec(&PersistedMembershipVersionState::empty(&identity()))
            .expect("canonical");
        let mut noncanonical = Vec::with_capacity(canonical.len() + 1);
        noncanonical.extend_from_slice(b" ");
        noncanonical.extend_from_slice(&canonical);
        fs::write(&path, noncanonical).expect("noncanonical");
        assert_eq!(
            store.load().expect_err("noncanonical"),
            MembershipVersionStateStoreError::Corrupt
        );
    }

    #[test]
    fn schema_and_version_fences_are_validated_after_decoding() {
        let directory = TestDirectory::new();
        let path = directory.state_path();
        let store =
            MembershipVersionStateStore::bootstrap(path.clone(), identity()).expect("bootstrap");

        let mut envelope = PersistedMembershipVersionState::empty(&identity());
        envelope.schema_version = MEMBERSHIP_VERSION_STATE_SCHEMA_VERSION + 1;
        fs::write(&path, serde_json::to_vec(&envelope).expect("schema json"))
            .expect("schema state");
        assert_eq!(
            store.load().expect_err("unsupported schema"),
            MembershipVersionStateStoreError::UnsupportedSchema(
                MEMBERSHIP_VERSION_STATE_SCHEMA_VERSION + 1
            )
        );

        fs::remove_file(&path).expect("remove schema state");
        drop(store);
        let store =
            MembershipVersionStateStore::bootstrap(path.clone(), identity()).expect("re-bootstrap");
        let mut envelope = PersistedMembershipVersionState::empty(&identity());
        envelope.state.checkpoint_version = Some(0);
        fs::write(&path, serde_json::to_vec(&envelope).expect("zero json")).expect("zero state");
        assert_eq!(
            store.load().expect_err("zero checkpoint"),
            MembershipVersionStateStoreError::InvalidState
        );

        fs::remove_file(&path).expect("remove zero state");
        drop(store);
        let store =
            MembershipVersionStateStore::bootstrap(path.clone(), identity()).expect("re-bootstrap");
        let mut envelope = PersistedMembershipVersionState::empty(&identity());
        envelope.state.node_versions.insert("relay-a".into(), 0);
        fs::write(
            &path,
            serde_json::to_vec(&envelope).expect("zero node json"),
        )
        .expect("zero node state");
        assert_eq!(
            store.load().expect_err("zero node version"),
            MembershipVersionStateStoreError::InvalidState
        );
    }

    #[test]
    fn oversized_and_invalid_states_are_bounded() {
        let directory = TestDirectory::new();
        let path = directory.state_path();
        let store =
            MembershipVersionStateStore::bootstrap(path.clone(), identity()).expect("bootstrap");
        fs::write(&path, vec![b'x'; MAX_MEMBERSHIP_VERSION_STATE_BYTES + 1])
            .expect("oversized file");
        assert_eq!(
            store.load().expect_err("oversized"),
            MembershipVersionStateStoreError::Oversized {
                size: MAX_MEMBERSHIP_VERSION_STATE_BYTES + 1,
                max: MAX_MEMBERSHIP_VERSION_STATE_BYTES,
            }
        );

        fs::remove_file(&path).expect("remove oversized state");
        drop(store);
        let store = MembershipVersionStateStore::bootstrap(path, identity())
            .expect("re-bootstrap after test replacement");
        assert_eq!(
            store.save(&MembershipVersionState {
                checkpoint_version: Some(0),
                node_versions: BTreeMap::new(),
            }),
            Err(MembershipVersionStateStoreError::InvalidState)
        );
        let too_many = (0..=MAX_AUTHORIZED_NODES)
            .map(|index| (format!("relay-{index}"), 1))
            .collect();
        assert_eq!(
            store.save(&MembershipVersionState {
                checkpoint_version: None,
                node_versions: too_many,
            }),
            Err(MembershipVersionStateStoreError::InvalidState)
        );
    }

    #[test]
    fn lower_fences_cannot_replace_durable_high_water() {
        let directory = TestDirectory::new();
        let store = MembershipVersionStateStore::bootstrap(directory.state_path(), identity())
            .expect("bootstrap");
        let current = state(8, &[("relay-a", 5), ("relay-b", 3)]);
        store.save(&current).expect("persist current");
        assert_eq!(
            store.save(&state(7, &[("relay-a", 5), ("relay-b", 3)])),
            Err(MembershipVersionStateStoreError::StateRollback)
        );
        assert_eq!(
            store.save(&state(8, &[("relay-a", 4), ("relay-b", 3)])),
            Err(MembershipVersionStateStoreError::StateRollback)
        );
        assert_eq!(store.load().expect("current remains"), current);
    }

    #[test]
    fn cloned_stores_serialize_writes_and_preserve_high_water() {
        let directory = TestDirectory::new();
        let store = MembershipVersionStateStore::bootstrap(directory.state_path(), identity())
            .expect("bootstrap");
        let high_store = store.clone();
        let low_store = store.clone();
        let high_state = state(9, &[("relay-a", 9)]);
        let low_state = state(3, &[("relay-a", 3)]);
        let high = std::thread::spawn(move || high_store.save(&high_state));
        let low = std::thread::spawn(move || low_store.save(&low_state));
        let high_result = high.join().expect("high writer");
        let low_result = low.join().expect("low writer");
        assert!(
            high_result.is_ok()
                || matches!(
                    high_result,
                    Err(MembershipVersionStateStoreError::StateRollback)
                )
        );
        assert!(
            low_result.is_ok()
                || matches!(
                    low_result,
                    Err(MembershipVersionStateStoreError::StateRollback)
                )
        );
        assert_eq!(
            store.load().expect("high-water state").checkpoint_version,
            Some(9)
        );
    }

    #[cfg(unix)]
    #[test]
    fn broad_permissions_fail_closed() {
        use std::os::unix::fs::PermissionsExt;

        let directory = TestDirectory::new();
        let store = MembershipVersionStateStore::bootstrap(directory.state_path(), identity())
            .expect("bootstrap");
        let mut permissions = fs::metadata(store.path()).expect("metadata").permissions();
        permissions.set_mode(0o644);
        fs::set_permissions(store.path(), permissions).expect("permissions");
        assert_eq!(
            store.load().expect_err("broad permissions"),
            MembershipVersionStateStoreError::InsecurePermissions
        );
    }

    #[cfg(unix)]
    #[test]
    fn parent_directory_must_be_private_and_symlink_free() {
        use std::os::unix::fs::PermissionsExt;

        let directory = TestDirectory::new();
        let public_parent = directory.0.join("public");
        fs::create_dir(&public_parent).expect("public parent");
        fs::set_permissions(&public_parent, fs::Permissions::from_mode(0o755))
            .expect("public permissions");
        let public_path = public_parent.join("membership-state.json");
        assert_eq!(
            MembershipVersionStateStore::bootstrap(public_path, identity())
                .expect_err("mutable parent"),
            MembershipVersionStateStoreError::ParentDirectoryNotPrivate
        );

        let alias = directory.0.join("alias");
        std::os::unix::fs::symlink(&directory.0, &alias).expect("parent symlink");
        let symlink_path = alias.join("membership-state.json");
        assert_eq!(
            MembershipVersionStateStore::bootstrap(symlink_path, identity())
                .expect_err("symlink parent"),
            MembershipVersionStateStoreError::SymlinkRejected
        );
    }

    #[test]
    fn invalid_identity_and_paths_are_rejected() {
        assert_eq!(
            MembershipVersionStateIdentity::new("deployment", "incarnation", " relay"),
            Err(MembershipVersionStateStoreError::InvalidIdentity)
        );
        let identity = identity();
        assert!(matches!(
            MembershipVersionStateStore::bootstrap("../state.json", identity),
            Err(MembershipVersionStateStoreError::InvalidPath)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn symlink_state_is_rejected() {
        let directory = TestDirectory::new();
        let target = directory.0.join("target.json");
        let path = directory.state_path();
        let target_store =
            MembershipVersionStateStore::bootstrap(target, identity()).expect("target bootstrap");
        std::os::unix::fs::symlink(target_store.path(), &path).expect("symlink");
        let error = MembershipVersionStateStore::open(path, identity())
            .expect_err("symlink must fail closed");
        assert_eq!(error, MembershipVersionStateStoreError::SymlinkRejected);
    }
}
