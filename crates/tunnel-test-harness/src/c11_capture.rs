//! Private, opt-in C11 capture hooks used by the diagnostics adapter.
//!
//! Ordinary acceptance commands do not write these files. A C11 child receives a
//! private capture directory through C11_INNER_CAPTURE_DIR; the hooks then
//! persist only bounded, joined process streams, payload-free snapshots, and
//! the exact values which the fixture actually used. The parent adapter reads
//! the files before the temporary directory is removed and never includes raw
//! values in a receipt or error.

use std::{
    collections::BTreeSet,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    sync::{Mutex, OnceLock},
};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use crate::{HarnessError, Result};

const MANIFEST_FILE: &str = "sentinels.bin";
/// Marks a manifest record as retiring a previously recorded value.
pub(crate) const RETIRED_SENTINEL_FLAG: u8 = 0x80;
const MAX_MANIFEST_BYTES: u64 = 4 * 1024 * 1024;
const MAX_RECORD_BYTES: usize = 256 * 1024;
const MAX_SNAPSHOT_BYTES: usize = 1024 * 1024;

static CAPTURE_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
static STREAM_SEQUENCE: AtomicU64 = AtomicU64::new(1);
type RecordedSentinel = (PathBuf, u8, Vec<u8>);
static RECORDED_SENTINELS: OnceLock<Mutex<BTreeSet<RecordedSentinel>>> = OnceLock::new();

/// Return the opt-in capture directory, if the current process is a C11
/// child. Ordinary acceptance runs do not pay any I/O cost at all.
pub(crate) fn capture_dir() -> Option<PathBuf> {
    std::env::var_os("C11_INNER_CAPTURE_DIR").map(PathBuf::from)
}

/// Record one exact value which the fixture really used. The category name is
/// stable and never caller data; values are bounded and written with a binary
/// length prefix so arbitrary token/payload bytes remain unambiguous.
/// Retire a previously recorded sentinel.
///
/// A `private_endpoint` sentinel names a socket address, and once that socket
/// closes the operating system is free to hand the same port to anything else
/// in the same run, including a managed child's own ephemeral client socket.
/// The scanner compares exact bytes, so a recycled port would be reported as a
/// leak of an endpoint that no longer exists. Retiring the value when its
/// socket closes removes that false positive without weakening the scan for
/// any endpoint that is still live: a real disclosure happens while the
/// endpoint is in use, and remains recorded and matched.
///
/// The manifest is append-only, so this writes a tombstone the reader applies
/// in order.
pub(crate) fn retire_sentinel(kind: &'static str, value: &[u8]) -> Result<()> {
    record_manifest_entry(kind, value, true)
}

pub(crate) fn record_sentinel(kind: &'static str, value: &[u8]) -> Result<()> {
    record_manifest_entry(kind, value, false)
}

fn record_manifest_entry(kind: &'static str, value: &[u8], retired: bool) -> Result<()> {
    let Some(directory) = capture_dir() else {
        return Ok(());
    };
    let kind_code = match kind {
        "credential" => 1_u8,
        "application_payload" => 2,
        "filesystem_path" => 3,
        "private_endpoint" => 4,
        _ => {
            return Err(HarnessError::Process(
                "C11 sentinel category is not supported".into(),
            ));
        }
    };
    if value.is_empty() || value.len() > MAX_RECORD_BYTES {
        return Err(HarnessError::Process(
            "C11 sentinel value exceeded its bounded capture limit".into(),
        ));
    }
    with_capture_lock(|| {
        let recorded = RECORDED_SENTINELS.get_or_init(|| Mutex::new(BTreeSet::new()));
        let mut recorded = recorded
            .lock()
            .map_err(|_| HarnessError::Process("C11 sentinel set was poisoned".into()))?;
        let kind_code = if retired {
            kind_code | RETIRED_SENTINEL_FLAG
        } else {
            kind_code
        };
        let key = (directory.clone(), kind_code, value.to_vec());
        if recorded.contains(&key) {
            return Ok(());
        }
        let path = directory.join(MANIFEST_FILE);
        let existing = existing_regular_file_len(&path, "C11 sentinel manifest")?;
        let record_bytes = 1_u64
            .saturating_add(4)
            .saturating_add(u64::try_from(value.len()).unwrap_or(u64::MAX));
        if existing.saturating_add(record_bytes) > MAX_MANIFEST_BYTES {
            return Err(HarnessError::Process(
                "C11 sentinel manifest exceeded its bounded capture limit".into(),
            ));
        }
        let mut file = open_private_append(&path, "C11 sentinel manifest")?;
        let length = u32::try_from(value.len()).map_err(|_| {
            HarnessError::Process("C11 sentinel length exceeded its bounded limit".into())
        })?;
        file.write_all(&[kind_code])
            .and_then(|_| file.write_all(&length.to_le_bytes()))
            .and_then(|_| file.write_all(value))
            .map_err(|_| HarnessError::Process("C11 sentinel manifest write failed".into()))?;
        recorded.insert(key);
        Ok(())
    })
}

/// Persist both joined output streams from one ManagedProcess. Each process
/// gets a distinct prefix, so the parent can expose explicit inner roles
/// without guessing how many clients a scenario launched.
#[allow(clippy::too_many_arguments)]
pub(crate) fn record_process_streams(
    pid: Option<u32>,
    name: &str,
    stdout: &[u8],
    stderr: &[u8],
    stdout_overflow: bool,
    stderr_overflow: bool,
    stdout_read_error: bool,
    stderr_read_error: bool,
) -> Result<()> {
    let Some(directory) = capture_dir() else {
        return Ok(());
    };
    if stdout_overflow || stderr_overflow {
        return Err(HarnessError::Process(
            "C11 managed-process capture overflowed its bounded stream".into(),
        ));
    }
    if stdout_read_error || stderr_read_error {
        return Err(HarnessError::Process(
            "C11 managed-process capture read failed".into(),
        ));
    }
    if stdout.len() > MAX_SNAPSHOT_BYTES || stderr.len() > MAX_SNAPSHOT_BYTES {
        return Err(HarnessError::Process(
            "C11 managed-process capture exceeded its bounded limit".into(),
        ));
    }
    let safe_name = safe_component(name);
    let sequence = STREAM_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let prefix = format!("managed-{}-{sequence}-{safe_name}", pid.unwrap_or(0));
    with_capture_lock(|| {
        write_new(&directory.join(format!("{prefix}.stdout")), stdout)?;
        write_new(&directory.join(format!("{prefix}.stderr")), stderr)
    })
}

/// Append a payload-free snapshot emitted by a relay or proxy. The caller
/// supplies fields from an existing typed diagnostic object; this function
/// performs no formatting or redaction and therefore cannot manufacture
/// evidence by itself.
pub(crate) fn record_snapshot(role: &str, bytes: &[u8]) -> Result<()> {
    let Some(directory) = capture_dir() else {
        return Ok(());
    };
    if bytes.is_empty() || bytes.len() > MAX_SNAPSHOT_BYTES {
        return Err(HarnessError::Process(
            "C11 payload-free snapshot exceeded its bounded limit".into(),
        ));
    }
    let path = directory.join(format!("snapshot-{}.bin", safe_component(role)));
    with_capture_lock(|| {
        let existing = existing_regular_file_len(&path, "C11 snapshot")?;
        let length = u32::try_from(bytes.len()).map_err(|_| {
            HarnessError::Process("C11 snapshot length exceeded its bounded limit".into())
        })?;
        let frame_bytes = 4_u64.saturating_add(u64::from(length));
        if existing.saturating_add(frame_bytes) > MAX_SNAPSHOT_BYTES as u64 {
            return Err(HarnessError::Process(
                "C11 snapshot exceeded its aggregate bounded limit".into(),
            ));
        }
        let mut file = open_private_append(&path, "C11 snapshot")?;
        file.write_all(&length.to_le_bytes())
            .and_then(|_| file.write_all(bytes))
            .map_err(|_| HarnessError::Process("C11 snapshot write failed".into()))
    })
}

fn with_capture_lock<T>(operation: impl FnOnce() -> Result<T>) -> Result<T> {
    let lock = CAPTURE_LOCK.get_or_init(|| Mutex::new(()));
    let _guard = lock
        .lock()
        .map_err(|_| HarnessError::Process("C11 capture lock was poisoned".into()))?;
    operation()
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(path).map_err(|_| {
        HarnessError::Process("C11 managed-process stream could not be opened".into())
    })?;
    ensure_private_regular_file(&file, "C11 managed-process stream")?;
    file.write_all(bytes)
        .map_err(|_| HarnessError::Process("C11 managed-process stream write failed".into()))
}

fn existing_regular_file_len(path: &Path, label: &str) -> Result<u64> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(HarnessError::Process(format!(
                    "{label} was not a private regular file"
                )));
            }
            ensure_private_mode(&metadata, label)?;
            Ok(metadata.len())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(_) => Err(HarnessError::Process(format!(
            "{label} metadata could not be read"
        ))),
    }
}

fn open_private_append(path: &Path, label: &str) -> Result<std::fs::File> {
    let mut options = OpenOptions::new();
    options.create(true).append(true).write(true);
    #[cfg(unix)]
    options.mode(0o600);
    let file = options
        .open(path)
        .map_err(|_| HarnessError::Process(format!("{label} could not be opened")))?;
    ensure_private_regular_file(&file, label)?;
    Ok(file)
}

fn ensure_private_regular_file(file: &std::fs::File, label: &str) -> Result<()> {
    let metadata = file
        .metadata()
        .map_err(|_| HarnessError::Process(format!("{label} metadata could not be read")))?;
    if !metadata.is_file() {
        return Err(HarnessError::Process(format!(
            "{label} was not a regular file"
        )));
    }
    ensure_private_mode(&metadata, label)
}

fn ensure_private_mode(metadata: &fs::Metadata, label: &str) -> Result<()> {
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(HarnessError::Process(format!(
            "{label} permissions were not private"
        )));
    }
    let _ = metadata;
    Ok(())
}

fn safe_component(value: &str) -> String {
    let mut output = String::with_capacity(value.len().min(64));
    for byte in value.bytes().take(64) {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_') {
            output.push(byte as char);
        } else {
            output.push('_');
        }
    }
    if output.is_empty() {
        output.push_str("role");
    }
    output
}

#[cfg(unix)]
pub(crate) fn harden_capture_directory(path: &Path) -> Result<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|_| HarnessError::Process("C11 capture directory permissions failed".into()))?;
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| HarnessError::Process("C11 capture directory metadata failed".into()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(HarnessError::Process(
            "C11 capture directory was not private".into(),
        ));
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(HarnessError::Process(
            "C11 capture directory permissions were not private".into(),
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
pub(crate) fn harden_capture_directory(_path: &Path) -> Result<()> {
    Ok(())
}
