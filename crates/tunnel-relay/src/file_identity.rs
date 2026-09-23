//! File identity for the relay's private state files.
//!
//! The membership-version store, the recovery fence store and the Redis
//! credential loader each check that the file or directory they opened is the
//! one they inspected by name, and that the name still refers to it
//! afterwards. That check needs a real file identity.
//!
//! * **Unix:** `(st_dev, st_ino)` from the same `stat` that supplied the
//!   metadata, exactly as before this module existed.
//! * **Windows:** the volume serial number and the 64-bit file index that
//!   `GetFileInformationByHandle` reports, read through `winapi-util`, which
//!   has no unsafe code at this call site. A path is opened for this with
//!   `FILE_FLAG_BACKUP_SEMANTICS`, which directories need, and
//!   `FILE_FLAG_OPEN_REPARSE_POINT`, so a link is identified as itself and not
//!   followed. `std`'s own `volume_serial_number` and `file_index` are
//!   unstable (`windows_by_handle`), and a comparison of timestamps, size and
//!   attributes is not an identity: a directory's last-write time moves on
//!   every create and rename inside it, and every one of those fields can be
//!   set by the file's owner (task row M6-C80).

use std::{fs, io, ops::Deref, path::Path};

/// A file's metadata together with an identity taken from the same object.
#[derive(Debug)]
pub(crate) struct Observed {
    metadata: fs::Metadata,
    identity: FileIdentity,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentity {
    volume: u64,
    index: u64,
}

impl Observed {
    /// Observe `path` without following a final symbolic link.
    pub(crate) fn path_no_follow(path: &Path) -> io::Result<Self> {
        let metadata = fs::symlink_metadata(path)?;
        let identity = identity_of_path(path, &metadata)?;
        Ok(Self { metadata, identity })
    }

    /// Observe an open file or directory handle.
    pub(crate) fn file(file: &fs::File) -> io::Result<Self> {
        let metadata = file.metadata()?;
        let identity = identity_of_file(file, &metadata)?;
        Ok(Self { metadata, identity })
    }

    /// Whether both observations are of the same file.
    pub(crate) fn same_file(&self, other: &Self) -> bool {
        self.identity == other.identity
    }
}

impl Deref for Observed {
    type Target = fs::Metadata;

    fn deref(&self) -> &fs::Metadata {
        &self.metadata
    }
}

#[cfg(unix)]
fn identity_of_path(_path: &Path, metadata: &fs::Metadata) -> io::Result<FileIdentity> {
    Ok(unix_identity(metadata))
}

#[cfg(unix)]
fn identity_of_file(_file: &fs::File, metadata: &fs::Metadata) -> io::Result<FileIdentity> {
    Ok(unix_identity(metadata))
}

#[cfg(unix)]
fn unix_identity(metadata: &fs::Metadata) -> FileIdentity {
    use std::os::unix::fs::MetadataExt;
    FileIdentity {
        volume: metadata.dev(),
        index: metadata.ino(),
    }
}

#[cfg(windows)]
fn identity_of_path(path: &Path, _metadata: &fs::Metadata) -> io::Result<FileIdentity> {
    use std::os::windows::fs::OpenOptionsExt;
    // FILE_READ_ATTRIBUTES: enough for GetFileInformationByHandle, and
    // grantable where read access is not.
    const FILE_READ_ATTRIBUTES: u32 = 0x0080;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    let file = fs::OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    windows_identity(&file)
}

#[cfg(windows)]
fn identity_of_file(file: &fs::File, _metadata: &fs::Metadata) -> io::Result<FileIdentity> {
    windows_identity(file)
}

#[cfg(windows)]
fn windows_identity(file: &fs::File) -> io::Result<FileIdentity> {
    let information = winapi_util::file::information(file)?;
    Ok(FileIdentity {
        volume: information.volume_serial_number(),
        index: information.file_index(),
    })
}

#[cfg(not(any(unix, windows)))]
fn identity_of_path(_path: &Path, _metadata: &fs::Metadata) -> io::Result<FileIdentity> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "file identity is not available on this host",
    ))
}

#[cfg(not(any(unix, windows)))]
fn identity_of_file(_file: &fs::File, _metadata: &fs::Metadata) -> io::Result<FileIdentity> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "file identity is not available on this host",
    ))
}

#[cfg(test)]
mod tests {
    use super::Observed;

    /// A fresh directory under the system temporary directory, removed on drop.
    struct TempDir(std::path::PathBuf);

    impl TempDir {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "tunnel-relay-file-identity-{label}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |elapsed| elapsed.as_nanos())
            ));
            std::fs::create_dir(&path).expect("create temporary directory");
            Self(path)
        }

        fn path(&self) -> &std::path::Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// Creating and renaming inside a directory must not change its
    /// identity: that is the case the timestamp comparison got wrong on
    /// Windows, and it runs on every host.
    #[test]
    fn a_directory_keeps_its_identity_across_a_create_and_a_rename_inside_it() {
        let directory = TempDir::new("directory");
        let before = Observed::path_no_follow(directory.path()).expect("observe directory");
        std::fs::write(directory.path().join("a"), b"x").expect("create");
        std::fs::rename(directory.path().join("a"), directory.path().join("b")).expect("rename");
        let after = Observed::path_no_follow(directory.path()).expect("observe directory");
        assert!(before.same_file(&after));
    }

    #[test]
    fn a_replaced_file_is_a_different_file_and_an_open_handle_is_the_same() {
        let directory = TempDir::new("replace");
        let path = directory.path().join("state");
        std::fs::write(&path, b"one").expect("create");
        let by_name = Observed::path_no_follow(&path).expect("observe path");
        let file = std::fs::File::open(&path).expect("open");
        let by_handle = Observed::file(&file).expect("observe handle");
        assert!(by_name.same_file(&by_handle));
        drop(file);

        let replacement = directory.path().join("state.new");
        std::fs::write(&replacement, b"one").expect("create replacement");
        std::fs::rename(&replacement, &path).expect("replace");
        let replaced = Observed::path_no_follow(&path).expect("observe replaced path");
        assert!(!by_name.same_file(&replaced));
    }
}
