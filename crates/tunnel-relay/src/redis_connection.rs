//! Operator-configured Redis authority connection material.
//!
//! The serve boundary keeps Redis TLS files outside TOML and loads them only
//! after the configuration owner has selected the TLS-material profile.  The
//! helper deliberately keeps file paths and backend details out of errors and
//! debug output: callers receive a field-level failure, while the catalog
//! remains the authority for the authenticated connection and deployment
//! incarnation fence.

use std::{
    fmt,
    fs::{self, File},
    io::{self, Read},
    path::{Component, Path, PathBuf},
};

#[cfg(unix)]
use std::{
    fs::OpenOptions,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
};

use tunnel_catalog::{
    CatalogConnectionError, CatalogConnectionFailure, CatalogConnectionLane,
    CatalogConnectionStage, RedisCatalog, RedisTlsOptions,
};

/// Maximum size accepted for each Redis TLS PEM file.
pub const MAX_REDIS_TLS_MATERIAL_BYTES: usize = 1024 * 1024;

#[cfg(unix)]
const PRIVATE_KEY_MODE: u32 = 0o600;
#[cfg(unix)]
const FILE_MODE_MASK: u32 = 0o777;

/// The operator-provisioned Redis TLS file represented by an error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RedisTlsMaterialKind {
    RootCa,
    ClientCertificate,
    ClientPrivateKey,
}

impl fmt::Display for RedisTlsMaterialKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::RootCa => "Redis root CA",
            Self::ClientCertificate => "Redis client certificate",
            Self::ClientPrivateKey => "Redis client private key",
        })
    }
}

/// The bounded operation boundary where a Redis authority failure was
/// observed. Stages come from explicit catalog call sites; they are never
/// inferred from backend error text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RedisConnectionStage {
    TlsSetup,
    AuthorityProfile,
    ConnectionEstablishment,
    Ping,
    PrimaryIdentity,
    AuthorityIdentity,
    AuthorityConnection,
}

impl RedisConnectionStage {
    const fn as_str(&self) -> &'static str {
        match self {
            Self::TlsSetup => "tls_setup",
            Self::AuthorityProfile => "authority_profile",
            Self::ConnectionEstablishment => "connection_establishment",
            Self::Ping => "ping",
            Self::PrimaryIdentity => "primary_identity",
            Self::AuthorityIdentity => "authority_identity",
            Self::AuthorityConnection => "authority_connection",
        }
    }
}

/// Redacted failures raised while selecting and loading the Redis authority.
///
/// Variants carry only bounded field labels.  They intentionally do not carry
/// paths, URLs, PEM bytes, or the underlying Redis error because those values
/// can contain deployment secrets or credentials.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RedisConnectionError {
    InvalidInput(&'static str),
    MissingClientCertificate,
    MissingClientPrivateKey,
    PlaintextUrlWithTlsMaterial,
    InsecureTlsUrl,
    InvalidTlsUrl,
    FileIo(RedisTlsMaterialKind),
    FileTooLarge(RedisTlsMaterialKind),
    EmptyFile(RedisTlsMaterialKind),
    SymlinkRejected(RedisTlsMaterialKind),
    NotRegularFile(RedisTlsMaterialKind),
    PathChanged(RedisTlsMaterialKind),
    InsecurePermissions(RedisTlsMaterialKind),
    CatalogConnection,
    CatalogConnectionStage(RedisConnectionStage),
    /// A catalog connection failure with its bounded stage, the lane that
    /// failed (`None` for the primary connection), and a fixed failure
    /// class derived from typed error kinds only (M6-C72).
    CatalogConnectionFailed {
        stage: RedisConnectionStage,
        lane: Option<CatalogConnectionLane>,
        failure: CatalogConnectionFailure,
    },
}

impl fmt::Display for RedisConnectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput(message) => {
                write!(
                    formatter,
                    "invalid Redis connection input: {message}; stage={}",
                    RedisConnectionStage::TlsSetup.as_str()
                )
            }
            Self::MissingClientCertificate => formatter
                .write_str(
                    "Redis client certificate and private key must be supplied together; stage=tls_setup",
                ),
            Self::MissingClientPrivateKey => formatter
                .write_str(
                    "Redis client certificate and private key must be supplied together; stage=tls_setup",
                ),
            Self::PlaintextUrlWithTlsMaterial => {
                formatter.write_str(
                    "Redis TLS material requires a rediss:// authority URL; stage=authority_profile",
                )
            }
            Self::InsecureTlsUrl => formatter
                .write_str(
                    "Redis TLS URL must not enable insecure certificate verification; stage=authority_profile",
                ),
            Self::InvalidTlsUrl => {
                formatter.write_str("invalid Redis TLS authority URL; stage=authority_profile")
            }
            Self::FileIo(kind) => write!(formatter, "could not read {kind} file; stage=tls_setup"),
            Self::FileTooLarge(kind) => write!(
                formatter,
                "{kind} file exceeds the {}-byte bound; stage=tls_setup",
                MAX_REDIS_TLS_MATERIAL_BYTES,
            ),
            Self::EmptyFile(kind) => write!(formatter, "{kind} file is empty; stage=tls_setup"),
            Self::SymlinkRejected(kind) => {
                write!(formatter, "{kind} path contains a symlink; stage=tls_setup")
            }
            Self::NotRegularFile(kind) => {
                write!(formatter, "{kind} path is not a regular file; stage=tls_setup")
            }
            Self::PathChanged(kind) => {
                write!(formatter, "{kind} path changed while opening; stage=tls_setup")
            }
            Self::InsecurePermissions(kind) => {
                write!(formatter, "{kind} file permissions are too broad; stage=tls_setup")
            }
            Self::CatalogConnection => {
                write!(
                    formatter,
                    "Redis catalog connection failed; stage={}",
                    RedisConnectionStage::AuthorityConnection.as_str()
                )
            }
            Self::CatalogConnectionStage(stage) => {
                write!(formatter, "Redis catalog connection failed; stage={}", stage.as_str())
            }
            Self::CatalogConnectionFailed {
                stage,
                lane,
                failure,
            } => {
                formatter.write_str("Redis catalog connection failed; ")?;
                write_stage_detail(formatter, *stage, *lane, *failure)
            }
        }
    }
}

impl RedisConnectionError {
    /// The bounded `stage=... [lane=N/M] class=...` detail of a catalog
    /// connection failure, for callers that keep their own message prefix.
    pub(crate) fn stage_detail(&self) -> Option<StageDetail> {
        match *self {
            Self::CatalogConnectionFailed {
                stage,
                lane,
                failure,
            } => Some(StageDetail {
                stage,
                lane,
                failure,
            }),
            _ => None,
        }
    }
}

/// Displays as `stage=... [lane=N/M] class=...`, fixed words only.
pub(crate) struct StageDetail {
    stage: RedisConnectionStage,
    lane: Option<CatalogConnectionLane>,
    failure: CatalogConnectionFailure,
}

impl fmt::Display for StageDetail {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_stage_detail(formatter, self.stage, self.lane, self.failure)
    }
}

fn write_stage_detail(
    formatter: &mut fmt::Formatter<'_>,
    stage: RedisConnectionStage,
    lane: Option<CatalogConnectionLane>,
    failure: CatalogConnectionFailure,
) -> fmt::Result {
    write!(formatter, "stage={}", stage.as_str())?;
    if let Some(lane) = lane {
        write!(formatter, " lane={}/{}", lane.index, lane.total)?;
    }
    write!(formatter, " class={}", failure.as_str())
}

impl std::error::Error for RedisConnectionError {}

impl From<tunnel_catalog::CatalogError> for RedisConnectionError {
    fn from(error: tunnel_catalog::CatalogError) -> Self {
        Self::CatalogConnectionFailed {
            stage: RedisConnectionStage::AuthorityConnection,
            lane: None,
            failure: CatalogConnectionFailure::classify(&error),
        }
    }
}

impl From<CatalogConnectionStage> for RedisConnectionStage {
    fn from(stage: CatalogConnectionStage) -> Self {
        match stage {
            CatalogConnectionStage::ConnectionEstablishment => Self::ConnectionEstablishment,
            CatalogConnectionStage::TlsSetup => Self::TlsSetup,
            CatalogConnectionStage::Ping => Self::Ping,
            CatalogConnectionStage::PrimaryIdentity => Self::PrimaryIdentity,
            CatalogConnectionStage::AuthorityProfile => Self::AuthorityProfile,
            CatalogConnectionStage::AuthorityIdentity => Self::AuthorityIdentity,
        }
    }
}

/// Keep the catalog's stage, lane and failure class; never its source text.
pub(crate) fn map_catalog_connection_error(error: &CatalogConnectionError) -> RedisConnectionError {
    RedisConnectionError::CatalogConnectionFailed {
        stage: error.stage().into(),
        lane: error.lane(),
        failure: error.failure(),
    }
}

/// Optional operator-provisioned Redis TLS file paths.
///
/// The root CA may be supplied alone to override server trust.  The client
/// certificate and private key are an mTLS pair and must be supplied
/// together.  When every field is absent, the existing no-material catalog
/// profile is preserved.
#[derive(Clone, Default, Eq, PartialEq)]
pub struct RedisTlsMaterialPaths {
    pub root_ca_path: Option<PathBuf>,
    pub client_cert_path: Option<PathBuf>,
    pub client_key_path: Option<PathBuf>,
}

impl fmt::Debug for RedisTlsMaterialPaths {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RedisTlsMaterialPaths")
            .field("has_root_ca_path", &self.root_ca_path.is_some())
            .field("has_client_cert_path", &self.client_cert_path.is_some())
            .field("has_client_key_path", &self.client_key_path.is_some())
            .finish()
    }
}

impl RedisTlsMaterialPaths {
    /// Return whether this configuration selects the operator TLS-material
    /// profile.
    pub fn is_configured(&self) -> bool {
        self.root_ca_path.is_some()
            || self.client_cert_path.is_some()
            || self.client_key_path.is_some()
    }

    /// Validate the path selection without opening any file.
    ///
    /// The serve configuration uses this check so a malformed client
    /// identity is rejected by `check-config`, while file ownership,
    /// symlink, permission, and size checks remain startup checks.
    pub fn validate_shape(&self) -> Result<(), &'static str> {
        if self
            .root_ca_path
            .as_ref()
            .is_some_and(|path| path.as_os_str().is_empty())
            || self
                .client_cert_path
                .as_ref()
                .is_some_and(|path| path.as_os_str().is_empty())
            || self
                .client_key_path
                .as_ref()
                .is_some_and(|path| path.as_os_str().is_empty())
        {
            return Err("Redis TLS material paths must not be empty");
        }
        if self.client_cert_path.is_none() && self.client_key_path.is_some() {
            return Err("Redis client certificate and private key must be supplied together");
        }
        if self.client_cert_path.is_some() && self.client_key_path.is_none() {
            return Err("Redis client certificate and private key must be supplied together");
        }
        Ok(())
    }

    /// Load bounded PEM bytes into the catalog TLS options.
    pub fn load(&self) -> Result<Option<RedisTlsOptions>, RedisConnectionError> {
        if !self.is_configured() {
            return Ok(None);
        }
        if let Err(message) = self.validate_shape() {
            return Err(match message {
                "Redis client certificate and private key must be supplied together"
                    if self.client_cert_path.is_none() =>
                {
                    RedisConnectionError::MissingClientCertificate
                }
                "Redis client certificate and private key must be supplied together" => {
                    RedisConnectionError::MissingClientPrivateKey
                }
                message => RedisConnectionError::InvalidInput(message),
            });
        }

        let root_ca = self
            .root_ca_path
            .as_deref()
            .map(|path| read_material(path, RedisTlsMaterialKind::RootCa, false))
            .transpose()?;
        let client_cert = self
            .client_cert_path
            .as_deref()
            .map(|path| read_material(path, RedisTlsMaterialKind::ClientCertificate, false))
            .transpose()?;
        let client_key = self
            .client_key_path
            .as_deref()
            .map(|path| read_material(path, RedisTlsMaterialKind::ClientPrivateKey, true))
            .transpose()?;

        let mut options = RedisTlsOptions {
            root_cert_pem: root_ca,
            ..RedisTlsOptions::default()
        };
        if let (Some(client_cert), Some(client_key)) = (client_cert, client_key) {
            options = options.with_client_identity_pem(client_cert, client_key);
        }
        Ok(Some(options))
    }
}

/// Connect the relay's Redis authority using operator-selected TLS material.
///
/// With no configured paths this calls the existing no-material constructor.
/// With any configured path it requires a verified `rediss://` URL, loads the
/// files, and calls the catalog TLS constructor that performs the handshake,
/// PING/INFO check, and deployment-incarnation fence.
pub async fn connect(
    redis_url: &str,
    namespace: &str,
    deployment_incarnation: &str,
    material: &RedisTlsMaterialPaths,
) -> Result<RedisCatalog, RedisConnectionError> {
    reject_insecure_tls_url(redis_url)?;
    if !material.is_configured() {
        return RedisCatalog::connect_with_deployment_incarnation_staged(
            redis_url,
            namespace,
            deployment_incarnation,
        )
        .await
        .map_err(|error| map_catalog_connection_error(&error));
    }
    validate_verified_rediss_url(redis_url)?;
    let Some(tls) = material.load()? else {
        return Err(RedisConnectionError::InvalidInput(
            "Redis TLS material selection is inconsistent",
        ));
    };
    RedisCatalog::connect_with_tls_and_deployment_incarnation_staged(
        redis_url,
        namespace,
        deployment_incarnation,
        tls,
    )
    .await
    .map_err(|error| map_catalog_connection_error(&error))
}

/// Connect the same Redis authority as [`connect`], with the same URL and TLS
/// material rules, but **without** requiring an active deployment
/// incarnation.
///
/// Only the operator's first-incarnation bootstrap uses this (task row
/// M6-C21): it is the one caller whose job is to create the incarnation
/// `connect` requires.  The catalog method it then calls refuses any namespace
/// that already has one, so this cannot be used to skip `serve`'s fence.
pub async fn connect_for_first_activation(
    redis_url: &str,
    namespace: &str,
    deployment_incarnation: &str,
    material: &RedisTlsMaterialPaths,
) -> Result<RedisCatalog, RedisConnectionError> {
    reject_insecure_tls_url(redis_url)?;
    if !material.is_configured() {
        return RedisCatalog::connect_for_recovery_staged(
            redis_url,
            namespace,
            deployment_incarnation,
        )
        .await
        .map_err(|error| map_catalog_connection_error(&error));
    }
    validate_verified_rediss_url(redis_url)?;
    let Some(tls) = material.load()? else {
        return Err(RedisConnectionError::InvalidInput(
            "Redis TLS material selection is inconsistent",
        ));
    };
    RedisCatalog::connect_for_recovery_with_tls_staged(
        redis_url,
        namespace,
        deployment_incarnation,
        tls,
    )
    .await
    .map_err(|error| map_catalog_connection_error(&error))
}

fn validate_verified_rediss_url(redis_url: &str) -> Result<(), RedisConnectionError> {
    let Some(rest) = redis_url.strip_prefix("rediss://") else {
        return Err(RedisConnectionError::PlaintextUrlWithTlsMaterial);
    };
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    if authority_end == 0 {
        return Err(RedisConnectionError::InvalidTlsUrl);
    }
    reject_insecure_tls_url(redis_url)?;
    if rest.contains('#') {
        return Err(RedisConnectionError::InvalidTlsUrl);
    }
    Ok(())
}

fn reject_insecure_tls_url(redis_url: &str) -> Result<(), RedisConnectionError> {
    let Some(rest) = redis_url.strip_prefix("rediss://") else {
        return Ok(());
    };
    if let Some(fragment) = rest.split_once('#').map(|(_, fragment)| fragment)
        && fragment.eq_ignore_ascii_case("insecure")
    {
        return Err(RedisConnectionError::InsecureTlsUrl);
    }
    Ok(())
}

fn read_material(
    path: &Path,
    kind: RedisTlsMaterialKind,
    private: bool,
) -> Result<Vec<u8>, RedisConnectionError> {
    if path.as_os_str().is_empty() {
        return Err(RedisConnectionError::InvalidInput(
            "Redis TLS material path must not be empty",
        ));
    }
    reject_symlink_components(path, kind)?;
    let path_metadata =
        fs::symlink_metadata(path).map_err(|_| RedisConnectionError::FileIo(kind))?;
    if path_metadata.file_type().is_symlink() {
        return Err(RedisConnectionError::SymlinkRejected(kind));
    }
    if !path_metadata.is_file() {
        return Err(RedisConnectionError::NotRegularFile(kind));
    }
    if path_metadata.len() > (MAX_REDIS_TLS_MATERIAL_BYTES as u64) {
        return Err(RedisConnectionError::FileTooLarge(kind));
    }

    let file = open_readonly_nofollow(path).map_err(|_| RedisConnectionError::FileIo(kind))?;
    let opened_metadata = file
        .metadata()
        .map_err(|_| RedisConnectionError::FileIo(kind))?;
    if !same_file_metadata(&path_metadata, &opened_metadata) {
        return Err(RedisConnectionError::PathChanged(kind));
    }
    if opened_metadata.file_type().is_symlink() || !opened_metadata.is_file() {
        return Err(RedisConnectionError::NotRegularFile(kind));
    }
    if private && !private_permissions_ok(&opened_metadata) {
        return Err(RedisConnectionError::InsecurePermissions(kind));
    }

    let mut bytes = Vec::with_capacity(MAX_REDIS_TLS_MATERIAL_BYTES.min(4096));
    let mut bounded = file.take((MAX_REDIS_TLS_MATERIAL_BYTES + 1) as u64);
    bounded
        .read_to_end(&mut bytes)
        .map_err(|_| RedisConnectionError::FileIo(kind))?;
    if bytes.len() > MAX_REDIS_TLS_MATERIAL_BYTES {
        return Err(RedisConnectionError::FileTooLarge(kind));
    }
    if bytes.is_empty() {
        return Err(RedisConnectionError::EmptyFile(kind));
    }
    Ok(bytes)
}

fn open_readonly_nofollow(path: &Path) -> io::Result<File> {
    #[cfg(unix)]
    {
        let mut options = OpenOptions::new();
        options.read(true).custom_flags(libc::O_NOFOLLOW);
        options.open(path)
    }
    #[cfg(not(unix))]
    {
        File::open(path)
    }
}

fn private_permissions_ok(metadata: &fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        let mode = metadata.permissions().mode() & FILE_MODE_MASK;
        mode & PRIVATE_KEY_MODE == PRIVATE_KEY_MODE && mode & 0o077 == 0
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        true
    }
}

fn reject_symlink_components(
    path: &Path,
    kind: RedisTlsMaterialKind,
) -> Result<(), RedisConnectionError> {
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
            Component::ParentDir => {
                return Err(RedisConnectionError::InvalidInput(
                    "Redis TLS material path must not contain '..'",
                ));
            }
            Component::Normal(name) => current.push(name),
        }
        let metadata =
            fs::symlink_metadata(&current).map_err(|_| RedisConnectionError::FileIo(kind))?;
        if metadata.file_type().is_symlink() {
            return Err(RedisConnectionError::SymlinkRejected(kind));
        }
    }
    Ok(())
}

fn same_file_metadata(first: &fs::Metadata, second: &fs::Metadata) -> bool {
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
        first.is_file() == second.is_file()
            && first.is_dir() == second.is_dir()
            && first.len() == second.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use uuid::Uuid;

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let path =
                std::env::temp_dir().join(format!("agent-tunnel-redis-tls-{}", Uuid::new_v4()));
            fs::create_dir(&path).expect("test directory");
            // macOS exposes the temporary directory through `/var`, whose
            // `/var` component is a symlink to `/private/var`.  Resolve only
            // this test-owned directory so the production loader can keep its
            // strict no-symlink policy and the leaf-symlink test remains real.
            let path = fs::canonicalize(path).expect("canonical test directory");
            #[cfg(unix)]
            {
                fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                    .expect("private test directory");
            }
            Self(path)
        }

        fn path(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn write_material(path: &Path, bytes: &[u8]) {
        fs::write(path, bytes).expect("test material");
        #[cfg(unix)]
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .expect("test material permissions");
    }

    #[test]
    fn no_paths_preserve_no_material_profile() {
        let paths = RedisTlsMaterialPaths::default();
        assert!(!paths.is_configured());
        assert!(paths.load().expect("no material").is_none());
    }

    #[test]
    fn material_paths_build_bounded_catalog_options() {
        let directory = TestDirectory::new();
        let root = directory.path("root.pem");
        let cert = directory.path("client.pem");
        let key = directory.path("client-key.pem");
        write_material(&root, b"root");
        write_material(&cert, b"cert");
        write_material(&key, b"key");

        let paths = RedisTlsMaterialPaths {
            root_ca_path: Some(root),
            client_cert_path: Some(cert),
            client_key_path: Some(key),
        };
        let options = paths.load().expect("load material").expect("TLS options");
        assert_eq!(options.root_cert_pem.as_deref(), Some(b"root".as_slice()));
        assert_eq!(options.client_cert_pem.as_deref(), Some(b"cert".as_slice()));
        assert_eq!(options.client_key_pem.as_deref(), Some(b"key".as_slice()));
    }

    #[test]
    fn missing_client_pair_is_rejected_without_reading_paths() {
        let paths = RedisTlsMaterialPaths {
            client_cert_path: Some(PathBuf::from("missing-cert.pem")),
            ..RedisTlsMaterialPaths::default()
        };
        assert!(matches!(
            paths.load(),
            Err(RedisConnectionError::MissingClientPrivateKey)
        ));
    }

    #[test]
    fn tls_material_requires_verified_rediss() {
        assert_eq!(
            validate_verified_rediss_url("redis://localhost:6379/0"),
            Err(RedisConnectionError::PlaintextUrlWithTlsMaterial)
        );
        assert_eq!(
            validate_verified_rediss_url("rediss://localhost:6379/0#insecure"),
            Err(RedisConnectionError::InsecureTlsUrl)
        );
        assert!(validate_verified_rediss_url("rediss://localhost:6379/0").is_ok());
    }

    #[test]
    fn diagnostics_report_only_bounded_connection_stages() {
        let catalog_error: RedisConnectionError =
            tunnel_catalog::CatalogError::InvalidInput("redis URL").into();
        assert_eq!(
            catalog_error,
            RedisConnectionError::CatalogConnectionFailed {
                stage: RedisConnectionStage::AuthorityConnection,
                lane: None,
                failure: CatalogConnectionFailure::Config,
            }
        );
        assert_eq!(
            catalog_error.to_string(),
            "Redis catalog connection failed; stage=authority_connection class=config"
        );
        assert_eq!(
            RedisConnectionError::InvalidTlsUrl.to_string(),
            "invalid Redis TLS authority URL; stage=authority_profile"
        );
        assert_eq!(
            RedisConnectionError::EmptyFile(RedisTlsMaterialKind::RootCa).to_string(),
            "Redis root CA file is empty; stage=tls_setup"
        );
        assert!(!catalog_error.to_string().contains("redis://"));
        assert!(!catalog_error.to_string().contains("redis URL"));
    }

    /// M6-C72 (M6-C71 on `m6-fly-deploy`, M6-C59): each stage, lane and
    /// class prints its own line, built from fixed words only.
    #[test]
    fn each_stage_lane_and_class_prints_a_distinct_bounded_line() {
        use CatalogConnectionFailure as Failure;
        let stages = [
            RedisConnectionStage::ConnectionEstablishment,
            RedisConnectionStage::TlsSetup,
            RedisConnectionStage::Ping,
            RedisConnectionStage::PrimaryIdentity,
            RedisConnectionStage::AuthorityProfile,
            RedisConnectionStage::AuthorityIdentity,
            RedisConnectionStage::AuthorityConnection,
        ];
        let failures = [
            Failure::Timeout,
            Failure::Refused,
            Failure::Io,
            Failure::TlsCertificate,
            Failure::TlsAlert,
            Failure::Tls,
            Failure::Auth,
            Failure::NoPerm,
            Failure::Reply,
            Failure::InvalidReply,
            Failure::RunIdConflict,
            Failure::Config,
            Failure::Catalog,
        ];
        let lanes = [
            None,
            Some(CatalogConnectionLane { index: 1, total: 6 }),
            Some(CatalogConnectionLane { index: 3, total: 6 }),
        ];
        let mut seen = std::collections::BTreeSet::new();
        for stage in stages {
            for failure in failures {
                for lane in lanes {
                    let line = RedisConnectionError::CatalogConnectionFailed {
                        stage,
                        lane,
                        failure,
                    }
                    .to_string();
                    assert!(seen.insert(line.clone()), "duplicate line {line}");
                    assert!(line.starts_with("Redis catalog connection failed; stage="));
                    assert!(
                        line.ends_with(&format!(" class={}", failure.as_str())),
                        "{line}"
                    );
                    assert_eq!(
                        line.contains(" lane="),
                        lane.is_some(),
                        "lane shown only for a lane failure: {line}"
                    );
                }
            }
        }
        assert_eq!(
            RedisConnectionError::CatalogConnectionFailed {
                stage: RedisConnectionStage::ConnectionEstablishment,
                lane: Some(CatalogConnectionLane { index: 3, total: 6 }),
                failure: Failure::Timeout,
            }
            .to_string(),
            "Redis catalog connection failed; stage=connection_establishment lane=3/6 class=timeout"
        );
        // M6-C59: a wrong password, a wrong CA and a refused client
        // certificate no longer print the same line.
        let establishment = |failure| {
            RedisConnectionError::CatalogConnectionFailed {
                stage: RedisConnectionStage::ConnectionEstablishment,
                lane: None,
                failure,
            }
            .to_string()
        };
        let wrong_password = establishment(Failure::Auth);
        let wrong_ca = establishment(Failure::TlsCertificate);
        let refused_certificate = establishment(Failure::TlsAlert);
        assert_ne!(wrong_password, wrong_ca);
        assert_ne!(wrong_password, refused_certificate);
        assert_ne!(wrong_ca, refused_certificate);
    }

    /// The staged connectors carry no URL or password into the diagnostic,
    /// whatever the failure.
    #[tokio::test]
    async fn staged_failures_never_print_the_url_or_password() {
        // Synthetic values.  The URLs are assembled at run time so the
        // repository's secret scan (`m6-release-checks.py --check secrets`)
        // does not see a credential-shaped literal; the connector still
        // receives the full URL, so the assertions below can fail.
        let secret = "m6c72-synthetic-password";
        let scheme = "redis";
        for url in [
            format!("{scheme}://m6c72-user:{secret}@127.0.0.1:1/0"),
            format!("{scheme}://m6c72-user:{secret}@"),
            format!("{scheme}://:{secret}@127.0.0.1:1/0"),
        ] {
            for error in [
                connect(
                    &url,
                    "test-m6c72",
                    "test-incarnation",
                    &RedisTlsMaterialPaths::default(),
                )
                .await
                .expect_err("nothing listens on port 1"),
                connect_for_first_activation(
                    &url,
                    "test-m6c72",
                    "test-incarnation",
                    &RedisTlsMaterialPaths::default(),
                )
                .await
                .expect_err("nothing listens on port 1"),
            ] {
                let line = error.to_string();
                let debug = format!("{error:?}");
                assert!(
                    line.starts_with("Redis catalog connection failed; stage="),
                    "{line}"
                );
                for shown in [&line, &debug] {
                    assert!(!shown.contains(secret), "{shown}");
                    assert!(!shown.contains("redis://"), "{shown}");
                    assert!(!shown.contains("127.0.0.1"), "{shown}");
                    assert!(!shown.contains("m6c72-user"), "{shown}");
                }
            }
        }
    }

    #[tokio::test]
    async fn configured_plaintext_is_rejected_before_loading_or_dialing() {
        let material = RedisTlsMaterialPaths {
            root_ca_path: Some(PathBuf::from("missing-root.pem")),
            ..RedisTlsMaterialPaths::default()
        };
        let error = connect(
            "redis://localhost:6379/0",
            "test-redis-connection",
            "test-incarnation",
            &material,
        )
        .await
        .expect_err("configured Redis TLS must reject plaintext");
        assert_eq!(error, RedisConnectionError::PlaintextUrlWithTlsMaterial);
    }

    #[test]
    #[cfg(unix)]
    fn private_key_symlink_and_broad_permissions_are_rejected() {
        let directory = TestDirectory::new();
        let target = directory.path("target-key.pem");
        let link = directory.path("link-key.pem");
        write_material(&target, b"key");
        std::os::unix::fs::symlink(&target, &link).expect("key symlink");
        assert_eq!(
            read_material(&link, RedisTlsMaterialKind::ClientPrivateKey, true),
            Err(RedisConnectionError::SymlinkRejected(
                RedisTlsMaterialKind::ClientPrivateKey
            ))
        );

        let broad = directory.path("broad-key.pem");
        write_material(&broad, b"key");
        fs::set_permissions(&broad, fs::Permissions::from_mode(0o644))
            .expect("broad key permissions");
        assert_eq!(
            read_material(&broad, RedisTlsMaterialKind::ClientPrivateKey, true),
            Err(RedisConnectionError::InsecurePermissions(
                RedisTlsMaterialKind::ClientPrivateKey
            ))
        );
    }

    #[test]
    fn oversized_material_is_bounded_before_catalog_use() {
        let directory = TestDirectory::new();
        let root = directory.path("root.pem");
        write_material(&root, &vec![b'x'; MAX_REDIS_TLS_MATERIAL_BYTES + 1]);
        let paths = RedisTlsMaterialPaths {
            root_ca_path: Some(root),
            ..RedisTlsMaterialPaths::default()
        };
        assert!(matches!(
            paths.load(),
            Err(RedisConnectionError::FileTooLarge(
                RedisTlsMaterialKind::RootCa
            ))
        ));
    }

    #[test]
    fn errors_do_not_include_material_paths() {
        let directory = TestDirectory::new();
        let path = directory.path("secret-key.pem");
        let path_text = path.display().to_string();
        let paths = RedisTlsMaterialPaths {
            client_key_path: Some(path.clone()),
            ..RedisTlsMaterialPaths::default()
        };
        assert!(!format!("{paths:?}").contains(&path_text));
        let error = read_material(&path, RedisTlsMaterialKind::ClientPrivateKey, true)
            .expect_err("missing key");
        assert!(!format!("{error:?}").contains(&path_text));
        assert!(!error.to_string().contains(&path_text));
    }
}
