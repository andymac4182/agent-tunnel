//! Deterministic, local-only connector diagnostics.
//!
//! The doctor deliberately stops at files owned by the configured profile and
//! the profile's local supervisor socket. It never opens a network socket,
//! starts the connector or invokes an export. Since M6-06 it reads the
//! running supervisor's status through the same owner-only, same-UID IPC
//! `tunnel-client status` uses (`main.rs`, `doctor_supervisor_ipc`), and
//! reports only a status and a closed code for it: a supervisor that is not
//! running is `not_running`, never a failure, and the check never changes
//! `ok` or the exit status.

use std::{
    io,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};
// Only the Unix permission check reads file metadata.
#[cfg(unix)]
use std::fs;

use serde::Serialize;
use tunnel_client::{
    ConnectConfig,
    credentials::{
        CredentialError, load_certificates, load_private_key, verify_certificate_key,
        verify_device_role,
    },
};

const SCHEMA_VERSION: u8 = 1;
const EXIT_INVALID_CONFIG: u8 = 2;
const EXIT_CREDENTIAL_ERROR: u8 = 3;

/// The complete output of one local doctor inspection.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct DoctorOutput {
    pub(crate) schema_version: u8,
    pub(crate) command: &'static str,
    pub(crate) ok: bool,
    /// The capability and credential checks, **always present**.
    ///
    /// This is deliberately not an `Option`. `DoctorResult` already carries a
    /// per-check `not_run` status, so "this check did not run" is expressible
    /// inside the struct; an outer `Option` is a second, coarser way to say
    /// the same thing, and the coarser one discards the checks that *did*
    /// run. It previously did exactly that on every failing run, which hid
    /// `process_containment` -- a check about the host, not the
    /// configuration -- from precisely the unprovisioned machines whose
    /// operator needs it (M6-C07). Making the field non-optional means that
    /// discard cannot be reintroduced without a compile error.
    pub(crate) result: DoctorResult,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) error: Option<DoctorError>,
}

/// The exit status paired with a doctor report.
#[derive(Clone, Debug)]
pub(crate) struct DoctorInspection {
    pub(crate) output: DoctorOutput,
    pub(crate) exit_code: u8,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct DoctorError {
    pub(crate) code: &'static str,
    pub(crate) message: &'static str,
    pub(crate) retryable: bool,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct DoctorResult {
    pub(crate) config: Check,
    pub(crate) credential_key_match: Check,
    pub(crate) permissions: PermissionCheck,
    pub(crate) expiry: ExpiryCheck,
    /// Whether the profile's `device_id` names the device in the client
    /// certificate's `urn:agent-tunnel:device:` role SAN, compared as UUIDs
    /// exactly as the relay compares them (task row M6-C44).  The relay
    /// refuses every HELLO that fails this, so a profile whose `device_id`
    /// was edited after `credentials import` is no longer reported healthy.
    /// It is placed after `expiry` so the fields before it keep their order.
    pub(crate) device_identity: Check,
    pub(crate) supervisor_ipc: CapabilityCheck,
    /// Whether this installation can contain a supervised child's process
    /// group when the device itself is killed (M3-09).
    ///
    /// The sentinel is a **separate executable**, so an installation missing
    /// it supervises children perfectly and leaks their process groups on
    /// every crash -- a state indistinguishable from correct operation unless
    /// something reports it. This is that something, and it is checked here
    /// because startup is the last moment at which it is cheap to fix.
    ///
    /// A missing sentinel is reported, **not** failed: it is a degradation of
    /// cleanup, not a reason to refuse to run, and an operator who cannot
    /// install the sentinel is better off with a warned-about device than no
    /// device. It never changes `ok` or the exit code.
    ///
    /// # What `..._SENTINEL_PRESENT` claims, exactly (M6-C08)
    ///
    /// It claims a **regular file of the sentinel's name** is at the resolved
    /// location and that **this process** has execute permission on it, asked
    /// of the kernel with `access(EXEC_OK)` rather than read off the mode
    /// bits -- a file executable only by a class this process is not in is
    /// rejected, and was not by the first draft of that rule. It does **not**
    /// claim the file is the sentinel, nor that spawning it will succeed: an
    /// executable script named `tunnel-deadman` produces this same `ok`, and
    /// so does a file `execve` rejects with `ENOEXEC`. The identity question
    /// is answered at bundle-assembly time, by executing the candidate and
    /// requiring the sentinel's exit 2
    /// (`scripts/client-bundle-sentinel.sh`, `scripts/m6-release-artifact.py`),
    /// which this surface deliberately does not do -- it reads a path and
    /// starts nothing, and running an unknown binary found beside the client
    /// would be a worse property than the one it checked.
    ///
    /// Until M6-C08, any `is_file()` satisfied this: a zero-byte, mode 0644
    /// decoy reported `ok` / `..._SENTINEL_PRESENT` while containment was
    /// wholly absent. That is now `degraded` / `..._SENTINEL_UNUSABLE`, kept
    /// distinct from `..._SENTINEL_MISSING` because the operator's fix
    /// differs.
    pub(crate) process_containment: CapabilityCheck,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct Check {
    pub(crate) status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) code: Option<&'static str>,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct CapabilityCheck {
    pub(crate) status: &'static str,
    pub(crate) code: &'static str,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct PermissionCheck {
    pub(crate) status: &'static str,
    pub(crate) private_key: FilePermissionCheck,
    pub(crate) credential_directory: FilePermissionCheck,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct FilePermissionCheck {
    pub(crate) status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) code: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) mode: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct ExpiryCheck {
    pub(crate) status: &'static str,
    pub(crate) client_certificate: CertificateBundleCheck,
    pub(crate) server_ca: CertificateBundleCheck,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct CertificateBundleCheck {
    pub(crate) status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) code: Option<&'static str>,
    pub(crate) certificates: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) not_before_unix: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) expires_at_unix: Option<i64>,
}

/// Inspect one configuration and its referenced credential files at `now`.
///
/// `now` is an explicit input so tests can exercise expiry deterministically.
/// The function only reads local files and does not expose any path, endpoint,
/// certificate body, private key material, or other secret in its output.
pub(crate) fn inspect(
    path: &Path,
    now: SystemTime,
    supervisor_ipc: CapabilityCheck,
) -> DoctorInspection {
    let process_containment = process_containment_check();

    let config = match ConnectConfig::load(path) {
        Ok(config) => config.resolve_relative_to(path.parent().unwrap_or_else(|| Path::new("."))),
        Err(_) => {
            let result = DoctorResult {
                config: failed("INVALID_CONFIG"),
                credential_key_match: not_run(),
                permissions: PermissionCheck::not_run(),
                expiry: ExpiryCheck::not_run(),
                device_identity: not_run(),
                supervisor_ipc,
                process_containment,
            };
            return inspection(
                result,
                Some(DoctorError {
                    code: "INVALID_CONFIG",
                    message: "local configuration is invalid or unreadable",
                    retryable: false,
                }),
                EXIT_INVALID_CONFIG,
            );
        }
    };

    let key_match = check_key_match(&config);
    let permissions = check_permissions(&config);
    let expiry = check_expiry(&config, now);
    let device_identity = check_device_identity(&config);
    let result = DoctorResult {
        config: ok(),
        credential_key_match: key_match,
        permissions,
        expiry,
        device_identity,
        supervisor_ipc,
        process_containment,
    };

    let failure = first_credential_failure(&result);
    let (error, exit_code) = match failure {
        None => (None, 0),
        Some(code) => (Some(credential_error(code)), EXIT_CREDENTIAL_ERROR),
    };
    inspection(result, error, exit_code)
}

/// Pair one `DoctorResult` with the error and exit code it produced.
///
/// `ok` is derived from `error` so the two can never disagree. The result is
/// reported whether or not the run failed: every leaf of `DoctorResult` is a
/// `&'static str` status or code, a permission mode, a certificate count or a
/// unix timestamp, so no path, endpoint or credential body can appear in it
/// and withholding it protects nothing.
fn inspection(result: DoctorResult, error: Option<DoctorError>, exit_code: u8) -> DoctorInspection {
    let ok = error.is_none();
    DoctorInspection {
        output: DoctorOutput {
            schema_version: SCHEMA_VERSION,
            command: "doctor",
            ok,
            result,
            error,
        },
        exit_code: if ok { 0 } else { exit_code },
    }
}

fn credential_error(code: &'static str) -> DoctorError {
    let message = match code {
        "CREDENTIAL_KEY_MISMATCH" => "client certificate does not match the private key",
        "CREDENTIAL_PERMISSIONS" => "private credential permissions are not owner-only",
        "CREDENTIAL_EXPIRED" => "a client certificate or server CA certificate is expired",
        "CREDENTIAL_NOT_YET_VALID" => {
            "a client certificate or server CA certificate is not yet valid"
        }
        "CREDENTIAL_MISSING" => "a configured credential file is missing or unreadable",
        "CREDENTIAL_DEVICE_MISMATCH" => {
            "the profile's device_id does not name the device in the client certificate's \
             role SAN; the relay refuses this device"
        }
        _ => "a configured credential is invalid",
    };
    DoctorError {
        code,
        message,
        retryable: false,
    }
}

fn first_credential_failure(result: &DoctorResult) -> Option<&'static str> {
    result
        .credential_key_match
        .code
        .or(result.permissions.private_key.code)
        .or(result.permissions.credential_directory.code)
        .or(result.expiry.client_certificate.code)
        .or(result.expiry.server_ca.code)
        .or(result.device_identity.code)
}

fn check_key_match(config: &ConnectConfig) -> Check {
    let certificates = match load_certificates(&config.credentials.client_certificate) {
        Ok(certificates) => certificates,
        Err(error) => return failed(credential_code(&error)),
    };
    if certificates.is_empty() {
        return failed("CREDENTIAL_INVALID");
    }
    let key = match load_private_key(&config.credentials.client_key) {
        Ok(key) => key,
        Err(error) => return failed(credential_code(&error)),
    };
    // M6-C42: only a genuine public-key mismatch is CREDENTIAL_KEY_MISMATCH.
    // A certificate the TLS stack refuses (a v1 certificate, say) is
    // CREDENTIAL_INVALID, as `credentials import` now reports it.
    match verify_certificate_key(&certificates, key) {
        Ok(()) => ok(),
        Err(error) => failed(credential_code(&error)),
    }
}

/// Task row M6-C44: compare the profile's `device_id` with the device the
/// client certificate names, using the same check `credentials import`
/// applies (`verify_device_role`, UUID comparison).  A certificate that does
/// not load is not re-reported here; `credential_key_match` already fails
/// for it, so this check is `not_run`.
fn check_device_identity(config: &ConnectConfig) -> Check {
    let Ok(certificates) = load_certificates(&config.credentials.client_certificate) else {
        return not_run();
    };
    let Some(leaf) = certificates.first() else {
        return not_run();
    };
    // The binding is named `refusal`, not `error`, so this arm stays textually
    // distinct from `check_key_match`'s, which `scripts/m0-guard-exit-codes.py`
    // anchors on exactly once.
    match verify_device_role(leaf, &config.device_id) {
        Ok(()) => ok(),
        Err(refusal) => failed(credential_code(&refusal)),
    }
}

fn credential_code(error: &CredentialError) -> &'static str {
    match error {
        CredentialError::Io(error) if error.kind() == io::ErrorKind::NotFound => {
            "CREDENTIAL_MISSING"
        }
        CredentialError::Io(_) => "CREDENTIAL_INVALID",
        CredentialError::NoCertificates(_) | CredentialError::NoPrivateKey(_) => {
            "CREDENTIAL_INVALID"
        }
        CredentialError::InvalidPem(_) | CredentialError::Tls(_) => "CREDENTIAL_INVALID",
        CredentialError::KeyMismatch(_) => "CREDENTIAL_KEY_MISMATCH",
        CredentialError::CertificateExpired { .. } => "CREDENTIAL_EXPIRED",
        // M6-C44: the relay refuses a HELLO whose `connector_id` is not the
        // certificate's device, and a `device_id` that is not a UUID names
        // no device; both are this profile/certificate disagreement.
        CredentialError::DeviceIdNotUuid(_) | CredentialError::DeviceIdMismatch { .. } => {
            "CREDENTIAL_DEVICE_MISMATCH"
        }
        CredentialError::CertificateUnparseable(_)
        | CredentialError::UnsupportedCertificateVersion(_)
        | CredentialError::UnsupportedPrivateKey(_)
        | CredentialError::CertificateRefused(_)
        | CredentialError::MissingDeviceRole(_)
        | CredentialError::RelayRefusedIdentity => "CREDENTIAL_INVALID",
        CredentialError::AlreadyExists(_)
        | CredentialError::Provision(_)
        | CredentialError::UnsupportedPlatform(_)
        | CredentialError::InsecurePermissions(_) => "CREDENTIAL_INVALID",
    }
}

#[cfg(unix)]
fn check_permissions(config: &ConnectConfig) -> PermissionCheck {
    use std::os::unix::fs::PermissionsExt;

    let key_path = &config.credentials.client_key;
    let key = match fs::symlink_metadata(key_path) {
        Ok(metadata) if metadata.file_type().is_file() => {
            let mode = metadata.permissions().mode() & 0o777;
            let safe = mode & 0o077 == 0 && mode & 0o400 != 0;
            FilePermissionCheck {
                status: if safe { "ok" } else { "failed" },
                code: (!safe).then_some("CREDENTIAL_PERMISSIONS"),
                mode: Some(format!("{mode:04o}")),
            }
        }
        Ok(_) => FilePermissionCheck::failed("CREDENTIAL_INVALID"),
        Err(error) => FilePermissionCheck::failed(io_permission_code(&error)),
    };

    let directory = key_path.parent().unwrap_or_else(|| Path::new("."));
    let directory = match fs::symlink_metadata(directory) {
        Ok(metadata) if metadata.file_type().is_dir() => {
            let mode = metadata.permissions().mode() & 0o777;
            let safe = mode & 0o077 == 0 && mode & 0o700 == 0o700;
            FilePermissionCheck {
                status: if safe { "ok" } else { "failed" },
                code: (!safe).then_some("CREDENTIAL_PERMISSIONS"),
                mode: Some(format!("{mode:04o}")),
            }
        }
        Ok(_) => FilePermissionCheck::failed("CREDENTIAL_INVALID"),
        Err(error) => FilePermissionCheck::failed(io_permission_code(&error)),
    };

    let status = if key.status == "ok" && directory.status == "ok" {
        "ok"
    } else {
        "failed"
    };
    PermissionCheck {
        status,
        private_key: key,
        credential_directory: directory,
    }
}

#[cfg(not(unix))]
fn check_permissions(_config: &ConnectConfig) -> PermissionCheck {
    PermissionCheck {
        status: "failed",
        private_key: FilePermissionCheck::failed("CREDENTIAL_PERMISSIONS_UNSUPPORTED"),
        credential_directory: FilePermissionCheck::failed("CREDENTIAL_PERMISSIONS_UNSUPPORTED"),
    }
}

#[cfg(unix)]
fn io_permission_code(error: &io::Error) -> &'static str {
    if error.kind() == io::ErrorKind::NotFound {
        "CREDENTIAL_MISSING"
    } else {
        "CREDENTIAL_PERMISSIONS"
    }
}

fn check_expiry(config: &ConnectConfig, now: SystemTime) -> ExpiryCheck {
    let now = unix_seconds(now);
    ExpiryCheck {
        status: "pending",
        client_certificate: inspect_bundle(&config.credentials.client_certificate, now),
        server_ca: inspect_bundle(&config.credentials.server_ca, now),
    }
    .with_status()
}

fn inspect_bundle(path: &Path, now: i64) -> CertificateBundleCheck {
    let certificates = match load_certificates(path) {
        Ok(certificates) => certificates,
        Err(error) => {
            return CertificateBundleCheck::failed(credential_code(&error));
        }
    };
    if certificates.is_empty() {
        return CertificateBundleCheck::failed("CREDENTIAL_INVALID");
    }

    let mut not_before = i64::MIN;
    let mut expires_at = i64::MAX;
    for certificate in &certificates {
        let validity = match certificate_validity(certificate.as_ref()) {
            Ok(validity) => validity,
            Err(()) => return CertificateBundleCheck::failed("CREDENTIAL_INVALID"),
        };
        not_before = not_before.max(validity.0);
        expires_at = expires_at.min(validity.1);
        if validity.0 > now {
            return CertificateBundleCheck {
                status: "failed",
                code: Some("CREDENTIAL_NOT_YET_VALID"),
                certificates: certificates.len(),
                not_before_unix: Some(not_before),
                expires_at_unix: Some(expires_at),
            };
        }
        if validity.1 <= now {
            return CertificateBundleCheck {
                status: "failed",
                code: Some("CREDENTIAL_EXPIRED"),
                certificates: certificates.len(),
                not_before_unix: Some(not_before),
                expires_at_unix: Some(expires_at),
            };
        }
    }
    CertificateBundleCheck {
        status: "ok",
        code: None,
        certificates: certificates.len(),
        not_before_unix: Some(not_before),
        expires_at_unix: Some(expires_at),
    }
}

impl ExpiryCheck {
    fn with_status(mut self) -> Self {
        self.status = if self.client_certificate.status == "ok" && self.server_ca.status == "ok" {
            "ok"
        } else {
            "failed"
        };
        self
    }

    fn not_run() -> Self {
        Self {
            status: "not_run",
            client_certificate: CertificateBundleCheck::not_run(),
            server_ca: CertificateBundleCheck::not_run(),
        }
    }
}

impl PermissionCheck {
    fn not_run() -> Self {
        Self {
            status: "not_run",
            private_key: FilePermissionCheck::not_run(),
            credential_directory: FilePermissionCheck::not_run(),
        }
    }
}

impl FilePermissionCheck {
    fn failed(code: &'static str) -> Self {
        Self {
            status: "failed",
            code: Some(code),
            mode: None,
        }
    }

    fn not_run() -> Self {
        Self {
            status: "not_run",
            code: None,
            mode: None,
        }
    }
}

impl CertificateBundleCheck {
    fn failed(code: &'static str) -> Self {
        Self {
            status: "failed",
            code: Some(code),
            certificates: 0,
            not_before_unix: None,
            expires_at_unix: None,
        }
    }

    fn not_run() -> Self {
        Self {
            status: "not_run",
            code: None,
            certificates: 0,
            not_before_unix: None,
            expires_at_unix: None,
        }
    }
}

fn ok() -> Check {
    Check {
        status: "ok",
        code: None,
    }
}

fn failed(code: &'static str) -> Check {
    Check {
        status: "failed",
        code: Some(code),
    }
}

fn not_run() -> Check {
    Check {
        status: "not_run",
        code: None,
    }
}

fn unix_seconds(now: SystemTime) -> i64 {
    match now.duration_since(UNIX_EPOCH) {
        Ok(duration) => i64::try_from(duration.as_secs()).unwrap_or(i64::MAX),
        Err(error) => -i64::try_from(error.duration().as_secs()).unwrap_or(i64::MAX),
    }
}

/// Report whether a parent-death sentinel could be armed on this host.
///
/// Reads a path and starts nothing, which keeps the doctor's promise that it
/// stops at files and never invokes an export.
fn process_containment_check() -> CapabilityCheck {
    containment_check(tunnel_deadman::availability())
}

/// The [`tunnel_deadman::Availability`] to [`CapabilityCheck`] mapping, as a
/// pure function of its input.
///
/// Split from the lookup above so a test can assert the **degraded** arm on a
/// machine where the sentinel happens to be installed. Left fused, a test
/// would take whichever arm the host produced — on any developer machine that
/// has built the workspace, the `Armable` one — and its assertions about the
/// degraded reporting would hold vacuously.
fn containment_check(availability: tunnel_deadman::Availability) -> CapabilityCheck {
    match availability {
        tunnel_deadman::Availability::Armable => CapabilityCheck {
            status: "ok",
            code: "PROCESS_CONTAINMENT_SENTINEL_PRESENT",
        },
        // A file of the sentinel's name is there and cannot be executed
        // (M6-C08). Degraded like `SentinelMissing` -- containment is equally
        // absent -- but a **distinct code**, because the two need different
        // actions and the missing code's advice is wrong for this state.
        tunnel_deadman::Availability::SentinelUnusable => CapabilityCheck {
            status: "degraded",
            code: "PROCESS_CONTAINMENT_SENTINEL_UNUSABLE",
        },
        tunnel_deadman::Availability::SentinelMissing => CapabilityCheck {
            status: "degraded",
            code: "PROCESS_CONTAINMENT_SENTINEL_MISSING",
        },
        tunnel_deadman::Availability::UnsupportedPlatform => CapabilityCheck {
            status: "not_implemented",
            code: "PROCESS_CONTAINMENT_UNSUPPORTED_PLATFORM",
        },
    }
}

/// Parse only the certificate validity sequence needed by the local doctor.
/// The parser is deliberately strict and rejects indefinite-length BER.
pub(crate) fn certificate_validity(der: &[u8]) -> Result<(i64, i64), ()> {
    let mut certificate_offset = 0;
    let certificate = parse_tlv(der, &mut certificate_offset)?;
    if certificate.tag != 0x30 || certificate.end != der.len() {
        return Err(());
    }
    let mut tbs_offset = 0;
    let tbs = parse_tlv(certificate.value, &mut tbs_offset)?;
    if tbs.tag != 0x30 {
        return Err(());
    }
    let mut offset = 0;
    let first = parse_tlv(tbs.value, &mut offset)?;
    if first.tag != 0xa0 {
        // Version is optional; the first field is the serial number in v1.
        offset = 0;
    }
    let serial = parse_tlv(tbs.value, &mut offset)?;
    if serial.tag != 0x02 {
        return Err(());
    }
    let signature = parse_tlv(tbs.value, &mut offset)?;
    if signature.tag != 0x30 {
        return Err(());
    }
    let issuer = parse_tlv(tbs.value, &mut offset)?;
    if issuer.tag != 0x30 {
        return Err(());
    }
    let validity = parse_tlv(tbs.value, &mut offset)?;
    if validity.tag != 0x30 {
        return Err(());
    }
    let mut validity_offset = 0;
    let not_before = parse_tlv(validity.value, &mut validity_offset)?;
    let not_after = parse_tlv(validity.value, &mut validity_offset)?;
    if validity_offset != validity.value.len() {
        return Err(());
    }
    Ok((parse_asn1_time(not_before)?, parse_asn1_time(not_after)?))
}

struct Tlv<'a> {
    tag: u8,
    value: &'a [u8],
    end: usize,
}

fn parse_tlv<'a>(input: &'a [u8], offset: &mut usize) -> Result<Tlv<'a>, ()> {
    let start = *offset;
    let tag = *input.get(*offset).ok_or(())?;
    *offset = (*offset).checked_add(1).ok_or(())?;
    let first_length = *input.get(*offset).ok_or(())?;
    *offset = (*offset).checked_add(1).ok_or(())?;
    let length = if first_length & 0x80 == 0 {
        usize::from(first_length)
    } else {
        let count = usize::from(first_length & 0x7f);
        if count == 0 || count > std::mem::size_of::<usize>() {
            return Err(());
        }
        let end = (*offset).checked_add(count).ok_or(())?;
        let bytes = input.get(*offset..end).ok_or(())?;
        *offset = end;
        let mut length = 0usize;
        for byte in bytes {
            length = length.checked_shl(8).ok_or(())?;
            length = length.checked_add(usize::from(*byte)).ok_or(())?;
        }
        if length < count || length > input.len() {
            return Err(());
        }
        length
    };
    let end = (*offset).checked_add(length).ok_or(())?;
    let value = input.get(*offset..end).ok_or(())?;
    *offset = end;
    if start > end {
        return Err(());
    }
    Ok(Tlv { tag, value, end })
}

fn parse_asn1_time(value: Tlv<'_>) -> Result<i64, ()> {
    let text = value.value;
    let (year, offset) = match value.tag {
        0x17 => {
            if text.len() < 13 {
                return Err(());
            }
            let year = parse_digits(&text[0..2])?;
            (if year < 50 { 2000 + year } else { 1900 + year }, 2)
        }
        0x18 => {
            if text.len() < 15 {
                return Err(());
            }
            (parse_digits(&text[0..4])?, 4)
        }
        _ => return Err(()),
    };
    let month = parse_digits(&text[offset..offset + 2])?;
    let day = parse_digits(&text[offset + 2..offset + 4])?;
    let hour = parse_digits(&text[offset + 4..offset + 6])?;
    let minute = parse_digits(&text[offset + 6..offset + 8])?;
    let second = parse_digits(&text[offset + 8..offset + 10])?;
    let suffix = &text[offset + 10..];
    let zone_offset = parse_time_suffix(suffix)?;
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return Err(());
    }
    let days = days_from_civil(year, month, day)?;
    days.checked_mul(86_400)
        .and_then(|seconds| seconds.checked_add(hour * 3_600))
        .and_then(|seconds| seconds.checked_add(minute * 60))
        .and_then(|seconds| seconds.checked_add(second))
        .and_then(|seconds| seconds.checked_sub(zone_offset))
        .ok_or(())
}

fn parse_time_suffix(suffix: &[u8]) -> Result<i64, ()> {
    if suffix == b"Z" {
        return Ok(0);
    }
    let position = suffix
        .iter()
        .position(|byte| *byte == b'+' || *byte == b'-')
        .ok_or(())?;
    let (fraction, timezone) = suffix.split_at(position);
    let sign = if timezone.first() == Some(&b'+') {
        1i64
    } else {
        -1i64
    };
    let timezone = &timezone[1..];
    if timezone.len() != 4 || !fraction.iter().all(u8::is_ascii_digit) {
        return Err(());
    }
    let hours = parse_digits(&timezone[0..2])?;
    let minutes = parse_digits(&timezone[2..4])?;
    if hours > 23 || minutes > 59 {
        return Err(());
    }
    Ok(sign * (hours * 3_600 + minutes * 60))
}

fn parse_digits(bytes: &[u8]) -> Result<i64, ()> {
    if bytes.is_empty() || !bytes.iter().all(u8::is_ascii_digit) {
        return Err(());
    }
    bytes.iter().try_fold(0i64, |value, byte| {
        value
            .checked_mul(10)
            .and_then(|value| value.checked_add(i64::from(byte - b'0')))
            .ok_or(())
    })
}

fn days_from_civil(year: i64, month: i64, day: i64) -> Result<i64, ()> {
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return Err(());
    }
    let adjusted_year = year - if month <= 2 { 1 } else { 0 };
    let era = if adjusted_year >= 0 {
        adjusted_year / 400
    } else {
        (adjusted_year - 399) / 400
    };
    let year_of_era = adjusted_year - era * 400;
    let month_prime = month + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * month_prime + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era.checked_mul(146_097)
        .and_then(|days| days.checked_add(day_of_era))
        .and_then(|days| days.checked_sub(719_468))
        .ok_or(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, KeyPair};
    use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf, time::Duration};
    use tempfile::tempdir;

    struct Fixture {
        directory: tempfile::TempDir,
        config: PathBuf,
    }

    /// The synthetic device the fixture certificate names in its role SAN.
    const FIXTURE_DEVICE: &str = "3a3b3c3d-3e3f-4a3b-8c3d-3e3f3a3b3c3d";

    /// Rewrite the fixture profile's `device_id`, as an operator editing the
    /// profile after `credentials import` would.
    fn set_device_id(fixture: &Fixture, device_id: &str) {
        let text = fs::read_to_string(&fixture.config).expect("fixture config read");
        let rewritten = text.replacen(
            &format!("device_id = \"{FIXTURE_DEVICE}\""),
            &format!("device_id = \"{device_id}\""),
            1,
        );
        assert_ne!(text, rewritten, "the fixture names FIXTURE_DEVICE");
        fs::write(&fixture.config, rewritten).expect("fixture config write");
    }

    fn fixture(expired: bool) -> Fixture {
        let directory = tempdir().expect("fixture directory");
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .expect("fixture directory permissions");
        let key_pair = KeyPair::generate().expect("fixture key");
        let mut params = CertificateParams::default();
        params.not_before = if expired {
            rcgen::date_time_ymd(2020, 1, 1)
        } else {
            rcgen::date_time_ymd(2023, 1, 1)
        };
        params.not_after = if expired {
            rcgen::date_time_ymd(2023, 1, 1)
        } else {
            rcgen::date_time_ymd(2030, 1, 1)
        };
        params.subject_alt_names = vec![rcgen::SanType::URI(
            format!("urn:agent-tunnel:device:{FIXTURE_DEVICE}")
                .try_into()
                .expect("device role URI SAN"),
        )];
        let certificate = params.self_signed(&key_pair).expect("fixture certificate");
        let cert_path = directory.path().join("client.pem");
        let key_path = directory.path().join("client-key.pem");
        let ca_path = directory.path().join("server-ca.pem");
        fs::write(&cert_path, certificate.pem()).expect("fixture certificate write");
        fs::write(&key_path, key_pair.serialize_pem()).expect("fixture key write");
        fs::write(&ca_path, certificate.pem()).expect("fixture CA write");
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600))
            .expect("fixture key permissions");
        let config = directory.path().join("client.toml");
        let config_text = format!(
            "device_id = \"{FIXTURE_DEVICE}\"\nrelay_url = \"wss://relay.example.test/v1/tunnel/control\"\nclient_cert = \"{}\"\nprivate_key = \"{}\"\nserver_ca = \"{}\"\n",
            cert_path.display(),
            key_path.display(),
            ca_path.display(),
        );
        fs::write(&config, config_text).expect("fixture config write");
        Fixture { directory, config }
    }

    /// `inspect` with the supervisor check a machine with no running
    /// `connect` produces; the IPC read itself is `main.rs`'s.
    fn inspect_without_supervisor(path: &Path, now: SystemTime) -> DoctorInspection {
        inspect(
            path,
            now,
            CapabilityCheck {
                status: "not_running",
                code: "SUPERVISOR_ABSENT",
            },
        )
    }

    #[test]
    fn valid_fixture_is_local_and_reports_the_supervisor_ipc_check() {
        let fixture = fixture(false);
        let inspection = inspect_without_supervisor(
            &fixture.config,
            UNIX_EPOCH + Duration::from_secs(1_800_000_000),
        );
        assert!(inspection.output.ok);
        assert_eq!(inspection.exit_code, 0);
        let result = &inspection.output.result;
        assert_eq!(result.supervisor_ipc.status, "not_running");
        assert_eq!(result.credential_key_match.status, "ok");
        assert_eq!(result.device_identity.status, "ok");
        let json = serde_json::to_string(&inspection.output).expect("doctor serializes");
        assert!(!json.contains("client-key.pem"));
        assert!(!json.contains("relay.example.test"));
        assert!(fixture.directory.path().exists());
    }

    /// M3-09 / M3-19: a missing parent-death sentinel must be **visible**.
    ///
    /// Without a report, an installation that shipped the device binary
    /// without `tunnel-deadman` beside it supervises children perfectly and
    /// leaks their process groups on every crash — a state nothing in the
    /// product distinguishes from correct operation. The check is also
    /// required **not** to fail the run: cleanup degrades, the device still
    /// works, and refusing to start would be worse than warning.
    #[test]
    fn a_missing_parent_death_sentinel_is_reported_and_does_not_fail_the_doctor() {
        // The degraded state is constructed, not waited for. On any machine
        // that has built this workspace the sentinel IS installed, so a test
        // that ran `inspect` and looked at whatever came back would take the
        // `Armable` arm and assert nothing about the case it is named for.
        let missing = containment_check(tunnel_deadman::Availability::SentinelMissing);
        assert_eq!(missing.status, "degraded");
        assert_eq!(missing.code, "PROCESS_CONTAINMENT_SENTINEL_MISSING");
        // M6-C08: a file wearing the sentinel's name is degraded like a
        // missing one -- containment is equally absent -- but must carry its
        // own code. Folded into the missing code, an operator staring at a
        // `tunnel-deadman` would be told to install one.
        let unusable = containment_check(tunnel_deadman::Availability::SentinelUnusable);
        assert_eq!(unusable.status, "degraded");
        assert_eq!(unusable.code, "PROCESS_CONTAINMENT_SENTINEL_UNUSABLE");
        assert_ne!(
            unusable.code, missing.code,
            "an unusable sentinel and an absent one need different fixes, so they \
             may not share a code"
        );
        assert_eq!(
            containment_check(tunnel_deadman::Availability::Armable).status,
            "ok"
        );
        assert_eq!(
            containment_check(tunnel_deadman::Availability::UnsupportedPlatform).status,
            "not_implemented"
        );

        // And a degraded containment does not become a failed doctor: it is a
        // degradation of cleanup, not a reason to refuse to run. Asserted
        // against a result that actually carries the degraded check, so the
        // claim holds on a host where the sentinel is present.
        let fixture = fixture(false);
        let inspection = inspect_without_supervisor(
            &fixture.config,
            UNIX_EPOCH + Duration::from_secs(1_800_000_000),
        );
        let mut result = inspection.output.result.clone();
        result.process_containment = missing;
        assert!(
            first_credential_failure(&result).is_none(),
            "containment is not part of the doctor's verdict"
        );
        assert!(inspection.output.ok);
        assert_eq!(inspection.exit_code, 0);
        let json = serde_json::to_string(&inspection.output).expect("doctor serializes");
        assert!(
            json.contains("process_containment"),
            "and it reaches the JSON an operator actually reads"
        );
    }

    #[test]
    fn key_mismatch_is_a_credential_failure_without_secret_output() {
        let fixture = fixture(false);
        let other_key = KeyPair::generate().expect("other key");
        let key_path = fixture.directory.path().join("client-key.pem");
        fs::write(&key_path, other_key.serialize_pem()).expect("replace fixture key");
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600))
            .expect("reapply key permissions");
        let inspection = inspect_without_supervisor(
            &fixture.config,
            UNIX_EPOCH + Duration::from_secs(1_800_000_000),
        );
        assert!(!inspection.output.ok);
        assert_eq!(inspection.exit_code, EXIT_CREDENTIAL_ERROR);
        assert_eq!(
            inspection.output.error.as_ref().map(|error| error.code),
            Some("CREDENTIAL_KEY_MISMATCH")
        );
        let json = serde_json::to_string(&inspection.output).expect("doctor serializes");
        assert!(!json.contains("PRIVATE"));
        assert!(!json.contains("BEGIN"));
    }

    /// M6-C42: a certificate the TLS stack cannot use is not a key mismatch.
    /// Before the fix every `CertifiedKey::from_der` refusal was reported as
    /// `CREDENTIAL_KEY_MISMATCH`, so this certificate, which is not X.509 at
    /// all, sent the operator to compare keys.
    #[test]
    fn an_unusable_certificate_is_invalid_not_a_key_mismatch() {
        let fixture = fixture(false);
        let cert_path = fixture.directory.path().join("client.pem");
        fs::write(
            &cert_path,
            "-----BEGIN CERTIFICATE-----\nMAMCAQA=\n-----END CERTIFICATE-----\n",
        )
        .expect("replace fixture certificate");
        let inspection = inspect_without_supervisor(
            &fixture.config,
            UNIX_EPOCH + Duration::from_secs(1_800_000_000),
        );
        assert!(!inspection.output.ok);
        assert_eq!(
            inspection.output.result.credential_key_match.code,
            Some("CREDENTIAL_INVALID")
        );
    }

    /// M6-C44: a profile whose `device_id` no longer names the certificate's
    /// device -- edited after `credentials import`, which checks it -- is a
    /// credential failure the relay would refuse on every HELLO.  Before the
    /// fix `doctor` reported `"ok":true` for it.
    #[test]
    fn a_device_id_that_is_not_the_certificates_device_fails_the_doctor() {
        let fixture = fixture(false);
        set_device_id(&fixture, "44444444-4444-4444-8444-444444444444");
        let inspection = inspect_without_supervisor(
            &fixture.config,
            UNIX_EPOCH + Duration::from_secs(1_800_000_000),
        );
        assert!(!inspection.output.ok);
        assert_eq!(inspection.exit_code, EXIT_CREDENTIAL_ERROR);
        let result = &inspection.output.result;
        assert_eq!(result.device_identity.status, "failed");
        assert_eq!(
            result.device_identity.code,
            Some("CREDENTIAL_DEVICE_MISMATCH")
        );
        assert_eq!(result.credential_key_match.status, "ok");
        assert_eq!(
            inspection.output.error.as_ref().map(|error| error.code),
            Some("CREDENTIAL_DEVICE_MISMATCH")
        );
        let json = serde_json::to_string(&inspection.output).expect("doctor serializes");
        assert!(
            !json.contains("44444444-4444-4444-8444-444444444444")
                && !json.contains(FIXTURE_DEVICE),
            "the report carries codes, not identifiers: {json}"
        );
    }

    /// M6-C44: the comparison is the relay's, by UUID value, so an uppercase
    /// or hyphen-less spelling of the certificate's device is not a
    /// mismatch, and a `device_id` that is not a UUID is one.
    #[test]
    fn the_device_identity_check_compares_uuids_as_the_relay_does() {
        let fixture = fixture(false);
        for spelling in [
            FIXTURE_DEVICE.to_uppercase(),
            FIXTURE_DEVICE.replace('-', ""),
        ] {
            set_device_id(&fixture, &spelling);
            let inspection = inspect_without_supervisor(
                &fixture.config,
                UNIX_EPOCH + Duration::from_secs(1_800_000_000),
            );
            assert_eq!(
                inspection.output.result.device_identity.status, "ok",
                "{spelling} names the certificate's device"
            );
            assert!(inspection.output.ok, "{spelling}");
            set_device_id_back(&fixture, &spelling);
        }
        set_device_id(&fixture, "doctor-fixture");
        let inspection = inspect_without_supervisor(
            &fixture.config,
            UNIX_EPOCH + Duration::from_secs(1_800_000_000),
        );
        assert_eq!(
            inspection.output.result.device_identity.code,
            Some("CREDENTIAL_DEVICE_MISMATCH")
        );
        assert_eq!(inspection.exit_code, EXIT_CREDENTIAL_ERROR);
    }

    fn set_device_id_back(fixture: &Fixture, from: &str) {
        let text = fs::read_to_string(&fixture.config).expect("fixture config read");
        let rewritten = text.replacen(
            &format!("device_id = \"{from}\""),
            &format!("device_id = \"{FIXTURE_DEVICE}\""),
            1,
        );
        fs::write(&fixture.config, rewritten).expect("fixture config write");
    }

    #[test]
    fn expired_certificate_and_insecure_key_permissions_are_reported() {
        let fixture = fixture(true);
        let inspection = inspect_without_supervisor(
            &fixture.config,
            UNIX_EPOCH + Duration::from_secs(1_800_000_000),
        );
        assert!(!inspection.output.ok);
        assert_eq!(inspection.exit_code, EXIT_CREDENTIAL_ERROR);
        assert_eq!(
            inspection.output.error.as_ref().map(|error| error.code),
            Some("CREDENTIAL_EXPIRED")
        );

        let key_path = fixture.directory.path().join("client-key.pem");
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o644))
            .expect("insecure key permissions");
        let inspection = inspect_without_supervisor(
            &fixture.config,
            UNIX_EPOCH + Duration::from_secs(1_800_000_000),
        );
        assert!(!inspection.output.ok);
        assert_eq!(inspection.exit_code, EXIT_CREDENTIAL_ERROR);
        assert_eq!(
            inspection.output.error.as_ref().map(|error| error.code),
            Some("CREDENTIAL_PERMISSIONS")
        );
    }

    #[test]
    fn invalid_configuration_is_exit_two_and_does_not_inspect_credentials() {
        let directory = tempdir().expect("fixture directory");
        let config = directory.path().join("client.toml");
        fs::write(
            &config,
            "device_id = \"bad\"\nrelay_url = \"ws://relay.example.test/v1/tunnel/control\"\nclient_cert = \"secret.pem\"\nprivate_key = \"secret-key.pem\"\nserver_ca = \"secret-ca.pem\"\n",
        )
        .expect("invalid config write");
        let inspection =
            inspect_without_supervisor(&config, UNIX_EPOCH + Duration::from_secs(1_800_000_000));
        assert!(!inspection.output.ok);
        assert_eq!(inspection.exit_code, EXIT_INVALID_CONFIG);
        assert_eq!(
            inspection.output.error.as_ref().map(|error| error.code),
            Some("INVALID_CONFIG")
        );
        // The result is **reported**, not discarded (M6-C07). What this test
        // is named for -- that an unparseable configuration does not go on to
        // read credential files -- is now asserted directly, per check,
        // instead of being inferred from a `result: null` that proved only
        // that nothing was said. `not_run` is a distinct status from
        // `failed`, so "was not attempted" and "was attempted and failed" do
        // not collapse into each other here.
        let result = &inspection.output.result;
        assert_eq!(result.config.status, "failed");
        assert_eq!(result.config.code, Some("INVALID_CONFIG"));
        assert_eq!(result.credential_key_match.status, "not_run");
        assert_eq!(result.permissions.status, "not_run");
        assert_eq!(result.permissions.private_key.status, "not_run");
        assert_eq!(result.permissions.credential_directory.status, "not_run");
        assert_eq!(result.expiry.status, "not_run");
        assert_eq!(result.expiry.client_certificate.status, "not_run");
        assert_eq!(result.expiry.server_ca.status, "not_run");
        assert_eq!(result.device_identity.status, "not_run");

        // The capability checks are about the host, not the configuration, so
        // an unparseable configuration is no reason to withhold them -- and
        // an unprovisioned machine is exactly where an operator needs them.
        assert_eq!(result.supervisor_ipc.code, "SUPERVISOR_ABSENT");
        assert!(
            result
                .process_containment
                .code
                .starts_with("PROCESS_CONTAINMENT_"),
            "containment must be reported on a failing run, got {:?}",
            result.process_containment.code
        );

        let json = serde_json::to_string(&inspection.output).expect("doctor serializes");
        // Without these two, the redaction assertions below would pass on an
        // empty object. They were near-vacuous while `result` was null: the
        // only serialized object was the static error, which never contained
        // a path or an endpoint in the first place.
        assert!(
            json.contains("\"process_containment\""),
            "the failing-run report must carry the capability checks: {json}"
        );
        assert!(
            json.contains("\"not_run\""),
            "the failing-run report must distinguish not-run from failed: {json}"
        );
        assert!(!json.contains("secret-key.pem"));
        assert!(!json.contains("relay.example.test"));
    }

    #[test]
    fn validity_parser_rejects_truncated_and_accepts_fixture_shape() {
        assert!(certificate_validity(&[0x30, 0x00]).is_err());
        let fixture = fixture(false);
        let certificates = load_certificates(fixture.directory.path().join("client.pem"))
            .expect("fixture certificate load");
        let (not_before, not_after) =
            certificate_validity(certificates[0].as_ref()).expect("fixture validity");
        assert!(not_before < not_after);
    }
}
