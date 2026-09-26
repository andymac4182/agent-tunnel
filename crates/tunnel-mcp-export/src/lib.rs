#![forbid(unsafe_code)]
//! Device-side MCP exports over `http-forward/1` (M3-02).
//!
//! An [`McpExport`] is built from validated operator configuration
//! ([`config::McpExportConfig`]) and served as an in-process HTTP handler by
//! the connector: [`McpExport::handle`] takes the bridge's typed request and
//! returns a streaming response.  It carries its selected profile's
//! `http-forward/1` policies ([`McpExport::profile_policies`]) so the device
//! validates heads against exactly the allowlist the relay enforces.
//!
//! * [`stdio::StdioExport`] supervises a fixed MCP stdio server.
//! * [`http_backend::HttpBackendExport`] forwards to a fixed loopback
//!   Streamable HTTP server.

pub mod body;
pub mod child;
pub mod config;
pub mod http_backend;
pub mod stdio;

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use http::{Request, Response};
use tunnel_http_bridge::{ChannelBody, Profile};
use tunnel_mcp::{McpLimits, McpProfile};

pub use body::ExportBody;
pub use config::{McpBackendConfig, McpConfigError, McpExportConfig, McpLimitsConfig};

/// The opaque per-principal binding the relay ingress derived for this
/// request, or `None` when no ingress supplied one.
///
/// The device never interprets the value and never derives one: it only
/// compares it for equality with the value a protocol session was opened
/// with (M3-04).  A deployment with no relay ingress in front of the export —
/// the in-process gate-2 bridge used by the export tests — has no
/// authenticated principal at all, and every request then carries `None`,
/// which binds a session to "no principal" and still refuses any other value.
#[must_use]
pub fn request_principal_binding(headers: &http::HeaderMap) -> Option<String> {
    headers
        .get(tunnel_mcp::headers::TUNNEL_PRINCIPAL_BINDING)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

/// An exchange the export interrupts instead of answering.  It carries no
/// message; the peer learns only the bridge's sanitized code.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ExportError;

impl std::fmt::Display for ExportError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("mcp export interrupted the exchange")
    }
}

impl std::error::Error for ExportError {}

/// Payload-free counters of one export.
#[derive(Debug, Default)]
pub struct ExportCounters {
    pub children: Arc<child::ChildCounters>,
    pub rejected: AtomicU64,
    pub json_responses: AtomicU64,
    pub sse_responses: AtomicU64,
    pub streamed_bytes: Arc<AtomicU64>,
    pub interrupted: AtomicU64,
    pub cancel_notifications_sent: AtomicU64,
    pub sessions_opened: AtomicU64,
    pub sessions_ended: AtomicU64,
    pub undeliverable: AtomicU64,
    pub dispatched: AtomicU64,
    pub backend_errors: AtomicU64,
    pub sessions_expired: AtomicU64,
    pub stalled_streams: AtomicU64,
    pub notifications_dropped: AtomicU64,
    /// Protocol sessions ended because the relay reported that their
    /// consumer's authorization ended (M3-16).
    pub sessions_revoked: AtomicU64,
}

/// A snapshot of [`ExportCounters`].
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ExportDiagnostics {
    pub children_spawned: u64,
    pub children_spawn_failed: u64,
    pub children_exited: u64,
    pub children_killed: u64,
    pub children_running: u64,
    pub child_invalid_output: u64,
    pub child_stderr_bytes: u64,
    pub rejected: u64,
    pub json_responses: u64,
    pub sse_responses: u64,
    pub streamed_bytes: u64,
    pub interrupted: u64,
    pub cancel_notifications_sent: u64,
    pub sessions_opened: u64,
    pub sessions_ended: u64,
    pub undeliverable: u64,
    pub dispatched: u64,
    pub backend_errors: u64,
    pub sessions_expired: u64,
    pub stalled_streams: u64,
    pub notifications_dropped: u64,
    pub child_group_kills: u64,
    pub sessions_revoked: u64,
}

impl ExportCounters {
    fn snapshot(&self) -> ExportDiagnostics {
        // `Acquire` pairs with the `Release` of a counter that announces an
        // outcome (`sessions_expired`, `sessions_ended`), so state published
        // before that announcement is visible to a reader that saw it (M3-27).
        let load = |counter: &AtomicU64| counter.load(Ordering::Acquire);
        ExportDiagnostics {
            children_spawned: load(&self.children.spawned),
            children_spawn_failed: load(&self.children.spawn_failed),
            children_exited: load(&self.children.exited),
            children_killed: load(&self.children.killed),
            children_running: load(&self.children.running),
            child_invalid_output: load(&self.children.invalid_output),
            child_stderr_bytes: load(&self.children.stderr_bytes),
            rejected: load(&self.rejected),
            json_responses: load(&self.json_responses),
            sse_responses: load(&self.sse_responses),
            streamed_bytes: load(&self.streamed_bytes),
            interrupted: load(&self.interrupted),
            cancel_notifications_sent: load(&self.cancel_notifications_sent),
            sessions_opened: load(&self.sessions_opened),
            sessions_ended: load(&self.sessions_ended),
            undeliverable: load(&self.undeliverable),
            dispatched: load(&self.dispatched),
            backend_errors: load(&self.backend_errors),
            sessions_expired: load(&self.sessions_expired),
            stalled_streams: load(&self.stalled_streams),
            notifications_dropped: load(&self.notifications_dropped),
            child_group_kills: load(&self.children.group_kills),
            sessions_revoked: load(&self.sessions_revoked),
        }
    }
}

#[derive(Debug)]
enum Kind {
    Stdio(Arc<stdio::StdioExport>),
    Http(Arc<http_backend::HttpBackendExport>),
}

/// One configured MCP export.
#[derive(Debug, Clone)]
pub struct McpExport {
    profile: McpProfile,
    limits: McpLimits,
    kind: Arc<Kind>,
    counters: Arc<ExportCounters>,
}

impl McpExport {
    /// Build an export from configuration.  A Streamable HTTP export reads
    /// its bearer token file here, once.
    ///
    /// # Errors
    /// The first configuration rule violated.
    pub fn from_config(config: &McpExportConfig) -> Result<Self, McpConfigError> {
        let validated = config.validate()?;
        let counters = Arc::new(ExportCounters::default());
        let kind = match validated.backend {
            config::ValidatedBackend::Stdio(backend) => {
                Kind::Stdio(Arc::new(stdio::StdioExport::new(
                    validated.profile,
                    validated.limits,
                    backend,
                    Arc::clone(&counters),
                )))
            }
            config::ValidatedBackend::Http(backend) => {
                Kind::Http(Arc::new(http_backend::HttpBackendExport::new(
                    validated.profile,
                    validated.limits,
                    backend,
                    Arc::clone(&counters),
                )?))
            }
        };
        Ok(Self {
            profile: validated.profile,
            limits: validated.limits,
            kind: Arc::new(kind),
            counters,
        })
    }

    #[must_use]
    pub const fn profile(&self) -> McpProfile {
        self.profile
    }

    /// The selected profile's `http-forward/1` policies with this export's
    /// limits.
    ///
    /// # Errors
    /// Only if the pinned profile tables are inconsistent.
    pub fn profile_policies(&self) -> Result<Profile, tunnel_http_forward::PolicyError> {
        self.profile.policies(self.limits)
    }

    /// Payload-free counters.
    #[must_use]
    pub fn diagnostics(&self) -> ExportDiagnostics {
        self.counters.snapshot()
    }

    /// Protocol sessions a stdio export currently holds open, or `None` for a
    /// Streamable HTTP export, whose sessions belong to its backend.
    ///
    /// A reader that has seen `sessions_expired` or `sessions_ended` in
    /// [`Self::diagnostics`] sees the session that count announces already
    /// gone from this figure (M3-27).
    #[must_use]
    pub fn open_stdio_sessions(&self) -> Option<usize> {
        match &*self.kind {
            Kind::Stdio(export) => Some(export.open_sessions()),
            Kind::Http(_) => None,
        }
    }

    /// End every open protocol session this export holds and kill each
    /// session child's process group.
    ///
    /// Dropping the export does the same; this is the explicit form for a
    /// connector that stops its handlers before dropping them.  Idempotent.
    pub fn shutdown(&self) {
        match &*self.kind {
            Kind::Stdio(export) => export.shutdown_sessions(),
            // A Streamable HTTP export owns no process: its sessions belong
            // to the operator's backend, and forgetting its bindings is what
            // dropping it already does.
            Kind::Http(_) => {}
        }
    }

    /// End every protocol session held for the consumer whose principal
    /// binding is `binding`, because the relay reported that its
    /// authorization for this export ended (task row M3-16).  Returns how
    /// many sessions were ended.
    ///
    /// A stdio session is removed and its child's process group killed, as a
    /// `DELETE` would; later requests naming it get the unknown-session
    /// `404`.  A Streamable HTTP export forgets the backend sessions it bound
    /// to `binding`, so they are refused before the backend is dialled; the
    /// backend's own session state is the backend's to expire.  Sessions of
    /// every other binding are untouched.  Idempotent.
    #[must_use]
    pub fn end_principal_sessions(&self, binding: &str) -> u64 {
        let ended = match &*self.kind {
            Kind::Stdio(export) => export.end_binding_sessions(binding),
            Kind::Http(export) => export.forget_binding_sessions(binding),
        };
        self.counters
            .sessions_revoked
            .fetch_add(ended, std::sync::atomic::Ordering::Release);
        ended
    }

    /// Serve one exchange in process.
    ///
    /// # Errors
    /// [`ExportError`] when the exchange must be interrupted.
    pub async fn handle(
        &self,
        request: Request<ChannelBody>,
    ) -> Result<Response<ExportBody>, ExportError> {
        match &*self.kind {
            Kind::Stdio(export) => Arc::clone(export).handle(request).await,
            Kind::Http(export) => Arc::clone(export).handle(request).await,
        }
    }
}
