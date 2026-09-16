//! The `agent-tunnel.fs.v1` capability descriptor.
//!
//! This is the JSON a consumer receives from an authenticated `GET` on the
//! service URL before upgrading.  It is informative and never an authorization
//! credential.
//!
//! The schema in `docs/contracts/filesystem-capabilities.schema.json` carries
//! three rules its `$comment` defers to runtime.  All three are made
//! structurally impossible here instead of being checked:
//!
//! * `availability == "online"` implies `capabilityStatus == "current"` —
//!   [`Availability`] is one enum and emits both fields.
//! * `root.readOnly` must agree with the operation grant — it is derived from
//!   [`CapabilitySet::is_read_only`].
//! * `operations` must not exceed the primitive grant — it is derived by
//!   [`ClientOperation::derive_all`].
//!
//! There is therefore no constructor that can produce a descriptor disagreeing
//! with the grant it was built from.
//!
//! The JSON is emitted by hand rather than by a serializer so that field order,
//! the closed field set and the absence of escaping are pinned by this module
//! rather than by a dependency's configuration.

use core::fmt;

use crate::capability::{CapabilitySet, ClientOperation, FeatureSet};
use crate::limits::{LimitField, Limits};

/// The descriptor's `schemaVersion`.
pub const SCHEMA_VERSION: &str = "agent-tunnel.fs.v1";
/// The descriptor's `transport.type`.
pub const TRANSPORT_TYPE: &str = "websocket";
/// The descriptor's `transport.subprotocol`.
pub const TRANSPORT_SUBPROTOCOL: &str = "agent-tunnel.9p.v1";
/// The descriptor's `transport.dialect`.
pub const TRANSPORT_DIALECT: &str = "9P2000.L";
/// The descriptor's `root.path`.  One connection is one root.
pub const ROOT_PATH: &str = "/";
/// The descriptor's `root.pathStyle`.
pub const ROOT_PATH_STYLE: &str = "virtual-posix";
/// Largest identifier length, matching the schema's `maxLength`.
pub const MAX_IDENTIFIER_BYTES: usize = 128;

/// `features` fields that this profile pins to `false`.
///
/// These are the non-baseline capabilities of `docs/filesystem-api.md`.  They
/// are emitted as constants rather than modelled, so no configuration can turn
/// one on without a contract change.
pub const NON_BASELINE_FEATURES: [&str; 7] = [
    "conditionalWrites",
    "versioning",
    "objectMetadata",
    "publicUrls",
    "signedUrls",
    "serverCopy",
    "serverSearch",
];

/// Why an identifier was refused.  Field-free.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum IdentifierRule {
    /// The identifier was empty.
    Empty,
    /// The identifier exceeded [`MAX_IDENTIFIER_BYTES`].
    TooLong,
    /// The identifier contained a character outside the permitted set.
    DisallowedCharacter,
}

impl IdentifierRule {
    /// The stable diagnostic token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Empty => "IDENTIFIER_EMPTY",
            Self::TooLong => "IDENTIFIER_TOO_LONG",
            Self::DisallowedCharacter => "IDENTIFIER_DISALLOWED_CHARACTER",
        }
    }

    /// Every rule.
    pub const ALL: [Self; 3] = [Self::Empty, Self::TooLong, Self::DisallowedCharacter];
}

impl fmt::Display for IdentifierRule {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl std::error::Error for IdentifierRule {}

/// A device, service or grant-revision identifier.
///
/// Restricted to ASCII alphanumerics, `-`, `_` and `.`.  That is narrower than
/// the schema's length-only rule, deliberately: it makes JSON escaping
/// unnecessary, so the emitter below cannot be the place a quote or a control
/// character escapes into the document.  Identifiers are the one class of value
/// `AGENTS.md` permits diagnostics to expose, so `Debug` shows them.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Identifier(String);

impl Identifier {
    /// Validate an identifier.
    ///
    /// # Errors
    ///
    /// Returns the [`IdentifierRule`] that refused it.
    pub fn parse(text: &str) -> Result<Self, IdentifierRule> {
        if text.is_empty() {
            return Err(IdentifierRule::Empty);
        }
        if text.len() > MAX_IDENTIFIER_BYTES {
            return Err(IdentifierRule::TooLong);
        }
        if !text
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            return Err(IdentifierRule::DisallowedCharacter);
        }
        Ok(Self(text.to_owned()))
    }

    /// The identifier text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Identifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Whether the device is connected, and by implication how fresh the
/// capabilities are.
///
/// One enum for both `availability` and `capabilityStatus`, so the schema's
/// conditional between them cannot be violated.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub enum Availability {
    /// The device is connected; capabilities are current.
    Online,
    /// The device is not connected; capabilities are last known.
    #[default]
    Offline,
}

impl Availability {
    /// The `availability` field value.
    #[must_use]
    pub const fn availability(self) -> &'static str {
        match self {
            Self::Online => "online",
            Self::Offline => "offline",
        }
    }

    /// The `capabilityStatus` field value implied by this availability.
    #[must_use]
    pub const fn capability_status(self) -> &'static str {
        match self {
            Self::Online => "current",
            Self::Offline => "last-known",
        }
    }
}

/// The host's observed case behaviour.
///
/// Reported, never assumed: the contract forbids lowercasing keys or claiming a
/// case-sensitive store on a case-insensitive host.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub enum CaseSensitivity {
    /// Distinct cases are distinct files.
    #[default]
    Sensitive,
    /// Cases collide, and the host preserves the case it was given.
    InsensitivePreserving,
}

impl CaseSensitivity {
    /// The `root.caseSensitivity` field value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sensitive => "sensitive",
            Self::InsensitivePreserving => "insensitive-preserving",
        }
    }
}

/// The three identifiers that name one export and the grant it was read at.
///
/// Grouped so a descriptor cannot be built with a service from one export and a
/// grant revision from another by argument transposition.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ExportIdentity {
    /// The enrolled device.
    pub device_id: Identifier,
    /// The service export on that device.
    pub service_id: Identifier,
    /// The opaque revision of the grant these capabilities were read at.
    pub grant_revision: Identifier,
}

/// A complete, internally consistent capability descriptor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Descriptor {
    identity: ExportIdentity,
    availability: Availability,
    case_sensitivity: CaseSensitivity,
    grant: CapabilitySet,
    features: FeatureSet,
    limits: Limits,
}

impl Descriptor {
    /// Build a descriptor from a grant.
    ///
    /// `operations` and `root.readOnly` are derived, not supplied, so the
    /// result always agrees with `grant` and `features`.
    #[must_use]
    pub const fn new(
        identity: ExportIdentity,
        availability: Availability,
        case_sensitivity: CaseSensitivity,
        grant: CapabilitySet,
        features: FeatureSet,
        limits: Limits,
    ) -> Self {
        Self {
            identity,
            availability,
            case_sensitivity,
            grant,
            features,
            limits,
        }
    }

    /// The export this descriptor names.
    #[must_use]
    pub const fn identity(&self) -> &ExportIdentity {
        &self.identity
    }

    /// The device identifier.
    #[must_use]
    pub const fn device_id(&self) -> &Identifier {
        &self.identity.device_id
    }

    /// The service identifier.
    #[must_use]
    pub const fn service_id(&self) -> &Identifier {
        &self.identity.service_id
    }

    /// The opaque grant revision.
    #[must_use]
    pub const fn grant_revision(&self) -> &Identifier {
        &self.identity.grant_revision
    }

    /// The device availability.
    #[must_use]
    pub const fn availability(&self) -> Availability {
        self.availability
    }

    /// The enforced capability grant.
    #[must_use]
    pub const fn grant(&self) -> CapabilitySet {
        self.grant
    }

    /// The implemented provider features.
    #[must_use]
    pub const fn features(&self) -> FeatureSet {
        self.features
    }

    /// The negotiated limits.
    #[must_use]
    pub const fn limits(&self) -> Limits {
        self.limits
    }

    /// The derived, advertised client operations.
    #[must_use]
    pub fn operations(&self) -> Vec<ClientOperation> {
        ClientOperation::derive_all(self.grant, self.features)
    }

    /// Whether the advertised root is read-only, derived from the grant.
    #[must_use]
    pub const fn is_read_only(&self) -> bool {
        self.grant.is_read_only()
    }

    /// Emit the descriptor as JSON.
    ///
    /// Two-space indentation and schema field order, matching
    /// `docs/contracts/filesystem-capabilities.example.json` exactly.  No value
    /// emitted here needs escaping: identifiers are restricted, every other
    /// string is a constant, and the rest are booleans and integers.
    #[must_use]
    pub fn to_json(&self) -> String {
        use core::fmt::Write as _;

        let mut out = String::with_capacity(1_536);
        out.push_str("{\n");
        let _ = writeln!(out, "  \"schemaVersion\": \"{SCHEMA_VERSION}\",");
        let _ = writeln!(out, "  \"deviceId\": \"{}\",", self.identity.device_id);
        let _ = writeln!(out, "  \"serviceId\": \"{}\",", self.identity.service_id);
        let _ = writeln!(
            out,
            "  \"grantRevision\": \"{}\",",
            self.identity.grant_revision
        );
        let _ = writeln!(
            out,
            "  \"availability\": \"{}\",",
            self.availability.availability()
        );
        let _ = writeln!(
            out,
            "  \"capabilityStatus\": \"{}\",",
            self.availability.capability_status()
        );

        out.push_str("  \"transport\": {\n");
        let _ = writeln!(out, "    \"type\": \"{TRANSPORT_TYPE}\",");
        let _ = writeln!(out, "    \"subprotocol\": \"{TRANSPORT_SUBPROTOCOL}\",");
        let _ = writeln!(out, "    \"dialect\": \"{TRANSPORT_DIALECT}\"");
        out.push_str("  },\n");

        out.push_str("  \"root\": {\n");
        let _ = writeln!(out, "    \"path\": \"{ROOT_PATH}\",");
        let _ = writeln!(out, "    \"pathStyle\": \"{ROOT_PATH_STYLE}\",");
        let _ = writeln!(
            out,
            "    \"caseSensitivity\": \"{}\",",
            self.case_sensitivity.as_str()
        );
        let _ = writeln!(out, "    \"readOnly\": {}", self.is_read_only());
        out.push_str("  },\n");

        let operations = self.operations();
        if operations.is_empty() {
            out.push_str("  \"operations\": [],\n");
        } else {
            out.push_str("  \"operations\": [\n");
            for (index, operation) in operations.iter().enumerate() {
                let comma = if index + 1 == operations.len() {
                    ""
                } else {
                    ","
                };
                let _ = writeln!(out, "    \"{}\"{comma}", operation.as_str());
            }
            out.push_str("  ],\n");
        }

        out.push_str("  \"features\": {\n");
        let negotiable = [
            ("atomicRename", crate::capability::Feature::AtomicRename),
            ("nativeAppend", crate::capability::Feature::NativeAppend),
            (
                "exclusiveCreate",
                crate::capability::Feature::ExclusiveCreate,
            ),
            ("symlinks", crate::capability::Feature::Symlinks),
            ("hardLinks", crate::capability::Feature::HardLinks),
            ("birthTime", crate::capability::Feature::BirthTime),
            ("fsync", crate::capability::Feature::Fsync),
        ];
        for (name, feature) in negotiable {
            let _ = writeln!(out, "    \"{name}\": {},", self.features.has(feature));
        }
        for (index, name) in NON_BASELINE_FEATURES.iter().enumerate() {
            let comma = if index + 1 == NON_BASELINE_FEATURES.len() {
                ""
            } else {
                ","
            };
            let _ = writeln!(out, "    \"{name}\": false{comma}");
        }
        out.push_str("  },\n");

        out.push_str("  \"limits\": {\n");
        for (index, field) in LimitField::ALL.into_iter().enumerate() {
            let comma = if index + 1 == LimitField::ALL.len() {
                ""
            } else {
                ","
            };
            let _ = writeln!(
                out,
                "    \"{}\": {}{comma}",
                field.as_str(),
                self.limits.get(field)
            );
        }
        out.push_str("  }\n");

        out.push_str("}\n");
        out
    }
}
