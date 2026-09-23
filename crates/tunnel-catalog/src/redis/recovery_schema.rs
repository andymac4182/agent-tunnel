//! Pure validation and canonicalisation for a complete Redis recovery scan.
//!
//! Recovery must observe one complete namespace before an operator-approved
//! activation.  This module deliberately has no Redis or catalog connection
//! dependency: the reader supplies bounded key/type/TTL/value observations,
//! and the module validates the namespace graph before producing the bytes
//! that are bound to a recovery approval.  Ephemeral leases, tickets and
//! membership caches are checked for shape and excluded from those bytes.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;

use uuid::Uuid;

/// Version of the canonical durable catalog observation schema.
pub const RECOVERY_SNAPSHOT_SCHEMA_VERSION: u16 = 1;

/// Maximum number of keys accepted from one complete namespace observation.
pub const MAX_RECOVERY_SNAPSHOT_KEYS: usize = 16_384;

/// Maximum number of fields or members in one observed Redis collection.
pub const MAX_RECOVERY_SNAPSHOT_MEMBERS: usize = 8_192;

/// Maximum size of an individual Redis key, field, member or value.
pub const MAX_RECOVERY_SNAPSHOT_VALUE_BYTES: usize = 256 * 1024;

/// Maximum size of a canonical snapshot.
pub const MAX_RECOVERY_SNAPSHOT_BYTES: usize = 4 * 1024 * 1024;

const MAX_RECOVERY_SNAPSHOT_FIELDS: usize = 8_192;
const MAX_IDENTIFIER_BYTES: usize = 128;
const MAX_IDENTITY_ISSUER_BYTES: usize = 2_048;
const MAX_IDENTITY_SUBJECT_BYTES: usize = 1_024;
const MAX_SAFE_REDIS_TIME_US: i64 = 9_000_000_000_000_000;
const MAX_OPERATOR_DIRECTORY_RECORDS: usize = 4_096;
const CANONICAL_PREFIX: &[u8] = b"tunnel-catalog-recovery\0";

/// Redis data types that can occur in a complete namespace scan.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObservedRedisType {
    Hash,
    Set,
    String,
    Zset,
}

/// Bounded values returned by the Redis reader.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ObservedRedisValue {
    Hash(Vec<(String, String)>),
    Set(Vec<String>),
    String(String),
    /// ZSET entries are `(member, score)`.  Scores are represented as their
    /// Redis decimal strings so the pure schema does not lose precision.
    Zset(Vec<(String, String)>),
}

/// One complete observed Redis key.  A missing key is represented by omission
/// from the enclosing slice; Redis's `-2` missing-key TTL is never accepted as
/// an observed value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObservedRedisKey {
    pub key: String,
    pub redis_type: ObservedRedisType,
    /// Redis PTTL semantics: `-1` means no expiry, and non-negative values
    /// are the remaining TTL for an ephemeral key.
    pub ttl_ms: i64,
    pub value: ObservedRedisValue,
}

#[cfg(test)]
impl ObservedRedisKey {
    pub fn hash(key: impl Into<String>, ttl_ms: i64, fields: Vec<(String, String)>) -> Self {
        Self {
            key: key.into(),
            redis_type: ObservedRedisType::Hash,
            ttl_ms,
            value: ObservedRedisValue::Hash(fields),
        }
    }

    pub fn set(key: impl Into<String>, ttl_ms: i64, members: Vec<String>) -> Self {
        Self {
            key: key.into(),
            redis_type: ObservedRedisType::Set,
            ttl_ms,
            value: ObservedRedisValue::Set(members),
        }
    }

    pub fn string(key: impl Into<String>, ttl_ms: i64, value: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            redis_type: ObservedRedisType::String,
            ttl_ms,
            value: ObservedRedisValue::String(value.into()),
        }
    }
}

/// A canonical entry included in the approval-bound durable observation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalEntry {
    kind: CanonicalKind,
    key: String,
    fields: Vec<(String, String)>,
}

/// Canonical Redis value kind.  ZSET and ephemeral entries never appear here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CanonicalKind {
    Hash,
    Set,
    String,
}

/// A validated, bounded durable snapshot ready for digesting and approval
/// comparison.  The catalog generation is a live concurrency fence only and
/// is intentionally absent from `canonical_bytes`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedCatalogSnapshot {
    canonical_entries: Vec<CanonicalEntry>,
    canonical_bytes: Vec<u8>,
    durable_key_count: usize,
    catalog_generation: Option<u64>,
}

impl ValidatedCatalogSnapshot {
    /// Number of observed durable Redis keys.
    pub fn durable_key_count(&self) -> usize {
        self.durable_key_count
    }

    /// Number of entries in the canonical byte stream.
    #[cfg(test)]
    pub fn canonical_entry_count(&self) -> usize {
        self.canonical_entries.len()
    }

    pub fn canonical_byte_count(&self) -> usize {
        self.canonical_bytes.len()
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    #[cfg(test)]
    pub fn canonical_entries(&self) -> &[CanonicalEntry] {
        &self.canonical_entries
    }

    /// The live mutation generation, when the namespace has created it.  It
    /// is not an external rollback checkpoint and is not digest-bound.
    pub fn catalog_generation(&self) -> Option<u64> {
        self.catalog_generation
    }
}

/// Errors returned by pure snapshot validation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SnapshotSchemaError {
    InvalidPrefix,
    InputBound,
    InputBytesBound,
    DuplicateKey,
    UnknownKey,
    MalformedKey,
    TypeMismatch,
    TtlMismatch,
    ValueBound,
    FieldShape,
    InvalidValue,
    InvalidRelationship,
    Orphan,
    MissingEpoch,
    CanonicalBound,
}

impl fmt::Display for SnapshotSchemaError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidPrefix => "invalid recovery namespace prefix",
            Self::InputBound => "recovery snapshot key bound",
            Self::InputBytesBound => "recovery snapshot input byte bound",
            Self::DuplicateKey => "duplicate recovery snapshot key",
            Self::UnknownKey => "unknown Redis key class",
            Self::MalformedKey => "malformed Redis key",
            Self::TypeMismatch => "Redis type does not match key class",
            Self::TtlMismatch => "Redis TTL does not match key class",
            Self::ValueBound => "Redis value bound",
            Self::FieldShape => "Redis hash field shape",
            Self::InvalidValue => "invalid Redis value",
            Self::InvalidRelationship => "invalid catalog relationship",
            Self::Orphan => "orphan Redis index or direct lookup",
            Self::MissingEpoch => "missing durable device epoch",
            Self::CanonicalBound => "canonical recovery snapshot bound",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for SnapshotSchemaError {}

#[derive(Clone, Debug, PartialEq, Eq)]
enum DurableHashClass {
    Tenant {
        tenant: String,
    },
    User {
        user: String,
    },
    Identity {
        issuer_component: String,
        subject_component: String,
    },
    Membership {
        tenant: String,
        user: String,
    },
    Device {
        tenant: String,
        device: String,
    },
    Credential {
        tenant: String,
        device: String,
        credential: String,
    },
    Service {
        tenant: String,
        device: String,
        service: String,
    },
    Grant {
        tenant: String,
        principal: String,
        device: String,
        service: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum DurableSetClass {
    Tenants,
    Users,
    Identities,
    Memberships { tenant: String },
    UserTenants { user: String },
    Devices { tenant: String },
    Credentials { tenant: String, device: String },
    Services { tenant: String, device: String },
    GrantsDevice { tenant: String, device: String },
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum DurableStringClass {
    Fingerprint { fingerprint: String },
    Epoch { tenant: String, device: String },
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum EphemeralHashClass {
    Owner {
        incarnation: String,
        tenant: String,
        device: String,
    },
    Ticket {
        incarnation: String,
        tenant: String,
        device: String,
        digest: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum EphemeralZsetClass {
    Tickets {
        incarnation: String,
        tenant: String,
        device: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum MetadataClass {
    ActiveIncarnation,
    RedisRunId,
    /// A single relay's restart continuity token (M6-C65).
    Continuity,
    CatalogGeneration,
    FixtureSeeded,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum ParsedClass {
    DurableHash(DurableHashClass),
    DurableSet(DurableSetClass),
    DurableString(DurableStringClass),
    EphemeralHash(EphemeralHashClass),
    EphemeralZset(EphemeralZsetClass),
    Metadata(MetadataClass),
    OperatorCurrent,
    OperatorDirectory,
}

impl ParsedClass {
    fn is_durable(&self) -> bool {
        matches!(
            self,
            Self::DurableHash(_) | Self::DurableSet(_) | Self::DurableString(_)
        )
    }

    fn expected_type(&self) -> ObservedRedisType {
        match self {
            Self::DurableHash(_)
            | Self::EphemeralHash(_)
            | Self::OperatorCurrent
            | Self::OperatorDirectory => ObservedRedisType::Hash,
            Self::DurableSet(_) => ObservedRedisType::Set,
            Self::DurableString(_) | Self::Metadata(_) => ObservedRedisType::String,
            Self::EphemeralZset(_) => ObservedRedisType::Zset,
        }
    }

    fn requires_ttl(&self) -> bool {
        matches!(
            self,
            Self::EphemeralHash(_)
                | Self::EphemeralZset(_)
                | Self::OperatorCurrent
                | Self::OperatorDirectory
        )
    }
}

struct ParsedObserved<'a> {
    observed: &'a ObservedRedisKey,
    class: ParsedClass,
}

#[derive(Default)]
struct CatalogFacts {
    tenants: HashSet<String>,
    users: HashSet<String>,
    identities: HashSet<String>,
    memberships: HashSet<(String, String)>,
    devices: HashSet<(String, String)>,
    device_owners: HashMap<(String, String), String>,
    credentials: HashSet<(String, String, String)>,
    credential_fingerprints: HashMap<String, String>,
    services: HashSet<(String, String, String)>,
    grants: HashSet<(String, String, String, String)>,
    grant_keys: HashSet<String>,
    indexes: HashMap<String, HashSet<String>>,
    fingerprint_indexes: HashMap<String, String>,
    epochs: HashMap<(String, String), u64>,
    ticket_indexes: HashMap<String, HashSet<String>>,
}

/// Validate one complete observed namespace and return its canonical durable
/// representation.  The caller must provide every key returned by its bounded
/// namespace scan, including ephemeral keys that were present at observation;
/// known ephemeral keys are validated but intentionally omitted from the
/// canonical digest.  If an ephemeral key disappears while collecting, the
/// reader should retry/abort under its owner-quiescence policy instead of
/// fabricating a durable value.
pub fn validate_observed_catalog(
    namespace_prefix: &str,
    keys: &[ObservedRedisKey],
) -> Result<ValidatedCatalogSnapshot, SnapshotSchemaError> {
    validate_prefix(namespace_prefix)?;
    if keys.len() > MAX_RECOVERY_SNAPSHOT_KEYS {
        return Err(SnapshotSchemaError::InputBound);
    }

    let mut parsed = Vec::with_capacity(keys.len());
    let mut seen = HashSet::with_capacity(keys.len());
    let mut input_bytes = 0_usize;
    for observed in keys {
        if observed.key.len() > MAX_RECOVERY_SNAPSHOT_VALUE_BYTES
            || !seen.insert(observed.key.as_str())
        {
            return Err(if observed.key.len() > MAX_RECOVERY_SNAPSHOT_VALUE_BYTES {
                SnapshotSchemaError::ValueBound
            } else {
                SnapshotSchemaError::DuplicateKey
            });
        }
        input_bytes = input_bytes
            .checked_add(observed.key.len())
            .ok_or(SnapshotSchemaError::InputBytesBound)?;
        validate_value_shape(observed, &mut input_bytes)?;

        let class = classify_key(namespace_prefix, &observed.key)?;
        if observed.redis_type != class.expected_type() {
            return Err(SnapshotSchemaError::TypeMismatch);
        }
        if class.requires_ttl() {
            if observed.ttl_ms < 0 {
                return Err(SnapshotSchemaError::TtlMismatch);
            }
        } else if observed.ttl_ms != -1 {
            return Err(SnapshotSchemaError::TtlMismatch);
        }
        validate_class_value(&class, observed)?;
        if input_bytes > MAX_RECOVERY_SNAPSHOT_BYTES {
            return Err(SnapshotSchemaError::InputBytesBound);
        }
        parsed.push(ParsedObserved { observed, class });
    }

    let mut facts = CatalogFacts::default();
    let mut catalog_generation = None;
    for parsed_key in &parsed {
        let key = &parsed_key.observed.key;
        match &parsed_key.class {
            ParsedClass::DurableHash(class) => {
                collect_durable_hash_facts(
                    namespace_prefix,
                    key,
                    class,
                    hash_value(parsed_key.observed)?,
                    &mut facts,
                )?;
            }
            ParsedClass::DurableSet(_) => {
                let members = set_value(parsed_key.observed)?;
                let mut set = HashSet::with_capacity(members.len());
                for member in members {
                    if !set.insert(member.clone()) {
                        return Err(SnapshotSchemaError::FieldShape);
                    }
                }
                facts.indexes.insert(key.clone(), set);
            }
            ParsedClass::DurableString(class) => {
                let value = string_value(parsed_key.observed)?;
                match class {
                    DurableStringClass::Fingerprint { fingerprint } => {
                        if facts
                            .fingerprint_indexes
                            .insert(fingerprint.clone(), value.to_owned())
                            .is_some()
                        {
                            return Err(SnapshotSchemaError::DuplicateKey);
                        }
                    }
                    DurableStringClass::Epoch { tenant, device } => {
                        let epoch = parse_u64(value)?;
                        if facts
                            .epochs
                            .insert((tenant.clone(), device.clone()), epoch)
                            .is_some()
                        {
                            return Err(SnapshotSchemaError::DuplicateKey);
                        }
                    }
                }
            }
            ParsedClass::EphemeralHash(_) => {}
            ParsedClass::EphemeralZset(EphemeralZsetClass::Tickets { .. }) => {
                let members = zset_value(parsed_key.observed)?;
                let mut set = HashSet::with_capacity(members.len());
                for (member, score) in members {
                    if !is_lower_hex(member, 64) || parse_i64(score)? < 0 {
                        return Err(SnapshotSchemaError::InvalidValue);
                    }
                    if !set.insert(member.clone()) {
                        return Err(SnapshotSchemaError::FieldShape);
                    }
                }
                facts.ticket_indexes.insert(key.clone(), set);
            }
            ParsedClass::Metadata(MetadataClass::CatalogGeneration) => {
                catalog_generation = Some(parse_u64(string_value(parsed_key.observed)?)?);
            }
            ParsedClass::Metadata(_)
            | ParsedClass::OperatorCurrent
            | ParsedClass::OperatorDirectory => {}
        }
    }

    // Redis SCAN order is unspecified.  Validate every index only after all
    // record facts have been collected, so an index cannot look orphaned just
    // because its record appeared later in the input slice.
    for parsed_key in &parsed {
        if let ParsedClass::DurableSet(class) = &parsed_key.class {
            let members = set_value(parsed_key.observed)?;
            let members = members.iter().cloned().collect::<HashSet<_>>();
            validate_index_members(namespace_prefix, class, &members, &facts)?;
        }
    }

    validate_catalog_relationships(namespace_prefix, &parsed, &facts)?;
    validate_ephemeral_relationships(namespace_prefix, &parsed, &facts)?;

    let mut entries = BTreeMap::new();
    for parsed_key in &parsed {
        if !parsed_key.class.is_durable() {
            continue;
        }
        let entry = canonical_entry(parsed_key.observed)?;
        if entries.insert(entry.key.clone(), entry).is_some() {
            return Err(SnapshotSchemaError::DuplicateKey);
        }
    }

    for (tenant, device) in &facts.devices {
        if !facts.epochs.contains_key(&(tenant.clone(), device.clone())) {
            return Err(SnapshotSchemaError::MissingEpoch);
        }
    }

    let canonical_entries: Vec<_> = entries.into_values().collect();
    let canonical_bytes = encode_canonical(&canonical_entries)?;
    Ok(ValidatedCatalogSnapshot {
        canonical_entries,
        canonical_bytes,
        durable_key_count: parsed.iter().filter(|item| item.class.is_durable()).count(),
        catalog_generation,
    })
}

fn validate_prefix(prefix: &str) -> Result<(), SnapshotSchemaError> {
    if prefix.is_empty()
        || prefix.len() > MAX_IDENTIFIER_BYTES
        || !prefix.ends_with(':')
        || prefix.as_bytes().contains(&0)
    {
        return Err(SnapshotSchemaError::InvalidPrefix);
    }
    Ok(())
}

fn validate_value_shape(
    observed: &ObservedRedisKey,
    input_bytes: &mut usize,
) -> Result<(), SnapshotSchemaError> {
    let mut add = |length: usize| {
        *input_bytes = (*input_bytes)
            .checked_add(length)
            .ok_or(SnapshotSchemaError::InputBytesBound)?;
        if length > MAX_RECOVERY_SNAPSHOT_VALUE_BYTES {
            Err(SnapshotSchemaError::ValueBound)
        } else {
            Ok(())
        }
    };
    match (&observed.redis_type, &observed.value) {
        (ObservedRedisType::Hash, ObservedRedisValue::Hash(fields)) => {
            if fields.len() > MAX_RECOVERY_SNAPSHOT_FIELDS {
                return Err(SnapshotSchemaError::ValueBound);
            }
            for (field, value) in fields {
                add(field.len())?;
                add(value.len())?;
            }
        }
        (ObservedRedisType::Set, ObservedRedisValue::Set(members)) => {
            if members.len() > MAX_RECOVERY_SNAPSHOT_MEMBERS {
                return Err(SnapshotSchemaError::ValueBound);
            }
            for member in members {
                add(member.len())?;
            }
        }
        (ObservedRedisType::String, ObservedRedisValue::String(value)) => add(value.len())?,
        (ObservedRedisType::Zset, ObservedRedisValue::Zset(entries)) => {
            if entries.len() > MAX_RECOVERY_SNAPSHOT_MEMBERS {
                return Err(SnapshotSchemaError::ValueBound);
            }
            for (member, score) in entries {
                add(member.len())?;
                add(score.len())?;
            }
        }
        _ => return Err(SnapshotSchemaError::TypeMismatch),
    }
    Ok(())
}

fn classify_key(prefix: &str, key: &str) -> Result<ParsedClass, SnapshotSchemaError> {
    let rest = key
        .strip_prefix(prefix)
        .ok_or(SnapshotSchemaError::UnknownKey)?;
    match rest {
        "meta:active_incarnation" => {
            return Ok(ParsedClass::Metadata(MetadataClass::ActiveIncarnation));
        }
        "meta:redis_run_id" => return Ok(ParsedClass::Metadata(MetadataClass::RedisRunId)),
        "meta:continuity" => return Ok(ParsedClass::Metadata(MetadataClass::Continuity)),
        "meta:catalog_generation" => {
            return Ok(ParsedClass::Metadata(MetadataClass::CatalogGeneration));
        }
        "meta:fixture_seeded" => return Ok(ParsedClass::Metadata(MetadataClass::FixtureSeeded)),
        "membership:operator:current" => return Ok(ParsedClass::OperatorCurrent),
        "membership:operator:directory" => return Ok(ParsedClass::OperatorDirectory),
        "idx:tenants" => return Ok(ParsedClass::DurableSet(DurableSetClass::Tenants)),
        "idx:users" => return Ok(ParsedClass::DurableSet(DurableSetClass::Users)),
        "idx:identities" => return Ok(ParsedClass::DurableSet(DurableSetClass::Identities)),
        _ => {}
    }

    if let Some(tail) = rest.strip_prefix("tenant:") {
        return one_uuid(tail)
            .map(|tenant| ParsedClass::DurableHash(DurableHashClass::Tenant { tenant }));
    }
    if let Some(tail) = rest.strip_prefix("user:") {
        return one_uuid(tail)
            .map(|user| ParsedClass::DurableHash(DurableHashClass::User { user }));
    }
    if let Some(tail) = rest.strip_prefix("identity:") {
        let parts = exact_parts(tail, 2)?;
        let issuer_component = key_component(&parts[0])?;
        let subject_component = key_component(&parts[1])?;
        return Ok(ParsedClass::DurableHash(DurableHashClass::Identity {
            issuer_component,
            subject_component,
        }));
    }
    if let Some(tail) = rest.strip_prefix("membership:") {
        let parts = exact_parts(tail, 2)?;
        return Ok(ParsedClass::DurableHash(DurableHashClass::Membership {
            tenant: uuid_component(&parts[0])?,
            user: uuid_component(&parts[1])?,
        }));
    }
    if let Some(tail) = rest.strip_prefix("device:") {
        let parts = exact_parts(tail, 2)?;
        return Ok(ParsedClass::DurableHash(DurableHashClass::Device {
            tenant: uuid_component(&parts[0])?,
            device: uuid_component(&parts[1])?,
        }));
    }
    if let Some(tail) = rest.strip_prefix("credential:") {
        let parts = exact_parts(tail, 3)?;
        return Ok(ParsedClass::DurableHash(DurableHashClass::Credential {
            tenant: uuid_component(&parts[0])?,
            device: uuid_component(&parts[1])?,
            credential: uuid_component(&parts[2])?,
        }));
    }
    if let Some(tail) = rest.strip_prefix("service:") {
        let parts = exact_parts(tail, 3)?;
        return Ok(ParsedClass::DurableHash(DurableHashClass::Service {
            tenant: uuid_component(&parts[0])?,
            device: uuid_component(&parts[1])?,
            service: uuid_component(&parts[2])?,
        }));
    }
    if let Some(tail) = rest.strip_prefix("grant:") {
        let parts = exact_parts(tail, 4)?;
        return Ok(ParsedClass::DurableHash(DurableHashClass::Grant {
            tenant: uuid_component(&parts[0])?,
            principal: uuid_component(&parts[1])?,
            device: uuid_component(&parts[2])?,
            service: uuid_component(&parts[3])?,
        }));
    }

    if let Some(tail) = rest.strip_prefix("idx:memberships:") {
        return one_uuid(tail)
            .map(|tenant| ParsedClass::DurableSet(DurableSetClass::Memberships { tenant }));
    }
    if let Some(tail) = rest.strip_prefix("idx:user_tenants:") {
        return one_uuid(tail)
            .map(|user| ParsedClass::DurableSet(DurableSetClass::UserTenants { user }));
    }
    if let Some(tail) = rest.strip_prefix("idx:devices:") {
        return one_uuid(tail)
            .map(|tenant| ParsedClass::DurableSet(DurableSetClass::Devices { tenant }));
    }
    if let Some(tail) = rest.strip_prefix("idx:credentials:") {
        let parts = exact_parts(tail, 2)?;
        return Ok(ParsedClass::DurableSet(DurableSetClass::Credentials {
            tenant: uuid_component(&parts[0])?,
            device: uuid_component(&parts[1])?,
        }));
    }
    if let Some(tail) = rest.strip_prefix("idx:services:") {
        let parts = exact_parts(tail, 2)?;
        return Ok(ParsedClass::DurableSet(DurableSetClass::Services {
            tenant: uuid_component(&parts[0])?,
            device: uuid_component(&parts[1])?,
        }));
    }
    if let Some(tail) = rest.strip_prefix("idx:grants_device:") {
        let parts = exact_parts(tail, 2)?;
        return Ok(ParsedClass::DurableSet(DurableSetClass::GrantsDevice {
            tenant: uuid_component(&parts[0])?,
            device: uuid_component(&parts[1])?,
        }));
    }
    if let Some(tail) = rest.strip_prefix("idx:fingerprint:") {
        if !is_lower_hex(tail, 64) {
            return Err(SnapshotSchemaError::MalformedKey);
        }
        return Ok(ParsedClass::DurableString(
            DurableStringClass::Fingerprint {
                fingerprint: tail.to_owned(),
            },
        ));
    }
    if let Some(tail) = rest.strip_prefix("coord:epoch:") {
        let parts = exact_parts(tail, 2)?;
        return Ok(ParsedClass::DurableString(DurableStringClass::Epoch {
            tenant: uuid_component(&parts[0])?,
            device: uuid_component(&parts[1])?,
        }));
    }
    if let Some(tail) = rest.strip_prefix("coord:owner:") {
        let parts = exact_parts(tail, 3)?;
        return Ok(ParsedClass::EphemeralHash(EphemeralHashClass::Owner {
            incarnation: key_component(&parts[0])?,
            tenant: uuid_component(&parts[1])?,
            device: uuid_component(&parts[2])?,
        }));
    }
    if let Some(tail) = rest.strip_prefix("coord:ticket:") {
        let parts = exact_parts(tail, 4)?;
        if !is_lower_hex(&parts[3], 64) {
            return Err(SnapshotSchemaError::MalformedKey);
        }
        return Ok(ParsedClass::EphemeralHash(EphemeralHashClass::Ticket {
            incarnation: key_component(&parts[0])?,
            tenant: uuid_component(&parts[1])?,
            device: uuid_component(&parts[2])?,
            digest: parts[3].clone(),
        }));
    }
    if let Some(tail) = rest.strip_prefix("coord:tickets:") {
        let parts = exact_parts(tail, 3)?;
        return Ok(ParsedClass::EphemeralZset(EphemeralZsetClass::Tickets {
            incarnation: key_component(&parts[0])?,
            tenant: uuid_component(&parts[1])?,
            device: uuid_component(&parts[2])?,
        }));
    }
    if rest.starts_with("meta:")
        || rest.starts_with("idx:")
        || rest.starts_with("coord:")
        || rest.starts_with("tenant:")
        || rest.starts_with("user:")
        || rest.starts_with("identity:")
        || rest.starts_with("membership:")
        || rest.starts_with("device:")
        || rest.starts_with("credential:")
        || rest.starts_with("service:")
        || rest.starts_with("grant:")
    {
        return Err(SnapshotSchemaError::MalformedKey);
    }
    Err(SnapshotSchemaError::UnknownKey)
}

fn exact_parts(value: &str, expected: usize) -> Result<Vec<String>, SnapshotSchemaError> {
    let parts: Vec<_> = value.split(':').collect();
    if parts.len() != expected || parts.iter().any(|part| part.is_empty()) {
        return Err(SnapshotSchemaError::MalformedKey);
    }
    Ok(parts.into_iter().map(str::to_owned).collect())
}

fn one_uuid(value: &str) -> Result<String, SnapshotSchemaError> {
    if value.contains(':') {
        return Err(SnapshotSchemaError::MalformedKey);
    }
    uuid_component(value)
}

fn uuid_component(value: &str) -> Result<String, SnapshotSchemaError> {
    let uuid = Uuid::parse_str(value).map_err(|_| SnapshotSchemaError::MalformedKey)?;
    let canonical = uuid.to_string();
    if canonical != value {
        return Err(SnapshotSchemaError::MalformedKey);
    }
    Ok(canonical)
}

fn key_component(value: &str) -> Result<String, SnapshotSchemaError> {
    let decoded = decode_key_component(value)?;
    if decoded.is_empty() || decoded.len() > MAX_RECOVERY_SNAPSHOT_VALUE_BYTES {
        return Err(SnapshotSchemaError::MalformedKey);
    }
    Ok(value.to_owned())
}

fn decode_key_component(value: &str) -> Result<String, SnapshotSchemaError> {
    if value.is_empty() {
        return Err(SnapshotSchemaError::MalformedKey);
    }
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'.' | b'-' => {
                decoded.push(bytes[index]);
                index += 1;
            }
            b'_' if index + 2 < bytes.len()
                && is_lower_hex_byte(bytes[index + 1])
                && is_lower_hex_byte(bytes[index + 2]) =>
            {
                decoded.push((hex_nibble(bytes[index + 1]) << 4) | hex_nibble(bytes[index + 2]));
                index += 3;
            }
            _ => return Err(SnapshotSchemaError::MalformedKey),
        }
    }
    let decoded = String::from_utf8(decoded).map_err(|_| SnapshotSchemaError::MalformedKey)?;
    if encode_key_component(&decoded) != value {
        return Err(SnapshotSchemaError::MalformedKey);
    }
    Ok(decoded)
}

fn encode_key_component(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-') {
            encoded.push(byte as char);
        } else {
            encoded.push('_');
            encoded.push_str(&format!("{byte:02x}"));
        }
    }
    encoded
}

fn hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => 0,
    }
}

fn is_lower_hex_byte(byte: u8) -> bool {
    byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn hash_value(observed: &ObservedRedisKey) -> Result<&[(String, String)], SnapshotSchemaError> {
    match &observed.value {
        ObservedRedisValue::Hash(fields) => Ok(fields),
        _ => Err(SnapshotSchemaError::TypeMismatch),
    }
}

fn set_value(observed: &ObservedRedisKey) -> Result<&[String], SnapshotSchemaError> {
    match &observed.value {
        ObservedRedisValue::Set(members) => Ok(members),
        _ => Err(SnapshotSchemaError::TypeMismatch),
    }
}

fn string_value(observed: &ObservedRedisKey) -> Result<&str, SnapshotSchemaError> {
    match &observed.value {
        ObservedRedisValue::String(value) => Ok(value),
        _ => Err(SnapshotSchemaError::TypeMismatch),
    }
}

fn zset_value(observed: &ObservedRedisKey) -> Result<&[(String, String)], SnapshotSchemaError> {
    match &observed.value {
        ObservedRedisValue::Zset(entries) => Ok(entries),
        _ => Err(SnapshotSchemaError::TypeMismatch),
    }
}

fn validate_class_value(
    class: &ParsedClass,
    observed: &ObservedRedisKey,
) -> Result<(), SnapshotSchemaError> {
    match class {
        ParsedClass::DurableHash(hash) => validate_durable_hash_fields(hash, hash_value(observed)?),
        ParsedClass::DurableString(DurableStringClass::Fingerprint { .. }) => {
            let value = string_value(observed)?;
            if value.len() > MAX_RECOVERY_SNAPSHOT_VALUE_BYTES || value.is_empty() {
                Err(SnapshotSchemaError::InvalidValue)
            } else {
                Ok(())
            }
        }
        ParsedClass::DurableString(DurableStringClass::Epoch { .. }) => {
            parse_u64(string_value(observed)?)?;
            Ok(())
        }
        ParsedClass::DurableSet(_) => {
            let members = set_value(observed)?;
            if members.len() > MAX_RECOVERY_SNAPSHOT_MEMBERS {
                return Err(SnapshotSchemaError::ValueBound);
            }
            Ok(())
        }
        ParsedClass::EphemeralHash(EphemeralHashClass::Owner {
            incarnation,
            tenant,
            device,
        }) => validate_owner_fields(incarnation, tenant, device, hash_value(observed)?),
        ParsedClass::EphemeralHash(EphemeralHashClass::Ticket {
            incarnation,
            tenant,
            device,
            digest,
        }) => validate_ticket_fields(incarnation, tenant, device, digest, hash_value(observed)?),
        ParsedClass::EphemeralZset(_) => {
            for (member, score) in zset_value(observed)? {
                if !is_lower_hex(member, 64) || parse_i64(score)? < 0 {
                    return Err(SnapshotSchemaError::InvalidValue);
                }
            }
            Ok(())
        }
        ParsedClass::Metadata(metadata) => validate_metadata(metadata, string_value(observed)?),
        ParsedClass::OperatorCurrent => validate_operator_current(hash_value(observed)?),
        ParsedClass::OperatorDirectory => validate_operator_directory(hash_value(observed)?),
    }
}

fn validate_durable_hash_fields(
    class: &DurableHashClass,
    fields: &[(String, String)],
) -> Result<(), SnapshotSchemaError> {
    match class {
        DurableHashClass::Tenant { .. } => {
            exact_fields(fields, &["tenant_id", "display_name", "active"])?;
            uuid_field(fields, "tenant_id")?;
            bool_field(fields, "active")?;
        }
        DurableHashClass::User { .. } => {
            exact_fields(fields, &["user_id", "display_name"])?;
            uuid_field(fields, "user_id")?;
        }
        DurableHashClass::Identity { .. } => {
            exact_fields(fields, &["issuer", "subject", "user_id"])?;
            identifier_field(fields, "issuer", MAX_IDENTITY_ISSUER_BYTES)?;
            identifier_field(fields, "subject", MAX_IDENTITY_SUBJECT_BYTES)?;
            uuid_field(fields, "user_id")?;
        }
        DurableHashClass::Membership { .. } => {
            exact_fields(fields, &["tenant_id", "user_id", "role", "active"])?;
            uuid_field(fields, "tenant_id")?;
            uuid_field(fields, "user_id")?;
            let role = field(fields, "role")?;
            if role != "member" && role != "admin" {
                return Err(SnapshotSchemaError::InvalidValue);
            }
            bool_field(fields, "active")?;
        }
        DurableHashClass::Device { .. } => {
            exact_fields(
                fields,
                &[
                    "tenant_id",
                    "device_id",
                    "owner_user_id",
                    "display_name",
                    "active",
                    "last_seen_at_us",
                    "device_version",
                ],
            )?;
            uuid_field(fields, "tenant_id")?;
            uuid_field(fields, "device_id")?;
            uuid_field(fields, "owner_user_id")?;
            bool_field(fields, "active")?;
            optional_i64_field(fields, "last_seen_at_us")?;
            parse_u64(field(fields, "device_version")?)?;
        }
        DurableHashClass::Credential { .. } => {
            exact_fields(
                fields,
                &[
                    "tenant_id",
                    "device_id",
                    "credential_id",
                    "spki_fingerprint",
                    "serial",
                    "not_before_us",
                    "expires_at_us",
                    "revoked_at_us",
                    "active",
                ],
            )?;
            uuid_field(fields, "tenant_id")?;
            uuid_field(fields, "device_id")?;
            uuid_field(fields, "credential_id")?;
            let fingerprint = field(fields, "spki_fingerprint")?;
            if !is_lower_hex(fingerprint, 64) {
                return Err(SnapshotSchemaError::InvalidValue);
            }
            let not_before = parse_i64(field(fields, "not_before_us")?)?;
            let expires = parse_i64(field(fields, "expires_at_us")?)?;
            if !(-MAX_SAFE_REDIS_TIME_US..=MAX_SAFE_REDIS_TIME_US).contains(&not_before)
                || !(-MAX_SAFE_REDIS_TIME_US..=MAX_SAFE_REDIS_TIME_US).contains(&expires)
                || expires <= not_before
            {
                return Err(SnapshotSchemaError::InvalidValue);
            }
            optional_i64_field(fields, "revoked_at_us")?;
            bool_field(fields, "active")?;
        }
        DurableHashClass::Service { .. } => {
            exact_fields(
                fields,
                &[
                    "tenant_id",
                    "device_id",
                    "service_id",
                    "service_type",
                    "display_name",
                    "capabilities",
                    "version",
                    "active",
                ],
            )?;
            uuid_field(fields, "tenant_id")?;
            uuid_field(fields, "device_id")?;
            uuid_field(fields, "service_id")?;
            identifier_field(fields, "service_type", MAX_RECOVERY_SNAPSHOT_VALUE_BYTES)?;
            json_field(fields, "capabilities")?;
            parse_u64(field(fields, "version")?)?;
            bool_field(fields, "active")?;
        }
        DurableHashClass::Grant { .. } => {
            exact_fields(
                fields,
                &[
                    "tenant_id",
                    "principal_id",
                    "device_id",
                    "service_id",
                    "revision",
                    "permissions",
                    "constraints",
                    "expires_at_us",
                    "active",
                    "revoked_at_us",
                ],
            )?;
            uuid_field(fields, "tenant_id")?;
            uuid_field(fields, "principal_id")?;
            uuid_field(fields, "device_id")?;
            uuid_field(fields, "service_id")?;
            parse_u64(field(fields, "revision")?)?;
            json_field(fields, "permissions")?;
            json_field(fields, "constraints")?;
            optional_i64_field(fields, "expires_at_us")?;
            bool_field(fields, "active")?;
            optional_i64_field(fields, "revoked_at_us")?;
        }
    }
    Ok(())
}

fn collect_durable_hash_facts(
    prefix: &str,
    key: &str,
    class: &DurableHashClass,
    fields: &[(String, String)],
    facts: &mut CatalogFacts,
) -> Result<(), SnapshotSchemaError> {
    match class {
        DurableHashClass::Tenant { tenant } => {
            if field(fields, "tenant_id")? != tenant {
                return Err(SnapshotSchemaError::InvalidRelationship);
            }
            facts.tenants.insert(tenant.clone());
        }
        DurableHashClass::User { user } => {
            if field(fields, "user_id")? != user {
                return Err(SnapshotSchemaError::InvalidRelationship);
            }
            facts.users.insert(user.clone());
        }
        DurableHashClass::Identity {
            issuer_component,
            subject_component,
        } => {
            let issuer = field(fields, "issuer")?;
            let subject = field(fields, "subject")?;
            if encode_key_component(issuer) != *issuer_component
                || encode_key_component(subject) != *subject_component
            {
                return Err(SnapshotSchemaError::InvalidRelationship);
            }
            facts.identities.insert(key.to_owned());
        }
        DurableHashClass::Membership { tenant, user } => {
            if field(fields, "tenant_id")? != tenant || field(fields, "user_id")? != user {
                return Err(SnapshotSchemaError::InvalidRelationship);
            }
            facts.memberships.insert((tenant.clone(), user.clone()));
        }
        DurableHashClass::Device { tenant, device } => {
            let owner = uuid_field_value(fields, "owner_user_id")?;
            if field(fields, "tenant_id")? != tenant || field(fields, "device_id")? != device {
                return Err(SnapshotSchemaError::InvalidRelationship);
            }
            if facts
                .device_owners
                .insert((tenant.clone(), device.clone()), owner)
                .is_some()
            {
                return Err(SnapshotSchemaError::DuplicateKey);
            }
            facts.devices.insert((tenant.clone(), device.clone()));
        }
        DurableHashClass::Credential {
            tenant,
            device,
            credential,
        } => {
            if field(fields, "tenant_id")? != tenant
                || field(fields, "device_id")? != device
                || field(fields, "credential_id")? != credential
            {
                return Err(SnapshotSchemaError::InvalidRelationship);
            }
            let tuple = (tenant.clone(), device.clone(), credential.clone());
            if !facts.credentials.insert(tuple) {
                return Err(SnapshotSchemaError::DuplicateKey);
            }
            let fingerprint = field(fields, "spki_fingerprint")?.to_owned();
            if facts
                .credential_fingerprints
                .insert(fingerprint, key.to_owned())
                .is_some()
            {
                return Err(SnapshotSchemaError::InvalidRelationship);
            }
        }
        DurableHashClass::Service {
            tenant,
            device,
            service,
        } => {
            if field(fields, "tenant_id")? != tenant
                || field(fields, "device_id")? != device
                || field(fields, "service_id")? != service
            {
                return Err(SnapshotSchemaError::InvalidRelationship);
            }
            if !facts
                .services
                .insert((tenant.clone(), device.clone(), service.clone()))
            {
                return Err(SnapshotSchemaError::DuplicateKey);
            }
        }
        DurableHashClass::Grant {
            tenant,
            principal,
            device,
            service,
        } => {
            if field(fields, "tenant_id")? != tenant
                || field(fields, "principal_id")? != principal
                || field(fields, "device_id")? != device
                || field(fields, "service_id")? != service
            {
                return Err(SnapshotSchemaError::InvalidRelationship);
            }
            if !facts.grants.insert((
                tenant.clone(),
                principal.clone(),
                device.clone(),
                service.clone(),
            )) {
                return Err(SnapshotSchemaError::DuplicateKey);
            }
            let expected_key = format!("{prefix}grant:{tenant}:{principal}:{device}:{service}");
            if expected_key != key || !facts.grant_keys.insert(key.to_owned()) {
                return Err(SnapshotSchemaError::InvalidRelationship);
            }
        }
    }
    Ok(())
}

fn validate_index_members(
    prefix: &str,
    class: &DurableSetClass,
    members: &HashSet<String>,
    facts: &CatalogFacts,
) -> Result<(), SnapshotSchemaError> {
    match class {
        DurableSetClass::Tenants => {
            for member in members {
                uuid_component(member)?;
                if !facts.tenants.contains(member) {
                    return Err(SnapshotSchemaError::Orphan);
                }
            }
        }
        DurableSetClass::Users => {
            for member in members {
                uuid_component(member)?;
                if !facts.users.contains(member) {
                    return Err(SnapshotSchemaError::Orphan);
                }
            }
        }
        DurableSetClass::Identities => {
            for member in members {
                if !member.starts_with(prefix)
                    || !matches!(
                        classify_key(prefix, member)?,
                        ParsedClass::DurableHash(DurableHashClass::Identity { .. })
                    )
                {
                    return Err(SnapshotSchemaError::Orphan);
                }
                if !facts.identities.contains(member) {
                    return Err(SnapshotSchemaError::Orphan);
                }
            }
        }
        DurableSetClass::Memberships { tenant } => {
            if !facts.tenants.contains(tenant) {
                return Err(SnapshotSchemaError::Orphan);
            }
            for member in members {
                let user = uuid_component(member)?;
                if !facts.memberships.contains(&(tenant.clone(), user)) {
                    return Err(SnapshotSchemaError::Orphan);
                }
            }
        }
        DurableSetClass::UserTenants { user } => {
            if !facts.users.contains(user) {
                return Err(SnapshotSchemaError::Orphan);
            }
            for member in members {
                let tenant = uuid_component(member)?;
                if !facts.memberships.contains(&(tenant, user.clone())) {
                    return Err(SnapshotSchemaError::Orphan);
                }
            }
        }
        DurableSetClass::Devices { tenant } => {
            if !facts.tenants.contains(tenant) {
                return Err(SnapshotSchemaError::Orphan);
            }
            for member in members {
                let device = uuid_component(member)?;
                if !facts.devices.contains(&(tenant.clone(), device)) {
                    return Err(SnapshotSchemaError::Orphan);
                }
            }
        }
        DurableSetClass::Credentials { tenant, device } => {
            if !facts.devices.contains(&(tenant.clone(), device.clone())) {
                return Err(SnapshotSchemaError::Orphan);
            }
            for member in members {
                let credential = uuid_component(member)?;
                if !facts
                    .credentials
                    .contains(&(tenant.clone(), device.clone(), credential))
                {
                    return Err(SnapshotSchemaError::Orphan);
                }
            }
        }
        DurableSetClass::Services { tenant, device } => {
            if !facts.devices.contains(&(tenant.clone(), device.clone())) {
                return Err(SnapshotSchemaError::Orphan);
            }
            for member in members {
                let service = uuid_component(member)?;
                if !facts
                    .services
                    .iter()
                    .any(|(t, d, s)| t == tenant && d == device && s == &service)
                {
                    return Err(SnapshotSchemaError::Orphan);
                }
            }
        }
        DurableSetClass::GrantsDevice { tenant, device } => {
            if !facts.devices.contains(&(tenant.clone(), device.clone())) {
                return Err(SnapshotSchemaError::Orphan);
            }
            for member in members {
                if !facts.grant_keys.contains(member) {
                    return Err(SnapshotSchemaError::Orphan);
                }
                match classify_key(prefix, member)? {
                    ParsedClass::DurableHash(DurableHashClass::Grant {
                        tenant: grant_tenant,
                        device: grant_device,
                        ..
                    }) if grant_tenant == *tenant && grant_device == *device => {}
                    _ => return Err(SnapshotSchemaError::Orphan),
                }
            }
        }
    }
    Ok(())
}

fn validate_catalog_relationships(
    prefix: &str,
    parsed: &[ParsedObserved<'_>],
    facts: &CatalogFacts,
) -> Result<(), SnapshotSchemaError> {
    let tenants_index = format!("{prefix}idx:tenants");
    let users_index = format!("{prefix}idx:users");
    let identities_index = format!("{prefix}idx:identities");
    for tenant in &facts.tenants {
        require_member(&facts.indexes, &tenants_index, tenant)?;
    }
    for user in &facts.users {
        require_member(&facts.indexes, &users_index, user)?;
    }
    for identity in &facts.identities {
        require_member(&facts.indexes, &identities_index, identity)?;
    }

    for (tenant, user) in &facts.memberships {
        require_member(
            &facts.indexes,
            &format!("{prefix}idx:memberships:{tenant}"),
            user,
        )?;
        require_member(
            &facts.indexes,
            &format!("{prefix}idx:user_tenants:{user}"),
            tenant,
        )?;
    }
    for (tenant, device) in &facts.devices {
        require_member(
            &facts.indexes,
            &format!("{prefix}idx:devices:{tenant}"),
            device,
        )?;
        let owner = facts
            .device_owners
            .get(&(tenant.clone(), device.clone()))
            .ok_or(SnapshotSchemaError::InvalidRelationship)?;
        if !facts.users.contains(owner)
            || !facts.memberships.contains(&(tenant.clone(), owner.clone()))
        {
            return Err(SnapshotSchemaError::InvalidRelationship);
        }
    }
    for (tenant, device, credential) in &facts.credentials {
        require_member(
            &facts.indexes,
            &format!("{prefix}idx:credentials:{tenant}:{device}"),
            credential,
        )?;
    }
    for (tenant, device, service) in &facts.services {
        require_member(
            &facts.indexes,
            &format!("{prefix}idx:services:{tenant}:{device}"),
            service,
        )?;
    }
    for (tenant, principal, device, service) in &facts.grants {
        require_member(
            &facts.indexes,
            &format!("{prefix}idx:grants_device:{tenant}:{device}"),
            &format!("{prefix}grant:{tenant}:{principal}:{device}:{service}"),
        )?;
        if !facts
            .memberships
            .contains(&(tenant.clone(), principal.clone()))
            || !facts.devices.contains(&(tenant.clone(), device.clone()))
            || !facts
                .services
                .contains(&(tenant.clone(), device.clone(), service.clone()))
        {
            return Err(SnapshotSchemaError::InvalidRelationship);
        }
    }

    for parsed_key in parsed {
        if let ParsedClass::DurableString(DurableStringClass::Fingerprint { fingerprint }) =
            &parsed_key.class
        {
            let target = facts
                .fingerprint_indexes
                .get(fingerprint)
                .ok_or(SnapshotSchemaError::Orphan)?;
            let expected = facts
                .credential_fingerprints
                .get(fingerprint)
                .ok_or(SnapshotSchemaError::Orphan)?;
            if target != expected {
                return Err(SnapshotSchemaError::InvalidRelationship);
            }
        }
    }
    for (fingerprint, credential_key) in &facts.credential_fingerprints {
        if facts.fingerprint_indexes.get(fingerprint) != Some(credential_key) {
            return Err(SnapshotSchemaError::Orphan);
        }
    }
    for (tenant, device) in facts.epochs.keys() {
        if !facts.devices.contains(&(tenant.clone(), device.clone())) {
            return Err(SnapshotSchemaError::Orphan);
        }
    }
    Ok(())
}

fn validate_ephemeral_relationships(
    prefix: &str,
    parsed: &[ParsedObserved<'_>],
    facts: &CatalogFacts,
) -> Result<(), SnapshotSchemaError> {
    for parsed_key in parsed {
        match &parsed_key.class {
            ParsedClass::EphemeralHash(EphemeralHashClass::Owner { tenant, device, .. })
            | ParsedClass::EphemeralHash(EphemeralHashClass::Ticket { tenant, device, .. })
            | ParsedClass::EphemeralZset(EphemeralZsetClass::Tickets { tenant, device, .. })
                if !facts.devices.contains(&(tenant.clone(), device.clone())) =>
            {
                return Err(SnapshotSchemaError::Orphan);
            }
            _ => {}
        }
    }

    let mut ticket_keys = HashSet::new();
    for parsed_key in parsed {
        if let ParsedClass::EphemeralHash(EphemeralHashClass::Ticket {
            incarnation,
            tenant,
            device,
            digest,
        }) = &parsed_key.class
        {
            let index_key = format!("{prefix}coord:tickets:{incarnation}:{tenant}:{device}");
            let members = facts
                .ticket_indexes
                .get(&index_key)
                .ok_or(SnapshotSchemaError::Orphan)?;
            if !members.contains(digest) {
                return Err(SnapshotSchemaError::Orphan);
            }
            ticket_keys.insert(parsed_key.observed.key.clone());
        }
    }
    for parsed_key in parsed {
        if let ParsedClass::EphemeralZset(EphemeralZsetClass::Tickets {
            incarnation,
            tenant,
            device,
        }) = &parsed_key.class
        {
            let members = facts
                .ticket_indexes
                .get(&parsed_key.observed.key)
                .ok_or(SnapshotSchemaError::Orphan)?;
            for digest in members {
                let ticket_key =
                    format!("{prefix}coord:ticket:{incarnation}:{tenant}:{device}:{digest}");
                if !ticket_keys.contains(&ticket_key) {
                    return Err(SnapshotSchemaError::Orphan);
                }
            }
        }
    }
    Ok(())
}

fn validate_owner_fields(
    incarnation_component: &str,
    tenant: &str,
    device: &str,
    fields: &[(String, String)],
) -> Result<(), SnapshotSchemaError> {
    exact_fields(
        fields,
        &[
            "tenant_id",
            "device_id",
            "deployment_incarnation",
            "node_id",
            "boot_id",
            "session_id",
            "owner_epoch",
            "lease_expires_at_us",
        ],
    )?;
    if field(fields, "tenant_id")? != tenant || field(fields, "device_id")? != device {
        return Err(SnapshotSchemaError::InvalidRelationship);
    }
    let incarnation = decode_key_component(incarnation_component)?;
    if field(fields, "deployment_incarnation")? != incarnation {
        return Err(SnapshotSchemaError::InvalidRelationship);
    }
    identifier_field(fields, "node_id", MAX_IDENTIFIER_BYTES)?;
    identifier_field(fields, "boot_id", MAX_IDENTIFIER_BYTES)?;
    identifier_field(fields, "session_id", MAX_IDENTIFIER_BYTES)?;
    if parse_u64(field(fields, "owner_epoch")?)? == 0
        || parse_i64(field(fields, "lease_expires_at_us")?)? <= 0
    {
        return Err(SnapshotSchemaError::InvalidValue);
    }
    Ok(())
}

fn validate_ticket_fields(
    incarnation_component: &str,
    tenant: &str,
    device: &str,
    digest: &str,
    fields: &[(String, String)],
) -> Result<(), SnapshotSchemaError> {
    exact_fields(
        fields,
        &[
            "tenant_id",
            "device_id",
            "spki_fingerprint",
            "deployment_incarnation",
            "node_id",
            "boot_id",
            "session_id",
            "owner_epoch",
            "generation",
            "connection_id",
            "purpose",
            "binding_digest",
            "expires_at_us",
            "spent",
        ],
    )?;
    if field(fields, "tenant_id")? != tenant || field(fields, "device_id")? != device {
        return Err(SnapshotSchemaError::InvalidRelationship);
    }
    let incarnation = decode_key_component(incarnation_component)?;
    if field(fields, "deployment_incarnation")? != incarnation
        || !is_lower_hex(digest, 64)
        || !is_lower_hex(field(fields, "spki_fingerprint")?, 64)
    {
        return Err(SnapshotSchemaError::InvalidRelationship);
    }
    identifier_field(fields, "node_id", MAX_IDENTIFIER_BYTES)?;
    identifier_field(fields, "boot_id", MAX_IDENTIFIER_BYTES)?;
    identifier_field(fields, "session_id", MAX_IDENTIFIER_BYTES)?;
    identifier_field(fields, "connection_id", MAX_IDENTIFIER_BYTES)?;
    identifier_field(fields, "purpose", MAX_IDENTIFIER_BYTES)?;
    identifier_field(fields, "binding_digest", MAX_IDENTIFIER_BYTES)?;
    if parse_u64(field(fields, "owner_epoch")?)? == 0
        || parse_u64(field(fields, "generation")?).is_err()
        || parse_i64(field(fields, "expires_at_us")?)? <= 0
        || (field(fields, "spent")? != "0" && field(fields, "spent")? != "1")
    {
        return Err(SnapshotSchemaError::InvalidValue);
    }
    Ok(())
}

fn validate_metadata(class: &MetadataClass, value: &str) -> Result<(), SnapshotSchemaError> {
    match class {
        MetadataClass::ActiveIncarnation
        | MetadataClass::RedisRunId
        | MetadataClass::Continuity => {
            identifier(value, MAX_IDENTIFIER_BYTES)?;
        }
        MetadataClass::CatalogGeneration => {
            parse_u64(value)?;
        }
        MetadataClass::FixtureSeeded => {
            if value != "1" {
                return Err(SnapshotSchemaError::InvalidValue);
            }
        }
    }
    Ok(())
}

fn validate_operator_current(fields: &[(String, String)]) -> Result<(), SnapshotSchemaError> {
    exact_fields(fields, &["version", "bytes"])?;
    if parse_u64(field(fields, "version")?)? == 0 || field(fields, "bytes")?.is_empty() {
        return Err(SnapshotSchemaError::InvalidValue);
    }
    Ok(())
}

fn validate_operator_directory(fields: &[(String, String)]) -> Result<(), SnapshotSchemaError> {
    if fields.len() > MAX_OPERATOR_DIRECTORY_RECORDS {
        return Err(SnapshotSchemaError::ValueBound);
    }
    let mut ids = HashSet::with_capacity(fields.len());
    for (node_id, envelope) in fields {
        identifier(node_id, MAX_IDENTIFIER_BYTES)?;
        if !ids.insert(node_id) || envelope.is_empty() {
            return Err(SnapshotSchemaError::FieldShape);
        }
    }
    Ok(())
}

fn exact_fields(fields: &[(String, String)], expected: &[&str]) -> Result<(), SnapshotSchemaError> {
    if fields.len() != expected.len() {
        return Err(SnapshotSchemaError::FieldShape);
    }
    let expected: HashSet<_> = expected.iter().copied().collect();
    let mut seen = HashSet::with_capacity(fields.len());
    for (field_name, _) in fields {
        if !expected.contains(field_name.as_str()) || !seen.insert(field_name.as_str()) {
            return Err(SnapshotSchemaError::FieldShape);
        }
    }
    Ok(())
}

fn field<'a>(fields: &'a [(String, String)], name: &str) -> Result<&'a str, SnapshotSchemaError> {
    fields
        .iter()
        .find_map(|(field_name, value)| (field_name == name).then_some(value.as_str()))
        .ok_or(SnapshotSchemaError::FieldShape)
}

fn identifier_field(
    fields: &[(String, String)],
    name: &str,
    max_bytes: usize,
) -> Result<(), SnapshotSchemaError> {
    identifier(field(fields, name)?, max_bytes)
}

fn identifier(value: &str, max_bytes: usize) -> Result<(), SnapshotSchemaError> {
    if value.trim().is_empty() || value.len() > max_bytes {
        return Err(SnapshotSchemaError::InvalidValue);
    }
    Ok(())
}

fn uuid_field(fields: &[(String, String)], name: &str) -> Result<(), SnapshotSchemaError> {
    uuid_component(field(fields, name)?)?;
    Ok(())
}

fn uuid_field_value(
    fields: &[(String, String)],
    name: &str,
) -> Result<String, SnapshotSchemaError> {
    uuid_component(field(fields, name)?)
}

fn bool_field(fields: &[(String, String)], name: &str) -> Result<(), SnapshotSchemaError> {
    match field(fields, name)? {
        "0" | "1" => Ok(()),
        _ => Err(SnapshotSchemaError::InvalidValue),
    }
}

fn optional_i64_field(fields: &[(String, String)], name: &str) -> Result<(), SnapshotSchemaError> {
    let value = field(fields, name)?;
    if value.is_empty() {
        return Ok(());
    }
    parse_i64(value)?;
    Ok(())
}

fn json_field(fields: &[(String, String)], name: &str) -> Result<(), SnapshotSchemaError> {
    serde_json::from_str::<serde_json::Value>(field(fields, name)?)
        .map(|_| ())
        .map_err(|_| SnapshotSchemaError::InvalidValue)
}

fn parse_u64(value: &str) -> Result<u64, SnapshotSchemaError> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(SnapshotSchemaError::InvalidValue);
    }
    value
        .parse::<u64>()
        .map_err(|_| SnapshotSchemaError::InvalidValue)
}

fn parse_i64(value: &str) -> Result<i64, SnapshotSchemaError> {
    value
        .parse::<i64>()
        .map_err(|_| SnapshotSchemaError::InvalidValue)
}

fn require_member(
    indexes: &HashMap<String, HashSet<String>>,
    index_key: &str,
    member: &str,
) -> Result<(), SnapshotSchemaError> {
    indexes
        .get(index_key)
        .ok_or(SnapshotSchemaError::Orphan)?
        .contains(member)
        .then_some(())
        .ok_or(SnapshotSchemaError::Orphan)
}

fn canonical_entry(observed: &ObservedRedisKey) -> Result<CanonicalEntry, SnapshotSchemaError> {
    let (kind, mut fields) = match &observed.value {
        ObservedRedisValue::Hash(fields) => (CanonicalKind::Hash, fields.clone()),
        ObservedRedisValue::Set(members) => (
            CanonicalKind::Set,
            members
                .iter()
                .cloned()
                .map(|member| ("member".to_owned(), member))
                .collect(),
        ),
        ObservedRedisValue::String(value) => (
            CanonicalKind::String,
            vec![("value".to_owned(), value.clone())],
        ),
        ObservedRedisValue::Zset(_) => return Err(SnapshotSchemaError::TypeMismatch),
    };
    fields.sort();
    Ok(CanonicalEntry {
        kind,
        key: observed.key.clone(),
        fields,
    })
}

fn encode_canonical(entries: &[CanonicalEntry]) -> Result<Vec<u8>, SnapshotSchemaError> {
    let count = u32::try_from(entries.len()).map_err(|_| SnapshotSchemaError::CanonicalBound)?;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(CANONICAL_PREFIX);
    bytes.extend_from_slice(&RECOVERY_SNAPSHOT_SCHEMA_VERSION.to_be_bytes());
    bytes.extend_from_slice(&count.to_be_bytes());
    for entry in entries {
        bytes.push(match entry.kind {
            CanonicalKind::Hash => 1,
            CanonicalKind::Set => 2,
            CanonicalKind::String => 3,
        });
        append_component(&mut bytes, entry.key.as_bytes())?;
        let field_count =
            u32::try_from(entry.fields.len()).map_err(|_| SnapshotSchemaError::CanonicalBound)?;
        bytes.extend_from_slice(&field_count.to_be_bytes());
        for (field_name, value) in &entry.fields {
            append_component(&mut bytes, field_name.as_bytes())?;
            append_component(&mut bytes, value.as_bytes())?;
        }
        if bytes.len() > MAX_RECOVERY_SNAPSHOT_BYTES {
            return Err(SnapshotSchemaError::CanonicalBound);
        }
    }
    Ok(bytes)
}

fn append_component(bytes: &mut Vec<u8>, value: &[u8]) -> Result<(), SnapshotSchemaError> {
    if value.len() > MAX_RECOVERY_SNAPSHOT_VALUE_BYTES {
        return Err(SnapshotSchemaError::CanonicalBound);
    }
    let length = u32::try_from(value.len()).map_err(|_| SnapshotSchemaError::CanonicalBound)?;
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(value);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const PREFIX: &str = "tunnel-catalog:test-schema:";
    const TENANT_A: &str = "00000000-0000-4000-8000-000000000001";
    const TENANT_B: &str = "00000000-0000-4000-8000-000000000002";
    const USER_A: &str = "00000000-0000-4000-8000-000000000011";
    const USER_B: &str = "00000000-0000-4000-8000-000000000012";
    const DEVICE: &str = "00000000-0000-4000-8000-000000000021";

    fn hash(key: &str, fields: &[(&str, &str)]) -> ObservedRedisKey {
        ObservedRedisKey::hash(
            format!("{PREFIX}{key}"),
            -1,
            fields
                .iter()
                .map(|(field, value)| ((*field).to_owned(), (*value).to_owned()))
                .collect(),
        )
    }

    fn set(key: &str, members: &[&str]) -> ObservedRedisKey {
        ObservedRedisKey::set(
            format!("{PREFIX}{key}"),
            -1,
            members.iter().map(|member| (*member).to_owned()).collect(),
        )
    }

    fn base_catalog() -> Vec<ObservedRedisKey> {
        vec![
            hash(
                &format!("tenant:{TENANT_A}"),
                &[
                    ("tenant_id", TENANT_A),
                    ("display_name", "A"),
                    ("active", "1"),
                ],
            ),
            hash(
                &format!("tenant:{TENANT_B}"),
                &[
                    ("tenant_id", TENANT_B),
                    ("display_name", "B"),
                    ("active", "1"),
                ],
            ),
            hash(
                &format!("user:{USER_A}"),
                &[("user_id", USER_A), ("display_name", "a")],
            ),
            hash(
                &format!("user:{USER_B}"),
                &[("user_id", USER_B), ("display_name", "b")],
            ),
            hash(
                &format!("membership:{TENANT_A}:{USER_A}"),
                &[
                    ("tenant_id", TENANT_A),
                    ("user_id", USER_A),
                    ("role", "member"),
                    ("active", "1"),
                ],
            ),
            hash(
                &format!("membership:{TENANT_B}:{USER_B}"),
                &[
                    ("tenant_id", TENANT_B),
                    ("user_id", USER_B),
                    ("role", "member"),
                    ("active", "1"),
                ],
            ),
            hash(
                &format!("device:{TENANT_A}:{DEVICE}"),
                &[
                    ("tenant_id", TENANT_A),
                    ("device_id", DEVICE),
                    ("owner_user_id", USER_A),
                    ("display_name", "A device"),
                    ("active", "1"),
                    ("last_seen_at_us", ""),
                    ("device_version", "1"),
                ],
            ),
            hash(
                &format!("device:{TENANT_B}:{DEVICE}"),
                &[
                    ("tenant_id", TENANT_B),
                    ("device_id", DEVICE),
                    ("owner_user_id", USER_B),
                    ("display_name", "B device"),
                    ("active", "1"),
                    ("last_seen_at_us", ""),
                    ("device_version", "1"),
                ],
            ),
            ObservedRedisKey::string(format!("{PREFIX}coord:epoch:{TENANT_A}:{DEVICE}"), -1, "0"),
            ObservedRedisKey::string(format!("{PREFIX}coord:epoch:{TENANT_B}:{DEVICE}"), -1, "0"),
            set("idx:tenants", &[TENANT_A, TENANT_B]),
            set("idx:users", &[USER_A, USER_B]),
            set("idx:identities", &[]),
            set(&format!("idx:memberships:{TENANT_A}"), &[USER_A]),
            set(&format!("idx:memberships:{TENANT_B}"), &[USER_B]),
            set(&format!("idx:user_tenants:{USER_A}"), &[TENANT_A]),
            set(&format!("idx:user_tenants:{USER_B}"), &[TENANT_B]),
            set(&format!("idx:devices:{TENANT_A}"), &[DEVICE]),
            set(&format!("idx:devices:{TENANT_B}"), &[DEVICE]),
        ]
    }

    #[test]
    fn same_device_uuid_is_scoped_by_tenant_and_epoch_is_durable() {
        let snapshot = validate_observed_catalog(PREFIX, &base_catalog()).expect("valid catalog");
        assert_eq!(snapshot.durable_key_count(), 19);
    }

    #[test]
    fn canonical_order_is_independent_of_scan_order() {
        let first = base_catalog();
        let mut second = first.clone();
        second.reverse();
        let one = validate_observed_catalog(PREFIX, &first).expect("first");
        let two = validate_observed_catalog(PREFIX, &second).expect("second");
        assert_eq!(one.canonical_bytes(), two.canonical_bytes());
        assert_eq!(one.canonical_entry_count(), one.canonical_entries().len());
        assert_eq!(one.canonical_byte_count(), one.canonical_bytes().len());
    }

    #[test]
    fn orphan_direct_lookup_is_rejected() {
        let mut keys = base_catalog();
        keys.push(ObservedRedisKey::string(
            format!("{PREFIX}idx:fingerprint:{}", "a".repeat(64)),
            -1,
            format!("{PREFIX}credential:{TENANT_A}:{DEVICE}:00000000-0000-4000-8000-000000000099"),
        ));
        assert_eq!(
            validate_observed_catalog(PREFIX, &keys),
            Err(SnapshotSchemaError::Orphan)
        );
    }

    #[test]
    fn malformed_index_and_durable_ttl_are_rejected() {
        let mut orphan = base_catalog();
        orphan.push(set(
            &format!("idx:devices:{TENANT_A}"),
            &["00000000-0000-4000-8000-000000000099"],
        ));
        assert!(validate_observed_catalog(PREFIX, &orphan).is_err());

        let mut ttl = base_catalog();
        ttl[0].ttl_ms = 500;
        assert_eq!(
            validate_observed_catalog(PREFIX, &ttl),
            Err(SnapshotSchemaError::TtlMismatch)
        );
    }

    #[test]
    fn unknown_namespace_key_is_rejected() {
        let mut keys = base_catalog();
        keys.push(ObservedRedisKey::string(
            format!("{PREFIX}unknown:record"),
            -1,
            "x",
        ));
        assert_eq!(
            validate_observed_catalog(PREFIX, &keys),
            Err(SnapshotSchemaError::UnknownKey)
        );
    }

    #[test]
    fn malformed_uuid_and_orphan_epoch_are_rejected() {
        let mut malformed = base_catalog();
        malformed[0].key = format!("{PREFIX}tenant:not-a-uuid");
        assert_eq!(
            validate_observed_catalog(PREFIX, &malformed),
            Err(SnapshotSchemaError::MalformedKey)
        );

        let mut orphan_epoch = base_catalog();
        orphan_epoch.push(ObservedRedisKey::string(
            format!("{PREFIX}coord:epoch:{TENANT_A}:00000000-0000-4000-8000-000000000099"),
            -1,
            "1",
        ));
        assert_eq!(
            validate_observed_catalog(PREFIX, &orphan_epoch),
            Err(SnapshotSchemaError::Orphan)
        );
    }

    #[test]
    fn missing_device_epoch_is_rejected() {
        let mut missing = base_catalog();
        missing.retain(|key| {
            !key.key
                .ends_with(&format!("coord:epoch:{TENANT_A}:{DEVICE}"))
        });
        assert_eq!(
            validate_observed_catalog(PREFIX, &missing),
            Err(SnapshotSchemaError::MissingEpoch)
        );
    }
}
