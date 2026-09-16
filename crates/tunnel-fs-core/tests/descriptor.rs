//! The descriptor against its checked-in golden example, and the three
//! consistency rules the schema defers to runtime.

mod common;

use common::{example_descriptor, example_grant, example_identity, identifier};
use tunnel_fs_core::{
    Availability, Capability, CapabilitySet, CaseSensitivity, ClientOperation, Descriptor, Feature,
    FeatureSet, Identifier, IdentifierRule, Limits, MAX_IDENTIFIER_BYTES, NON_BASELINE_FEATURES,
};

/// The checked-in example the emitter must reproduce byte for byte.
const GOLDEN: &str = include_str!("../../../docs/contracts/filesystem-capabilities.example.json");

#[test]
fn the_emitter_reproduces_the_checked_in_example_byte_for_byte() {
    assert_eq!(
        example_descriptor().to_json(),
        GOLDEN,
        "the emitted descriptor drifted from docs/contracts/filesystem-capabilities.example.json"
    );
}

#[test]
fn availability_and_capability_status_cannot_disagree() {
    // The schema's only conditional: online implies current, offline implies
    // last-known.  One enum emits both, so the pair is unfalsifiable.
    assert_eq!(Availability::Online.availability(), "online");
    assert_eq!(Availability::Online.capability_status(), "current");
    assert_eq!(Availability::Offline.availability(), "offline");
    assert_eq!(Availability::Offline.capability_status(), "last-known");
    assert_eq!(Availability::default(), Availability::Offline);

    for availability in [Availability::Online, Availability::Offline] {
        let json = descriptor_with(availability, example_grant(), FeatureSet::NONE).to_json();
        let expected_availability =
            format!("\"availability\": \"{}\"", availability.availability());
        let expected_status = format!(
            "\"capabilityStatus\": \"{}\"",
            availability.capability_status()
        );
        assert!(json.contains(&expected_availability), "{json}");
        assert!(json.contains(&expected_status), "{json}");
    }
}

#[test]
fn read_only_is_derived_from_the_grant_not_supplied() {
    for capability in [Capability::Read, Capability::List] {
        let descriptor = descriptor_with(
            Availability::Online,
            CapabilitySet::DENY.with(capability),
            FeatureSet::NONE,
        );
        assert!(
            descriptor.is_read_only(),
            "{capability} must stay read-only"
        );
        assert!(descriptor.to_json().contains("\"readOnly\": true"));
    }
    for capability in [Capability::Write, Capability::Delete] {
        let descriptor = descriptor_with(
            Availability::Online,
            CapabilitySet::DENY.with(capability),
            FeatureSet::NONE,
        );
        assert!(!descriptor.is_read_only(), "{capability} makes it writable");
        assert!(descriptor.to_json().contains("\"readOnly\": false"));
    }
}

#[test]
fn advertised_operations_never_exceed_the_grant() {
    // Exhaustive over every grant and feature set: whatever the descriptor
    // advertises must be executable under the same grant.
    for grant_bits in 0u8..16 {
        let mut grant = CapabilitySet::DENY;
        for (index, capability) in Capability::ALL.into_iter().enumerate() {
            if grant_bits & (1 << index) != 0 {
                grant = grant.with(capability);
            }
        }
        for feature_bits in 0u8..128 {
            let mut features = FeatureSet::NONE;
            for (index, feature) in Feature::ALL.into_iter().enumerate() {
                if feature_bits & (1 << index) != 0 {
                    features = features.with(feature);
                }
            }
            let descriptor = descriptor_with(Availability::Online, grant, features);
            let operations = descriptor.operations();
            assert!(operations.len() <= 17);
            for operation in &operations {
                assert!(
                    operation.is_available(grant, features),
                    "{operation} advertised beyond the grant"
                );
            }
            // A read-only grant advertises no mutating operation.
            if grant.is_read_only() {
                for operation in &operations {
                    assert!(
                        !operation.required_capabilities().allows(Capability::Write),
                        "a read-only descriptor advertised {operation}"
                    );
                }
            }
            // The emitted list matches the derived list exactly.
            let json = descriptor.to_json();
            for operation in ClientOperation::ALL {
                let quoted = format!("\"{}\"", operation.as_str());
                assert_eq!(
                    json.contains(&quoted),
                    operations.contains(&operation),
                    "{operation} disagreed between the derived list and the JSON"
                );
            }
        }
    }
}

#[test]
fn an_empty_grant_advertises_nothing_at_all() {
    let descriptor = descriptor_with(Availability::Online, CapabilitySet::DENY, FeatureSet::NONE);
    assert!(descriptor.operations().is_empty());
    let json = descriptor.to_json();
    assert!(json.contains("\"operations\": [],"), "{json}");
    assert!(json.contains("\"readOnly\": true"));
}

#[test]
fn non_baseline_features_are_pinned_false_for_every_configuration() {
    let all_features = FeatureSet::from_slice(&Feature::ALL);
    let everything = CapabilitySet::from_slice(&Capability::ALL);
    let json = descriptor_with(Availability::Online, everything, all_features).to_json();

    for name in NON_BASELINE_FEATURES {
        assert!(
            json.contains(&format!("\"{name}\": false")),
            "{name} must be pinned false"
        );
    }
    // And the negotiable ones did turn on, so the check above is not vacuous.
    for feature in Feature::ALL {
        assert!(
            json.contains(&format!("\"{}\": true", feature.as_str())),
            "{feature} should be advertised"
        );
    }
    assert_eq!(NON_BASELINE_FEATURES.len(), 7);
}

#[test]
fn the_emitted_document_has_the_schemas_closed_field_set() {
    let json = descriptor_with(
        Availability::Offline,
        CapabilitySet::from_slice(&Capability::ALL),
        FeatureSet::from_slice(&Feature::ALL),
    )
    .to_json();

    for required in [
        "\"schemaVersion\": \"agent-tunnel.fs.v1\"",
        "\"deviceId\"",
        "\"serviceId\"",
        "\"grantRevision\"",
        "\"availability\"",
        "\"capabilityStatus\"",
        "\"transport\"",
        "\"type\": \"websocket\"",
        "\"subprotocol\": \"agent-tunnel.9p.v1\"",
        "\"dialect\": \"9P2000.L\"",
        "\"root\"",
        "\"path\": \"/\"",
        "\"pathStyle\": \"virtual-posix\"",
        "\"caseSensitivity\"",
        "\"readOnly\"",
        "\"operations\"",
        "\"features\"",
        "\"limits\"",
    ] {
        assert!(json.contains(required), "missing {required} in\n{json}");
    }

    // Nothing that could disclose a host.
    for forbidden in ["/Users", "/home", "uid", "gid", "inode", "token", "Bearer"] {
        assert!(!json.contains(forbidden), "descriptor leaked {forbidden}");
    }
}

#[test]
fn case_sensitivity_is_reported_not_assumed() {
    assert_eq!(CaseSensitivity::default(), CaseSensitivity::Sensitive);
    for (case, expected) in [
        (CaseSensitivity::Sensitive, "sensitive"),
        (
            CaseSensitivity::InsensitivePreserving,
            "insensitive-preserving",
        ),
    ] {
        let descriptor = Descriptor::new(
            example_identity(),
            Availability::Online,
            case,
            example_grant(),
            FeatureSet::NONE,
            Limits::PROFILE_DEFAULT,
        );
        assert!(
            descriptor
                .to_json()
                .contains(&format!("\"caseSensitivity\": \"{expected}\"")),
        );
    }
}

#[test]
fn identifiers_are_restricted_so_the_emitter_never_has_to_escape() {
    for valid in [
        "a",
        "device-123",
        "workspace",
        "opaque.rev_1",
        "A9",
        &"z".repeat(128),
    ] {
        assert!(Identifier::parse(valid).is_ok(), "{valid} should be valid");
    }
    assert_eq!(Identifier::parse(""), Err(IdentifierRule::Empty));
    assert_eq!(
        Identifier::parse(&"z".repeat(MAX_IDENTIFIER_BYTES + 1)),
        Err(IdentifierRule::TooLong)
    );
    for invalid in [
        "with space",
        "quote\"break",
        "back\\slash",
        "new\nline",
        "nul\u{0}",
        "brace{}",
        "slash/path",
        "unicode-\u{e9}",
        "<script>",
    ] {
        assert_eq!(
            Identifier::parse(invalid),
            Err(IdentifierRule::DisallowedCharacter),
            "{invalid} must be refused"
        );
    }

    // Consequently no emitted document needs escaping.
    let json = example_descriptor().to_json();
    assert!(!json.contains('\\'), "no value should require an escape");
}

#[test]
fn the_descriptor_exposes_what_it_was_built_from() {
    let descriptor = example_descriptor();
    assert_eq!(descriptor.device_id().as_str(), "device-123");
    assert_eq!(descriptor.service_id().as_str(), "workspace");
    assert_eq!(
        descriptor.grant_revision().as_str(),
        "opaque-example-revision"
    );
    assert_eq!(descriptor.availability(), Availability::Online);
    assert_eq!(descriptor.grant(), example_grant());
    assert_eq!(descriptor.features(), FeatureSet::NONE);
    assert_eq!(descriptor.limits(), Limits::PROFILE_DEFAULT);
    assert_eq!(descriptor.identity(), &example_identity());
    assert_eq!(identifier("workspace").as_str(), "workspace");
}

fn descriptor_with(
    availability: Availability,
    grant: CapabilitySet,
    features: FeatureSet,
) -> Descriptor {
    Descriptor::new(
        example_identity(),
        availability,
        CaseSensitivity::Sensitive,
        grant,
        features,
        Limits::PROFILE_DEFAULT,
    )
}
