//! Default deny, the primitive authorization table, and the derivation of
//! advertised operations from it.

mod common;

use common::{Rng, example_grant};
use tunnel_fs_core::{
    Capability, CapabilitySet, ClientOperation, Feature, FeatureSet, Primitive, admits_session,
};

#[test]
fn the_default_grant_denies_everything() {
    let default = CapabilitySet::default();
    assert_eq!(default, CapabilitySet::DENY);
    assert!(default.is_empty());
    assert_eq!(default.len(), 0);
    assert!(default.is_read_only());

    for capability in Capability::ALL {
        assert!(
            !default.allows(capability),
            "the default grant must not allow {capability}"
        );
    }
    for primitive in Primitive::ALL {
        assert!(
            !primitive.is_permitted(default, FeatureSet::NONE),
            "the default grant must not permit {primitive}"
        );
    }
    for operation in ClientOperation::ALL {
        assert!(
            !operation.is_available(default, FeatureSet::NONE),
            "the default grant must not advertise {operation}"
        );
    }
    assert!(
        !admits_session(default),
        "an export granting nothing must admit no session"
    );
    assert!(admits_session(CapabilitySet::DENY.with(Capability::Read)));
}

#[test]
fn every_primitive_requires_exactly_its_documented_capabilities() {
    use Capability::{Delete, List, Read, Write};
    let expected: &[(Primitive, &[Capability])] = &[
        (Primitive::Version, &[]),
        (Primitive::Attach, &[]),
        (Primitive::Flush, &[]),
        (Primitive::Clunk, &[]),
        (Primitive::Walk, &[]),
        (Primitive::Getattr, &[List]),
        (Primitive::Readdir, &[List]),
        (Primitive::OpenDir, &[List]),
        (Primitive::Readlink, &[Read]),
        (Primitive::OpenRead, &[Read]),
        (Primitive::Read, &[Read]),
        (Primitive::OpenWrite, &[Write]),
        (Primitive::OpenTruncate, &[Write]),
        (Primitive::Create, &[Write]),
        (Primitive::Write, &[Write]),
        (Primitive::Mkdir, &[Write]),
        (Primitive::SetattrSize, &[Write]),
        (Primitive::SetattrMode, &[Write]),
        (Primitive::SetattrTimes, &[Write]),
        (Primitive::Symlink, &[Write]),
        (Primitive::Link, &[Write]),
        (Primitive::Unlink, &[Delete]),
        (Primitive::RemoveDir, &[Delete]),
        (Primitive::Rename, &[Write, Delete]),
    ];
    assert_eq!(
        expected.len(),
        Primitive::ALL.len(),
        "every primitive must appear in this table"
    );
    for (primitive, capabilities) in expected {
        assert_eq!(
            primitive.required_capabilities(),
            CapabilitySet::from_slice(capabilities),
            "{primitive} requires the wrong capabilities"
        );
    }
}

#[test]
fn removing_any_required_capability_denies_the_primitive() {
    // The load-bearing check: for every primitive and every capability it
    // requires, a grant of everything-but-that-capability must refuse it.
    let everything = CapabilitySet::from_slice(&Capability::ALL);
    let all_features = FeatureSet::from_slice(&Feature::ALL);

    for primitive in Primitive::ALL {
        assert!(
            primitive.is_permitted(everything, all_features),
            "{primitive} must be permitted by a full grant"
        );
        for capability in primitive.required_capabilities().iter() {
            let reduced = everything.without(capability);
            assert!(
                !primitive.is_permitted(reduced, all_features),
                "{primitive} stayed permitted without {capability}"
            );
        }
        // Removing a capability it does not require must not affect it.
        for capability in Capability::ALL {
            if primitive.required_capabilities().allows(capability) {
                continue;
            }
            assert!(
                primitive.is_permitted(everything.without(capability), all_features),
                "{primitive} was wrongly denied for lacking {capability}"
            );
        }
    }
}

#[test]
fn removing_a_required_feature_denies_the_primitive() {
    let everything = CapabilitySet::from_slice(&Capability::ALL);
    let all_features = FeatureSet::from_slice(&Feature::ALL);

    let gated = [
        (Primitive::Symlink, Feature::Symlinks),
        (Primitive::Readlink, Feature::Symlinks),
        (Primitive::Link, Feature::HardLinks),
        (Primitive::Rename, Feature::AtomicRename),
    ];
    for (primitive, feature) in gated {
        assert_eq!(primitive.required_feature(), Some(feature));
        assert!(primitive.is_permitted(everything, all_features));
        assert!(
            !primitive.is_permitted(everything, all_features.without(feature)),
            "{primitive} stayed permitted without {feature}"
        );
    }

    // Links are denied by default, which is the contract's stated posture.
    for primitive in [Primitive::Symlink, Primitive::Link, Primitive::Readlink] {
        assert!(
            !primitive.is_permitted(everything, FeatureSet::NONE),
            "{primitive} must be denied when no feature is advertised"
        );
    }
}

#[test]
fn an_operation_is_advertised_only_when_every_primitive_is_permitted() {
    let everything = CapabilitySet::from_slice(&Capability::ALL);
    let all_features = FeatureSet::from_slice(&Feature::ALL);

    for operation in ClientOperation::ALL {
        assert!(
            operation.is_available(everything, all_features),
            "{operation} must be available under a full grant"
        );
        for capability in operation.required_capabilities().iter() {
            assert!(
                !operation.is_available(everything.without(capability), all_features),
                "{operation} stayed advertised without {capability}"
            );
        }
    }
}

#[test]
fn copy_cannot_be_granted_without_its_underlying_read_and_write() {
    // The contract is explicit that no copy-only, grep-only or framework-only
    // access can be promised.
    let required = ClientOperation::Copy.required_capabilities();
    assert!(required.allows(Capability::Read));
    assert!(required.allows(Capability::Write));

    let read_only = CapabilitySet::from_slice(&[Capability::Read, Capability::List]);
    assert!(!ClientOperation::Copy.is_available(read_only, FeatureSet::NONE));

    let write_only = CapabilitySet::from_slice(&[Capability::Write]);
    assert!(!ClientOperation::Copy.is_available(write_only, FeatureSet::NONE));

    // Granting copy necessarily grants plain reads and writes.
    let copy_grant =
        CapabilitySet::from_slice(&[Capability::Read, Capability::Write, Capability::List]);
    assert!(ClientOperation::Copy.is_available(copy_grant, FeatureSet::NONE));
    assert!(ClientOperation::ReadFile.is_available(copy_grant, FeatureSet::NONE));
    assert!(ClientOperation::WriteFile.is_available(copy_grant, FeatureSet::NONE));
}

#[test]
fn the_recursive_operations_compose_their_traversal_primitives() {
    // `copy` and `remove` are recursive in the shared-client contract, so both
    // enumerate directories and both need `list`.  Omitting the traversal
    // primitives advertised `remove` under `delete` alone and `copy` under
    // read+write, which the provider would then have refused part-way through
    // a directory — exactly the partial advertisement the model forbids.
    for (operation, expected) in [
        (
            ClientOperation::Remove,
            CapabilitySet::from_slice(&[Capability::Delete, Capability::List]),
        ),
        (
            ClientOperation::Copy,
            CapabilitySet::from_slice(&[Capability::Read, Capability::Write, Capability::List]),
        ),
    ] {
        assert_eq!(
            operation.required_capabilities(),
            expected,
            "{operation} requires the wrong capabilities"
        );
        assert!(
            operation.primitives().contains(&Primitive::Readdir),
            "{operation} must enumerate"
        );
        assert!(
            operation.primitives().contains(&Primitive::OpenDir),
            "{operation} must open a directory to enumerate it"
        );
        assert!(
            !operation.is_available(expected.without(Capability::List), FeatureSet::NONE),
            "{operation} stayed advertised without list"
        );
    }

    // `copy` also creates directories when it recurses into one.
    assert!(
        ClientOperation::Copy
            .primitives()
            .contains(&Primitive::Mkdir),
        "a recursive copy creates directories"
    );

    // Delete alone no longer advertises remove.
    let delete_only = CapabilitySet::from_slice(&[Capability::Delete]);
    assert!(!ClientOperation::Remove.is_available(delete_only, FeatureSet::NONE));
}

#[test]
fn rename_needs_delete_so_a_create_only_grant_cannot_remove_a_name() {
    let required = ClientOperation::Rename.required_capabilities();
    assert!(required.allows(Capability::Write));
    assert!(
        required.allows(Capability::Delete),
        "renaming away removes a name and must need delete"
    );

    let create_only = CapabilitySet::from_slice(&[Capability::Write, Capability::List]);
    let rename_feature = FeatureSet::NONE.with(Feature::AtomicRename);
    assert!(!ClientOperation::Rename.is_available(create_only, rename_feature));
    assert!(
        ClientOperation::Rename.is_available(create_only.with(Capability::Delete), rename_feature)
    );
}

#[test]
fn listing_a_directory_does_not_grant_reading_its_files() {
    let list_only = CapabilitySet::from_slice(&[Capability::List]);
    assert!(ClientOperation::ReadDirectory.is_available(list_only, FeatureSet::NONE));
    assert!(ClientOperation::Stat.is_available(list_only, FeatureSet::NONE));
    assert!(
        !ClientOperation::ReadFile.is_available(list_only, FeatureSet::NONE),
        "enumerating names must not imply reading content"
    );

    let read_only = CapabilitySet::from_slice(&[Capability::Read]);
    assert!(ClientOperation::ReadFile.is_available(read_only, FeatureSet::NONE));
    assert!(
        !ClientOperation::ReadDirectory.is_available(read_only, FeatureSet::NONE),
        "reading content must not imply enumerating names"
    );
}

#[test]
fn read_only_is_derived_from_the_grant_and_denies_every_mutating_primitive() {
    let read_only = example_grant();
    assert!(read_only.is_read_only());

    let all_features = FeatureSet::from_slice(&Feature::ALL);
    let mutating = [
        Primitive::OpenWrite,
        Primitive::OpenTruncate,
        Primitive::Create,
        Primitive::Write,
        Primitive::Mkdir,
        Primitive::Unlink,
        Primitive::RemoveDir,
        Primitive::Rename,
        Primitive::SetattrSize,
        Primitive::SetattrMode,
        Primitive::SetattrTimes,
        Primitive::Symlink,
        Primitive::Link,
    ];
    for primitive in mutating {
        assert!(
            !primitive.is_permitted(read_only, all_features),
            "a read-only grant must deny {primitive}"
        );
    }

    for capability in [Capability::Write, Capability::Delete] {
        assert!(
            !CapabilitySet::DENY.with(capability).is_read_only(),
            "{capability} makes a grant writable"
        );
    }
}

#[test]
fn walking_without_list_discloses_qids_and_nothing_further() {
    // A recorded decision: `Twalk` requires no capability, so a read-by-name
    // grant (`read` without `list`) can reach a file it already knows the path
    // of.  The cost is that a write-only or delete-only grant can probe name
    // existence and node type through `Rwalk` qids.  This test pins the extent
    // of that disclosure: qids only, never attributes or directory contents.
    for capability in [Capability::Write, Capability::Delete] {
        let grant = CapabilitySet::DENY.with(capability);
        assert!(
            Primitive::Walk.is_permitted(grant, FeatureSet::NONE),
            "{capability} alone may walk"
        );
        for denied in [Primitive::Getattr, Primitive::Readdir, Primitive::OpenDir] {
            assert!(
                !denied.is_permitted(grant, FeatureSet::NONE),
                "{capability} alone must not reach {denied}"
            );
        }
        assert!(
            !Primitive::Read.is_permitted(grant, FeatureSet::NONE),
            "{capability} alone must not read content"
        );
        // And no metadata operation is advertised to such a grant.
        for operation in ClientOperation::derive_all(grant, FeatureSet::NONE) {
            assert_ne!(operation, ClientOperation::Stat);
            assert_ne!(operation, ClientOperation::ReadDirectory);
        }
    }

    // The point of the decision: read-by-name works without list.
    let read_by_name = CapabilitySet::DENY.with(Capability::Read);
    assert!(ClientOperation::ReadFile.is_available(read_by_name, FeatureSet::NONE));
}

#[test]
fn the_read_only_profile_is_read_and_list_together() {
    // Named so integrators do not configure `read` alone: without `list` there
    // is no `stat`, and a Files SDK head or exists call has nothing to call.
    let read_alone = CapabilitySet::DENY.with(Capability::Read);
    assert!(!ClientOperation::Stat.is_available(read_alone, FeatureSet::NONE));

    let profile = example_grant();
    assert_eq!(
        profile,
        CapabilitySet::from_slice(&[Capability::Read, Capability::List])
    );
    assert!(profile.is_read_only());
    for operation in [
        ClientOperation::ReadFile,
        ClientOperation::ReadStream,
        ClientOperation::Stat,
        ClientOperation::ReadDirectory,
        ClientOperation::Realpath,
    ] {
        assert!(
            operation.is_available(profile, FeatureSet::NONE),
            "{operation} belongs to the read-only profile"
        );
    }
}

#[test]
fn the_example_grant_derives_exactly_the_checked_in_operation_list() {
    // `docs/contracts/filesystem-capabilities.example.json` advertises these
    // five operations with no feature enabled.  The derivation must reproduce
    // that list from the grant alone.
    let derived = ClientOperation::derive_all(example_grant(), FeatureSet::NONE);
    let names: Vec<&str> = derived.iter().map(|operation| operation.as_str()).collect();
    assert_eq!(
        names,
        [
            "readFile",
            "readStream",
            "stat",
            "readDirectory",
            "realpath"
        ]
    );
}

#[test]
fn every_spelling_round_trips_and_is_unique() {
    let mut seen = Vec::new();
    for capability in Capability::ALL {
        assert_eq!(Capability::parse(capability.as_str()), Some(capability));
        seen.push(capability.as_str());
    }
    for operation in ClientOperation::ALL {
        assert_eq!(
            ClientOperation::parse(operation.as_str()),
            Some(operation),
            "{operation}"
        );
    }
    seen.sort_unstable();
    let before = seen.len();
    seen.dedup();
    assert_eq!(before, seen.len(), "capability spellings must be unique");

    let mut primitives: Vec<&str> = Primitive::ALL.iter().map(|p| p.as_str()).collect();
    primitives.sort_unstable();
    let before = primitives.len();
    primitives.dedup();
    assert_eq!(
        before,
        primitives.len(),
        "primitive spellings must be unique"
    );

    assert_eq!(ClientOperation::ALL.len(), 17, "the schema allows 17 names");
    assert_eq!(Capability::parse("admin"), None);
    assert_eq!(ClientOperation::parse("exec"), None);
}

#[test]
fn derivation_is_monotone_in_the_grant_across_every_subset() {
    // Over all 16 grants and all 128 feature sets, adding a capability can only
    // add operations, never remove one.  A rule that accidentally made a
    // capability exclusive would fail here.
    for grant_bits in 0u8..16 {
        let grant = subset_grant(grant_bits);
        for feature_bits in 0u8..128 {
            let features = subset_features(feature_bits);
            let base: Vec<ClientOperation> = ClientOperation::derive_all(grant, features);
            for capability in Capability::ALL {
                if grant.allows(capability) {
                    continue;
                }
                let wider = ClientOperation::derive_all(grant.with(capability), features);
                for operation in &base {
                    assert!(
                        wider.contains(operation),
                        "adding {capability} removed {operation}"
                    );
                }
            }
        }
    }
}

#[test]
fn no_grant_can_advertise_an_operation_it_cannot_execute() {
    // Exhaustive over every grant and feature set: an advertised operation's
    // every primitive must be independently permitted.  This is the invariant
    // that makes the descriptor's `operations` non-fictional.
    for grant_bits in 0u8..16 {
        let grant = subset_grant(grant_bits);
        for feature_bits in 0u8..128 {
            let features = subset_features(feature_bits);
            for operation in ClientOperation::derive_all(grant, features) {
                for primitive in operation.primitives() {
                    assert!(
                        primitive.is_permitted(grant, features),
                        "{operation} was advertised but {primitive} is denied"
                    );
                }
            }
        }
    }
}

#[test]
fn seeded_random_grants_never_advertise_an_unpermitted_operation() {
    for seed in 0..10_000u64 {
        let mut rng = Rng::new(seed | 1);
        let grant = subset_grant((rng.below(16)) as u8);
        let features = subset_features((rng.below(128)) as u8);
        for operation in ClientOperation::ALL {
            let advertised = operation.is_available(grant, features);
            let executable = operation
                .primitives()
                .iter()
                .all(|primitive| primitive.is_permitted(grant, features));
            assert_eq!(advertised, executable, "seed {seed}: {operation}");
        }
    }
}

fn subset_grant(bits: u8) -> CapabilitySet {
    let mut grant = CapabilitySet::DENY;
    for (index, capability) in Capability::ALL.into_iter().enumerate() {
        if bits & (1 << index) != 0 {
            grant = grant.with(capability);
        }
    }
    grant
}

fn subset_features(bits: u8) -> FeatureSet {
    let mut features = FeatureSet::NONE;
    for (index, feature) in Feature::ALL.into_iter().enumerate() {
        if bits & (1 << index) != 0 {
            features = features.with(feature);
        }
    }
    features
}
