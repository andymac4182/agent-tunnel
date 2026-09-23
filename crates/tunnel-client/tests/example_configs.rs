//! The client half of the checked-in example walk.
//!
//! `crates/tunnel-relay/tests/example_configs.rs` classifies every file under
//! `examples/` and validates the relay ones. It defers the client files to this
//! test, which validates each with the type the corresponding command actually
//! loads: `ConnectConfig` (`tunnel_client::config::RuntimeConfig`) for
//! `config check --config` and `connect --config`, and the legacy
//! `tunnel_core::ClientConfig` for `check-config [PATH]`.
//!
//! Both parsers validate TOML without touching the filesystem, so this walk is
//! deterministic and does not require the credential files the placeholder
//! paths name.

use std::{
    collections::BTreeMap,
    ffi::OsStr,
    fs,
    path::{Path, PathBuf},
};

use tunnel_client::ConnectConfig;
use tunnel_core::ClientConfig;

/// The parser that owns an example file at runtime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExampleParser {
    /// `tunnel_client::ConnectConfig`: the type `config check --config PATH`
    /// and `connect --config PATH` both load.
    ClientRuntime,
    /// `tunnel_core::ClientConfig`: the legacy `check-config [PATH]` type. It
    /// carries no endpoint or credential reference and cannot connect.
    ClientLegacy,
    /// A relay file, validated by the relay walk.
    Relay,
}

/// Every example under `examples/`, with the parser that validates it. The
/// relay walk keeps the same inventory, so an example added without
/// classification fails both tests.
const CLASSIFIED_EXAMPLES: &[(&str, ExampleParser)] = &[
    ("client.toml", ExampleParser::ClientLegacy),
    ("m1-client.toml", ExampleParser::ClientRuntime),
    ("m1-relay.toml", ExampleParser::Relay),
    // The relay's provisioning records document (task row M6-C21); the relay
    // walk parses it.
    ("m6-catalog.toml", ExampleParser::Relay),
    ("m7-cluster-relay.toml", ExampleParser::Relay),
    ("relay.toml", ExampleParser::Relay),
];

fn examples_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples")
        .canonicalize()
        .expect("canonicalize the checked-in examples directory")
}

fn present_examples() -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(examples_dir())
        .expect("read the checked-in examples directory")
        .map(|entry| entry.expect("read an examples directory entry"))
        .filter(|entry| {
            entry
                .file_type()
                .expect("read an examples entry file type")
                .is_file()
        })
        .map(|entry| entry.path())
        .filter(|path| path.extension() == Some(OsStr::new("toml")))
        .map(|path| {
            path.file_name()
                .expect("example file name")
                .to_str()
                .expect("example file names are UTF-8")
                .to_owned()
        })
        .collect();
    names.sort();
    names
}

#[test]
fn every_checked_in_client_example_is_classified_and_parsed_by_its_loading_parser() {
    let table: BTreeMap<&'static str, ExampleParser> =
        CLASSIFIED_EXAMPLES.iter().copied().collect();
    assert_eq!(
        table.len(),
        CLASSIFIED_EXAMPLES.len(),
        "the classification table lists a file twice"
    );
    let classified: Vec<String> = table.keys().map(|name| (*name).to_owned()).collect();
    assert_eq!(
        present_examples(),
        classified,
        "every examples/*.toml file must be classified with the parser that validates it"
    );

    let directory = examples_dir();
    for (name, parser) in CLASSIFIED_EXAMPLES {
        let path = directory.join(name);
        let input = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("read example {name}: {error}"));
        match parser {
            ExampleParser::ClientRuntime => {
                ConnectConfig::parse(&input).unwrap_or_else(|error| {
                    panic!("example {name} is not a valid runtime client configuration: {error}")
                });
            }
            ExampleParser::ClientLegacy => {
                ClientConfig::parse(&input).unwrap_or_else(|error| {
                    panic!("example {name} is not a valid legacy client configuration: {error}")
                });
                // The legacy starter must stay distinguishable from a runnable
                // profile: it has no endpoint or credential reference, so a
                // reader cannot mistake it for something `connect` accepts.
                assert!(
                    ConnectConfig::parse(&input).is_err(),
                    "legacy starter {name} parsed as a runnable connect profile"
                );
            }
            ExampleParser::Relay => {
                // Validated by the relay walk. Confirm only that a relay
                // document cannot pass as a client profile, so a misclassified
                // file cannot satisfy both walks vacuously.
                assert!(
                    ConnectConfig::parse(&input).is_err(),
                    "relay example {name} parsed as a runtime client configuration"
                );
            }
        }
    }
}
