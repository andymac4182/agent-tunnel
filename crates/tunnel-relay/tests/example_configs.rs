//! Every checked-in example must be validated by the parser that actually
//! serves with it.
//!
//! `examples/m1-relay.toml` shipped a `redis_namespace` the Redis authority
//! rejects, so the documented `serve --config examples/m1-relay.toml` failed at
//! startup while the legacy `check-config` command — the only relay example
//! check CI ran — stayed green on a different file. These tests close that
//! drift from two directions: the walk refuses an example nobody parses, and
//! the glob assertion keeps the CI dry-run step's file selection in step with
//! the classification table.
//!
//! The walk reads only the configuration documents. It opens no socket, makes
//! no Redis connection and reads no credential material, so it is
//! deterministic and does not require the deployment files the placeholder
//! paths name.

use std::{
    collections::BTreeMap,
    ffi::OsStr,
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

use tunnel_core::RelayConfig;
use tunnel_relay::{ServeConfig, provisioning::ProvisioningRecords};

/// The shell glob the CI dry-run step expands. Every `RelayServe` example must
/// match it and nothing else may, so a newly added serving example is covered
/// by CI without editing the workflow.
const CI_SERVE_GLOB_SUFFIX: &str = "-relay.toml";

/// The parser that owns an example file at runtime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExampleParser {
    /// `tunnel_relay::ServeConfig`: the type `serve --config PATH` and the new
    /// `check-serve-config --config PATH` dry run both construct.
    RelayServe,
    /// `tunnel_core::RelayConfig`: the legacy `check-config [PATH]` type. It
    /// configures no listener and is not a serving document.
    RelayLegacy,
    /// `tunnel_relay::provisioning::ProvisioningRecords`: the records document
    /// `provision-catalog --records PATH` reads (task row M6-C21).
    CatalogRecords,
    /// A `tunnel-client` type. Covered by the matching walk in
    /// `crates/tunnel-client/tests/example_configs.rs`; the relay crate cannot
    /// construct those parsers.
    Client,
}

/// Every example under `examples/`, with the parser that validates it.
///
/// The walk asserts this table lists the directory exactly, so adding an
/// example without classifying it fails here rather than shipping unvalidated.
const CLASSIFIED_EXAMPLES: &[(&str, ExampleParser)] = &[
    ("client.toml", ExampleParser::Client),
    ("m1-client.toml", ExampleParser::Client),
    ("m1-relay.toml", ExampleParser::RelayServe),
    ("m6-catalog.toml", ExampleParser::CatalogRecords),
    ("m7-cluster-relay.toml", ExampleParser::RelayServe),
    ("relay.toml", ExampleParser::RelayLegacy),
];

fn examples_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples")
        .canonicalize()
        .expect("canonicalize the checked-in examples directory")
}

/// Every `.toml` file actually present, sorted.
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

fn classification_table() -> BTreeMap<&'static str, ExampleParser> {
    CLASSIFIED_EXAMPLES.iter().copied().collect()
}

#[test]
fn every_checked_in_example_is_classified_and_parsed_by_its_serving_parser() {
    let table = classification_table();
    assert_eq!(
        table.len(),
        CLASSIFIED_EXAMPLES.len(),
        "the classification table lists a file twice"
    );
    let classified: Vec<String> = table.keys().map(|name| (*name).to_owned()).collect();
    assert_eq!(
        present_examples(),
        classified,
        "every examples/*.toml file must be classified with the parser that validates it; \
         add the new example to CLASSIFIED_EXAMPLES (and to the client walk if it is a client file)"
    );

    let directory = examples_dir();
    for (name, parser) in CLASSIFIED_EXAMPLES {
        let path = directory.join(name);
        let input = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("read example {name}: {error}"));
        match parser {
            ExampleParser::RelayServe => {
                ServeConfig::parse(&input).unwrap_or_else(|error| {
                    panic!("example {name} is not a valid serving configuration: {error}")
                });
            }
            ExampleParser::RelayLegacy => {
                RelayConfig::parse(&input).unwrap_or_else(|error| {
                    panic!("example {name} is not a valid legacy relay configuration: {error}")
                });
            }
            ExampleParser::CatalogRecords => {
                toml::from_str::<ProvisioningRecords>(&input).unwrap_or_else(|error| {
                    panic!("example {name} is not a valid provisioning records document: {error}")
                });
                assert!(
                    ServeConfig::parse(&input).is_err(),
                    "records example {name} parsed as a relay serving configuration"
                );
            }
            ExampleParser::Client => {
                // Asserted by the tunnel-client walk. Confirm only that the
                // relay parsers do not silently accept a client document, so a
                // misclassified file cannot pass both walks vacuously.
                assert!(
                    ServeConfig::parse(&input).is_err(),
                    "client example {name} parsed as a relay serving configuration"
                );
            }
        }
    }
}

#[test]
fn serving_examples_are_exactly_the_files_the_ci_dry_run_glob_expands() {
    for (name, parser) in CLASSIFIED_EXAMPLES {
        let matches_glob = name.ends_with(CI_SERVE_GLOB_SUFFIX);
        assert_eq!(
            matches_glob,
            *parser == ExampleParser::RelayServe,
            "example {name} must match the CI dry-run glob examples/*{CI_SERVE_GLOB_SUFFIX} \
             exactly when it is a serving configuration"
        );
    }
    assert!(
        CLASSIFIED_EXAMPLES
            .iter()
            .any(|(_, parser)| *parser == ExampleParser::RelayServe),
        "the CI dry-run glob would expand to nothing"
    );
}

fn relay_binary() -> std::ffi::OsString {
    std::env::var_os("CARGO_BIN_EXE_tunnel-relay")
        .expect("Cargo must provide the tunnel-relay binary for CLI tests")
}

fn run_cli<I, S>(args: I) -> Output
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    Command::new(relay_binary())
        .args(args)
        .output()
        .expect("run the tunnel-relay CLI")
}

#[test]
fn check_serve_config_accepts_every_serving_example_and_exits_zero() {
    let directory = examples_dir();
    for (name, parser) in CLASSIFIED_EXAMPLES {
        if *parser != ExampleParser::RelayServe {
            continue;
        }
        let output = run_cli([
            OsStr::new("check-serve-config"),
            OsStr::new("--config"),
            directory.join(name).as_os_str(),
        ]);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(
            output.status.code(),
            Some(0),
            "check-serve-config must exit 0 for {name}; stderr: {stderr}"
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("serving configuration is valid"),
            "check-serve-config printed no success line for {name}"
        );
    }
}

#[test]
fn check_serve_config_rejects_the_namespace_that_broke_the_documented_serve_command() {
    let directory = examples_dir();
    let valid = fs::read_to_string(directory.join("m1-relay.toml")).expect("read m1-relay example");
    // The exact regression: a namespace the Redis authority refuses, which
    // `serve` previously discovered only when it connected.
    let broken = valid.replace(
        "redis_namespace = \"agent-tunnel-m1\"",
        "redis_namespace = \"agent-tunnel/m1\"",
    );
    assert_ne!(
        broken, valid,
        "the m1-relay example no longer carries the namespace this regression pins"
    );

    assert!(
        ServeConfig::parse(&broken).is_err(),
        "ServeConfig::parse accepted a namespace the Redis authority rejects, so serve would \
         bind listeners before failing"
    );

    let temporary = std::env::temp_dir().join(format!(
        "agent-tunnel-example-dry-run-{}.toml",
        std::process::id()
    ));
    fs::write(&temporary, &broken).expect("write the invalid serving configuration");
    let output = run_cli([
        OsStr::new("check-serve-config"),
        OsStr::new("--config"),
        temporary.as_os_str(),
    ]);
    let status = output.status.code();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    fs::remove_file(&temporary).expect("remove the invalid serving configuration");
    assert_eq!(
        status,
        Some(1),
        "check-serve-config must exit 1 for an invalid configuration; stderr: {stderr}"
    );
    assert!(
        stderr.contains("redis_namespace"),
        "the failure must name the offending field: {stderr}"
    );
}

#[test]
fn check_serve_config_rejects_a_legacy_relay_example_instead_of_serving_with_it() {
    let directory = examples_dir();
    let output = run_cli([
        OsStr::new("check-serve-config"),
        OsStr::new("--config"),
        directory.join("relay.toml").as_os_str(),
    ]);
    assert_eq!(
        output.status.code(),
        Some(1),
        "the legacy relay starter is not a serving configuration"
    );
}

#[test]
fn check_serve_config_requires_exactly_the_config_flag() {
    for args in [
        vec!["check-serve-config"],
        vec!["check-serve-config", "examples/m1-relay.toml"],
        vec!["check-serve-config", "--config"],
        vec![
            "check-serve-config",
            "--config",
            "examples/m1-relay.toml",
            "--config",
            "examples/m1-relay.toml",
        ],
    ] {
        let output = run_cli(args.iter().map(OsStr::new));
        assert_eq!(
            output.status.code(),
            Some(1),
            "malformed invocation {args:?} must fail"
        );
    }
}
