//! `--help` on every relay subcommand prints the help and exits 0.
//!
//! Demo-readiness defect D6 was found on `tunnel-client connect --help`,
//! which exited 2; the relay's subcommands fell through to the same usage
//! error. The relay runs only on Unix, so this runs only there.
#![cfg(unix)]

use std::process::Command;

const SUBCOMMANDS: [&str; 17] = [
    "check-config",
    "check-serve-config",
    "serve",
    "initialize",
    "activate-first-incarnation",
    "rebind-redis-run",
    "provision-catalog",
    "add-user",
    "add-device",
    "add-service",
    "set-grant",
    "revoke-grant",
    "revoke-device",
    "revoke-credential",
    "recovery-initialize",
    "recovery-observe",
    "recover",
];

fn relay(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_tunnel-relay"))
        .args(args)
        .output()
        .expect("run tunnel-relay")
}

#[test]
fn help_on_every_subcommand_exits_zero_and_prints_the_help() {
    for subcommand in SUBCOMMANDS {
        for flag in ["--help", "-h"] {
            let output = relay(&[subcommand, flag]);
            assert_eq!(
                output.status.code(),
                Some(0),
                "{subcommand} {flag} must exit 0; stderr: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(
                stdout.contains("Usage: tunnel-relay") && stdout.contains(subcommand),
                "{subcommand} {flag} must print the help naming it: {stdout}"
            );
        }
    }
    // After other arguments too, and without the subcommand's required ones.
    let output = relay(&["serve", "--config", "absent.toml", "--help"]);
    assert_eq!(output.status.code(), Some(0));
}

#[test]
fn an_unknown_subcommand_with_help_is_still_an_error() {
    let output = relay(&["definitely-not-a-command", "--help"]);
    assert_ne!(output.status.code(), Some(0));
}
