//! The `tunnel-test-harness` executable.
//!
//! **Unix-only, by declaration.** The harness drives real processes and
//! sockets the way a Unix host offers them -- process groups and `kill`,
//! Unix-domain sockets for the MCP gate, `lsof`, POSIX file modes -- and it has
//! never compiled for Windows. The Windows CI job builds the whole workspace,
//! so rather than leave it red on a crate no Windows host runs, the library is
//! `#![cfg(unix)]` and this entry point says so at run time. The acceptance
//! command itself stays in `src/main.rs`, where `scripts/m7-evidence-guard.py`
//! reads its `verify-*` commands from.

#[cfg(unix)]
#[path = "main.rs"]
mod cli;

#[cfg(unix)]
fn main() -> std::process::ExitCode {
    cli::main()
}

#[cfg(not(unix))]
fn main() -> std::process::ExitCode {
    eprintln!("tunnel-test-harness: the acceptance harness requires a Unix host");
    std::process::ExitCode::from(2)
}
