#![forbid(unsafe_code)]
//! The synthetic ACP agent fixture binary.
//!
//! * `tunnel-acp-fixture agent` serves the deterministic v1 agent on stdio.
//! * `tunnel-acp-fixture detached <pid-file>` is the descendant that calls
//!   `setsid` and deliberately outlives its process group.
//! * `tunnel-acp-fixture helper <pid-file>` is the in-group control: the same
//!   shape, staying in the group, so a group signal is supposed to reach it.
//! * `tunnel-acp-fixture wrapper <pid-file> <helper-pid-file>` is the
//!   `npx`-shaped wrapper that starts such a helper and then drains stdin.
//! * `tunnel-acp-fixture supervise <workspace>` runs a real export supervisor
//!   over that wrapper and parks, so a test can `SIGKILL` it from outside.

use std::path::PathBuf;

use tunnel_acp_fixture::{AGENT_MODE, DETACHED_MODE, HELPER_MODE, SUPERVISE_MODE, WRAPPER_MODE};

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> std::process::ExitCode {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    match arguments.first().map(String::as_str) {
        Some(mode) if mode == AGENT_MODE && arguments.len() == 1 => {
            tunnel_acp_fixture::run_agent().await;
            std::process::ExitCode::SUCCESS
        }
        Some(mode) if mode == DETACHED_MODE && arguments.len() == 2 => {
            tunnel_acp_fixture::run_detached(&PathBuf::from(&arguments[1])).await;
            std::process::ExitCode::SUCCESS
        }
        Some(mode) if mode == HELPER_MODE && arguments.len() == 2 => {
            tunnel_acp_fixture::run_helper(&PathBuf::from(&arguments[1])).await;
            std::process::ExitCode::SUCCESS
        }
        Some(mode) if mode == WRAPPER_MODE && arguments.len() == 3 => {
            tunnel_acp_fixture::run_wrapper(
                &PathBuf::from(&arguments[1]),
                &PathBuf::from(&arguments[2]),
            )
            .await;
            std::process::ExitCode::SUCCESS
        }
        Some(mode) if mode == SUPERVISE_MODE && arguments.len() == 2 => {
            tunnel_acp_fixture::run_supervise(&PathBuf::from(&arguments[1])).await;
            std::process::ExitCode::SUCCESS
        }
        _ => std::process::ExitCode::from(2),
    }
}
