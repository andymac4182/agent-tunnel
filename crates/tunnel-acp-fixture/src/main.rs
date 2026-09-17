#![forbid(unsafe_code)]
//! The synthetic ACP agent fixture binary.
//!
//! * `tunnel-acp-fixture agent` serves the deterministic v1 agent on stdio.
//! * `tunnel-acp-fixture detached <pid-file>` is the descendant that calls
//!   `setsid` and deliberately outlives its process group.

use std::path::PathBuf;

use tunnel_acp_fixture::{AGENT_MODE, DETACHED_MODE};

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
        _ => std::process::ExitCode::from(2),
    }
}
