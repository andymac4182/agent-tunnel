#![forbid(unsafe_code)]
//! The synthetic CUA fixture binary.
//!
//! * `tunnel-cua-fixture backend <address-file> <journal> <helper-pid-file>
//!   [<hang-command>]` is the **supervised backend**: it serves `/cmd` on
//!   `127.0.0.1:0`, publishes the address it bound, starts an in-group helper,
//!   and waits for stdin to close. The optional fifth argument names one
//!   command that records its effect and then never answers -- the hung
//!   backend a supervisor exists to restart.
//! * `tunnel-cua-fixture detach-host <setsid|daemon> <address-file> <journal>
//!   <pid-file>` is the same backend, plus one descendant that deliberately
//!   **leaves** its process group (M3-09).
//! * `tunnel-cua-fixture helper <pid-file>` is the in-group worker that never
//!   reads stdin.
//! * `tunnel-cua-fixture detached <setsid|daemon> <pid-file>` is the escaping
//!   descendant, and `daemonize <pid-file>` is the middle process of the
//!   double-fork route.
//! * `tunnel-cua-fixture supervise <workspace>` is a real
//!   [`tunnel_cua_export`] supervisor in a process a test can `SIGKILL`.
//!
//! An unrecognised mode or arity exits `2` rather than picking a default: a
//! typo in a test must not quietly run a different measurement.

use std::path::PathBuf;

use tunnel_cua_fixture::process::{
    BACKEND_MODE, DAEMONIZER_MODE, DETACH_HOST_MODE, DETACHED_MODE, DetachRoute, HELPER_MODE,
    SUPERVISE_MODE,
};

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> std::process::ExitCode {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    let path = |index: usize| PathBuf::from(&arguments[index]);
    match arguments.first().map(String::as_str) {
        Some(mode) if mode == BACKEND_MODE && (arguments.len() == 4 || arguments.len() == 5) => {
            let hang = arguments.get(4).map(String::as_str);
            tunnel_cua_fixture::process::run_backend(&path(1), &path(2), &path(3), hang).await;
            std::process::ExitCode::SUCCESS
        }
        Some(mode) if mode == DETACH_HOST_MODE && arguments.len() == 5 => {
            let Some(route) = DetachRoute::parse(&arguments[1]) else {
                return std::process::ExitCode::from(2);
            };
            tunnel_cua_fixture::process::run_detach_host(route, &path(2), &path(3), &path(4)).await;
            std::process::ExitCode::SUCCESS
        }
        Some(mode) if mode == HELPER_MODE && arguments.len() == 2 => {
            tunnel_cua_fixture::process::run_helper(&path(1)).await;
            std::process::ExitCode::SUCCESS
        }
        Some(mode) if mode == DETACHED_MODE && arguments.len() == 3 => {
            let Some(route) = DetachRoute::parse(&arguments[1]) else {
                return std::process::ExitCode::from(2);
            };
            tunnel_cua_fixture::process::run_detached(route, &path(2)).await;
            std::process::ExitCode::SUCCESS
        }
        Some(mode) if mode == DAEMONIZER_MODE && arguments.len() == 2 => {
            tunnel_cua_fixture::process::run_daemonizer(&path(1));
            // Exiting here is the point: it orphans the descendant.
            std::process::ExitCode::SUCCESS
        }
        Some(mode) if mode == SUPERVISE_MODE && arguments.len() == 2 => {
            tunnel_cua_fixture::process::run_supervise(&path(1)).await;
            std::process::ExitCode::SUCCESS
        }
        _ => std::process::ExitCode::from(2),
    }
}
