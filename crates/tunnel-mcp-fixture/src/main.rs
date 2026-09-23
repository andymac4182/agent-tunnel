#![forbid(unsafe_code)]
//! The synthetic fixture server binary.
//!
//! * `tunnel-mcp-fixture stdio` serves [`tunnel_mcp_fixture::FixtureServer`]
//!   over stdio, recording markers in its working directory (the export's
//!   configured synthetic workspace).
//! * `tunnel-mcp-fixture http <marker-dir> <port> <stateless|legacy>
//!   <address-file>` serves it with the official rmcp Streamable HTTP server
//!   on `127.0.0.1:<port>` (0 picks a free port) and writes the bound address
//!   to `<address-file>`.  `legacy` enables rmcp's 2025-11-25 sessions.
//! * `tunnel-mcp-fixture descendant <pid-file>` is the synthetic descendant
//!   the `sleep` and `crash` tools can start.  It stays in the server's
//!   process group, so a group kill reaches it.
//! * `tunnel-mcp-fixture detached <setsid|daemon> <pid-file>` is the
//!   descendant that deliberately **leaves** that group (M3-09).
//! * `tunnel-mcp-fixture daemonize <pid-file>` is the middle process of the
//!   `daemon` route: it starts the descendant in a new process group and
//!   exits, orphaning it.
//! * `tunnel-mcp-fixture wrapper <pid-file> <helper-pid-file>` is the
//!   `npx`-shaped backend the `supervise` probe supervises.
//! * `tunnel-mcp-fixture supervise <workspace>` is a real export supervisor
//!   in a process a test can `SIGKILL`.

use std::path::PathBuf;

use rmcp::ServiceExt;
use tunnel_mcp_fixture::{
    DAEMONIZER_MODE, DESCENDANT_MODE, DETACHED_MODE, DetachRoute, FixtureServer, SUPERVISE_MODE,
    SUPERVISE_RETURN_MODE, WRAPPER_MODE,
};

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> std::process::ExitCode {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    match arguments.first().map(String::as_str) {
        Some("stdio") if arguments.len() == 1 => {
            let server = FixtureServer::new(std::env::current_dir().ok());
            let Ok(running) = server.serve(rmcp::transport::stdio()).await else {
                return std::process::ExitCode::from(1);
            };
            let _ = running.waiting().await;
            std::process::ExitCode::SUCCESS
        }
        Some("http") if arguments.len() == 5 => {
            let marker_dir = PathBuf::from(&arguments[1]);
            let Ok(port) = arguments[2].parse::<u16>() else {
                return std::process::ExitCode::from(2);
            };
            let legacy = match arguments[3].as_str() {
                "legacy" => true,
                "stateless" => false,
                _ => return std::process::ExitCode::from(2),
            };
            let Ok(listener) = tokio::net::TcpListener::bind(("127.0.0.1", port)).await else {
                return std::process::ExitCode::from(1);
            };
            let Ok(address) = listener.local_addr() else {
                return std::process::ExitCode::from(1);
            };
            let address_file = PathBuf::from(&arguments[4]);
            let temporary = address_file.with_extension("tmp");
            if tokio::fs::write(&temporary, address.to_string())
                .await
                .is_err()
                || tokio::fs::rename(&temporary, &address_file).await.is_err()
            {
                return std::process::ExitCode::from(1);
            }
            tunnel_mcp_fixture::serve_http(
                listener,
                legacy,
                marker_dir,
                tokio_util::sync::CancellationToken::new(),
            )
            .await;
            std::process::ExitCode::SUCCESS
        }
        Some(mode) if mode == DESCENDANT_MODE && arguments.len() == 2 => {
            tunnel_mcp_fixture::run_descendant(&PathBuf::from(&arguments[1])).await;
            std::process::ExitCode::SUCCESS
        }
        Some(mode) if mode == DETACHED_MODE && arguments.len() == 3 => {
            // An unknown route exits non-zero rather than picking one: a
            // typo must not silently measure the other escape.
            let Some(route) = DetachRoute::parse(&arguments[1]) else {
                return std::process::ExitCode::from(2);
            };
            tunnel_mcp_fixture::run_detached(route, &PathBuf::from(&arguments[2])).await;
            std::process::ExitCode::SUCCESS
        }
        Some(mode) if mode == DAEMONIZER_MODE && arguments.len() == 2 => {
            tunnel_mcp_fixture::run_daemonizer(&PathBuf::from(&arguments[1]));
            // Exiting here is the point: it orphans the descendant.
            std::process::ExitCode::SUCCESS
        }
        Some(mode) if mode == WRAPPER_MODE && arguments.len() == 3 => {
            tunnel_mcp_fixture::run_wrapper(
                &PathBuf::from(&arguments[1]),
                &PathBuf::from(&arguments[2]),
            )
            .await;
            std::process::ExitCode::SUCCESS
        }
        Some(mode) if mode == tunnel_mcp_fixture::DETACH_HOST_MODE && arguments.len() == 3 => {
            let Some(route) = DetachRoute::parse(&arguments[1]) else {
                return std::process::ExitCode::from(2);
            };
            tunnel_mcp_fixture::run_detach_host(route, &PathBuf::from(&arguments[2])).await;
            std::process::ExitCode::SUCCESS
        }
        Some(mode) if mode == SUPERVISE_RETURN_MODE && arguments.len() == 4 => {
            let wait_for_reap = match arguments[2].as_str() {
                "wait" => true,
                "nowait" => false,
                _ => return std::process::ExitCode::from(2),
            };
            let workspace = PathBuf::from(&arguments[1]);
            match arguments[3].as_str() {
                // This runtime, torn down when `main` returns: the flavour
                // `tunnel-client` runs on, where whether the supervisor task
                // is polled first is a race.
                "multi" => {
                    tunnel_mcp_fixture::run_supervise_then_return(&workspace, wait_for_reap).await;
                }
                // A current-thread runtime of its own, dropped as soon as the
                // probe returns: nothing else can poll the supervisor task, so
                // the race is always lost and the outcome is deterministic.
                "single" => {
                    let probe = std::thread::spawn(move || {
                        let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                            .enable_all()
                            .build()
                        else {
                            return false;
                        };
                        runtime.block_on(tunnel_mcp_fixture::run_supervise_then_return(
                            &workspace,
                            wait_for_reap,
                        ));
                        drop(runtime);
                        true
                    });
                    if !probe.join().unwrap_or(false) {
                        return std::process::ExitCode::from(1);
                    }
                }
                _ => return std::process::ExitCode::from(2),
            }
            std::process::ExitCode::SUCCESS
        }
        Some(mode) if mode == SUPERVISE_MODE && arguments.len() == 2 => {
            tunnel_mcp_fixture::run_supervise(&PathBuf::from(&arguments[1])).await;
            std::process::ExitCode::SUCCESS
        }
        _ => std::process::ExitCode::from(2),
    }
}
