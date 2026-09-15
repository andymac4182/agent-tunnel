#![forbid(unsafe_code)]
//! `tunnel-mcp-fixture stdio` serves [`tunnel_mcp_fixture::FixtureServer`]
//! over stdio, recording markers in its working directory (the export's
//! configured synthetic workspace).

use rmcp::ServiceExt;
use tunnel_mcp_fixture::FixtureServer;

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> std::process::ExitCode {
    let mode = std::env::args().nth(1);
    if mode.as_deref() != Some("stdio") {
        return std::process::ExitCode::from(2);
    }
    let server = FixtureServer::new(std::env::current_dir().ok());
    let Ok(running) = server.serve(rmcp::transport::stdio()).await else {
        return std::process::ExitCode::from(1);
    };
    let _ = running.waiting().await;
    std::process::ExitCode::SUCCESS
}
