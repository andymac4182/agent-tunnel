use std::{process::ExitCode, time::Duration};
use tunnel_test_harness::{HarnessError, acceptance, redis_restart};

#[tokio::main]
async fn main() -> ExitCode {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn"));
    let _ = tracing_subscriber::fmt()
        .json()
        .with_writer(std::io::stderr)
        .with_env_filter(filter)
        .try_init();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.as_slice() {
        [command] if command == "verify" => {
            match tokio::time::timeout(Duration::from_secs(180), acceptance::verify()).await {
                Ok(result) => result,
                Err(_) => Err(HarnessError::Timeout(
                    "M1 acceptance exceeded 180 seconds".to_owned(),
                )),
            }
        }
        [
            command,
            url_flag,
            url,
            namespace_flag,
            namespace,
            receipt_flag,
            receipt,
        ] if matches!(
            command.as_str(),
            "redis-restart-seed" | "redis-restart-check"
        ) && url_flag == "--redis-url"
            && namespace_flag == "--namespace"
            && receipt_flag == "--receipt-file" =>
        {
            let operation = async {
                if command == "redis-restart-seed" {
                    redis_restart::seed(url, namespace, receipt).await
                } else {
                    redis_restart::check(url, namespace, receipt).await
                }
            };
            match tokio::time::timeout(Duration::from_secs(30), operation).await {
                Ok(result) => result.map_err(|error| HarnessError::Redis(error.to_string())),
                Err(_) => Err(HarnessError::Timeout(
                    "Redis restart probe exceeded 30 seconds".to_owned(),
                )),
            }
        }
        [] => {
            print_help();
            Ok(())
        }
        [command] if matches!(command.as_str(), "help" | "--help" | "-h") => {
            print_help();
            Ok(())
        }
        _ => Err(HarnessError::InvalidInput(
            "unknown command; use --help".to_owned(),
        )),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("tunnel-test-harness: {error}");
            ExitCode::FAILURE
        }
    }
}

fn print_help() {
    println!(
        "Usage: tunnel-test-harness verify\n       tunnel-test-harness redis-restart-{{seed|check}} --redis-url URL --namespace NAME --receipt-file PATH\n\nverify requires TEST_REDIS_URL and built workspace binaries.\nRuns real Redis, HTTPS, device mTLS WebSocket, CLI and HTTP/3 acceptance checks.\nUses isolated Redis namespaces, ephemeral certificates and synthetic echo data.\nRun restart probes through scripts/m1-redis-restart-verify.sh."
    );
}
