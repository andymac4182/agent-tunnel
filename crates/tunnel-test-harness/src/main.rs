use std::{process::ExitCode, time::Duration};
use tunnel_test_harness::{HarnessError, acceptance, m2_acceptance, redis_restart};

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
        [command] if command == "verify-m2" => {
            match m2_outer_timeout(Duration::from_secs(300), Duration::from_secs(270)) {
                Ok(budget) => match tokio::time::timeout(budget, m2_acceptance::verify()).await {
                    Ok(result) => result,
                    Err(_) => Err(HarnessError::Timeout(
                        "M2 accelerated acceptance exceeded its bounded outer timeout".to_owned(),
                    )),
                },
                Err(error) => Err(error),
            }
        }
        [command] if command == "verify-m2-default" => {
            match m2_outer_timeout(Duration::from_secs(1_020), Duration::from_secs(1_020)) {
                Ok(budget) => {
                    match tokio::time::timeout(budget, m2_acceptance::verify_default()).await {
                        Ok(result) => result,
                        Err(_) => Err(HarnessError::Timeout(
                            "M2 default-interval acceptance exceeded its bounded outer timeout"
                                .to_owned(),
                        )),
                    }
                }
                Err(error) => Err(error),
            }
        }
        [command] if command == "verify-m2-faults" => {
            match m2_outer_timeout(Duration::from_secs(300), Duration::from_secs(270)) {
                Ok(budget) => {
                    match tokio::time::timeout(budget, m2_acceptance::verify_faults()).await {
                        Ok(result) => result,
                        Err(_) => Err(HarnessError::Timeout(
                            "M2 targeted-fault acceptance exceeded its bounded outer timeout"
                                .to_owned(),
                        )),
                    }
                }
                Err(error) => Err(error),
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
        "Usage: tunnel-test-harness verify\n       tunnel-test-harness verify-m2\n       tunnel-test-harness verify-m2-default\n       tunnel-test-harness verify-m2-faults\n       tunnel-test-harness redis-restart-{{seed|check}} --redis-url URL --namespace NAME --receipt-file PATH\n\nverify and verify-m2 commands require TEST_REDIS_URL and built workspace binaries.\nRuns real Redis, HTTPS, device mTLS WebSocket, CLI and HTTP/3 acceptance checks.\nverify-m2 drives a long-lived public echo WebSocket through accelerated real rotations;\nverify-m2-default repeats the same flow at the 300-second policy.\nverify-m2-faults closes exact control/data/candidate sockets and checks explicit recovery outcomes.\nUses isolated Redis namespaces, ephemeral certificates and synthetic echo data.\nRun restart probes through scripts/m1-redis-restart-verify.sh.\nSet M2_HARNESS_TIMEOUT_SECONDS to override a bounded M2 command timeout."
    );
}

fn m2_outer_timeout(default: Duration, minimum: Duration) -> Result<Duration, HarnessError> {
    let Some(value) = std::env::var("M2_HARNESS_TIMEOUT_SECONDS")
        .ok()
        .filter(|value| !value.trim().is_empty())
    else {
        return Ok(default);
    };
    let seconds = value.parse::<u64>().map_err(|_| {
        HarnessError::InvalidInput(
            "M2_HARNESS_TIMEOUT_SECONDS must be an integer between the mode minimum and 3600"
                .to_owned(),
        )
    })?;
    if !(minimum.as_secs()..=3_600).contains(&seconds) {
        return Err(HarnessError::InvalidInput(format!(
            "M2_HARNESS_TIMEOUT_SECONDS must be between {} and 3600 seconds for this mode",
            minimum.as_secs()
        )));
    }
    Ok(Duration::from_secs(seconds))
}
