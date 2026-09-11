use std::{env, error::Error, ffi::OsStr, fs, path::Path, process::ExitCode, sync::Arc};

use jsonwebtoken::{Algorithm, DecodingKey};
use serde::Deserialize;
use tokio::net::TcpListener;
use tracing_subscriber::{EnvFilter, fmt};
use tunnel_catalog::{ApprovedJwk, OidcConfig, OidcVerifier, RedisCatalog, SharedCatalog};
use tunnel_core::RelayConfig;
use tunnel_relay::{RelayOptions, ServeConfig};
use tunnel_transport::load_server_config_from_pem;

#[tokio::main]
async fn main() -> ExitCode {
    init_tracing();
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("tunnel-relay: {error}");
            ExitCode::FAILURE
        }
    }
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = fmt()
        .json()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init();
}

async fn run() -> Result<(), Box<dyn Error>> {
    let args: Vec<_> = env::args_os().skip(1).collect();
    match args.as_slice() {
        [] => print_help(),
        [flag] if flag == OsStr::new("--help") || flag == OsStr::new("-h") => print_help(),
        [command] if command == OsStr::new("check-config") => {
            RelayConfig::default().validate()?;
            println!("Default relay configuration is valid.");
        }
        [command, path] if command == OsStr::new("check-config") => {
            let input = fs::read_to_string(path)?;
            RelayConfig::parse(&input)?;
            println!("Relay configuration is valid.");
        }
        [command, flag, path]
            if command == OsStr::new("serve") && flag == OsStr::new("--config") =>
        {
            serve(Path::new(path)).await?;
        }
        _ => {
            return Err(
                "usage: tunnel-relay [--help | check-config [PATH] | serve --config PATH]".into(),
            );
        }
    }
    Ok(())
}

async fn serve(path: &Path) -> Result<(), Box<dyn Error>> {
    let config = ServeConfig::parse(&fs::read_to_string(path)?)?;
    let jwks = parse_jwks(&fs::read(&config.oidc_jwks_path)?)?;
    let oidc = Arc::new(OidcVerifier::new(OidcConfig::new(
        config.oidc_issuer.clone(),
        config.oidc_audience.clone(),
        jwks,
    )?)?);
    let catalog = RedisCatalog::connect_with_deployment_incarnation(
        &config.redis_url,
        &config.redis_namespace,
        &config.deployment_incarnation,
    )
    .await?;
    let catalog: SharedCatalog = Arc::new(catalog);
    let options = RelayOptions::new(oidc);
    let consumer_listener = TcpListener::bind(config.consumer_bind).await?;
    let device_listener = TcpListener::bind(config.device_bind).await?;
    let consumer_cert = fs::read(&config.consumer_tls_cert_chain)?;
    let consumer_key = fs::read(&config.consumer_tls_private_key)?;
    let consumer_ca = config
        .consumer_tls_client_ca
        .as_ref()
        .map(fs::read)
        .transpose()?;
    let consumer_tls =
        load_server_config_from_pem(&consumer_cert, &consumer_key, consumer_ca.as_deref())?;
    let device_cert = fs::read(&config.device_tls_cert_chain)?;
    let device_key = fs::read(&config.device_tls_private_key)?;
    let device_ca = fs::read(&config.device_tls_client_ca)?;
    let device_tls = load_server_config_from_pem(&device_cert, &device_key, Some(&device_ca))?;
    let running = config
        .start(
            options,
            catalog,
            consumer_listener,
            device_listener,
            consumer_tls,
            device_tls,
        )
        .await?;
    eprintln!(
        "tunnel-relay listening: consumer={} device={}",
        running.consumer_addr, running.device_addr
    );
    tokio::signal::ctrl_c().await?;
    running.shutdown().await?;
    Ok(())
}

#[derive(Deserialize)]
struct Jwks {
    keys: Vec<Jwk>,
}

#[derive(Deserialize)]
struct Jwk {
    kid: String,
    kty: String,
    alg: Option<String>,
    n: Option<String>,
    e: Option<String>,
}

fn parse_jwks(bytes: &[u8]) -> Result<Vec<ApprovedJwk>, Box<dyn Error>> {
    let jwks: Jwks = serde_json::from_slice(bytes)?;
    let mut approved = Vec::with_capacity(jwks.keys.len());
    for key in jwks.keys {
        if key.kty != "RSA" || key.alg.as_deref().unwrap_or("RS256") != "RS256" {
            return Err("OIDC JWKS contains a non-RS256 key; configure an approved RSA key".into());
        }
        let decoding = DecodingKey::from_rsa_components(
            key.n.as_deref().ok_or("OIDC RSA key has no modulus")?,
            key.e.as_deref().ok_or("OIDC RSA key has no exponent")?,
        )?;
        approved.push(ApprovedJwk::from_decoding_key(
            key.kid,
            Algorithm::RS256,
            decoding,
        )?);
    }
    if approved.is_empty() {
        return Err("OIDC JWKS contains no approved keys".into());
    }
    Ok(approved)
}

fn print_help() {
    println!(
        "tunnel-relay — authenticated multi-user Agent Tunnel relay\n\n\
         Usage: tunnel-relay [--help | check-config [PATH] | serve --config PATH]\n\n\
         check-config [PATH]  Validate legacy relay TOML without opening listeners.\n\
         serve --config PATH Start consumer HTTPS and device mTLS WSS listeners."
    );
}
