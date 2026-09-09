use std::{env, error::Error, ffi::OsStr, fs, process::ExitCode};
use tunnel_core::RelayConfig;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("tunnel-relay: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let args: Vec<_> = env::args_os().skip(1).collect();
    match args.as_slice() {
        [] => print_help(),
        [flag] if flag == OsStr::new("--help") || flag == OsStr::new("-h") => print_help(),
        [command] if command == OsStr::new("check-config") => {
            RelayConfig::default().validate()?;
            println!("Default relay configuration is valid. Server is not implemented.");
        }
        [command, path] if command == OsStr::new("check-config") => {
            let input = fs::read_to_string(path)?;
            RelayConfig::parse(&input)?;
            println!("Relay configuration is valid. Server is not implemented.");
        }
        _ => return Err("usage: tunnel-relay [--help | check-config [PATH]]".into()),
    }
    Ok(())
}

fn print_help() {
    println!(
        "tunnel-relay — configuration-only starter\n\n\
         Usage: tunnel-relay [--help | check-config [PATH]]\n\n\
         check-config [PATH]  Validate TOML from PATH, or built-in defaults.\n\n\
         No listener, authentication, routing, or network transport is implemented."
    );
}
