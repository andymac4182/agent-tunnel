use std::{env, error::Error, ffi::OsStr, fs, process::ExitCode};
use tunnel_core::ClientConfig;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("tunnel-client: {error}");
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
            ClientConfig::default().validate()?;
            println!("Default client configuration is valid. Transport is not implemented.");
        }
        [command, path] if command == OsStr::new("check-config") => {
            let input = fs::read_to_string(path)?;
            ClientConfig::parse(&input)?;
            println!("Client configuration is valid. Transport is not implemented.");
        }
        _ => return Err("usage: tunnel-client [--help | check-config [PATH]]".into()),
    }
    Ok(())
}

fn print_help() {
    println!(
        "tunnel-client — configuration-only starter\n\n\
         Usage: tunnel-client [--help | check-config [PATH]]\n\n\
         check-config [PATH]  Validate TOML from PATH, or built-in defaults.\n\n\
         No tunnel connections, filesystem access, or computer control are implemented."
    );
}
