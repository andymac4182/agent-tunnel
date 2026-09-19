#![forbid(unsafe_code)]
//! The parent-death sentinel: `tunnel-deadman <process-group-leader-pid>`.
//!
//! It blocks on stdin, which is the read end of a pipe the supervisor holds.
//! See [`tunnel_deadman`] for what this closes and — just as important — what
//! it does not.

fn main() -> std::process::ExitCode {
    let mut arguments = std::env::args().skip(1);
    let (Some(leader), None) = (arguments.next(), arguments.next()) else {
        return std::process::ExitCode::from(2);
    };
    let Ok(leader) = leader.parse::<u32>() else {
        return std::process::ExitCode::from(2);
    };
    let status = tunnel_deadman::watch(leader);
    std::process::ExitCode::from(u8::try_from(status).unwrap_or(1))
}
