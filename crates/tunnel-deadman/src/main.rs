#![forbid(unsafe_code)]
//! The parent-death sentinel: `tunnel-deadman <process-group-leader-pid>`,
//! or `tunnel-deadman --pin`, the group member a sentinel holds (M3-18).
//!
//! It blocks on stdin, which is the read end of a pipe the supervisor holds.
//! See [`tunnel_deadman`] for what this closes and — just as important — what
//! it does not.

fn main() -> std::process::ExitCode {
    let mut arguments = std::env::args().skip(1);
    let (Some(leader), None) = (arguments.next(), arguments.next()) else {
        return std::process::ExitCode::from(2);
    };
    if leader == tunnel_deadman::PIN_ARGUMENT {
        // A member of the watched group, spawned by a sentinel (M3-18).
        return std::process::ExitCode::from(u8::try_from(tunnel_deadman::pin()).unwrap_or(1));
    }
    let Ok(leader) = leader.parse::<u32>() else {
        return std::process::ExitCode::from(2);
    };
    let status = tunnel_deadman::watch(leader);
    std::process::ExitCode::from(u8::try_from(status).unwrap_or(1))
}
