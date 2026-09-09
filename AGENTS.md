# Repository guidance

- This is a Rust project at configuration/bootstrap stage. Networking and remote operations are not implemented yet. Keep status claims precise.
- Read README.md, docs/roadmap.md, and the relevant design document before implementing a milestone.
- Rust 1.95.0 is pinned in rust-toolchain.toml. Use Cargo.lock and `--locked` for validation.
- Required Rust checks: `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings`, and `cargo test --workspace --locked`.
- Keep client/relay core and privileged adapters in Rust. A thin TypeScript adapter is planned for just-bash's native IFileSystem interface.
- Multi-user isolation, per-device policy, bounded queues/replay, and explicit ambiguous-operation outcomes are design requirements, not optional follow-up hardening.
- Two sockets are steady state; data rotation permits a bounded temporary third socket as documented. Do not silently change that invariant.
- Avoid unsafe code in current crates. Any future platform-specific unsafe boundary requires a narrow documented abstraction and focused review.
- Use synthetic test data and dedicated desktop VMs. Do not exercise computer control against a user's active desktop as a side effect of tests.
- Do not commit secrets or unredacted payloads. The repository must remain private unless the user explicitly requests publication.
