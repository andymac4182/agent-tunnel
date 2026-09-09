# Contributing

Agent Tunnel is at bootstrap stage. Start with [the roadmap](docs/roadmap.md) and the matching protocol or adapter document. Work in small pull requests with an explicit acceptance gate.

## Local checks

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo run --locked -p tunnel-client -- check-config examples/client.toml
cargo run --locked -p tunnel-relay -- check-config examples/relay.toml
```

Keep Cargo.lock committed. Add dependencies only with a concrete need, supported-platform review, and compatible licensing. CI runs on Linux, macOS, and Windows; a local macOS pass does not establish the other platforms.

Protocol changes must update the wire contract and tests together. Tests should demonstrate behavior under failures or at public boundaries. Never represent mock-only tests as real adapter compatibility. Keep documentation explicit about implemented, planned, and experimentally verified behavior.

Use disposable directories, synthetic identities, and dedicated VM desktops in tests. Do not point automated computer-use tests at a developer's working desktop. Never commit credentials, screenshots of real accounts, or home-directory content.

Describe PRs with the behavior changed, the relevant invariant, and verification evidence. Public releases need clean-consumer artifact checks and the security/platform gates in the roadmap.
