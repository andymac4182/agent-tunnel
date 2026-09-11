# Repository guidance

- M1 authenticated echo and M2 ordered rotation/retained replay are locally verified against Redis, including real-socket faults and three actual 300-second rotations. M7 multi-relay routing is in progress; remote service adapters remain planned. Re-run the complete acceptance commands when networking or authorization changes; keep status claims precise and distinguish local evidence from hosted CI.
- Read README.md, docs/roadmap.md, and the relevant design document before implementing a milestone.
- Maintain docs/tasks.md as the task-level milestone tracker. Record newly discovered defects, implementation work, and missing tests when found; update status, current owner, remaining work, and verification evidence as work progresses. Link M7 edge-case task coverage to docs/m7-edge-cases.md. Do not mark implementation or a milestone verified from narrower tests, and record required reruns after relevant changes.
- Record `Completed at` in docs/tasks.md and docs/m7-edge-cases.md when the full row scope is verified, using ISO 8601 timestamps with seconds and an explicit timezone offset. Append first completions, reopenings, re-verifications, and new scope to each document's Completion history; preserve historical dates without inventing missing times. Follow each document's completion timing rules.
- Rust 1.95.0 is pinned in rust-toolchain.toml. Use Cargo.lock and `--locked` for validation.
- Required Rust checks: `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings`, and `cargo test --workspace --locked`.
- Keep client/relay core and privileged adapters in Rust. A shared TypeScript client and thin native adapters are planned for Files SDK, Mastra, AI SDK Files and just-bash.
- Multi-user isolation, per-device policy, bounded queues/replay, and explicit ambiguous-operation outcomes are design requirements, not optional follow-up hardening.
- Two sockets are steady state; data rotation permits a bounded temporary third socket as documented. Do not silently change that invariant.
- Drain immutable per-stream/direction sequence fences before committing a replacement data socket. Transport acknowledgements do not prove application side effects completed.
- Axum serves public HTTP and device WebSockets. Both CLI sockets require mTLS. Private HTTP/3 peers use separate relay mTLS identities; Redis distributes signed approved public keys, not root trust or private keys.
- Cluster support is a private-alpha requirement. Read docs/cluster.md before changing ownership, shared Redis authorization, Redis leases, or recovery assumptions.
- Keep handlers thin, state machines explicit, and actor queues bounded. Diagnostics must expose identifiers, phases and counters without payloads or credentials.
- Avoid unsafe code in current crates. Any future platform-specific unsafe boundary requires a narrow documented abstraction and focused review.
- Use synthetic test data and dedicated desktop VMs. Do not exercise computer control against a user's active desktop as a side effect of tests.
- Do not commit secrets or unredacted payloads. The repository must remain private unless the user explicitly requests publication.

- Use gpt-5.6-luna subagents with max reasoning for most implementation work unless the user changes this preference.
- Redis is the only authoritative catalog and coordination store. Preserve atomic tenant-scoped authorization, revocation, and owner fencing; never add a PostgreSQL dependency. Durable catalog keys must survive deployment-incarnation changes.
