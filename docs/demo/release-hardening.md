# Demo: a tester-grade release archive, verified where it runs

This recipe shows the release path end to end on one machine: build the
binaries, pack the archive exactly as CI does, and run the release gate
against the **unpacked** archive with its planted-defect controls. It then
shows how a tester checks a published archive's build attestation. The
hosted equivalent runs in `.github/workflows/release.yml` on every main
release and on every same-repository pull request that touches the release
path (task rows M6-C13, M6-C102, M6-C113, M6-C114, M6-C116).

It needs no relay: the archive is the thing being demonstrated. To go on and
connect the unpacked client to a relay, follow
[join-relay.md](../join-relay.md) from section 2.

## 1. Build and pack (Apple silicon Mac; Linux x86_64 is the same with its triple)

From a checkout, with the pinned toolchain:

```text
cargo build --release --locked --target aarch64-apple-darwin \
  -p tunnel-client -p tunnel-deadman -p tunnel-relay --bins
python3 scripts/package_release.py --target aarch64-apple-darwin \
  --sha "$(git rev-parse HEAD)" --run 1 --output dist
```

`package_release.py` reads the binaries from `target/<triple>/release`. If you
build with `CARGO_TARGET_DIR` elsewhere, link `target` to it first and remove
the link afterwards. It prints the archive path, and writes
`<archive>.sha256` beside it.

## 2. Verify the unpacked archive, with controls

```text
python3 scripts/verify_release_archive.py \
  --archive dist/agentuplink-v0.1.0-main.1.<sha12>-aarch64-apple-darwin.tar.gz \
  --target aarch64-apple-darwin --sha "$(git rev-parse HEAD)" --run 1 --self-test
```

Expected (measured on this host; digests and counts vary):

```text
verify_release_archive: agentuplink-...-aarch64-apple-darwin.tar.gz for aarch64-apple-darwin on macos/aarch64
ok      checksums: ... matches ....sha256
ok      layout: 7 top-level entries, bin/ = ['tunnel-client', 'tunnel-deadman', 'tunnel-relay'], ...
ok      targets: 3 binaries are macho/aarch64, and so is this host
ok      notices: 381 dependencies listed, 354 third-party each with a licence expression, 326 shipping licence text
ok      assets: sentinel beside the client exits 2 on both usage probes; 8 example paths named by 9 shipped documents, ...
ok      cli: 17 probes from the unpacked archive, including 7 client subcommand --help, config check and 2 serving dry run(s)
ok      portability: 3 binaries, 8 dynamic dependencies, all provided by a clean macos system
self-test: each planted defect must fail with its own witness
  ok      checksum names another digest -> want checksum-mismatch: ...
  ... (9 controls, each "ok")
summary: 7 of 7 checks passed (checksums, layout, targets, notices, assets, cli, portability)
```

Exit `0` means every check passed and every control went red with its own
witness. The `scope:` line it prints names what the CI archive cannot show
(no per-file checksums or `PROVENANCE.txt`, no lockfile reconciliation of
notices, no launched relay and device).

**Failure recovery.**
- `targets ... [witness=not-native-host]`: you ran it on a host of another
  OS or CPU. The check refuses on purpose; run it on a host of the target's
  own kind (the hosted `verify` job does).
- `portability ... [witness=non-system-dependency]`: a binary links a library
  a clean machine lacks. On Windows this was `VCRUNTIME140.dll` until
  `.cargo/config.toml` linked the C runtime statically (M6-C116).
- `cli ... [witness=subcommand-help]`: a subcommand's `--help` did not exit
  `0` (D6, M6-C113).
- `assets ... [witness=example-missing]`: a shipped document names an example
  the archive lacks (M6-C102); `package_release.py` derives the set from the
  documents, so re-pack from the same checkout.

## 3. Check a published archive's build attestation

Releases built after this change carry an attestation for every archive and
`.sha256` file. With the GitHub CLI:

```text
gh release download <tag> -R andymac4182/agentuplink -p '*aarch64-apple-darwin*'
gh attestation verify agentuplink-*.tar.gz -R andymac4182/agentuplink \
  --signer-workflow andymac4182/agentuplink/.github/workflows/release.yml \
  --source-ref refs/heads/main
```

A pass names the workflow run and commit that built the file; compare the
commit with `sourceSha` in the archive's `release.json`. It is provenance, not
code signing and not a review of the source (see join-relay.md section 1).
A release published before this change answers `HTTP 404`.

## 4. An aarch64 Linux client (CI-built, not a release target)

`aarch64-unknown-linux-gnu` is a CI-only target (`ci-only-targets` in the
root `Cargo.toml`). Advertising it is an owner decision (M6-C115). The
release workflow builds it on `ubuntu-24.04-arm` as a client-only archive,
verifies the unpacked archive there, and attests it, but never publishes it.
Take it from a green run's workflow artifact, which is kept for 7 days. Run
36153487478 is one such run:

```text
gh run download <run-id> -R andymac4182/agentuplink -n release-aarch64-unknown-linux-gnu -D armlinux
cd armlinux && sha256sum -c agentuplink-*.tar.gz.sha256
gh attestation verify agentuplink-*.tar.gz -R andymac4182/agentuplink \
  --signer-workflow andymac4182/agentuplink/.github/workflows/release.yml
mkdir release && tar -xzf agentuplink-*.tar.gz -C release
```

The unpacked `bin/` holds `tunnel-client` and `tunnel-deadman`. Keep them
together, then continue with [join-relay.md](../join-relay.md) section 2.

### 4.1 Local build without CI

On an Apple silicon Mac with Docker, the local
`rust:1.95.0` image (linux/arm64) builds the device half natively, reusing the
host's crate cache so nothing is fetched:

```text
docker run --rm --platform linux/arm64 \
  -v "$PWD":/src:ro -v "$PWD/../armlinux-target":/target \
  -v "$HOME/.cargo/registry":/usr/local/cargo/registry:ro \
  -e CARGO_TARGET_DIR=/target -w /src rust:1.95.0 \
  cargo build --release --locked --offline --target aarch64-unknown-linux-gnu \
  -p tunnel-client -p tunnel-deadman --bins
```

**Not run to completion: Docker unavailable.** This exact command was started
on the maintainer's Apple silicon host on 2026-09-25. It compiled about 95
crates, and then Docker Desktop wedged under machine-wide load. The command is
documented but not measured. No aarch64 Linux binary from it has been
executed.

The binaries land in `../armlinux-target/aarch64-unknown-linux-gnu/release/`.
Copy `tunnel-client` and `tunnel-deadman` together into the guest's `bin/`.
On an arm64 Linux host, the same `cargo build` line without Docker does the
same. If `--offline` reports a missing crate, run `cargo fetch --locked` on the
host once and retry.
