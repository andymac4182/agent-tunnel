#!/bin/sh
set -eu

# Build a bounded copy of the current local workspace and emit a receipt that
# ties the resulting local binaries to the copied source digest.  This script
# is intentionally separate from m7-local-artifact-verify.sh: that script is
# observation-only, while this one owns the source-copy Cargo build when the
# caller explicitly runs it.  Do not run this script from an agent turn that
# is not the root Cargo runner.

usage() {
    cat >&2 <<'EOF'
Usage:
  scripts/m7-local-source-parity-build.sh \
    [--output-dir DIR] [--profile debug|release|NAME]

The default output is work/m7-local-source-parity-build.  An existing output
directory is preserved by creating a new run-* child.  The script snapshots a
bounded local workspace input set (Cargo metadata, Rust sources, compile-time
examples, and vendor files), builds only that copy with Cargo --locked, and
packages local macOS binaries plus an immutable source-parity receipt.

The caller's Cargo cache, CARGO_HOME, offline/network settings, RUSTFLAGS and
other build environment remain in force.  If CARGO_TARGET_DIR is supplied it
is honored; otherwise an isolated target directory is created under the run
output.  The original checkout is never cleaned, reset, committed, published,
or used as the build source.

The receipt proves the allowlisted source-copy build only.  It does not claim
release readiness, another OS/architecture, complete repository provenance,
or full M7 row closure.
Codesign and CLI preflight subprocesses have a fixed 10-second deadline; a
timed-out direct child is reaped after bounded TERM/KILL attempts when cleanup
succeeds.  Descendant cleanup remains best effort and is never claimed as a
process-group join.

For executable bundle checks, prefer --output-dir on native local storage such
as /tmp/m7-local-source-parity-build over a Documents copy.  A prior Documents
copy showed compressed/dataless state and an actual process reported Code
Signature Invalid despite unchanged hashes and subsequent codesign verification;
this is an operational precaution only and does not identify a file-provider
cause.
EOF
    exit 2
}

die() {
    echo "m7-local-source-parity-build: $*" >&2
    exit 1
}

sha256_file() {
    parity_sha_path=$1
    if command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$parity_sha_path" | awk '{print $1}'
    elif command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$parity_sha_path" | awk '{print $1}'
    else
        die "neither shasum nor sha256sum is available"
    fi
}

sha256_stdin() {
    if command -v shasum >/dev/null 2>&1; then
        shasum -a 256 | awk '{print $1}'
    elif command -v sha256sum >/dev/null 2>&1; then
        sha256sum | awk '{print $1}'
    else
        die "neither shasum nor sha256sum is available"
    fi
}

file_size() {
    parity_size_path=$1
    if parity_size_value=$(stat -f '%z' "$parity_size_path" 2>/dev/null); then
        printf '%s\n' "$parity_size_value"
    else
        stat -c '%s' "$parity_size_path"
    fi
}

verify_codesign() {
    verify_codesign_name=$1
    verify_codesign_path=$2
    verify_codesign_log=$3
    command -v codesign >/dev/null 2>&1 || die "codesign is required for the native macOS bundle preflight"
    # Verify one copied executable only.  This never signs, deep-verifies, or
    # disables platform security; the caller can inspect the bounded log.
    if run_bounded "$preflight_timeout_seconds" "$verify_codesign_log" \
        codesign --verify --strict --verbose=2 "$verify_codesign_path"; then
        :
    else
        verify_codesign_status=$?
        echo "m7-local-source-parity-build: codesign verification failed for $verify_codesign_name; inspect $verify_codesign_log" >&2
        sed -n '1,40p' "$verify_codesign_log" >&2 || true
        if [ "$verify_codesign_status" -eq 124 ]; then
            die "copied $verify_codesign_name codesign preflight timed out after ${preflight_timeout_seconds}s"
        fi
        if [ "$verify_codesign_status" -eq 125 ]; then
            die "copied $verify_codesign_name codesign preflight timed out and direct-child cleanup failed; inspect $verify_codesign_log"
        fi
        die "copied $verify_codesign_name failed native macOS codesign preflight"
    fi
    chmod 0444 "$verify_codesign_log"
}

run_bounded() {
    run_bounded_timeout=$1
    run_bounded_log=$2
    shift 2
    [ "$#" -gt 0 ] || die "bounded preflight command is empty"
    command -v python3 >/dev/null 2>&1 || die "python3 is required for bounded macOS preflight commands"
    [ -x "$bounded_runner" ] || die "bounded preflight helper is missing or not executable: $bounded_runner"
    if python3 "$bounded_runner" "$run_bounded_timeout" "$run_bounded_log" "$@"; then
        return 0
    else
        return $?
    fi
}

cleanup() {
    for parity_temp in \
        "${status_tmp:-}" \
        "${inventory_tmp:-}" \
        "${inventory_after_tmp:-}" \
        "${snapshot_actual_tmp:-}" \
        "${manifest_tmp:-}"; do
        if [ -n "$parity_temp" ] && [ -f "$parity_temp" ]; then
            rm -f "$parity_temp"
        fi
    done
}

trap cleanup EXIT HUP INT TERM

script_path=$0
case "$script_path" in
    /*) ;;
    *) script_path=$(pwd -P)/$script_path ;;
esac
script_path=$(CDPATH= cd -- "$(dirname -- "$script_path")" && pwd -P)/$(basename -- "$script_path")
repo_root=$(CDPATH= cd -- "$(dirname -- "$(dirname -- "$script_path")")" && pwd -P)
caller_root=$(pwd -P)
bounded_runner=$repo_root/scripts/m7-run-bounded.py
preflight_timeout_seconds=10

output_base=$repo_root/work/m7-local-source-parity-build
profile=debug

while [ "$#" -gt 0 ]; do
    case "$1" in
        --output-dir|-o)
            [ "$#" -ge 2 ] || usage
            output_base=$2
            shift 2
            ;;
        --profile)
            [ "$#" -ge 2 ] || usage
            profile=$2
            shift 2
            ;;
        --help|-h)
            usage
            ;;
        *)
            echo "m7-local-source-parity-build: unknown option: $1" >&2
            usage
            ;;
    esac
done

case "$profile" in
    ''|*[!A-Za-z0-9_.-]*)
        die "profile must contain only ASCII letters, digits, '.', '_' or '-'"
        ;;
esac

if [ "$(uname -s)" != Darwin ]; then
    die "this source-parity foundation is restricted to local macOS (uname -s was $(uname -s))"
fi
if ! platform_release=$(sw_vers -productVersion 2>/dev/null); then
    die "sw_vers -productVersion failed; required macOS metadata is unavailable"
fi
[ -n "$platform_release" ] || die "sw_vers -productVersion returned an empty release"

case "$output_base" in
    /*) ;;
    *) output_base=$caller_root/$output_base ;;
esac
if [ -e "$output_base" ] && [ ! -d "$output_base" ]; then
    die "output path is not a directory: $output_base"
fi

# Capture repository identity before output creation.  The output is normally
# under work/, which is deliberately excluded from the source inventory.
status_tmp=$(mktemp "${TMPDIR:-/tmp}/m7-source-parity-status.XXXXXX")
git -C "$repo_root" status --porcelain=v1 --untracked-files=all > "$status_tmp"
status_sha256=$(sha256_file "$status_tmp")
status_count=$(wc -l < "$status_tmp" | tr -d ' ')
if [ "$status_count" -gt 0 ]; then
    worktree_dirty=true
else
    worktree_dirty=false
fi
base_head=$(git -C "$repo_root" rev-parse --verify HEAD)
base_tree=$(git -C "$repo_root" show -s --format=%T HEAD)
tracked_diff_sha256=$(git -C "$repo_root" diff --no-ext-diff --binary HEAD -- | sha256_stdin)

mkdir -p "$output_base"
if [ -n "$(find "$output_base" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null)" ]; then
    output_run=$output_base/run-$(date -u '+%Y%m%dT%H%M%SZ')-$$
    output_suffix=0
    while [ -e "$output_run" ]; do
        output_suffix=$((output_suffix + 1))
        output_run=$output_base/run-$(date -u '+%Y%m%dT%H%M%SZ')-$$-$output_suffix
    done
    mkdir "$output_run"
else
    output_run=$output_base
fi

source_copy=$output_run/source
bundle_dir=$output_run/bundle
bin_dir=$bundle_dir/bin
mkdir -p "$source_copy" "$bin_dir"

# Only these paths can become Cargo build inputs in this workspace.  The full
# crates/examples/vendor subtrees are retained because build scripts and
# compile-time includes can consume files beyond Rust/Cargo extensions.
# Sensitive file names are rejected before any copy occurs.
collect_inventory() {
    parity_inventory_root=$1
    {
        for parity_root_file in Cargo.toml Cargo.lock rust-toolchain.toml .cargo/config .cargo/config.toml; do
            if [ -f "$parity_inventory_root/$parity_root_file" ]; then
                printf '%s\n' "$parity_root_file"
            fi
        done
        if [ -f "$parity_inventory_root/build.rs" ]; then
            printf '%s\n' build.rs
        fi
        if [ -d "$parity_inventory_root/examples" ]; then
            find "$parity_inventory_root/examples" -type f -print \
                | sed "s#^$parity_inventory_root/##"
        fi
        if [ -d "$parity_inventory_root/crates" ]; then
            find "$parity_inventory_root/crates" -type f -print \
                | sed "s#^$parity_inventory_root/##"
        fi
        if [ -d "$parity_inventory_root/vendor" ]; then
            find "$parity_inventory_root/vendor" -type f -print \
                | sed "s#^$parity_inventory_root/##"
        fi
    } | LC_ALL=C sort -u
}

for parity_allowed_root in crates vendor examples .cargo; do
    if [ -d "$repo_root/$parity_allowed_root" ] \
        && find "$repo_root/$parity_allowed_root" -type l -print -quit | grep -q .; then
        die "symlinks are not accepted in the source-copy input roots: $parity_allowed_root"
    fi
done

inventory_tmp=$(mktemp "${TMPDIR:-/tmp}/m7-source-parity-inventory.XXXXXX")
collect_inventory "$repo_root" > "$inventory_tmp"
source_count=$(wc -l < "$inventory_tmp" | tr -d ' ')
if [ "$source_count" -eq 0 ]; then
    die "source inventory is empty"
fi
if [ "$source_count" -gt 8192 ]; then
    die "bounded source inventory exceeded 8192 files ($source_count)"
fi

while IFS= read -r parity_inventory_path; do
    case "$parity_inventory_path" in
        *.pem|*.key|.env|.env.*|*/.git/*|*/target/*|*/work/*|*/output/*|private/*|*/private/*|secrets/*|*/secrets/*)
            die "sensitive path is outside the source-copy contract: $parity_inventory_path"
            ;;
        Cargo.toml|Cargo.lock|rust-toolchain.toml|build.rs|.cargo/config|.cargo/config.toml|examples/*|crates/*|vendor/*)
            ;;
        *)
            die "source inventory escaped its allowlist: $parity_inventory_path"
            ;;
    esac
    parity_source_path=$repo_root/$parity_inventory_path
    [ -f "$parity_source_path" ] || die "source input disappeared: $parity_inventory_path"
    parity_destination_path=$source_copy/$parity_inventory_path
    mkdir -p "$(dirname -- "$parity_destination_path")"
    cp -p "$parity_source_path" "$parity_destination_path"
done < "$inventory_tmp"

# No generated target, VCS directory, work directory, or output file is copied.
snapshot_actual_tmp=$(mktemp "${TMPDIR:-/tmp}/m7-source-parity-snapshot.XXXXXX")
find "$source_copy" -type f -print \
    | sed "s#^$source_copy/##" \
    | LC_ALL=C sort -u > "$snapshot_actual_tmp"
if ! cmp -s "$inventory_tmp" "$snapshot_actual_tmp"; then
    die "source copy contains a file outside the bounded inventory"
fi

# Make the copied inputs immutable before Cargo sees them.  Cargo writes its
# generated state to CARGO_TARGET_DIR, never into this source tree.
find "$source_copy" -type f -exec chmod 0444 {} +
find "$source_copy" -type d -exec chmod 0555 {} +

# A target selected only through copied Cargo config would make the packaged
# output path ambiguous and could silently turn this local macOS check into a
# cross-target claim.  Require the caller to make that choice explicit.
if [ -z "${CARGO_BUILD_TARGET:-}" ]; then
    for parity_cargo_config in "$source_copy/.cargo/config" "$source_copy/.cargo/config.toml"; do
        if [ -f "$parity_cargo_config" ] \
            && grep -Eq '^[[:space:]]*target[[:space:]]*=' "$parity_cargo_config"; then
            die "Cargo config selects a target; set CARGO_BUILD_TARGET explicitly for the local bundle"
        fi
    done
fi

write_manifest() {
    parity_manifest_root=$1
    parity_manifest_paths=$2
    parity_manifest_output=$3
    parity_manifest_tmp=$parity_manifest_output.tmp
    manifest_tmp=$parity_manifest_tmp
    {
        printf '%s\n' '# Agent Tunnel source parity manifest v1'
        printf '%s\n' '# path<TAB>size_bytes<TAB>sha256'
        while IFS= read -r parity_manifest_path; do
            parity_manifest_file=$parity_manifest_root/$parity_manifest_path
            [ -f "$parity_manifest_file" ] || die "manifest input disappeared: $parity_manifest_path"
            printf '%s\t%s\t%s\n' \
                "$parity_manifest_path" \
                "$(file_size "$parity_manifest_file")" \
                "$(sha256_file "$parity_manifest_file")"
        done < "$parity_manifest_paths"
    } > "$parity_manifest_tmp"
    mv "$parity_manifest_tmp" "$parity_manifest_output"
    chmod 0444 "$parity_manifest_output"
    manifest_tmp=
}

source_manifest_before=$output_run/source-manifest-before.tsv
source_manifest_snapshot=$output_run/source-manifest-snapshot.tsv
write_manifest "$repo_root" "$inventory_tmp" "$source_manifest_before"
write_manifest "$source_copy" "$inventory_tmp" "$source_manifest_snapshot"
source_manifest_before_sha256=$(sha256_file "$source_manifest_before")
source_manifest_snapshot_sha256=$(sha256_file "$source_manifest_snapshot")
if ! cmp -s "$source_manifest_before" "$source_manifest_snapshot"; then
    die "source copy digest differs from the original before build"
fi

rustc_verbose_file=$output_run/rustc-vV.txt
cargo_version_file=$output_run/cargo-version.txt
if ! rustc -vV > "$rustc_verbose_file" 2>&1; then
    die "rustc -vV failed; required compiler metadata is unavailable"
fi
if ! cargo --version > "$cargo_version_file" 2>&1; then
    die "cargo --version failed; required Cargo metadata is unavailable"
fi
chmod 0444 "$rustc_verbose_file" "$cargo_version_file"
rustc_verbose_sha256=$(sha256_file "$rustc_verbose_file")
cargo_version_sha256=$(sha256_file "$cargo_version_file")
rustc_version=$(sed -n '1p' "$rustc_verbose_file")
cargo_version=$(sed -n '1p' "$cargo_version_file")
[ -n "$rustc_version" ] || die "rustc -vV returned no version line"
if ! rustc_host=$(awk -F': ' '$1 == "host" {host=$2} END {if (host == "") exit 1; print host}' "$rustc_verbose_file"); then
    die "rustc -vV returned no host triple"
fi
[ -n "$rustc_host" ] || die "rustc -vV returned an empty host triple"
[ -n "$cargo_version" ] || die "cargo --version returned no version line"
rust_toolchain_file_sha256=$(sha256_file "$source_copy/rust-toolchain.toml")
workspace_lockfile_sha256=$(sha256_file "$source_copy/Cargo.lock")

original_cargo_target_dir=${CARGO_TARGET_DIR:-}
if [ -n "$original_cargo_target_dir" ]; then
    cargo_target_strategy=caller-CARGO_TARGET_DIR
    case "$original_cargo_target_dir" in
        /*) cargo_target_absolute=$original_cargo_target_dir ;;
        *)
            # Preserve the checkout-relative target/cache convention while
            # keeping generated files outside the immutable source copy.
            cargo_target_absolute=$repo_root/$original_cargo_target_dir
            export CARGO_TARGET_DIR=$cargo_target_absolute
            ;;
    esac
else
    cargo_target_strategy=isolated-parity-output
    cargo_target_absolute=$output_run/cargo-target
    export CARGO_TARGET_DIR=$cargo_target_absolute
fi

build_log=$output_run/cargo-build.log
build_profile_dir=$profile
build_command_description='cargo build --locked --workspace --bins'
case "$profile" in
    debug)
        build_command_description='cargo build --locked --workspace --bins'
        if ! (cd "$source_copy" && cargo build --locked --workspace --bins) > "$build_log" 2>&1; then
            die "Cargo debug build failed; inspect $build_log"
        fi
        build_profile_dir=debug
        ;;
    release)
        build_command_description='cargo build --locked --workspace --bins --release'
        if ! (cd "$source_copy" && cargo build --locked --workspace --bins --release) > "$build_log" 2>&1; then
            die "Cargo release build failed; inspect $build_log"
        fi
        build_profile_dir=release
        ;;
    *)
        build_command_description="cargo build --locked --workspace --bins --profile $profile"
        if ! (cd "$source_copy" && cargo build --locked --workspace --bins --profile "$profile") > "$build_log" 2>&1; then
            die "Cargo $profile build failed; inspect $build_log"
        fi
        build_profile_dir=$profile
        ;;
esac
chmod 0444 "$build_log"

source_manifest_snapshot_after=$output_run/source-manifest-snapshot-after.tsv
source_manifest_original_after=$output_run/source-manifest-original-after.tsv
inventory_after_tmp=$(mktemp "${TMPDIR:-/tmp}/m7-source-parity-inventory-after.XXXXXX")
collect_inventory "$repo_root" > "$inventory_after_tmp"
if ! cmp -s "$inventory_tmp" "$inventory_after_tmp"; then
    die "the source input inventory changed during the isolated build"
fi
write_manifest "$source_copy" "$inventory_tmp" "$source_manifest_snapshot_after"
write_manifest "$repo_root" "$inventory_tmp" "$source_manifest_original_after"
source_manifest_snapshot_after_sha256=$(sha256_file "$source_manifest_snapshot_after")
source_manifest_original_after_sha256=$(sha256_file "$source_manifest_original_after")
if ! cmp -s "$source_manifest_snapshot" "$source_manifest_snapshot_after"; then
    die "Cargo changed an allowlisted source input in the immutable source copy"
fi
if ! cmp -s "$source_manifest_before" "$source_manifest_original_after"; then
    die "the original checkout source inputs changed during the isolated build"
fi

target_triple=${CARGO_BUILD_TARGET:-}
if [ -n "$target_triple" ]; then
    binary_dir=$cargo_target_absolute/$target_triple/$build_profile_dir
else
    binary_dir=$cargo_target_absolute/$build_profile_dir
fi

copy_binary() {
    parity_binary_name=$1
    parity_binary_source=$binary_dir/$parity_binary_name
    if [ ! -f "$parity_binary_source" ] || [ ! -x "$parity_binary_source" ]; then
        die "Cargo did not produce executable $parity_binary_source"
    fi
    if [ -L "$parity_binary_source" ]; then
        die "Cargo output is unexpectedly a symlink: $parity_binary_source"
    fi
    parity_binary_file=$(file -b "$parity_binary_source")
    case "$parity_binary_file" in
        *Mach-O*) ;;
        *) die "built binary is not a local macOS Mach-O executable: $parity_binary_source ($parity_binary_file)" ;;
    esac
    cp -p "$parity_binary_source" "$bin_dir/$parity_binary_name"
    chmod 0555 "$bin_dir/$parity_binary_name"
    verify_codesign "$parity_binary_name" "$bin_dir/$parity_binary_name" "$output_run/codesign-$parity_binary_name.txt"
    parity_binary_sha256=$(sha256_file "$bin_dir/$parity_binary_name")
    printf '%s\t%s\t%s\n' \
        "$parity_binary_name" "$parity_binary_sha256" "$parity_binary_file" \
        >> "$output_run/binary-records.tsv"
}

: > "$output_run/binary-records.tsv"
copy_binary tunnel-client
copy_binary tunnel-relay
copy_binary tunnel-test-harness

client_bundle=$bin_dir/tunnel-client
client_help=$output_run/cli-help.txt
client_version=$output_run/cli-version.txt
if run_bounded "$preflight_timeout_seconds" "$client_help" "$client_bundle" --help; then
    :
else
    preflight_status=$?
    if [ "$preflight_status" -eq 124 ]; then
        die "bundled tunnel-client --help preflight timed out after ${preflight_timeout_seconds}s; inspect $client_help"
    fi
    if [ "$preflight_status" -eq 125 ]; then
        die "bundled tunnel-client --help preflight timed out and direct-child cleanup failed; inspect $client_help"
    fi
    die "bundled tunnel-client --help preflight failed; inspect $client_help"
fi
if run_bounded "$preflight_timeout_seconds" "$client_version" "$client_bundle" --version; then
    :
else
    preflight_status=$?
    if [ "$preflight_status" -eq 124 ]; then
        die "bundled tunnel-client --version preflight timed out after ${preflight_timeout_seconds}s; inspect $client_version"
    fi
    if [ "$preflight_status" -eq 125 ]; then
        die "bundled tunnel-client --version preflight timed out and direct-child cleanup failed; inspect $client_version"
    fi
    die "bundled tunnel-client --version preflight failed; inspect $client_version"
fi
grep -q 'tunnel-client' "$client_help" || die "bundled client --help output lacks the CLI name"
grep -q '^tunnel-client ' "$client_version" || die "bundled client --version output is unexpected"
chmod 0444 "$client_help" "$client_version"

run_cli_help() {
    run_cli_help_name=$1
    run_cli_help_path=$2
    run_cli_help_output=$3
    if run_bounded "$preflight_timeout_seconds" "$run_cli_help_output" "$run_cli_help_path" --help; then
        :
    else
        run_cli_help_status=$?
        if [ "$run_cli_help_status" -eq 124 ]; then
            die "bundled $run_cli_help_name --help preflight timed out after ${preflight_timeout_seconds}s; inspect $run_cli_help_output"
        fi
        if [ "$run_cli_help_status" -eq 125 ]; then
            die "bundled $run_cli_help_name --help preflight timed out and direct-child cleanup failed; inspect $run_cli_help_output"
        fi
        die "bundled $run_cli_help_name --help preflight failed; inspect $run_cli_help_output"
    fi
    grep -q "$run_cli_help_name" "$run_cli_help_output" \
        || die "bundled $run_cli_help_name --help output lacks the CLI name"
    chmod 0444 "$run_cli_help_output"
}

run_cli_help tunnel-relay "$bin_dir/tunnel-relay" "$output_run/cli-help-tunnel-relay.txt"
run_cli_help tunnel-test-harness "$bin_dir/tunnel-test-harness" "$output_run/cli-help-tunnel-test-harness.txt"

tab=$(printf '\t')
checksum_file=$output_run/SHA256SUMS
source_manifest_checksum=$(sha256_file "$source_manifest_snapshot")
{
    printf '%s  %s\n' "$source_manifest_checksum" source-manifest-snapshot.tsv
    printf '%s  %s\n' "$(sha256_file "$client_help")" cli-help.txt
    printf '%s  %s\n' "$(sha256_file "$client_version")" cli-version.txt
    printf '%s  %s\n' "$(sha256_file "$output_run/cli-help-tunnel-relay.txt")" cli-help-tunnel-relay.txt
    printf '%s  %s\n' "$(sha256_file "$output_run/cli-help-tunnel-test-harness.txt")" cli-help-tunnel-test-harness.txt
    while IFS="$tab" read -r parity_binary_name parity_binary_sha256 parity_binary_file; do
        printf '%s  %s\n' "$parity_binary_sha256" "bundle/bin/$parity_binary_name"
        printf '%s  %s\n' "$(sha256_file "$output_run/codesign-$parity_binary_name.txt")" "codesign-$parity_binary_name.txt"
    done < "$output_run/binary-records.tsv"
} | LC_ALL=C sort > "$checksum_file"
chmod 0444 "$checksum_file"
checksum_sha256=$(sha256_file "$checksum_file")

env_file=$output_run/tunnel-client-env.sh
{
    printf '%s\n' '# Source this file before a fixture acceptance command.'
    printf 'export TUNNEL_CLIENT_BIN=%s\n' "$(printf "'%s'" "$(printf '%s' "$client_bundle" | sed "s/'/'\\\\''/g")")"
    printf 'export TUNNEL_ARTIFACT_DIR=%s\n' "$(printf "'%s'" "$(printf '%s' "$output_run" | sed "s/'/'\\\\''/g")")"
} > "$env_file"
chmod 0444 "$env_file"

receipt=$output_run/source-parity-receipt.txt
{
    printf '%s\n' 'schema_version=1'
    printf '%s\n' 'kind=local-source-copy-build-receipt'
    printf '%s\n' 'scope=local-macos-source-copy-only'
    printf '%s\n' 'source_provenance=verified-for-allowlisted-snapshot-by-local-cargo-build'
    printf '%s\n' 'provenance_limit=does-not-attest-unlisted-files,external-toolchain-components,registry-cache-contents,or-other-platforms'
    printf '%s\n' 'claims=source-copy-build-and-binary-hashes-only;not-release;not-other-os;not-complete-repository-parity;not-full-m7-row-closure'
    printf '%s\n' 'source_copy_read_only=true'
    printf 'created_at_utc=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    printf 'platform_os=%s\n' "$(uname -s)"
    printf 'platform_release=%s\n' "$platform_release"
    printf 'platform_arch=%s\n' "$(uname -m)"
    printf 'base_head=%s\n' "$base_head"
    printf 'base_tree=%s\n' "$base_tree"
    printf 'worktree_dirty=%s\n' "$worktree_dirty"
    printf 'worktree_status_entries=%s\n' "$status_count"
    printf 'worktree_status_sha256=%s\n' "$status_sha256"
    printf 'tracked_diff_from_base_sha256=%s\n' "$tracked_diff_sha256"
    printf 'source_inventory_scope=root-cargo;examples-tree;crates-tree;vendor-tree'
    printf '\n'
    printf 'source_file_count=%s\n' "$source_count"
    printf 'source_manifest_before_sha256=%s\n' "$source_manifest_before_sha256"
    printf 'source_manifest_snapshot_sha256=%s\n' "$source_manifest_snapshot_sha256"
    printf 'source_manifest_snapshot_after_sha256=%s\n' "$source_manifest_snapshot_after_sha256"
    printf 'source_manifest_original_after_sha256=%s\n' "$source_manifest_original_after_sha256"
    printf '%s\n' 'source_copy_pre_post_equal=true'
    printf '%s\n' 'original_source_pre_post_equal=true'
    printf 'rustc_version=%s\n' "$rustc_version"
    printf 'rustc_host=%s\n' "$rustc_host"
    printf 'rustc_vV_sha256=%s\n' "$rustc_verbose_sha256"
    printf 'rust_toolchain_file_sha256=%s\n' "$rust_toolchain_file_sha256"
    printf 'workspace_lockfile_sha256=%s\n' "$workspace_lockfile_sha256"
    printf 'cargo_version=%s\n' "$cargo_version"
    printf 'cargo_version_sha256=%s\n' "$cargo_version_sha256"
    printf 'build_profile=%s\n' "$profile"
    printf 'build_command=%s\n' "$build_command_description"
    printf 'cargo_locked=true\n'
    printf 'cargo_target_dir_strategy=%s\n' "$cargo_target_strategy"
    printf 'cargo_target_dir=%s\n' "$cargo_target_absolute"
    printf 'cargo_build_target=%s\n' "${target_triple:-host-default}"
    printf 'checksum_manifest_sha256=%s\n' "$checksum_sha256"
    printf '%s\n' 'codesign_scope=native-macos-only;verify-only;no-signing;no-deep-verification'
    printf 'preflight_timeout_seconds=%s\n' "$preflight_timeout_seconds"
    while IFS="$tab" read -r parity_binary_name parity_binary_sha256 parity_binary_file; do
        printf 'binary_%s_sha256=%s\n' "$parity_binary_name" "$parity_binary_sha256"
        printf 'binary_%s_file=%s\n' "$parity_binary_name" "$parity_binary_file"
        printf 'binary_%s_bundle_path=%s\n' "$parity_binary_name" "bundle/bin/$parity_binary_name"
        printf 'codesign_%s=passed\n' "$parity_binary_name"
        printf 'codesign_%s_log=%s\n' "$parity_binary_name" "codesign-$parity_binary_name.txt"
    done < "$output_run/binary-records.tsv"
    printf '%s\n' 'client_help=passed'
    printf '%s\n' 'client_version=passed'
    printf '%s\n' 'relay_help=passed'
    printf '%s\n' 'test_harness_help=passed'
    printf '%s\n' 'acceptance_invocation=not-run-by-this-script'
} > "$receipt"
chmod 0444 "$receipt"

rm -f "$output_run/binary-records.tsv"

echo "m7-local-source-parity-build: source-copy build completed: $output_run"
echo "m7-local-source-parity-build: receipt: $receipt"
echo "m7-local-source-parity-build: bundled client: $client_bundle"
echo "m7-local-source-parity-build: source TUNNEL_CLIENT_BIN from: $env_file"
echo "m7-local-source-parity-build: codesign --verify preflight passed for copied bundle binaries"
echo "m7-local-source-parity-build: codesign/CLI preflights are bounded at ${preflight_timeout_seconds}s; direct children are reaped after bounded TERM/KILL"
echo "m7-local-source-parity-build: native local output such as /tmp is recommended for executable checks"
echo "m7-local-source-parity-build: local source-copy scope only; no release or full-parity claim"
