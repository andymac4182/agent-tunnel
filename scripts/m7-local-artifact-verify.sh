#!/bin/sh
set -eu

# This is an observation and unpacked-bundle check for the local macOS CLI
# scope of IN-10/OG-05.  It deliberately does not build, publish, clean, or
# reset anything.  The caller supplies binaries that it has already built.
# Hashing a supplied binary beside a source snapshot does not prove that the
# binary was built from that snapshot; this script records that provenance as
# unverified because it does not consume a trusted build receipt.

usage() {
    cat >&2 <<'EOF'
Usage:
  scripts/m7-local-artifact-verify.sh \
    --client-bin PATH \
    [--harness-bin PATH] [--relay-bin PATH] [--profile NAME] \
    [--output-dir DIR] [--] ACCEPTANCE_COMMAND [ARG...]

The command must be run from the repository checkout or with repository-
relative binary paths.  --client-bin is required.  --harness-bin and
--relay-bin are optional additional root-built binaries to put in the
unpacked bundle.  --profile is normally debug or release and is inferred from
the first binary path when omitted; pass it explicitly for a custom profile.

The output is an unpacked local bundle plus a read-only observation manifest,
checksums, CLI help/version output, and metadata.  If --output-dir already
contains files, a new run-* child is created so existing output is preserved.

When an acceptance command follows --, it runs with
TUNNEL_CLIENT_BIN=<bundle>/bin/tunnel-client and TUNNEL_ARTIFACT_DIR=<run>.
If its basename is tunnel-test-harness or tunnel-relay and that binary was
supplied above, the copied bundle member is executed.
The command's stdout/stderr are left with the caller and are not archived.
This script records local macOS artifact observations and CLI smoke checks
only.  Source-to-binary provenance is unverified unless a trusted build
receipt is supplied outside this script; this script does not claim a release
artifact, another OS/architecture, source parity, or full M7 row closure.
Codesign and CLI preflight subprocesses have a fixed 10-second deadline; a
timed-out direct child is reaped after bounded TERM/KILL attempts when cleanup
succeeds.  Descendant cleanup remains best effort and is never claimed as a
process-group join.

For executable bundle checks, prefer --output-dir on native local storage such
as /tmp/m7-local-artifact-verify over a Documents copy.  A prior Documents
copy showed compressed/dataless state and an actual process reported Code
Signature Invalid despite unchanged hashes and subsequent codesign verification;
this is an operational precaution only and does not identify a file-provider
cause.
EOF
    exit 2
}

die() {
    echo "m7-local-artifact-verify: $*" >&2
    exit 1
}

sha256_file() {
    sha256_file_path=$1
    if command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$sha256_file_path" | awk '{print $1}'
    elif command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$sha256_file_path" | awk '{print $1}'
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
        echo "m7-local-artifact-verify: codesign verification failed for $verify_codesign_name; inspect $verify_codesign_log" >&2
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

file_size() {
    file_size_path=$1
    if file_size_value=$(stat -f '%z' "$file_size_path" 2>/dev/null); then
        printf '%s\n' "$file_size_value"
    else
        stat -c '%s' "$file_size_path"
    fi
}

shell_quote() {
    # The generated environment file contains only a fixed path selected by
    # this script.  Quote it even when the checkout/output path has spaces.
    printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"
}

cleanup() {
    if [ -n "${status_tmp:-}" ] && [ -f "$status_tmp" ]; then
        rm -f "$status_tmp"
    fi
    if [ -n "${inventory_tmp:-}" ] && [ -f "$inventory_tmp" ]; then
        rm -f "$inventory_tmp"
    fi
    if [ -n "${manifest_tmp:-}" ] && [ -f "$manifest_tmp" ]; then
        rm -f "$manifest_tmp"
    fi
    if [ -n "${binary_records:-}" ] && [ -f "$binary_records" ]; then
        rm -f "$binary_records"
    fi
    if [ -n "${metadata_tmp:-}" ] && [ -f "$metadata_tmp" ]; then
        rm -f "$metadata_tmp"
    fi
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

client_input=
harness_input=
relay_input=
profile=
output_base=$repo_root/work/m7-local-artifact-verify
acceptance_requested=false

while [ "$#" -gt 0 ]; do
    case "$1" in
        --client-bin)
            [ "$#" -ge 2 ] || usage
            client_input=$2
            shift 2
            ;;
        --harness-bin)
            [ "$#" -ge 2 ] || usage
            harness_input=$2
            shift 2
            ;;
        --relay-bin)
            [ "$#" -ge 2 ] || usage
            relay_input=$2
            shift 2
            ;;
        --profile)
            [ "$#" -ge 2 ] || usage
            profile=$2
            shift 2
            ;;
        --output-dir|-o)
            [ "$#" -ge 2 ] || usage
            output_base=$2
            shift 2
            ;;
        --)
            shift
            acceptance_requested=true
            break
            ;;
        --help|-h)
            usage
            ;;
        *)
            echo "m7-local-artifact-verify: unknown option: $1" >&2
            usage
            ;;
    esac
done

[ -n "$client_input" ] || {
    echo "m7-local-artifact-verify: --client-bin is required" >&2
    usage
}

resolve_input_path() {
    resolve_input_value=$1
    case "$resolve_input_value" in
        /*) resolve_input_path_value=$resolve_input_value ;;
        *) resolve_input_path_value=$caller_root/$resolve_input_value ;;
    esac
    if [ ! -f "$resolve_input_path_value" ]; then
        die "binary does not exist: $resolve_input_value"
    fi
    if [ -L "$resolve_input_path_value" ]; then
        die "binary must be a regular root-built file, not a symlink: $resolve_input_value"
    fi
    if [ ! -x "$resolve_input_path_value" ]; then
        die "binary is not executable: $resolve_input_value"
    fi
    resolve_input_path_value=$(CDPATH= cd -- "$(dirname -- "$resolve_input_path_value")" && pwd -P)/$(basename -- "$resolve_input_path_value")
    resolved_binary_path=$resolve_input_path_value
}

validate_binary() {
    validate_binary_label=$1
    validate_binary_input=$2
    resolve_input_path "$validate_binary_input"
    validate_binary_path=$resolved_binary_path
    validate_binary_type=$(file -b "$validate_binary_path")
    case "$validate_binary_type" in
        *Mach-O*) ;;
        *)
            die "$validate_binary_label is not a macOS Mach-O executable: $validate_binary_path ($validate_binary_type)"
            ;;
    esac
}

infer_profile() {
    infer_profile_path=$1
    case "$infer_profile_path" in
        */target/debug/*) printf '%s\n' debug ;;
        */target/release/*) printf '%s\n' release ;;
        *) printf '%s\n' unknown ;;
    esac
}

validate_profile() {
    case "$1" in
        ''|*[!A-Za-z0-9_.-]*) die "build profile must contain only ASCII letters, digits, '.', '_' or '-'" ;;
        unknown) die "build profile is ambiguous; pass --profile debug, release, or a named custom profile" ;;
    esac
}

if [ "$(uname -s)" != Darwin ]; then
    die "this verifier is restricted to the local macOS scope (uname -s was $(uname -s))"
fi

validate_binary tunnel-client "$client_input"
client_path=$validate_binary_path
client_file_type=$validate_binary_type

if [ -z "$profile" ]; then
    profile=$(infer_profile "$client_path")
fi
validate_profile "$profile"

harness_path=
harness_file_type=
if [ -n "$harness_input" ]; then
    validate_binary tunnel-test-harness "$harness_input"
    harness_path=$validate_binary_path
    harness_file_type=$validate_binary_type
fi

relay_path=
relay_file_type=
if [ -n "$relay_input" ]; then
    validate_binary tunnel-relay "$relay_input"
    relay_path=$validate_binary_path
    relay_file_type=$validate_binary_type
fi

case "$output_base" in
    /*) ;;
    *) output_base=$caller_root/$output_base ;;
esac
if [ -e "$output_base" ] && [ ! -d "$output_base" ]; then
    die "output path is not a directory: $output_base"
fi
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

# Capture repository identity before creating output inside the checkout.  The
# status hash records names/state without copying unrelated untracked content;
# the source manifest below hashes only the bounded known source inventory.
status_tmp=$(mktemp "${TMPDIR:-/tmp}/m7-local-artifact-status.XXXXXX")
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
verification_script_sha256=$(sha256_file "$script_path")

rustc_verbose_file=$output_run/rustc-vV.txt
if ! rustc -vV > "$rustc_verbose_file" 2>&1; then
    die "rustc -vV failed; required compiler metadata is unavailable"
fi
chmod 0444 "$rustc_verbose_file"
rustc_version=$(sed -n '1p' "$rustc_verbose_file")
[ -n "$rustc_version" ] || die "rustc -vV returned no version line"
if ! rustc_host=$(awk -F': ' '$1 == "host" {host=$2} END {if (host == "") exit 1; print host}' "$rustc_verbose_file"); then
    die "rustc -vV returned no host triple"
fi
[ -n "$rustc_host" ] || die "rustc -vV returned an empty host triple"
if ! platform_release=$(sw_vers -productVersion 2>/dev/null); then
    die "sw_vers -productVersion failed; required macOS metadata is unavailable"
fi
[ -n "$platform_release" ] || die "sw_vers -productVersion returned an empty release"
rustc_verbose_sha256=$(sha256_file "$rustc_verbose_file")

bundle_dir=$output_run/bundle
bin_dir=$bundle_dir/bin
mkdir -p "$bin_dir"

binary_records=$output_run/.binary-records.tsv
: > "$binary_records"

copy_binary() {
    copy_binary_name=$1
    copy_binary_path=$2
    copy_binary_type=$3
    cp -p "$copy_binary_path" "$bin_dir/$copy_binary_name"
    chmod 0555 "$bin_dir/$copy_binary_name"
    verify_codesign "$copy_binary_name" "$bin_dir/$copy_binary_name" "$output_run/codesign-$copy_binary_name.txt"
    copy_binary_sha256=$(sha256_file "$bin_dir/$copy_binary_name")
    printf '%s\t%s\t%s\t%s\n' \
        "$copy_binary_name" "$copy_binary_sha256" "$copy_binary_type" "$copy_binary_path" \
        >> "$binary_records"
}

copy_binary tunnel-client "$client_path" "$client_file_type"
if [ -n "$harness_path" ]; then
    copy_binary tunnel-test-harness "$harness_path" "$harness_file_type"
fi
if [ -n "$relay_path" ]; then
    copy_binary tunnel-relay "$relay_path" "$relay_file_type"
fi

# Build a bounded, deterministic list.  Do not use git archive/status output
# as the source inventory: this checkout intentionally contains untracked
# implementation files, while unrelated untracked files and credentials must
# never enter the artifact.
inventory_tmp=$(mktemp "${TMPDIR:-/tmp}/m7-local-artifact-inventory.XXXXXX")
{
    for root_file in Cargo.toml Cargo.lock rust-toolchain.toml .cargo/config .cargo/config.toml; do
        if [ -f "$repo_root/$root_file" ]; then
            printf '%s\n' "$root_file"
        fi
    done
    if [ -d "$repo_root/crates" ]; then
        find "$repo_root/crates" -type f \( -name '*.rs' -o -name 'Cargo.toml' \) -print \
            | sed "s#^$repo_root/##"
    fi
    if [ -d "$repo_root/vendor" ]; then
        find "$repo_root/vendor" -type f -print \
            | sed "s#^$repo_root/##"
    fi
} | LC_ALL=C sort -u > "$inventory_tmp"

source_count=$(wc -l < "$inventory_tmp" | tr -d ' ')
if [ "$source_count" -gt 4096 ]; then
    die "bounded source inventory exceeded 4096 files ($source_count)"
fi

manifest_tmp=$output_run/source-manifest.tsv.tmp
{
    printf '%s\n' '# Agent Tunnel local source manifest v1'
    printf '%s\n' '# path<TAB>size_bytes<TAB>sha256'
    while IFS= read -r inventory_path; do
        case "$inventory_path" in
            Cargo.toml|Cargo.lock|rust-toolchain.toml|.cargo/config|.cargo/config.toml)
                ;;
            crates/*)
                ;;
            vendor/*)
                ;;
            *)
                die "source inventory escaped the allowlisted roots: $inventory_path"
                ;;
        esac
        source_path=$repo_root/$inventory_path
        [ -f "$source_path" ] || die "source inventory disappeared: $inventory_path"
        printf '%s\t%s\t%s\n' \
            "$inventory_path" "$(file_size "$source_path")" "$(sha256_file "$source_path")"
    done < "$inventory_tmp"
} > "$manifest_tmp"
mv "$manifest_tmp" "$output_run/source-manifest.tsv"
chmod 0444 "$output_run/source-manifest.tsv"
source_manifest_sha256=$(sha256_file "$output_run/source-manifest.tsv")
binary_count=$(wc -l < "$binary_records" | tr -d ' ')

client_bundle=$bin_dir/tunnel-client
help_output=$output_run/cli-help.txt
version_output=$output_run/cli-version.txt
if run_bounded "$preflight_timeout_seconds" "$help_output" "$client_bundle" --help; then
    :
else
    preflight_status=$?
    if [ "$preflight_status" -eq 124 ]; then
        die "unpacked tunnel-client --help preflight timed out after ${preflight_timeout_seconds}s; inspect $help_output"
    fi
    if [ "$preflight_status" -eq 125 ]; then
        die "unpacked tunnel-client --help preflight timed out and direct-child cleanup failed; inspect $help_output"
    fi
    die "unpacked tunnel-client --help preflight failed; inspect $help_output"
fi
if run_bounded "$preflight_timeout_seconds" "$version_output" "$client_bundle" --version; then
    :
else
    preflight_status=$?
    if [ "$preflight_status" -eq 124 ]; then
        die "unpacked tunnel-client --version preflight timed out after ${preflight_timeout_seconds}s; inspect $version_output"
    fi
    if [ "$preflight_status" -eq 125 ]; then
        die "unpacked tunnel-client --version preflight timed out and direct-child cleanup failed; inspect $version_output"
    fi
    die "unpacked tunnel-client --version preflight failed; inspect $version_output"
fi
grep -q 'tunnel-client' "$help_output" || die "unpacked tunnel-client --help output lacks the CLI name"
grep -q '^tunnel-client ' "$version_output" || die "unpacked tunnel-client --version output is unexpected"
chmod 0444 "$help_output" "$version_output"

run_cli_help() {
    run_cli_help_name=$1
    run_cli_help_path=$2
    run_cli_help_output=$3
    if run_bounded "$preflight_timeout_seconds" "$run_cli_help_output" "$run_cli_help_path" --help; then
        :
    else
        run_cli_help_status=$?
        if [ "$run_cli_help_status" -eq 124 ]; then
            die "unpacked $run_cli_help_name --help preflight timed out after ${preflight_timeout_seconds}s; inspect $run_cli_help_output"
        fi
        if [ "$run_cli_help_status" -eq 125 ]; then
            die "unpacked $run_cli_help_name --help preflight timed out and direct-child cleanup failed; inspect $run_cli_help_output"
        fi
        die "unpacked $run_cli_help_name --help preflight failed; inspect $run_cli_help_output"
    fi
    grep -q "$run_cli_help_name" "$run_cli_help_output" \
        || die "unpacked $run_cli_help_name --help output lacks the CLI name"
    chmod 0444 "$run_cli_help_output"
}

if [ -n "$harness_path" ]; then
    run_cli_help tunnel-test-harness "$bin_dir/tunnel-test-harness" "$output_run/cli-help-tunnel-test-harness.txt"
fi
if [ -n "$relay_path" ]; then
    run_cli_help tunnel-relay "$bin_dir/tunnel-relay" "$output_run/cli-help-tunnel-relay.txt"
fi

checksum_file=$output_run/SHA256SUMS
tab=$(printf '\t')
{
    printf '%s  %s\n' "$source_manifest_sha256" source-manifest.tsv
    while IFS="$tab" read -r binary_name binary_sha256 binary_type binary_input; do
        printf '%s  %s\n' "$binary_sha256" "bundle/bin/$binary_name"
        printf '%s  %s\n' "$(sha256_file "$output_run/codesign-$binary_name.txt")" "codesign-$binary_name.txt"
    done < "$binary_records"
    printf '%s  %s\n' "$rustc_verbose_sha256" rustc-vV.txt
    printf '%s  %s\n' "$(sha256_file "$help_output")" cli-help.txt
    printf '%s  %s\n' "$(sha256_file "$version_output")" cli-version.txt
    if [ -n "$harness_path" ]; then
        printf '%s  %s\n' "$(sha256_file "$output_run/cli-help-tunnel-test-harness.txt")" cli-help-tunnel-test-harness.txt
    fi
    if [ -n "$relay_path" ]; then
        printf '%s  %s\n' "$(sha256_file "$output_run/cli-help-tunnel-relay.txt")" cli-help-tunnel-relay.txt
    fi
} | LC_ALL=C sort > "$checksum_file"
chmod 0444 "$checksum_file"
checksum_manifest_sha256=$(sha256_file "$checksum_file")

metadata_file=$output_run/artifact-metadata.txt
{
    printf '%s\n' 'schema_version=1'
    printf '%s\n' 'purpose=IN-10/OG-05 local macOS CLI artifact observation'
    printf '%s\n' 'scope=local-macos-observation-only'
    printf '%s\n' 'claims=hashes-and-cli-smoke-only;source-provenance-unverified;not-release;not-other-os;not-source-parity;not-full-m7-row-closure'
    printf '%s\n' 'binary_provenance=unverified;caller-supplied-binary-hashes-only;compiler-rebuild-not-performed'
    printf '%s\n' 'build_receipt=none-consumed;source-to-binary-provenance-unverified'
    printf 'platform_os=%s\n' "$(uname -s)"
    printf 'platform_release=%s\n' "$platform_release"
    printf 'platform_arch=%s\n' "$(uname -m)"
    printf 'build_profile=%s\n' "$profile"
    printf 'rustc_version=%s\n' "$rustc_version"
    printf 'rustc_host=%s\n' "$rustc_host"
    printf 'rustc_vV_sha256=%s\n' "$rustc_verbose_sha256"
    printf 'base_head=%s\n' "$base_head"
    printf 'base_tree=%s\n' "$base_tree"
    printf 'worktree_dirty=%s\n' "$worktree_dirty"
    printf 'worktree_status_entries=%s\n' "$status_count"
    printf 'worktree_status_sha256=%s\n' "$status_sha256"
    printf 'tracked_diff_from_base_sha256=%s\n' "$tracked_diff_sha256"
    printf 'verification_script_sha256=%s\n' "$verification_script_sha256"
    printf 'source_file_count=%s\n' "$source_count"
    printf 'binary_count=%s\n' "$binary_count"
    printf 'source_manifest_sha256=%s\n' "$source_manifest_sha256"
    printf 'checksum_manifest_sha256=%s\n' "$checksum_manifest_sha256"
    printf '%s\n' 'codesign_scope=native-macos-only;verify-only;no-signing;no-deep-verification'
    printf 'preflight_timeout_seconds=%s\n' "$preflight_timeout_seconds"
    while IFS="$tab" read -r binary_name binary_sha256 binary_type binary_input; do
        printf 'binary_%s_sha256=%s\n' "$binary_name" "$binary_sha256"
        printf 'binary_%s_file=%s\n' "$binary_name" "$binary_type"
        printf 'binary_%s_bundle_path=%s\n' "$binary_name" "bundle/bin/$binary_name"
        printf 'codesign_%s=passed\n' "$binary_name"
        printf 'codesign_%s_log=%s\n' "$binary_name" "codesign-$binary_name.txt"
    done < "$binary_records"
    printf '%s\n' 'tunnel_client_help=passed'
    printf '%s\n' 'tunnel_client_version=passed'
    if [ -n "$harness_path" ]; then
        printf '%s\n' 'tunnel_test_harness_help=passed'
    fi
    if [ -n "$relay_path" ]; then
        printf '%s\n' 'tunnel_relay_help=passed'
    fi
    printf '%s\n' 'acceptance_command_invoked=false'
} > "$metadata_file"
chmod 0444 "$metadata_file"

env_file=$output_run/tunnel-client-env.sh
{
    printf '%s\n' '# Source this file before the existing real acceptance command.'
    printf 'export TUNNEL_CLIENT_BIN=%s\n' "$(shell_quote "$client_bundle")"
    printf 'export TUNNEL_ARTIFACT_DIR=%s\n' "$(shell_quote "$output_run")"
} > "$env_file"
chmod 0444 "$env_file"

rm -f "$binary_records"

if [ "$acceptance_requested" = true ]; then
    [ "$#" -gt 0 ] || die "-- must be followed by an acceptance command"
    acceptance_input=$1
    shift
    acceptance_command=$acceptance_input
    case "$acceptance_command" in
        /*) ;;
        *)
            case "$acceptance_command" in
                */*) acceptance_command=$caller_root/$acceptance_command ;;
            esac
            ;;
    esac
    acceptance_basename=$(basename -- "$acceptance_command")
    case "$acceptance_basename" in
        tunnel-test-harness)
            if [ -n "$harness_path" ]; then
                acceptance_command=$bin_dir/tunnel-test-harness
            fi
            ;;
        tunnel-relay)
            if [ -n "$relay_path" ]; then
                acceptance_command=$bin_dir/tunnel-relay
            fi
            ;;
    esac
    if [ ! -x "$acceptance_command" ]; then
        die "acceptance command is not executable: $acceptance_input"
    fi
    # Do not capture this command's output in the artifact: acceptance logs can
    # contain environment-specific paths or fixture details.  The caller can
    # redirect it to its selected evidence location.
    echo "m7-local-artifact-verify: invoking supplied acceptance with TUNNEL_CLIENT_BIN=$client_bundle" >&2
    if TUNNEL_CLIENT_BIN="$client_bundle" TUNNEL_ARTIFACT_DIR="$output_run" "$acceptance_command" "$@"; then
        acceptance_status=0
    else
        acceptance_status=$?
    fi
    if [ "$acceptance_status" -ne 0 ]; then
        die "supplied acceptance command failed with exit $acceptance_status"
    fi
    # Rewrite metadata only after the command succeeds.  It remains read-only
    # after this final write, and the source/binary checksums above are stable.
    metadata_tmp=$output_run/artifact-metadata.txt.tmp
    sed 's/^acceptance_command_invoked=false$/acceptance_command_invoked=true/' "$metadata_file" > "$metadata_tmp"
    mv "$metadata_tmp" "$metadata_file"
    chmod 0444 "$metadata_file"
fi

echo "m7-local-artifact-verify: local macOS bundle prepared: $output_run"
echo "m7-local-artifact-verify: source manifest: $output_run/source-manifest.tsv"
echo "m7-local-artifact-verify: bundle client: $client_bundle"
echo "m7-local-artifact-verify: source TUNNEL_CLIENT_BIN from: $env_file"
echo "m7-local-artifact-verify: source provenance is unverified (no build receipt consumed)"
echo "m7-local-artifact-verify: codesign --verify preflight passed for copied bundle binaries"
echo "m7-local-artifact-verify: codesign/CLI preflights are bounded at ${preflight_timeout_seconds}s; direct children are reaped after bounded TERM/KILL"
echo "m7-local-artifact-verify: native local output such as /tmp is recommended for executable checks"
echo "m7-local-artifact-verify: no release, other-OS, source-parity, or full-M7-row claim"
