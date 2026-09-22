# shellcheck shell=sh
#
# One assertion, shared by every script that assembles a directory of tunnel
# binaries: **a bundle that contains `tunnel-client` contains a working
# `tunnel-deadman` beside it.**
#
# This is a property of the product, not a packaging preference, which is why
# it is shared as an assertion rather than as a list.  `tunnel_deadman::
# sentinel_path()` (crates/tunnel-deadman/src/lib.rs) resolves `SENTINEL_BIN`
# relative to `std::env::current_exe()` -- beside the running executable, then
# one directory up when that directory is `deps`.  So the sentinel's location
# is determined by where the client binary is put, and any script that puts a
# client somewhere without putting a sentinel beside it has shipped a client
# whose process containment is degraded.
#
# **Why a shared list would have been the wrong fix.**  The three assemblers
# legitimately carry different binaries: `scripts/m6-release-artifact.py`
# ships client/relay/deadman and no test harness; `m7-local-source-parity-
# build.sh` ships the whole workspace's product binaries; `m7-local-artifact-
# verify.sh` takes a required client and two optional extras from the caller.
# Collapsing those into one list would be wrong.  What all three must obey,
# and what all three got wrong independently, is the single sentence above.
#
# **Why the degradation needs asserting at assembly time rather than being
# left to the runtime warning.**  `Deadman::arm` does print one line to stderr
# when the sentinel is absent -- once per process, not per child -- so the
# condition is not silent.  But it is announced only at the moment an export
# first arms a sentinel, and it is invisible to `--help`, `--version` and both
# config checks, which is everything an unpacking tester runs first.  Assembly
# time is the last moment at which the fix is free.
#
# **Why presence is not enough, and this executes the file.**  `resolve_
# sentinel` accepts any `is_file()`, so a zero-byte or non-executable file
# named `tunnel-deadman` makes `availability()` answer `Armable` while every
# arming attempt fails.  `tunnel-deadman` with no argument exits 2 (its
# `main` rejects an argument count other than one), so running it is what
# distinguishes a working sentinel from a file wearing its name.  This is the
# same probe `scripts/m6-release-artifact.py`'s `assets` check makes, kept
# deliberately identical so the two cannot drift into disagreeing about what
# counts as a sentinel.

CLIENT_BUNDLE_CLIENT_BIN=tunnel-client
CLIENT_BUNDLE_SENTINEL_BIN=tunnel-deadman

# Fail on CONTEXT's behalf, naming the witness so a harness can require this
# rule to have failed *for the reason it declares* rather than for any reason.
# Distinct witnesses because the fixes differ: an absent sentinel means the
# assembler's binary list is wrong, a non-executable or wrong-answering one
# means the file it copied is not the sentinel.
client_bundle_fail() {
    echo "$1: [witness=$2] $3" >&2
    exit 1
}

# assert_client_sentinel_beside DIR CONTEXT
#
# Exits 1 with a witnessed diagnostic on CONTEXT's behalf when DIR holds a
# client without a working sentinel.
#
# **This function announces that it ran, and the reason is instance seventeen
# of the running list in `docs/tasks.md` row M5-C11 -- caught in this
# function's own first draft.**  The draft opened with `[ ! -e "$dir/tunnel-
# client" ] && return 0`, on the reasoning that a directory holding no client
# is not this rule's business.  True, and it made a silent pass the response
# to a mistyped, unset or not-yet-populated `$dir` -- so the single most
# likely way to *defeat* this check, calling it on the wrong path, was
# indistinguishable from the check passing.  A missing directory is now
# fatal, the no-client case says so out loud, and the success path prints
# what it verified.  A caller who moves the call above the copies gets a
# diagnostic instead of a green line.
assert_client_sentinel_beside() {
    client_bundle_dir=$1
    client_bundle_context=$2

    [ -d "$client_bundle_dir" ] || client_bundle_fail "$client_bundle_context" \
        bundle-dir-missing \
        "the client-bundle sentinel rule was asked about $client_bundle_dir, which is not a directory; this check cannot pass by being pointed somewhere empty"

    if [ ! -e "$client_bundle_dir/$CLIENT_BUNDLE_CLIENT_BIN" ]; then
        echo "$client_bundle_context: no $CLIENT_BUNDLE_CLIENT_BIN in $client_bundle_dir, so the sentinel rule does not apply here" >&2
        return 0
    fi

    client_bundle_sentinel=$client_bundle_dir/$CLIENT_BUNDLE_SENTINEL_BIN
    [ -f "$client_bundle_sentinel" ] || client_bundle_fail "$client_bundle_context" \
        sentinel-missing \
        "no $CLIENT_BUNDLE_SENTINEL_BIN beside the bundled $CLIENT_BUNDLE_CLIENT_BIN in $client_bundle_dir; a client shipped without its sentinel supervises children correctly and leaks their process groups on every crash, announced only by a one-line stderr warning at arm time"
    [ ! -L "$client_bundle_sentinel" ] || client_bundle_fail "$client_bundle_context" \
        sentinel-not-a-regular-file \
        "the bundled $CLIENT_BUNDLE_SENTINEL_BIN is a symlink, not a regular file: $client_bundle_sentinel"
    [ -x "$client_bundle_sentinel" ] || client_bundle_fail "$client_bundle_context" \
        sentinel-not-executable \
        "the bundled $CLIENT_BUNDLE_SENTINEL_BIN is not executable: $client_bundle_sentinel"

    # Run it.  `resolve_sentinel` would accept this file on `is_file()` alone,
    # so presence and executability still do not establish that it is the
    # sentinel.  A cwd outside the bundle keeps a pass from depending on
    # where this ran, and a closed stdin keeps the sentinel's blocking read
    # from holding the check open if the file really is `tunnel-deadman`.
    client_bundle_probe_status=0
    ( cd / && "$client_bundle_sentinel" </dev/null >/dev/null 2>&1 ) \
        || client_bundle_probe_status=$?
    [ "$client_bundle_probe_status" -eq 2 ] || client_bundle_fail "$client_bundle_context" \
        sentinel-not-the-sentinel \
        "the bundled $CLIENT_BUNDLE_SENTINEL_BIN answered a no-argument probe with exit $client_bundle_probe_status, not the sentinel's 2; it is not a working $CLIENT_BUNDLE_SENTINEL_BIN"

    echo "$client_bundle_context: $CLIENT_BUNDLE_SENTINEL_BIN is beside the bundled $CLIENT_BUNDLE_CLIENT_BIN in $client_bundle_dir and answered the no-argument probe with exit 2" >&2
}
