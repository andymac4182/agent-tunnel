#!/usr/bin/env bash
# Re-fetch and re-hash the pinned CUA artifact (M5-01).
#
# The repository's pin rule says a verified row may cite an upstream artifact
# only when the repo pins it in code with a test, docs/sources.md records
# repository, commit, path and digest, and the verification pass re-fetches and
# re-hashes it. This script is that third clause, made executable.
#
# It downloads the wheel and the sdist from PyPI, hashes them, and compares
# against the digests recorded in crates/tunnel-http-forward/src/cua_pin.rs and
# docs/sources.md. It does NOT install, import or execute the server: the pin
# is over an artifact, not over a running process, and nothing in this chunk
# may touch the host's input or screen.
#
# Usage: scripts/m5-cua-refetch.sh
# Exit 0 only when both artifacts re-hash to the recorded digests.

set -euo pipefail

VERSION="0.3.46"

WHEEL_NAME="cua_computer_server-${VERSION}-py3-none-any.whl"
WHEEL_URL="https://files.pythonhosted.org/packages/76/00/ad010c3aa97010785aeb2c5ad3078b76009dd4c2ca691777102b09171eec/${WHEEL_NAME}"
WHEEL_SHA256="45f551d80054d8f993590b7428e94e7415501dbccdcda2ca5ad4148300883b3f"

SDIST_NAME="cua_computer_server-${VERSION}.tar.gz"
SDIST_URL="https://files.pythonhosted.org/packages/b4/33/1b88061b137e19a8ed23bb4d027bf0e84cd5b95a6679a12c644a25b62a98/${SDIST_NAME}"
SDIST_SHA256="3c434b421aa8f7dadcce5eeb92e186eae8f3c21e3720cc9da840a824e22e5494"

# computer_server/main.py, identical in both artifacts and at the release
# commit. Hashing it separately is what ties the PyPI files to the git tree,
# a Python sdist having no in-artifact record of its source commit.
RELEASE_COMMIT="c07d287af35cf37cfcf94290c46db2720ec47822"
MAIN_PY_URL="https://raw.githubusercontent.com/trycua/cua/${RELEASE_COMMIT}/libs/python/computer-server/computer_server/main.py"
MAIN_PY_SHA256="a5986dfc5e43ab3baaa9fa2ab6740dea5d6155e0f32b3f6bb444c9cd8ac9c6e4"

workdir="$(mktemp -d)"
trap 'rm -rf "${workdir}"' EXIT

sha256_of() {
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | cut -d' ' -f1
  else
    sha256sum "$1" | cut -d' ' -f1
  fi
}

failures=0

check() {
  local label="$1" url="$2" expected="$3" path="${workdir}/$4"

  if ! curl -sSfL --retry 3 --max-time 120 -o "${path}" "${url}"; then
    echo "FAIL ${label}: could not download ${url}" >&2
    failures=$((failures + 1))
    return
  fi

  local actual
  actual="$(sha256_of "${path}")"
  if [ "${actual}" = "${expected}" ]; then
    echo "ok   ${label}: sha-256 ${actual} ($(wc -c <"${path}" | tr -d ' ') bytes)"
  else
    echo "FAIL ${label}: recorded ${expected}, re-fetched ${actual}" >&2
    failures=$((failures + 1))
  fi
}

echo "Re-fetching pinned cua-computer-server ${VERSION} and re-hashing."
check "wheel  " "${WHEEL_URL}" "${WHEEL_SHA256}" "wheel"
check "sdist  " "${SDIST_URL}" "${SDIST_SHA256}" "sdist"
check "main.py" "${MAIN_PY_URL}" "${MAIN_PY_SHA256}" "main.py"

if [ "${failures}" -ne 0 ]; then
  echo "${failures} pinned artifact(s) did not re-hash to the recorded digest." >&2
  echo "Do not update the digests to match: find out why the artifact moved." >&2
  exit 1
fi

echo "All 3 pinned artifacts re-hashed to their recorded digests."
