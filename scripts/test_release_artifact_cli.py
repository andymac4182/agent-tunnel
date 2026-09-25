"""The release-artifact gate's misuse paths report "did not run", not "failed".

`scripts/m6-release-artifact.py` defines three exit codes: 0 every selected
check passed, 1 at least one failed, 2 the script could not run a selected
check at all.  docs/tasks.md M6-C12: `--self-test` with no `--bundle` died in a
`TypeError` traceback and exited 1, so a wrapper branching on 1 versus 2 read a
typo as a failed release check.  Each case here is an invocation that cannot
reach a single control or check, and each must exit 2 with a usage message and
no traceback.  The positive case proves the harness can see a success, so a
harness that always reported 2 could not pass.
"""

import subprocess
import sys
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent / "m6-release-artifact.py"


def invoke(*args):
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        capture_output=True,
        text=True,
        timeout=120,
    )


class MisuseExitsTwo(unittest.TestCase):
    def assert_usage_error(self, completed, needle):
        self.assertEqual(completed.returncode, 2, completed.stderr[-400:])
        self.assertNotIn("Traceback", completed.stderr)
        self.assertIn(needle, completed.stderr)

    def test_self_test_without_a_bundle(self):
        self.assert_usage_error(invoke("--self-test"), "--self-test requires --bundle")

    def test_self_test_with_a_check_but_no_bundle(self):
        self.assert_usage_error(
            invoke("--self-test", "--check", "notices"), "--self-test requires --bundle"
        )

    def test_a_top_level_check_without_self_test(self):
        # `--check` at top level only selects controls for `--self-test`; on
        # its own it would print help and exit 2 without saying why.
        self.assert_usage_error(invoke("--check", "notices"), "--check selects")

    def test_self_test_bundle_that_is_not_a_directory(self):
        # The pre-existing not-a-directory path, kept as the reference shape.
        completed = invoke("--self-test", "--bundle", str(SCRIPT.parent / "no-such-bundle"))
        self.assertEqual(completed.returncode, 2)
        self.assertNotIn("Traceback", completed.stderr)

    def test_the_harness_can_see_a_success(self):
        completed = invoke("--help")
        self.assertEqual(completed.returncode, 0, completed.stderr[-400:])
        self.assertIn("--self-test", completed.stdout)


if __name__ == "__main__":
    unittest.main()
