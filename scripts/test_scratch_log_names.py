"""Two runs of a script that writes logs never share an output location.

docs/tasks.md M6-C16: every agent in a session shares one scratchpad, so a
generic output name resolves to whichever worker wrote it last, and a stale log
reads exactly like a fresh one.  `scripts/m7-gates-parallel.sh` was the one
script here that chose a fixed, label-keyed directory (`gates-<label>`) and
truncated its summary in place.  It now makes a new directory per run and
stamps it with the run's nonce and head.

The script is run in `M7_GATES_LIST_ONLY=1` mode, which stops after it has
chosen its directory and written the gate lists, so no gate runs.  The same
label is used twice, into one output root, the way two agents collide.
"""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SCRIPT = Path(os.environ.get("M7_GATES_SCRIPT", REPO / "scripts" / "m7-gates-parallel.sh"))


def run(root, label):
    env = dict(os.environ, M7_GATE_OUTPUT_DIR=str(root), M7_GATES_LIST_ONLY="1")
    completed = subprocess.run(
        ["sh", str(SCRIPT), label], cwd=REPO, env=env, capture_output=True, text=True,
        timeout=120,
    )
    return completed


class OutputLocationsAreUnique(unittest.TestCase):
    def test_same_label_twice_gets_two_stamped_directories(self):
        head = subprocess.run(
            ["git", "rev-parse", "--short=12", "HEAD"], cwd=REPO, capture_output=True,
            text=True, check=True,
        ).stdout.strip()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = run(root, "final")
            self.assertEqual(first.returncode, 0, first.stderr[-400:])
            directories = sorted(p for p in root.iterdir() if p.is_dir())
            self.assertEqual(len(directories), 1, directories)
            first_dir = directories[0]
            # A file the first run's reader will later trust.
            marker = first_dir / "gates.list"
            before = marker.read_bytes()
            os.utime(marker, (1, 1))

            second = run(root, "final")
            self.assertEqual(second.returncode, 0, second.stderr[-400:])
            directories = sorted(p for p in root.iterdir() if p.is_dir())
            self.assertEqual(len(directories), 2, f"both runs wrote into {directories}")
            self.assertEqual(marker.stat().st_mtime, 1, "the second run touched the first's files")
            self.assertEqual(marker.read_bytes(), before)

            nonces = set()
            for directory, completed in zip(directories, (first, second)):
                stamp = dict(
                    line.split("=", 1)
                    for line in (directory / "run.txt").read_text().splitlines()
                )
                self.assertEqual(stamp["head"], head)
                self.assertEqual(stamp["label"], "final")
                self.assertEqual(stamp["output"], str(directory))
                nonces.add(stamp["nonce"])
            self.assertEqual(len(nonces), 2)
            # Each run names its own directory on stdout, so a reader can
            # check the file it opens against the run it started.
            self.assertIn(f"output={directories[0]}", first.stdout + second.stdout)
            self.assertIn(f"output={directories[1]}", first.stdout + second.stdout)


if __name__ == "__main__":
    unittest.main()
