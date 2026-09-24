import json
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path
from package_release import BINARIES, TARGETS, binaries_for, package, version
from publish_release import assets


class PackagingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        # The synthetic root carries the advertised-target declaration because
        # `package()` now reads it from the manifest under `root` rather than
        # from a literal tuple in the module. The list is **copied from the
        # real declaration** via `TARGETS` rather than spelled out again here:
        # a fixture that hard-coded four triples would reintroduce, in the
        # tests, exactly the second source of truth this change removed from
        # the script (docs/tasks.md M6-C11, M5-C11).
        declaration = "".join(f'    "{target}",\n' for target in TARGETS)
        (self.root / "Cargo.toml").write_text(
            '[workspace.package]\nversion = "0.1.0"\n\n'
            "[workspace.metadata.release]\n"
            f"advertised-targets = [\n{declaration}]\n"
        )
        (self.root / "LICENSE").write_text("Synthetic project licence")
        (self.root / "examples").mkdir()
        for name in ("m1-client.toml", "m1-relay.toml"):
            (self.root / "examples" / name).write_text("# template")
        (self.root / "secret.key").write_text("must not ship")
        for target in TARGETS:
            directory = self.root / "target" / target / "release"
            directory.mkdir(parents=True)
            for name in binaries_for(target):
                binary = directory / (name + (".exe" if target.endswith("windows-msvc") else ""))
                binary.write_bytes(b"synthetic binary")
                binary.chmod(0o755)
        self.sha = "a" * 40
        self.output = self.root / "dist"

    def build_all(self):
        for target in TARGETS:
            package(self.root, target, self.sha, "123", self.output, {"packages": []})

    def test_complete_archives_and_checksums(self):
        self.build_all()
        self.assertEqual(len(assets(self.output, version(self.root, self.sha, "123"))), 8)
        for file in self.output.iterdir():
            if file.name.endswith("tar.gz"):
                with tarfile.open(file) as archive:
                    names = archive.getnames()
                    manifest = json.load(archive.extractfile("release.json"))
                    self.assertTrue(archive.getmember("bin/tunnel-client").mode & 0o111)
            elif file.suffix == ".zip":
                with zipfile.ZipFile(file) as archive:
                    names = archive.namelist()
                    manifest = json.loads(archive.read("release.json"))
            else:
                continue
            self.assertNotIn("secret.key", names)
            self.assertIn("notices/dependencies.json", names)
            self.assertIn("LICENSE", names)
            self.assertTrue(any("tunnel-deadman" in name for name in names))
            # The relay is in every Unix bundle and in no Windows bundle.
            has_relay = any("tunnel-relay" in name for name in names)
            self.assertEqual(has_relay, not manifest["target"].endswith("windows-msvc"), file.name)
            self.assertEqual(manifest["sourceSha"], self.sha)

    def test_tar_modes_do_not_depend_on_the_build_host(self):
        # A Windows runner's file system has no execute bits, so the release
        # job's packaging test saw mode 0 for bin/tunnel-client. Simulate that
        # host here by clearing the execute bits before packaging: the archive
        # must still mark the binaries executable and nothing else, and must not
        # carry host bits the other way either (LICENSE is 0777 on this "host").
        target = next(t for t in TARGETS if not t.endswith("windows-msvc"))
        release = self.root / "target" / target / "release"
        for name in binaries_for(target):
            (release / name).chmod(0o644)
        (self.root / "LICENSE").chmod(0o777)
        archive = package(self.root, target, self.sha, "123", self.output, {"packages": []})
        with tarfile.open(archive) as handle:
            for member in handle.getmembers():
                with self.subTest(member=member.name):
                    self.assertEqual((member.uid, member.gid, member.uname, member.gname), (0, 0, "", ""))
                    if member.isdir() or member.name.startswith("bin/"):
                        self.assertEqual(member.mode, 0o755)
                    else:
                        self.assertEqual(member.mode, 0o644)

    def test_missing_helper_fails(self):
        (self.root / "target" / TARGETS[0] / "release" / "tunnel-deadman").unlink()
        with self.assertRaises(ValueError):
            package(self.root, TARGETS[0], self.sha, "123", self.output, {"packages": []})

    def test_incomplete_matrix_fails(self):
        package(self.root, TARGETS[0], self.sha, "123", self.output, {"packages": []})
        with self.assertRaises(FileNotFoundError):
            assets(self.output, version(self.root, self.sha, "123"))

    def test_tampered_archive_fails(self):
        self.build_all()
        next(self.output.glob("*.zip")).write_bytes(b"tampered")
        with self.assertRaises(ValueError):
            assets(self.output, version(self.root, self.sha, "123"))

    def test_invalid_identifiers_fail(self):
        for sha, run in [("main", "123"), (self.sha, "../bad"), (self.sha, "0")]:
            with self.assertRaises(ValueError):
                version(self.root, sha, run)


if __name__ == "__main__":
    unittest.main()
