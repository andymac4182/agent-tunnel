import json
import os
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path
import package_release
from package_release import (
    BINARIES, GUIDE, ROOT, SOURCE_URL, TARGETS, binaries_for, package,
    release_documents, stage_documents, unresolved_links, version,
)
from publish_release import assets

# A synthetic guide and the documents it links (docs/tasks.md M6-C50). The
# guide links one shipped document with a fragment, an absolute URL and an
# in-page anchor; the linked document links the guide back (must stay
# relative), an unshipped document (must be pinned to the source commit) and
# an unshipped directory one level up.
GUIDE_TEXT = (
    "# Guide\n\nSee [runtime](runtime.md#exit-codes), [site](https://example.test/x) "
    "and [below](#below).\n\n## below\n"
)
RUNTIME_TEXT = (
    "# Runtime\n\nBack to [the guide](operator.md#1-download), on to "
    "[testing](testing.md#gate) and [deploy](../deploy/fly).\n"
)


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
        (self.root / "docs").mkdir()
        (self.root / "docs" / "operator.md").write_text(GUIDE_TEXT)
        (self.root / "docs" / "runtime.md").write_text(RUNTIME_TEXT)
        (self.root / "docs" / "testing.md").write_text("# Testing, not shipped\n")
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
            # M6-C50: the guide and exactly the documents it links ship.
            documents = sorted(name for name in names if name.startswith("docs/"))
            self.assertEqual(documents, ["docs/operator.md", "docs/runtime.md"], file.name)

    def extracted(self, target):
        """Package one target and unpack it the way a tester would."""
        archive = package(self.root, target, self.sha, "123", self.output, {"packages": []})
        destination = self.root / "unpacked" / target
        destination.mkdir(parents=True)
        if archive.suffix == ".zip":
            with zipfile.ZipFile(archive) as handle:
                handle.extractall(destination)
        else:
            with tarfile.open(archive) as handle:
                handle.extractall(destination, filter="data")
        return destination

    def test_every_archive_ships_the_guide_and_its_links_resolve(self):
        for target in TARGETS:
            with self.subTest(target=target):
                unpacked = self.extracted(target)
                # The guide is byte-identical: the docs check executes this copy.
                self.assertEqual(
                    (unpacked / GUIDE).read_bytes(), (self.root / GUIDE).read_bytes()
                )
                runtime = (unpacked / "docs" / "runtime.md").read_text()
                self.assertIn("](operator.md#1-download)", runtime)
                self.assertIn(f"]({SOURCE_URL}/{self.sha}/docs/testing.md#gate)", runtime)
                self.assertIn(f"]({SOURCE_URL}/{self.sha}/deploy/fly)", runtime)
                self.assertEqual(unresolved_links(unpacked), [])
                self.assertFalse((unpacked / "docs" / "testing.md").exists())

    def test_a_guide_link_that_cannot_ship_is_refused(self):
        for link in ("../site/docs/downloads.html", "missing.md", "../../outside.md"):
            with self.subTest(link=link):
                (self.root / GUIDE).write_text(GUIDE_TEXT + f"\n[x]({link})\n")
                with self.assertRaises(ValueError):
                    package(self.root, TARGETS[0], self.sha, "123", self.output, {"packages": []})

    def test_a_dangling_link_in_a_bundle_is_reported(self):
        unpacked = self.extracted(TARGETS[0])
        (unpacked / "docs" / "runtime.md").unlink()
        self.assertEqual(unresolved_links(unpacked), ["docs/operator.md -> runtime.md#exit-codes"])

    def test_the_real_guide_ships_with_every_link_resolving(self):
        # Against this repository, not a fixture: a link added to the real
        # guide that cannot ship, or a shipped document linking a file no
        # longer in the repository, goes red here before a release does.
        documents = release_documents(ROOT)
        self.assertIn(GUIDE, documents)
        self.assertGreaterEqual(len(documents), 7)
        staged = self.root / "real"
        self.assertEqual(stage_documents(ROOT, staged, self.sha), documents)
        self.assertEqual((staged / GUIDE).read_bytes(), (ROOT / GUIDE).read_bytes())
        self.assertEqual(unresolved_links(staged), [])
        for document in documents:
            text = (staged / document).read_text()
            for url in package_release._LINK_RE.findall(text):
                if url.startswith(SOURCE_URL):
                    target = url[len(SOURCE_URL) + 42:].partition("#")[0]
                    self.assertTrue((ROOT / target).exists(), f"{document}: {url}")

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

    def test_zip_accepts_files_dated_before_1980(self):
        # crates.io sources can carry epoch (1970) mtimes, and packaging copies
        # dependency licence files with shutil.copy2, which keeps them. ZIP
        # cannot encode dates before 1980, so the Windows archive failed in
        # release run 35984188758 while the tar archives did not care.
        dependency = self.root / "vendor-dep"
        dependency.mkdir()
        (dependency / "Cargo.toml").write_text("[package]\n")
        licence = dependency / "LICENSE"
        licence.write_text("synthetic dependency licence")
        os.utime(licence, (0, 0))
        metadata = {"packages": [{"name": "dep", "version": "1.0.0", "license": "MIT", "source": None, "manifest_path": str(dependency / "Cargo.toml")}]}
        target = next(t for t in TARGETS if t.endswith("windows-msvc"))
        archive = package(self.root, target, self.sha, "123", self.output, metadata)
        with zipfile.ZipFile(archive) as handle:
            self.assertIn("notices/dep-1.0.0/LICENSE", handle.namelist())
            self.assertEqual(handle.getinfo("notices/dep-1.0.0/LICENSE").date_time[0], 1980)

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
