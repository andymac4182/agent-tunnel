"""Unit tests for scripts/verify_release_archive.py's host-independent parts.

The checks that execute binaries are exercised against real archives by the
release workflow's `verify` job with `--self-test`; these cover the parsers
and refusals that must behave the same on every host.
"""
import io
import struct
import tarfile
import tempfile
import unittest
from pathlib import Path

import verify_release_archive as v


def elf(machine: int) -> bytes:
    header = bytearray(64)
    header[:4] = b"\x7fELF"
    header[4], header[5] = 2, 1
    struct.pack_into("<H", header, 18, machine)
    return bytes(header)


def macho(cpu: int) -> bytes:
    return b"\xcf\xfa\xed\xfe" + struct.pack("<I", cpu) + bytes(56)


def pe(machine: int) -> bytes:
    data = bytearray(0x100)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<H", data, 0x84, machine)
    return bytes(data)


class VerifierTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.dir = Path(self.temp.name)

    def write(self, name: str, data: bytes) -> Path:
        path = self.dir / name
        path.write_bytes(data)
        return path

    def test_binary_format_reads_each_header(self):
        cases = [
            (elf(62), ("elf", "x86_64")), (elf(183), ("elf", "aarch64")), (elf(3), ("elf", "machine-3")),
            (macho(0x0100000C), ("macho", "aarch64")), (macho(0x01000007), ("macho", "x86_64")),
            (pe(0x8664), ("pe", "x86_64")), (pe(0x14C), ("pe", "machine-0x14c")),
            (b"#!/bin/sh\n", ("unknown", "unknown")),
        ]
        for index, (data, expected) in enumerate(cases):
            with self.subTest(expected=expected):
                self.assertEqual(v.binary_format(self.write(f"b{index}", data)), expected)

    def test_member_names_that_escape_are_refused(self):
        for name in ("/etc/passwd", "../outside", "bin/../../x", "C:\\Windows\\x", "C:/x"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                v.check_member_name(name)
        v.check_member_name("bin/tunnel-client")
        v.check_member_name("docs/operator.md")

    def test_a_tar_with_a_symbolic_link_is_refused(self):
        archive = self.dir / "a.tar.gz"
        with tarfile.open(archive, "w:gz") as handle:
            link = tarfile.TarInfo("bin/tunnel-deadman")
            link.type = tarfile.SYMTYPE
            link.linkname = "/bin/true"
            handle.addfile(link)
            body = b"x"
            info = tarfile.TarInfo("LICENSE")
            info.size = len(body)
            handle.addfile(info, io.BytesIO(body))
        with self.assertRaises(ValueError):
            v.unpack(archive, self.dir / "out")

    def test_checksum_must_name_the_archive_and_its_digest(self):
        archive = self.write("agentuplink-x.tar.gz", b"archive bytes")
        good = self.write("good.sha256", (
            __import__("hashlib").sha256(b"archive bytes").hexdigest() + "  agentuplink-x.tar.gz\n").encode())
        self.assertTrue(v.check_checksums(archive, good).ok)
        renamed = self.write("renamed.sha256", good.read_bytes().replace(b"agentuplink-x", b"agentuplink-y"))
        self.assertEqual(v.check_checksums(archive, renamed).witness, "checksum-mismatch")
        self.assertEqual(v.check_checksums(archive, self.dir / "absent.sha256").witness, "checksum-missing")

    def test_target_and_host_names_agree_on_one_vocabulary(self):
        self.assertEqual(v.target_os_arch("aarch64-apple-darwin"), ("macos", "aarch64"))
        self.assertEqual(v.target_os_arch("x86_64-unknown-linux-gnu"), ("linux", "x86_64"))
        self.assertEqual(v.target_os_arch("x86_64-pc-windows-msvc"), ("windows", "x86_64"))
        host_os, host_arch = v.host_os_arch()
        self.assertIn(host_os, ("macos", "linux", "windows"))
        self.assertIn(host_arch, ("x86_64", "aarch64"))

    def test_system_library_classifiers(self):
        for name in ("libc.so.6", "libm.so.6", "libgcc_s.so.1", "ld-linux-x86-64.so.2", "ld-linux-aarch64.so.1"):
            self.assertTrue(v.LINUX_SYSTEM.match(name), name)
        for name in ("libssl.so.3", "libcrypto.so.3", "libz.so.1"):
            self.assertFalse(v.LINUX_SYSTEM.match(name), name)
        for name in ("VCRUNTIME140.dll", "vcruntime140_1.dll", "MSVCP140.dll"):
            self.assertTrue(v.WINDOWS_REDISTRIBUTABLE.match(name), name)
        for name in ("KERNEL32.dll", "ntdll.dll", "api-ms-win-crt-runtime-l1-1-0.dll"):
            self.assertFalse(v.WINDOWS_REDISTRIBUTABLE.match(name), name)


if __name__ == "__main__":
    unittest.main()
