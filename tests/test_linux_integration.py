"""Integration tests against a real Linux kernel.

Skipped unless running as root on Linux, which is exactly what the ``integration``
job in CI does inside a throw-away container. These tests create files, ACLs and
tighten modes in a temporary directory, then assert on the verdicts ``why``
produces for the ``nobody`` user.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from why.checks import run_all  # noqa: E402
from why.collect import collect_environment, collect_target, resolve_subject  # noqa: E402
from why.model import Op, Status  # noqa: E402

LINUX = sys.platform.startswith("linux")
IS_ROOT = LINUX and os.geteuid() == 0 if LINUX else False
VICTIM = "nobody"


def _have(binary: str) -> bool:
    return shutil.which(binary) is not None


def _run(argv) -> int:
    try:
        return subprocess.run(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False).returncode
    except OSError:
        return 127


@unittest.skipUnless(LINUX, "Linux only")
@unittest.skipUnless(IS_ROOT, "needs root to set up foreign-owned fixtures")
class LinuxIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            cls.subject = resolve_subject(user=VICTIM)
        except ValueError:
            raise unittest.SkipTest(f"user {VICTIM} does not exist") from None
        cls.env = collect_environment()
        cls.dir = tempfile.mkdtemp(prefix="why-it-")

    @classmethod
    def tearDownClass(cls):
        for root, _dirs, files in os.walk(cls.dir):
            for name in files:
                try:
                    os.chmod(os.path.join(root, name), 0o600)
                except OSError:
                    pass
        shutil.rmtree(cls.dir, ignore_errors=True)

    # -- helpers ---------------------------------------------------------- #
    def make_file(self, name: str, mode: int, content: str = "x") -> str:
        path = os.path.join(self.dir, name)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(content)
        os.chmod(path, mode)
        os.chown(path, 0, 0)
        return path

    def verdict_for(self, path: str, op: Op = Op.READ):
        target = collect_target(path)
        return run_all(target, self.subject, op, env=self.env, gather_evidence=False)

    def status_of(self, report, layer_id: str) -> str:
        layer = report.layer(layer_id)
        self.assertIsNotNone(layer, f"layer {layer_id} missing")
        return layer.status

    # -- tests ------------------------------------------------------------ #
    def test_mode_bits_deny(self):
        path = self.make_file("mode600.txt", 0o600)
        report = self.verdict_for(path)
        self.assertEqual(report.verdict.value, "denied")
        self.assertEqual(report.deciding_layer, "mode")
        self.assertEqual(self.status_of(report, "mode"), Status.DENY)

    def test_other_bits_allow(self):
        path = self.make_file("mode644.txt", 0o644)
        report = self.verdict_for(path)
        self.assertEqual(self.status_of(report, "mode"), Status.OK)
        self.assertEqual(report.verdict.value, "allowed")

    def test_group_bits_deny_when_not_a_member(self):
        path = self.make_file("mode640.txt", 0o640)
        report = self.verdict_for(path)
        self.assertEqual(self.status_of(report, "mode"), Status.DENY)
        self.assertEqual(self.status_of(report, "ownership"), Status.WARN)

    def test_missing_ancestor_execute_denies_traversal(self):
        locked = os.path.join(self.dir, "locked")
        os.makedirs(locked, exist_ok=True)
        os.chmod(locked, 0o700)
        os.chown(locked, 0, 0)
        path = os.path.join(locked, "inner.txt")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("x")
        os.chmod(path, 0o644)
        report = self.verdict_for(path)
        self.assertEqual(report.deciding_layer, "traverse")
        self.assertIn(locked, report.reason)

    def test_execute_without_x_bit(self):
        path = self.make_file("script.sh", 0o644, "#!/bin/sh\necho hi\n")
        report = self.verdict_for(path, Op.EXEC)
        self.assertEqual(report.deciding_layer, "mode")

    def test_acl_grant_is_detected(self):
        if not _have("setfacl"):
            self.skipTest("setfacl is not installed")
        path = self.make_file("acl.txt", 0o600)
        if _run(["setfacl", "-m", f"u:{VICTIM}:r--", path]) != 0:
            self.skipTest("setfacl failed (filesystem without ACL support?)")
        report = self.verdict_for(path)
        mode_layer = report.layer("mode")
        self.assertEqual(mode_layer.status, Status.OK)
        self.assertEqual(mode_layer.data.get("class"), "acl")

    def test_acl_mask_trap_is_explained(self):
        if not _have("setfacl"):
            self.skipTest("setfacl is not installed")
        path = self.make_file("mask.txt", 0o600)
        if _run(["setfacl", "-m", f"u:{VICTIM}:rw-", path]) != 0:
            self.skipTest("setfacl failed")
        # A plain chmod rewrites the ACL mask and silently strips the granted write.
        os.chmod(path, 0o640)
        report = self.verdict_for(path, Op.WRITE)
        self.assertEqual(report.layer("mode").status, Status.DENY)
        self.assertIn("mask", report.layer("acl").detail)

    def test_immutable_attribute_denies_even_root(self):
        if not _have("chattr"):
            self.skipTest("chattr is not installed")
        path = self.make_file("immutable.txt", 0o644)
        if _run(["chattr", "+i", path]) != 0:
            self.skipTest("filesystem does not support the immutable attribute")
        try:
            report = self.verdict_for(path, Op.WRITE)
            self.assertEqual(self.status_of(report, "attrs"), Status.DENY)
        finally:
            _run(["chattr", "-i", path])

    def test_sticky_directory_blocks_delete(self):
        sticky = os.path.join(self.dir, "sticky")
        os.makedirs(sticky, exist_ok=True)
        os.chmod(sticky, 0o1777)
        path = os.path.join(sticky, "victim.txt")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("x")
        os.chmod(path, 0o666)
        os.chown(path, 0, 0)
        report = self.verdict_for(path, Op.DELETE)
        self.assertEqual(self.status_of(report, "sticky"), Status.DENY)

    def test_create_in_unwritable_directory(self):
        readonly = os.path.join(self.dir, "readonly")
        os.makedirs(readonly, exist_ok=True)
        os.chmod(readonly, 0o755)
        os.chown(readonly, 0, 0)
        path = os.path.join(readonly, "new.txt")
        report = self.verdict_for(path, Op.CREATE)
        self.assertEqual(report.deciding_layer, "mode")

    def test_noexec_mount_is_reported_when_available(self):
        """Bind-mount a tmpfs noexec over a scratch dir, if the kernel lets us."""
        scratch = os.path.join(self.dir, "noexec")
        os.makedirs(scratch, exist_ok=True)
        if _run(["mount", "-t", "tmpfs", "-o", "noexec,size=1M", "tmpfs", scratch]) != 0:
            self.skipTest("cannot mount tmpfs here (needs CAP_SYS_ADMIN)")
        try:
            path = os.path.join(scratch, "tool.sh")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("#!/bin/sh\necho hi\n")
            os.chmod(path, 0o755)
            report = self.verdict_for(path, Op.EXEC)
            self.assertEqual(self.status_of(report, "mount"), Status.DENY)
            self.assertIn("noexec", report.layer("mount").detail)
        finally:
            _run(["umount", scratch])

    def test_root_is_not_blocked_by_dac(self):
        root = resolve_subject(user="root")
        path = self.make_file("rootreads.txt", 0o000)
        target = collect_target(path)
        report = run_all(target, root, Op.READ, env=self.env, gather_evidence=False)
        self.assertEqual(report.layer("mode").status, Status.OK)
        self.assertEqual(report.verdict.value, "allowed")

    def test_evidence_layers_do_not_crash(self):
        path = self.make_file("evidence.txt", 0o644)
        target = collect_target(path)
        report = run_all(target, self.subject, Op.READ, env=self.env, gather_evidence=True)
        self.assertTrue(report.layers)
        for layer in report.layers:
            self.assertIsNotNone(layer.detail)


if __name__ == "__main__":
    unittest.main()
