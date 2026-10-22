"""Tests for the attribution layers, driven entirely by fixtures."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

import support  # noqa: E402

from why.checks import LAYER_META, dac_layers, system_layers  # noqa: E402
from why.model import Op, Status  # noqa: E402


class ExistsLayerTests(unittest.TestCase):
    def test_missing_target_is_enoent_not_permission(self):
        ctx = support.make_ctx(
            target=support.make_target("/nonexistent-why-test/file", exists=False),
            op=Op.READ,
        )
        result = dac_layers.layer_exists(ctx, 1)
        self.assertIs(result.status, Status.DENY)
        self.assertIn("ENOENT", result.detail)

    def test_create_on_existing_entry_is_not_a_permission_problem(self):
        ctx = support.make_ctx(op=Op.CREATE)
        result = dac_layers.layer_exists(ctx, 1)
        self.assertIs(result.status, Status.WARN)
        self.assertIn("EEXIST", result.detail)

    def test_existing_target_reports_mode(self):
        ctx = support.make_ctx()
        result = dac_layers.layer_exists(ctx, 1)
        self.assertIs(result.status, Status.OK)
        self.assertIn("0640", result.detail)


class ModeLayerTests(unittest.TestCase):
    def test_denied_for_other_class(self):
        result = dac_layers.layer_mode(support.shadow_ctx(), 9)
        self.assertIs(result.status, Status.DENY)
        self.assertIn("setfacl", result.fix or "")

    def test_allowed_for_owner(self):
        ctx = support.make_ctx(
            target=support.make_target("/home/alice/notes.txt", mode=0o600, uid=1000, gid=1000),
            subject=support.make_subject(uid=1000, gid=1000, groups=(1000,)),
        )
        self.assertIs(dac_layers.layer_mode(ctx, 9).status, Status.OK)

    def test_create_checks_the_parent_directory(self):
        ctx = support.make_ctx(
            target=support.make_target(
                "/srv/readonly/new.txt",
                exists=False,
                ancestors=[("/", 0o755, 0, 0), ("/srv", 0o755, 0, 0), ("/srv/readonly", 0o555, 0, 0)],
            ),
            op=Op.CREATE,
        )
        result = dac_layers.layer_mode(ctx, 9)
        self.assertIs(result.status, Status.DENY)
        self.assertIn("/srv/readonly", result.detail)


class TraverseLayerTests(unittest.TestCase):
    def test_blocked_ancestor(self):
        ctx = support.make_ctx(
            target=support.make_target(
                "/srv/private/report.txt",
                ancestors=[("/", 0o755, 0, 0), ("/srv/private", 0o700, 0, 0)],
            )
        )
        result = dac_layers.layer_traverse(ctx, 6)
        self.assertIs(result.status, Status.DENY)
        self.assertIn("/srv/private", result.detail)

    def test_all_ancestors_ok(self):
        ctx = support.make_ctx()
        self.assertIs(dac_layers.layer_traverse(ctx, 6).status, Status.OK)

    def test_parent_write_check_is_left_to_the_mode_layer(self):
        ctx = support.make_ctx(
            target=support.make_target(
                "/srv/private/new.txt",
                exists=False,
                ancestors=[("/", 0o755, 0, 0), ("/srv/private", 0o700, 0, 0)],
            ),
            op=Op.CREATE,
        )
        # For create/delete the parent's w+x requirement belongs to the mode layer,
        # which is why the traverse layer only walks the ancestors above it.
        self.assertIs(dac_layers.layer_traverse(ctx, 6).status, Status.OK)
        self.assertIs(dac_layers.layer_mode(ctx, 9).status, Status.DENY)


class OwnershipLayerTests(unittest.TestCase):
    def test_hints_when_group_membership_is_the_only_problem(self):
        result = dac_layers.layer_ownership(support.shadow_ctx(), 7)
        self.assertIs(result.status, Status.WARN)
        self.assertIn("usermod", result.fix or "")


class AclLayerTests(unittest.TestCase):
    def test_absent_acl(self):
        ctx = support.make_ctx()
        self.assertIs(dac_layers.layer_acl(ctx, 8).status, Status.INFO)

    def test_extended_acl_is_explained(self):
        ctx = support.make_ctx()
        ctx.acl = support.extended_acl(mask=0o4, named_user_perm=0o6, named_uid=1000)
        result = dac_layers.layer_acl(ctx, 8)
        self.assertIn("mask", result.detail)
        self.assertIn("user:1000", result.detail)


class StickyLayerTests(unittest.TestCase):
    def test_delete_in_sticky_dir(self):
        ctx = support.make_ctx(
            target=support.make_target(
                "/tmp/other.txt",
                mode=0o644,
                uid=0,
                gid=0,
                ancestors=[("/", 0o755, 0, 0), ("/tmp", 0o1777, 0, 0)],
            ),
            op=Op.DELETE,
        )
        self.assertIs(dac_layers.layer_sticky(ctx, 10).status, Status.DENY)

    def test_skipped_for_read(self):
        self.assertIs(dac_layers.layer_sticky(support.make_ctx(), 10).status, Status.SKIP)


class SystemLayerTests(unittest.TestCase):
    def test_read_only_mount_blocks_write(self):
        ctx = support.make_ctx(op=Op.WRITE, mounts=[support.make_mount(options=("ro", "relatime"))])
        result = system_layers.layer_mount(ctx, 4)
        self.assertIs(result.status, Status.DENY)
        self.assertIn("EROFS", result.detail)

    def test_noexec_blocks_exec(self):
        ctx = support.make_ctx(
            target=support.make_target("/opt/tool/run.sh", mode=0o755),
            op=Op.EXEC,
            mounts=[support.make_mount(options=("rw", "noexec"))],
        )
        result = system_layers.layer_mount(ctx, 4)
        self.assertIs(result.status, Status.DENY)
        self.assertIn("noexec", result.detail)

    def test_immutable_attribute_blocks_write(self):
        ctx = support.make_ctx(op=Op.WRITE)
        ctx.fs_flags = 0x00000010
        ctx.fs_flags_reason = None
        result = system_layers.layer_attrs(ctx, 5)
        self.assertIs(result.status, Status.DENY)
        self.assertIn("chattr -i", result.fix or "")

    def test_attrs_unknown_is_not_a_denial(self):
        ctx = support.make_ctx(op=Op.WRITE)
        ctx.fs_flags = None
        ctx.fs_flags_reason = "not Linux: file attributes unavailable"
        self.assertIs(system_layers.layer_attrs(ctx, 5).status, Status.UNKNOWN)

    def test_container_root_warning(self):
        ctx = support.make_ctx(subject=support.make_subject(uid=0, gid=0, groups=(0,), label="pid 1"))
        ctx.env.container = "docker"
        ctx.uid_map = [(0, 100000, 65536)]
        result = system_layers.layer_sandbox(ctx, 2)
        self.assertIs(result.status, Status.WARN)
        self.assertIn("100000", result.detail)

    def test_capabilities_bypass_is_reported(self):
        subject = support.make_subject(uid=0, gid=0, groups=(0,), caps=frozenset({"CAP_DAC_OVERRIDE"}))
        ctx = support.make_ctx(subject=subject)
        result = system_layers.layer_capabilities(ctx, 3)
        self.assertIn("CAP_DAC_OVERRIDE", result.detail)

    def test_apparmor_evidence_is_used(self):
        from why.parsers import parse_apparmor_denials

        ctx = support.make_ctx()
        ctx.apparmor = parse_apparmor_denials(
            'apparmor="DENIED" operation="open" profile="/usr/sbin/nginx" name="/etc/shadow" '
            'pid=1 comm="nginx" requested_mask="r" denied_mask="r"\n'
        )
        ctx.env.apparmor_profiles = 42
        result = system_layers.layer_apparmor(ctx, 12)
        self.assertIs(result.status, Status.DENY)
        self.assertIn("aa-complain", result.fix or "")

    def test_selinux_no_evidence_is_a_warning_not_a_verdict(self):
        ctx = support.make_ctx()
        ctx.env.selinux_enforcing = True
        result = system_layers.layer_selinux(ctx, 11)
        self.assertIs(result.status, Status.WARN)
        self.assertIn("no matching AVC", result.detail)


class PipelineTests(unittest.TestCase):
    def test_twelve_layers_are_run(self):
        from why.checks import run_layers

        ctx = support.shadow_ctx()
        layers = run_layers(ctx)
        self.assertEqual(len(layers), len(LAYER_META))
        self.assertEqual([item.index for item in layers], list(range(1, len(LAYER_META) + 1)))
        self.assertEqual([item.id for item in layers], [layer_id for layer_id, _ in LAYER_META])

    def test_shadow_case_verdict(self):
        report = support.denied_report()
        self.assertEqual(report.verdict.value, "denied")
        self.assertEqual(report.deciding_layer, "mode")
        self.assertTrue(report.fixes)
        self.assertIn("setfacl", report.fixes[0])

    def test_layer_failure_never_breaks_the_run(self):
        from why import checks

        ctx = support.shadow_ctx()
        original = checks.PIPELINE

        def boom(_ctx, _index):
            raise RuntimeError("synthetic failure")

        checks.PIPELINE = tuple(boom if fn is dac_layers.layer_mode else fn for fn in original)
        try:
            layers = checks.run_layers(ctx)
        finally:
            checks.PIPELINE = original
        fallback = [item for item in layers if item.status is Status.UNKNOWN]
        self.assertTrue(fallback)
        self.assertIn("synthetic failure", fallback[0].detail)


if __name__ == "__main__":
    unittest.main()
