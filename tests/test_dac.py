"""Tests for the DAC decision engine — the core of the tool's correctness."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

import support  # noqa: E402

from why import dac  # noqa: E402
from why.model import Op  # noqa: E402


class ClassifyTests(unittest.TestCase):
    def test_owner(self):
        klass, why = dac.classify(1000, (1000,), 1000, 1000)
        self.assertEqual(klass, "user")
        self.assertIn("owner", why)

    def test_group_via_primary_gid(self):
        klass, _ = dac.classify(1000, (1000,), 0, 1000)
        self.assertEqual(klass, "group")

    def test_group_via_supplementary(self):
        klass, _ = dac.classify(1000, (1000, 27), 0, 27)
        self.assertEqual(klass, "group")

    def test_other(self):
        klass, why = dac.classify(1000, (1000,), 0, 42)
        self.assertEqual(klass, "other")
        self.assertIn("42", why)


class DacCheckTests(unittest.TestCase):
    def test_owner_bits_allow(self):
        decision = dac.dac_check(0o640, 1000, 1000, 1000, (1000,), dac.READ)
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.klass, "user")

    def test_other_bits_deny(self):
        decision = dac.dac_check(0o640, 0, 42, 1000, (1000,), dac.READ)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.effective, 0o0)

    def test_group_membership_flips_the_answer(self):
        denied = dac.dac_check(0o640, 0, 42, 1000, (1000,), dac.READ)
        allowed = dac.dac_check(0o640, 0, 42, 1000, (1000, 42), dac.READ)
        self.assertFalse(denied.allowed)
        self.assertTrue(allowed.allowed)

    def test_root_default_capabilities_bypass_dac(self):
        decision = dac.dac_check(0o000, 0, 0, 0, (0,), dac.READ, caps=None)
        self.assertTrue(decision.allowed)
        self.assertIn("CAP_DAC_OVERRIDE", decision.bypass or "")

    def test_root_still_needs_one_x_bit_to_execute(self):
        decision = dac.dac_check(0o644, 0, 0, 0, (0,), dac.EXEC, caps=None)
        self.assertFalse(decision.allowed)
        self.assertIn("does not grant execute", decision.bypass or "")

    def test_root_with_x_bit_can_execute(self):
        decision = dac.dac_check(0o755, 0, 0, 0, (0,), dac.EXEC, caps=None)
        self.assertTrue(decision.allowed)

    def test_uid0_without_capabilities_is_not_privileged(self):
        """The container case: uid 0 but --cap-drop=ALL, so DAC still applies."""
        decision = dac.dac_check(0o000, 0, 0, 0, (0,), dac.READ, caps=frozenset())
        self.assertFalse(decision.allowed)
        self.assertIsNone(decision.bypass)

    def test_dac_read_search_bypasses_read_and_search_only(self):
        caps = frozenset({"CAP_DAC_READ_SEARCH"})
        self.assertTrue(dac.dac_check(0o000, 0, 0, 1000, (1000,), dac.READ, caps=caps).allowed)
        self.assertTrue(dac.dac_check(0o000, 0, 0, 1000, (1000,), dac.EXEC, is_dir=True, caps=caps).allowed)
        self.assertFalse(dac.dac_check(0o000, 0, 0, 1000, (1000,), dac.WRITE, caps=caps).allowed)
        self.assertFalse(dac.dac_check(0o750, 0, 0, 1000, (1000,), dac.EXEC, caps=caps).allowed)

    def test_acl_mask_strips_a_named_user_grant(self):
        acl = support.extended_acl(mask=0o4, named_user_perm=0o6, named_uid=1000)
        read = dac.dac_check(0o640, 0, 42, 1000, (1000,), dac.READ, acl=acl)
        write = dac.dac_check(0o640, 0, 42, 1000, (1000,), dac.WRITE, acl=acl)
        self.assertTrue(read.allowed)
        self.assertFalse(write.allowed)
        self.assertEqual(read.klass, "acl")

    def test_acl_owner_entry_ignores_mask(self):
        acl = support.extended_acl(mask=0o0, named_user_perm=0o6, named_uid=1000)
        decision = dac.dac_check(0o600, 1000, 1000, 1000, (1000,), dac.READ, acl=acl)
        self.assertTrue(decision.allowed)

    def test_mask_note_explains_the_chmod_trap(self):
        acl = support.extended_acl(mask=0o4, named_user_perm=0o4, named_uid=1000)
        decision = dac.dac_check(0o600, 0, 42, 1000, (1000,), dac.READ, acl=acl)
        self.assertIsNotNone(decision.mask_note)
        self.assertIn("mask", decision.mask_note or "")


class StickyTests(unittest.TestCase):
    def test_owner_of_file_may_delete_in_sticky_dir(self):
        allowed, why = dac.sticky_allows_delete(0o1777, 0, 1000, 1000)
        self.assertTrue(allowed, why)

    def test_stranger_may_not_delete_in_sticky_dir(self):
        allowed, why = dac.sticky_allows_delete(0o1777, 0, 0, 2000)
        self.assertFalse(allowed)
        self.assertIn("sticky", why)

    def test_root_may_always_delete(self):
        self.assertTrue(dac.sticky_allows_delete(0o1777, 0, 0, 0)[0])

    def test_non_sticky_dir_has_no_restriction(self):
        self.assertTrue(dac.sticky_allows_delete(0o777, 0, 0, 2000)[0])


class AttributeTests(unittest.TestCase):
    def test_immutable_blocks_even_root(self):
        blocked, why = dac.immutable_blocks(Op.WRITE, {"immutable"}, has_cap_linux_immutable=False)
        self.assertTrue(blocked)
        self.assertIn("immutable", why)

    def test_immutable_with_capability_is_allowed(self):
        blocked, _ = dac.immutable_blocks(Op.WRITE, {"immutable"}, has_cap_linux_immutable=True)
        self.assertFalse(blocked)

    def test_append_only_blocks_write_and_delete(self):
        self.assertTrue(dac.immutable_blocks(Op.WRITE, {"append_only"}, False)[0])
        self.assertTrue(dac.immutable_blocks(Op.DELETE, {"append_only"}, False)[0])

    def test_append_only_allows_creating_inside(self):
        self.assertFalse(dac.immutable_blocks(Op.CREATE, {"append_only"}, False)[0])

    def test_no_flags_means_no_block(self):
        self.assertFalse(dac.immutable_blocks(Op.WRITE, set(), False)[0])


if __name__ == "__main__":
    unittest.main()
