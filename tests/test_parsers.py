"""Tests for the pure parsers. These run on any platform, including Windows."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

import support  # noqa: E402

from why import parsers  # noqa: E402


class ModeBitTests(unittest.TestCase):
    def test_perm_letters(self):
        self.assertEqual(parsers.perm_letters(0o0), "---")
        self.assertEqual(parsers.perm_letters(0o4), "r--")
        self.assertEqual(parsers.perm_letters(0o7), "rwx")
        self.assertEqual(parsers.perm_letters(0o2), "-w-")

    def test_bits_of(self):
        self.assertEqual(parsers.bits_of(0o640, "user"), 0o6)
        self.assertEqual(parsers.bits_of(0o640, "group"), 0o4)
        self.assertEqual(parsers.bits_of(0o640, "other"), 0o0)

    def test_mode_string(self):
        self.assertEqual(parsers.mode_string(0o100640), "-rw-r-----")
        self.assertEqual(parsers.mode_string(0o040755), "drwxr-xr-x")
        self.assertEqual(parsers.mode_string(0o104755), "-rwsr-xr-x")
        self.assertEqual(parsers.mode_string(0o041777), "drwxrwxrwt")

    def test_special_bits(self):
        self.assertEqual(parsers.special_bits(0o4755), "s--")
        self.assertEqual(parsers.special_bits(0o1777), "--t")


class AclTests(unittest.TestCase):
    def test_decode_posix_acl(self):
        blob = support.acl_blob(
            [
                (parsers.ACL_TAG_USER_OBJ, 0o6, None),
                (parsers.ACL_TAG_USER, 0o4, 1000),
                (parsers.ACL_TAG_GROUP_OBJ, 0o4, None),
                (parsers.ACL_TAG_MASK, 0o4, None),
                (parsers.ACL_TAG_OTHER, 0o0, None),
            ]
        )
        acl = parsers.decode_posix_acl(blob)
        self.assertTrue(acl.is_extended)
        self.assertEqual(acl.owner_entry.perms, "rw-")
        self.assertEqual(acl.named_users, {1000: 0o4})
        self.assertEqual(acl.mask_entry.perms, "r--")
        self.assertEqual(
            acl.lines(),
            ["user::rw-", "user:1000:r--", "group::r--", "mask::r--", "other::---"],
        )

    def test_decode_rejects_bad_version(self):
        with self.assertRaises(ValueError):
            parsers.decode_posix_acl(b"\x03\x00\x00\x00")

    def test_decode_rejects_ragged_blob(self):
        blob = (2).to_bytes(4, "little") + b"\x01\x00\x06\x00\xff\xff\xff"
        with self.assertRaises(ValueError):
            parsers.decode_posix_acl(blob)

    def test_plain_acl_is_not_extended(self):
        blob = support.acl_blob(
            [
                (parsers.ACL_TAG_USER_OBJ, 0o6, None),
                (parsers.ACL_TAG_GROUP_OBJ, 0o4, None),
                (parsers.ACL_TAG_OTHER, 0o0, None),
            ]
        )
        self.assertFalse(parsers.decode_posix_acl(blob).is_extended)

    def test_acl_perms_owner_ignores_mask(self):
        acl = support.extended_acl(mask=0o4, named_user_perm=0o6, named_uid=1000)
        perms, why = parsers.acl_perms_for(acl, 1000, (1000,), file_uid=1000, file_gid=1000)
        self.assertEqual(perms, 0o6, why)

    def test_acl_perms_named_user_is_masked(self):
        acl = support.extended_acl(mask=0o4, named_user_perm=0o6, named_uid=1000)
        perms, why = parsers.acl_perms_for(acl, 1000, (2000,), file_uid=0, file_gid=42)
        self.assertEqual(perms, 0o4, why)  # write was stripped by the mask

    def test_acl_perms_group_union_then_mask(self):
        blob = support.acl_blob(
            [
                (parsers.ACL_TAG_USER_OBJ, 0o6, None),
                (parsers.ACL_TAG_GROUP_OBJ, 0o0, None),
                (parsers.ACL_TAG_GROUP, 0o4, 27),
                (parsers.ACL_TAG_MASK, 0o6, None),
                (parsers.ACL_TAG_OTHER, 0o0, None),
            ]
        )
        acl = parsers.decode_posix_acl(blob)
        perms, why = parsers.acl_perms_for(acl, 1000, (27,), file_uid=0, file_gid=999)
        self.assertEqual(perms, 0o4, why)

    def test_acl_perms_other(self):
        acl = support.extended_acl()
        perms, _why = parsers.acl_perms_for(acl, 4242, (4242,), file_uid=0, file_gid=42)
        self.assertEqual(perms, 0o0)

    def test_acl_unresolved_names_are_reported_not_guessed(self):
        acl = parsers.parse_getfacl("user::rw-\nuser:alice:r--\nmask::r--\nother::---\n")
        perms, why = parsers.acl_perms_for(acl, 1000, (1000,), file_uid=0, file_gid=42)
        self.assertIsNone(perms)
        self.assertIn("symbolic", why)

    def test_parse_getfacl_numeric(self):
        acl = parsers.parse_getfacl(
            "# file: /etc/shadow\n# owner: root\n# group: shadow\n"
            "user::rw-\nuser:1000:r--\ngroup::---\nmask::r--\nother::---\n"
        )
        self.assertEqual(acl.named_users, {1000: 0o4})
        self.assertTrue(acl.is_extended)
        self.assertFalse(acl.unresolved_names)


class MountInfoTests(unittest.TestCase):
    SAMPLE = (
        "21 26 0:20 / /proc rw,nosuid,nodev,noexec,relatime shared:5 - proc proc rw\n"
        "22 26 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw\n"
        "23 26 8:2 / /mnt/data\\040drive rw,noexec,relatime shared:9 - ext4 /dev/sdb1 rw\n"
        "24 26 0:42 / /mnt/data rw,nosuid,nodev,relatime shared:11 - nfs server:/export rw\n"
        "25 26 8:3 / /tmp tmpfs rw,nosuid,nodev shared:13 - tmpfs tmpfs rw\n"
    )

    def test_parse_and_escape(self):
        mounts = parsers.parse_mountinfo(self.SAMPLE)
        self.assertEqual(len(mounts), 5)
        self.assertEqual(mounts[2].mount_point, "/mnt/data drive")
        self.assertIn("noexec", mounts[2].options)
        self.assertEqual(mounts[1].fstype, "ext4")
        self.assertEqual(mounts[3].source, "server:/export")
        self.assertEqual(mounts[0].optional, ("shared:5",))

    def test_find_mount_respects_component_boundaries(self):
        mounts = parsers.parse_mountinfo(self.SAMPLE)
        self.assertEqual(parsers.find_mount(mounts, "/mnt/database").mount_point, "/")
        self.assertEqual(parsers.find_mount(mounts, "/mnt/data/file").mount_point, "/mnt/data")
        self.assertEqual(parsers.find_mount(mounts, "/proc/1/status").mount_point, "/proc")
        self.assertEqual(parsers.find_mount(mounts, "/etc/shadow").mount_point, "/")

    def test_malformed_lines_are_skipped(self):
        mounts = parsers.parse_mountinfo("garbage\n\n1 2 3 4 5\n")
        self.assertEqual(mounts, [])


class ProcParsingTests(unittest.TestCase):
    STATUS = (
        "Name:\tnginx\n"
        "State:\tS (sleeping)\n"
        "Uid:\t0\t33\t33\t33\n"
        "Gid:\t0\t33\t33\t33\n"
        "Groups:\t33 100\n"
        "CapEff:\t0000000000000000\n"
        "Seccomp:\t2\n"
        "NoNewPrivs:\t1\n"
    )

    def test_parse_proc_status(self):
        parsed = parsers.parse_proc_status(self.STATUS)
        self.assertEqual(parsed["Name"], "nginx")
        self.assertEqual(parsed["Uid"], [0, 33, 33, 33])
        self.assertEqual(parsed["Groups"], [33, 100])
        self.assertEqual(parsed["CapEff"], "0000000000000000")
        self.assertEqual(parsed["Seccomp"], "2")

    def test_uid_map(self):
        maps = parsers.parse_uid_map("         0       1000          1\n")
        self.assertEqual(maps, [(0, 1000, 1)])
        self.assertEqual(parsers.map_id(maps, 0), 1000)
        self.assertIsNone(parsers.map_id(maps, 5))
        self.assertIn("uid 1000 on the host", parsers.describe_userns(maps, 0))


class CapabilityTests(unittest.TestCase):
    def test_full_root_mask(self):
        caps = parsers.decode_cap_mask("000001ffffffffff")
        self.assertIn("CAP_CHOWN", caps)
        self.assertIn("CAP_DAC_OVERRIDE", caps)
        self.assertIn("CAP_CHECKPOINT_RESTORE", caps)

    def test_empty_and_invalid(self):
        self.assertEqual(parsers.decode_cap_mask("0000000000000000"), frozenset())
        self.assertEqual(parsers.decode_cap_mask("not-hex"), frozenset())

    def test_unknown_high_bits_are_flagged(self):
        caps = parsers.decode_cap_mask(1 << 45)
        self.assertTrue(any(name.startswith("CAP_UNKNOWN_BITS") for name in caps))


class FileFlagTests(unittest.TestCase):
    def test_decode_fs_flags(self):
        flags = parsers.decode_fs_flags(0x00000010 | 0x00040000)
        self.assertEqual(flags, frozenset({"immutable", "extents"}))

    def test_decode_flags_reports_unknown(self):
        flags = parsers.decode_fs_flags(1 << 30)
        self.assertTrue(any(name.startswith("unknown_flags") for name in flags))

    def test_parse_lsattr(self):
        line = parsers.flags_to_lsattr_string({"immutable", "extents"})
        parsed = parsers.parse_lsattr(f"{line} /etc/shadow\n{'-' * 24} /tmp/x\n")
        self.assertEqual(parsed["/etc/shadow"], frozenset({"immutable", "extents"}))
        self.assertEqual(parsed["/tmp/x"], frozenset())

    def test_lsattr_roundtrip(self):
        text = parsers.flags_to_lsattr_string({"immutable", "extents"})
        self.assertEqual(len(text), 24)
        self.assertEqual(text[4], "i")
        self.assertEqual(text[18], "e")

    def test_lsattr_sudo_warning_skipped(self):
        self.assertEqual(parsers.parse_lsattr("lsattr: Operation not supported\n"), {})


class SecurityLogTests(unittest.TestCase):
    AVC = (
        "type=AVC msg=audit(1712345678.123:456): avc:  denied  { read } for  pid=1234 "
        'comm="nginx" name="shadow" dev="sda1" ino=123 scontext=system_u:system_r:httpd_t:s0 '
        "tcontext=system_u:object_r:shadow_t:s0 tclass=file permissive=0\n"
        "type=AVC msg=audit(1712345678.124:457): avc:  granted  { read } for  pid=1 "
        'comm="systemd" name="hosts" tclass=file\n'
    )

    def test_parse_avc_denials(self):
        denials = parsers.parse_avc_lines(self.AVC)
        self.assertEqual(len(denials), 1)
        self.assertEqual(denials[0].perms, ("read",))
        self.assertEqual(denials[0].path, "shadow")
        self.assertEqual(denials[0].comm, "nginx")
        self.assertEqual(denials[0].permissive, False)

    def test_match_avc_for_path_by_basename(self):
        denials = parsers.parse_avc_lines(self.AVC)
        self.assertEqual(len(parsers.match_avc_for_path(denials, "/etc/shadow")), 1)
        self.assertEqual(len(parsers.match_avc_for_path(denials, "/etc/hosts")), 0)

    APPARMOR = (
        'audit: type=1400 audit(1712345678.125:458): apparmor="DENIED" operation="open" '
        'profile="/usr/sbin/nginx" name="/etc/shadow" pid=1234 comm="nginx" '
        'requested_mask="r" denied_mask="r" fsuid=0 ouid=0\n'
    )

    def test_parse_apparmor_denials(self):
        denials = parsers.parse_apparmor_denials(self.APPARMOR)
        self.assertEqual(len(denials), 1)
        self.assertEqual(denials[0].profile, "/usr/sbin/nginx")
        self.assertEqual(denials[0].name, "/etc/shadow")
        self.assertEqual(denials[0].denied_mask, "r")

    def test_lsm_notes(self):
        notes = parsers.lsm_notes(["lockdown", "capability", "selinux"])
        self.assertTrue(any("SELinux" in note for note in notes))
        self.assertTrue(parsers.lsm_notes([])[0].startswith("no mandatory"))


if __name__ == "__main__":
    unittest.main()
