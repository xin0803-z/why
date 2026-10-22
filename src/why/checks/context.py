"""Shared context handed to every attribution layer."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Sequence, Tuple

from ..collect import Environment
from ..model import Op, Subject, Target
from ..parsers import Acl, AppArmorDenial, AvcDenial, Mount


@dataclass
class CheckContext:
    target: Target
    subject: Subject
    op: Op
    env: Environment
    mounts: Sequence[Mount] = ()
    acl: Optional[Acl] = None
    acl_reason: Optional[str] = None
    default_acl: Optional[Acl] = None
    default_acl_reason: Optional[str] = None
    fs_flags: Optional[int] = None
    fs_flags_reason: Optional[str] = None
    avc: Sequence[AvcDenial] = ()
    apparmor: Sequence[AppArmorDenial] = ()
    uid_map: Sequence[Tuple[int, int, int]] = ()
    evidence_notes: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    @property
    def flag_names(self) -> frozenset:
        from ..parsers import decode_fs_flags

        if self.fs_flags is None:
            return frozenset()
        return decode_fs_flags(self.fs_flags)

    def mount_for(self, path: str) -> Optional[Mount]:
        from ..parsers import find_mount

        return find_mount(self.mounts, path)

    @property
    def cap_label(self) -> str:
        caps = self.subject.caps_eff
        if not caps:
            return "no effective capabilities reported"
        return ", ".join(sorted(caps))


def perm_for_need(need: int) -> str:
    from ..parsers import MODE_R, MODE_W, MODE_X

    letters = ""
    letters += "r" if need & MODE_R else ""
    letters += "w" if need & MODE_W else ""
    letters += "x" if need & MODE_X else ""
    return letters or "---"


def suggested_grant(subject: Subject, need: int, path: str, is_dir: bool = False) -> List[str]:
    """Least-privilege first: an ACL entry for this uid, then the blunt chmod."""
    perms = perm_for_need(need).ljust(3, "-")
    if is_dir and "x" not in perms:
        perms = perms[:2] + "x"
    prefix = "sudo " if subject.uid != 0 and getattr(subject, "pid", None) is None else ""
    fixes = [f"{prefix}setfacl -m u:{subject.uid}:{perms} {path}   # grants only uid {subject.uid}"]
    if not is_dir:
        other_bit = "r" if "r" in perms else ("w" if "w" in perms else "x")
        fixes.append(f"{prefix}chmod o+{other_bit} {path}   # blunter: grants this to everyone")
    return fixes


def describe_class(klass: str) -> str:
    return {
        "user": "owner class (user bits)",
        "group": "group class (group bits)",
        "other": "other class",
        "acl": "POSIX ACL",
    }.get(klass, klass)
