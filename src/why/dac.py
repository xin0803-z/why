"""The DAC decision engine: UNIX mode bits + POSIX ACL + the root/capability rules.

Pure functions only — no syscalls — so the trickiest logic in ``why`` is fully
unit-testable, and so the same code can explain an access attempt for the current
process, for ``--user``, or for ``--pid``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional, Set, Tuple

from .model import Op
from .parsers import (
    CLASS_GROUP,
    CLASS_OTHER,
    CLASS_USER,
    MODE_R,
    MODE_W,
    MODE_X,
    Acl,
    acl_perms_for,
    bits_of,
    perm_letters,
)

CAP_DAC_OVERRIDE = "CAP_DAC_OVERRIDE"
CAP_DAC_READ_SEARCH = "CAP_DAC_READ_SEARCH"
CAP_FOWNER = "CAP_FOWNER"
CAP_LINUX_IMMUTABLE = "CAP_LINUX_IMMUTABLE"

READ, WRITE, EXEC, SEARCH = MODE_R, MODE_W, MODE_X, MODE_X

#: Which permission bit an operation needs on the object itself.
OP_NEEDS = {
    Op.READ: READ,
    Op.WRITE: WRITE,
    Op.EXEC: EXEC,
    Op.CREATE: WRITE,  # on the parent directory
    Op.DELETE: WRITE,  # on the parent directory
}

#: Which permission bits an operation needs on the *parent* directory.
PARENT_NEEDS = {
    Op.CREATE: WRITE | EXEC,
    Op.DELETE: WRITE | EXEC,
}

#: Operations where the subject is really acting on the parent directory.
PARENT_OPS = frozenset({Op.CREATE, Op.DELETE})


@dataclass
class DacDecision:
    """Result of one DAC check, with enough detail to explain it to a human."""

    allowed: bool
    klass: str
    effective: int
    source: str
    reason: str
    bypass: Optional[str] = None
    mask_note: Optional[str] = None
    unresolved: bool = False  # ACL had symbolic names we could not resolve

    @property
    def effective_letters(self) -> str:
        return perm_letters(self.effective)


def classify(uid: int, groups: Iterable[int], file_uid: Optional[int], file_gid: Optional[int]) -> Tuple[str, str]:
    """Which permission class applies: ``(class, explanation)``."""
    groups = set(groups)
    if file_uid is not None and uid == file_uid:
        return CLASS_USER, f"you are the owner (uid {uid})"
    if file_gid is not None and file_gid in groups:
        return CLASS_GROUP, f"you are in the owning group (gid {file_gid})"
    matched = sorted(groups)
    if file_gid is not None and matched:
        return CLASS_OTHER, f"uid {uid} is not the owner and none of groups {matched} is gid {file_gid}"
    return CLASS_OTHER, f"uid {uid} is neither owner nor owning-group member"


def any_exec_bit(mode: int, acl_perm: Optional[int] = None) -> bool:
    if mode & 0o111:
        return True
    return bool(acl_perm is not None and acl_perm & MODE_X)


def dac_check(
    mode: int,
    file_uid: Optional[int],
    file_gid: Optional[int],
    uid: int,
    groups: Iterable[int],
    need: int,
    *,
    is_dir: bool = False,
    acl: Optional[Acl] = None,
    caps: Optional[frozenset] = None,
) -> DacDecision:
    """Decide a single DAC question and explain the reasoning.

    ``caps=None`` means "unknown"; for uid 0 that is treated as the usual
    default root privileges (and the reason says so). Pass an explicit
    (possibly empty) set when you know better, e.g. from ``/proc/<pid>/status``.
    """
    groups = tuple(groups)
    acl_perm, acl_reason = acl_perms_for(acl, uid, groups, file_uid, file_gid)
    unresolved = bool(acl is not None and acl.unresolved_names)

    if acl_perm is not None:
        klass = "acl"
        effective = acl_perm
        source = "acl"
        reason = acl_reason
    else:
        klass, why_class = classify(uid, groups, file_uid, file_gid)
        effective = bits_of(mode, klass)
        source = f"mode:{klass}"
        reason = f"{why_class}; {klass} bits are {perm_letters(effective)}"

    mask_note = None
    if acl is not None and acl.is_extended:
        mask_entry = acl.mask_entry
        is_owner = file_uid is not None and uid == file_uid
        if mask_entry is not None and not is_owner:
            mode_group_bits = bits_of(mode, CLASS_GROUP)
            if mode_group_bits != mask_entry.perm:
                mask_note = (
                    f"note: this file has an ACL, so the group mode bits ({perm_letters(mode_group_bits)}) "
                    f"are really the ACL mask, currently {perm_letters(mask_entry.perm)}"
                )

    # Every requested bit is required, not just one of them (w+x on a directory).
    allowed = (effective & need) == need
    bypass = None
    caps_known = caps is not None
    if not caps_known and uid == 0:
        caps = frozenset({CAP_DAC_OVERRIDE, CAP_DAC_READ_SEARCH, CAP_FOWNER, CAP_LINUX_IMMUTABLE})
        caps_known_note = "assumed default root privileges"
    else:
        caps_known_note = "effective capabilities"

    if caps:
        if CAP_DAC_OVERRIDE in caps:
            if need in (READ, WRITE):
                allowed, bypass = True, f"{CAP_DAC_OVERRIDE} ({caps_known_note})"
            elif need == EXEC:
                if any_exec_bit(mode, acl_perm):
                    allowed, bypass = True, f"{CAP_DAC_OVERRIDE} ({caps_known_note}; needs one x bit, which is set)"
                else:
                    bypass = f"{CAP_DAC_OVERRIDE} does not grant execute when no x bit is set ({caps_known_note})"
        elif CAP_DAC_READ_SEARCH in caps:
            if need == READ or (need == SEARCH and is_dir):
                allowed, bypass = True, f"{CAP_DAC_READ_SEARCH} ({caps_known_note})"

    if bypass is None and unresolved:
        reason += "; " + acl_reason

    detail = f"effective {perm_letters(effective)} via {source} ({reason})"
    if bypass:
        detail = f"{bypass} bypasses DAC (the mode bits alone would have given {perm_letters(effective)})"

    return DacDecision(
        allowed=allowed,
        klass=klass,
        effective=effective,
        source=source,
        reason=detail,
        bypass=bypass,
        mask_note=mask_note,
        unresolved=unresolved,
    )


def sticky_allows_delete(sticky_dir_mode: int, dir_uid: int, file_uid: int, uid: int) -> Tuple[bool, str]:
    """Apply the sticky-bit rule for deletions inside a directory."""
    if not sticky_dir_mode & 0o1000:
        return True, "parent is not a sticky directory"
    if uid == 0:
        return True, "sticky directory, but you are root"
    if uid == dir_uid:
        return True, f"sticky directory and you own it (uid {dir_uid})"
    if uid == file_uid:
        return True, "sticky directory and you own the file being removed"
    return False, (
        f"sticky directory owned by uid {dir_uid}; only its owner, the file owner (uid {file_uid}) "
        "or root may delete entries"
    )


def immutable_blocks(op: Op, flags: Set[str], has_cap_linux_immutable: bool) -> Tuple[bool, str]:
    """Immutable/append-only attributes deny even root (unless CAP_LINUX_IMMUTABLE)."""
    if "immutable" in flags:
        if has_cap_linux_immutable:
            return False, "immutable flag is set, but CAP_LINUX_IMMUTABLE is held"
        return True, "the immutable attribute (chattr +i) is set: not even root can write or delete this"
    if "append_only" in flags and op in (Op.WRITE, Op.DELETE):
        return True, "the append-only attribute (chattr +a) only permits appending, not overwriting or deleting"
    return False, "no blocking file attribute"


__all__ = [
    "CAP_DAC_OVERRIDE",
    "CAP_DAC_READ_SEARCH",
    "CAP_FOWNER",
    "CAP_LINUX_IMMUTABLE",
    "DacDecision",
    "OP_NEEDS",
    "PARENT_NEEDS",
    "PARENT_OPS",
    "any_exec_bit",
    "classify",
    "dac_check",
    "immutable_blocks",
    "sticky_allows_delete",
]
