"""Discretionary-access layers: existence, ownership, ACLs, traversal, mode, sticky."""

from __future__ import annotations

import os
from typing import List, Optional, Tuple

from ..collect import read_acl
from ..dac import (
    OP_NEEDS,
    PARENT_NEEDS,
    PARENT_OPS,
    DacDecision,
    dac_check,
    sticky_allows_delete,
)
from ..model import Confidence, LayerResult, Op, Status
from ..parsers import MODE_X, acl_perms_for, bits_of, perm_letters
from .context import CheckContext, describe_class, suggested_grant


def _stat_prefix(ctx: CheckContext) -> str:
    return ctx.target.fs_root


def _stat_path(ctx: CheckContext, path: str) -> str:
    prefix = _stat_prefix(ctx)
    return (prefix + path) if prefix else path


def first_missing_component(ctx: CheckContext) -> Optional[str]:
    """The deepest path component that does not exist, for a clean ENOENT story."""
    path = ctx.target.path
    parts = [p for p in path.split("/") if p]
    current = ""
    for part in parts:
        current = f"{current}/{part}"
        try:
            if not os.path.lexists(_stat_path(ctx, current)):
                return current
        except OSError:
            return current
    return None


def _acl_aware_dir_check(
    ctx: CheckContext, path: str, mode: int, uid: int, gid: int, need: int
) -> Tuple[DacDecision, Optional[str]]:
    """Decide access to a directory, consulting its ACL only if the mode denies.

    Ancestor directories can carry ACLs too (``setfacl -m u:alice:x /home``), and
    ignoring them would produce a confidently wrong answer.
    """
    decision = dac_check(
        mode,
        uid,
        gid,
        ctx.subject.uid,
        ctx.subject.groups,
        need,
        is_dir=True,
        caps=ctx.subject.caps_eff if ctx.subject.caps_eff or ctx.subject.uid != 0 else None,
    )
    if decision.allowed:
        return decision, None
    acl, _reason = read_acl(_stat_path(ctx, path))
    if acl is not None and acl.is_extended:
        retry = dac_check(
            mode,
            uid,
            gid,
            ctx.subject.uid,
            ctx.subject.groups,
            need,
            is_dir=True,
            acl=acl,
            caps=ctx.subject.caps_eff if ctx.subject.caps_eff or ctx.subject.uid != 0 else None,
        )
        if retry.allowed:
            return retry, "granted by a POSIX ACL on this directory"
    return decision, None


# --------------------------------------------------------------------------- #
# 1. exists
# --------------------------------------------------------------------------- #


def layer_exists(ctx: CheckContext, index: int) -> LayerResult:
    target = ctx.target
    if ctx.op is Op.CREATE:
        if target.exists:
            return LayerResult(
                id="exists",
                index=index,
                title="Does the entry exist?",
                status=Status.WARN,
                confidence=Confidence.DECISIVE,
                detail=(
                    f"{target.path} already exists, so creating it again would fail with EEXIST "
                    "(that is not a permission problem)"
                ),
                fix="pick another name, or use --op write to test writing the existing entry",
            )
        missing = first_missing_component(ctx)
        if missing:
            return LayerResult(
                id="exists",
                index=index,
                title="Does the entry exist?",
                status=Status.DENY,
                confidence=Confidence.DECISIVE,
                detail=f"the directory {missing} does not exist: this is ENOENT, not a permission denial",
                fix=f"mkdir -p {os.path.dirname(missing) or '/'}",
            )
        return LayerResult(
            id="exists",
            index=index,
            title="Does the entry exist?",
            status=Status.OK,
            confidence=Confidence.DECISIVE,
            detail=f"{target.path} does not exist yet and its parent directory does, so creation is possible",
        )

    if not target.exists:
        detail = f"{target.path} does not exist: this is ENOENT, not a permission denial"
        fix = "check the spelling, or verify the path inside the relevant mount namespace"
        if target.is_symlink and target.symlink_target:
            detail = f"{target.path} is a dangling symlink pointing at {target.symlink_target!r}, which does not exist"
            fix = f"fix or remove the symlink: ls -l {target.path}"
        else:
            missing = first_missing_component(ctx)
            if missing:
                detail += f" (missing component: {missing})"
        return LayerResult(
            id="exists",
            index=index,
            title="Does the entry exist?",
            status=Status.DENY,
            confidence=Confidence.DECISIVE,
            detail=detail,
            fix=fix,
        )

    kind = "directory" if target.is_dir else "file"
    detail = f"{target.path} exists ({kind}, {target.mode_str}"
    if target.mode is not None:
        detail += f" {oct(target.mode)[2:].zfill(4)}"
    detail += ")"
    if target.is_symlink:
        detail += f"; it is a symlink to {target.symlink_target!r} (access is checked on the target)"
    return LayerResult(
        id="exists",
        index=index,
        title="Does the entry exist?",
        status=Status.OK,
        confidence=Confidence.DECISIVE,
        detail=detail,
        data={"mode": target.mode, "uid": target.uid, "gid": target.gid, "is_dir": target.is_dir},
    )


# --------------------------------------------------------------------------- #
# 2. ownership / class selection
# --------------------------------------------------------------------------- #


def layer_ownership(ctx: CheckContext, index: int) -> LayerResult:
    target = ctx.target
    subject = ctx.subject
    if not target.exists or target.mode is None:
        return LayerResult(
            id="ownership",
            index=index,
            title="Which permission class applies to you?",
            status=Status.SKIP,
            detail="no object to compare against",
        )
    need = OP_NEEDS[ctx.op] if ctx.op not in PARENT_OPS else PARENT_NEEDS[ctx.op]
    from ..dac import classify

    klass, why = classify(subject.uid, subject.groups, target.uid, target.gid)
    effective_class = klass
    effective_bits = bits_of(target.mode, klass)
    note = (
        f"you are {subject.describe()}; the object is owned by "
        f"{target.uid}:{target.gid} -> {describe_class(effective_class)}"
    )
    detail = f"{note} ({why}); those bits are {perm_letters(effective_bits)}"

    group_bits = bits_of(target.mode, "group")
    other_bits = bits_of(target.mode, "other")
    if klass == "other" and (group_bits & need) and not (other_bits & need):
        return LayerResult(
            id="ownership",
            index=index,
            title="Which permission class applies to you?",
            status=Status.WARN,
            confidence=Confidence.ADVISORY,
            detail=(
                f"{detail}. The group bits ({perm_letters(group_bits)}) would have allowed this, but you are "
                f"not in gid {target.gid} ({target.gid} is not in {list(subject.groups)})"
            ),
            fix=(
                f"sudo usermod -aG {target.gid} {subject.name_of(subject.uid)}   # then log out and back in, "
                "or use a fresh login shell"
            ),
            data={"class": klass, "why": why, "group_bits": group_bits},
        )
    return LayerResult(
        id="ownership",
        index=index,
        title="Which permission class applies to you?",
        status=Status.OK,
        confidence=Confidence.DECISIVE,
        detail=detail,
        data={"class": effective_class, "why": why},
    )


# --------------------------------------------------------------------------- #
# 3. acl
# --------------------------------------------------------------------------- #


def layer_acl(ctx: CheckContext, index: int) -> LayerResult:
    target = ctx.target
    if not target.exists:
        return LayerResult(
            id="acl",
            index=index,
            title="POSIX ACL",
            status=Status.SKIP,
            detail="the object does not exist, so it has no ACL",
        )
    acl = ctx.acl
    if acl is None or not acl.is_extended:
        detail = "no extended ACL on this object"
        if ctx.acl_reason:
            detail += f" ({ctx.acl_reason})"
        return LayerResult(
            id="acl",
            index=index,
            title="POSIX ACL",
            status=Status.INFO,
            confidence=Confidence.DECISIVE,
            detail=detail,
            data={"extended": False},
        )

    need = OP_NEEDS[ctx.op] if ctx.op not in PARENT_OPS else PARENT_NEEDS[ctx.op]
    perms, why = acl_perms_for(acl, ctx.subject.uid, ctx.subject.groups, target.uid, target.gid)
    entries = ", ".join(acl.lines())
    data = {"extended": True, "entries": acl.lines()}

    if perms is None:
        return LayerResult(
            id="acl",
            index=index,
            title="POSIX ACL",
            status=Status.WARN,
            confidence=Confidence.ADVISORY,
            detail=f"an extended ACL is present ({entries}) but {why}",
            fix="re-run with root so symbolic ACL names can be resolved",
            data=data,
        )

    status = Status.OK if perms & need else Status.INFO
    mask = acl.mask_entry
    mode = target.mode
    fix = None
    detail = f"extended ACL: {entries}; for you: {why} -> {perm_letters(perms)}"
    if mask is not None and mode is not None:
        # A chmod on a file that carries an ACL rewrites the ACL mask, which is the
        # group triad of the mode bits — the trap this layer exists to expose.
        if bits_of(mode, "group") != mask.perm:
            status = Status.WARN
            fix = (
                f"sudo setfacl -m m::{perm_letters(mask.perm)} {target.path}   # "
                "restore the mask if the ACL entry looks right"
            )
            detail += (
                ". Trap: a chmod on a file with an ACL rewrites the ACL mask (mode group bits "
                f"{perm_letters(bits_of(mode, 'group'))} vs mask {perm_letters(mask.perm)})"
            )
    return LayerResult(
        id="acl",
        index=index,
        title="POSIX ACL",
        status=status,
        confidence=Confidence.DECISIVE,
        detail=detail,
        fix=fix,
        data=data,
    )


# --------------------------------------------------------------------------- #
# 4. traverse
# --------------------------------------------------------------------------- #


def layer_traverse(ctx: CheckContext, index: int) -> LayerResult:
    target = ctx.target
    if not target.ancestors:
        return LayerResult(
            id="traverse",
            index=index,
            title="Directory traversal (x on every parent)",
            status=Status.SKIP,
            detail="no ancestor directories were collected",
        )
    ancestors: List[Tuple[str, int, int, int]] = list(target.ancestors)
    if ctx.op in PARENT_OPS:
        # the parent's own w+x requirement is reported by the "mode" layer
        ancestors = ancestors[:-1]
    if not ancestors:
        return LayerResult(
            id="traverse",
            index=index,
            title="Directory traversal (x on every parent)",
            status=Status.OK,
            confidence=Confidence.DECISIVE,
            detail="the object sits directly in /, which always has x for everyone",
        )

    checked = []
    grant_notes = []
    for path, mode, uid, gid in ancestors:
        decision, granted_by_acl = _acl_aware_dir_check(ctx, path, mode, uid, gid, MODE_X)
        checked.append({"path": path, "mode": mode, "allowed": decision.allowed})
        if granted_by_acl:
            grant_notes.append(f"{path} ({granted_by_acl})")
        if not decision.allowed:
            return LayerResult(
                id="traverse",
                index=index,
                title="Directory traversal (x on every parent)",
                status=Status.DENY,
                confidence=Confidence.DECISIVE,
                detail=(
                    f"the kernel cannot traverse into {path}: it needs x (search) but you have "
                    f"{decision.effective_letters} ({decision.reason})"
                ),
                fix=f"sudo chmod o+x {path}   # or: sudo setfacl -m u:{ctx.subject.uid}:x {path}",
                data={"checked": checked, "blocked_at": path},
            )
    detail = f"x is available on all {len(ancestors)} ancestor directories (/ .. {ancestors[-1][0]})"
    if grant_notes:
        detail += "; " + "; ".join(grant_notes)
    return LayerResult(
        id="traverse",
        index=index,
        title="Directory traversal (x on every parent)",
        status=Status.OK,
        confidence=Confidence.DECISIVE,
        detail=detail,
        data={"checked": checked},
    )


# --------------------------------------------------------------------------- #
# 5. mode
# --------------------------------------------------------------------------- #


def layer_mode(ctx: CheckContext, index: int) -> LayerResult:
    target = ctx.target
    subject = ctx.subject
    caps = subject.caps_eff if (subject.caps_eff or subject.uid != 0) else None

    if ctx.op in PARENT_OPS:
        if not target.ancestors:
            return LayerResult(
                id="mode",
                index=index,
                title="Permission bits",
                status=Status.SKIP,
                detail="the parent directory could not be inspected",
            )
        parent_path, parent_mode, parent_uid, parent_gid = target.ancestors[-1]
        need = PARENT_NEEDS[ctx.op]
        decision = dac_check(
            parent_mode,
            parent_uid,
            parent_gid,
            subject.uid,
            subject.groups,
            need,
            is_dir=True,
            caps=caps,
        )
        if not decision.allowed:
            acl, _reason = read_acl(_stat_path(ctx, parent_path))
            if acl is not None and acl.is_extended:
                retry = dac_check(
                    parent_mode,
                    parent_uid,
                    parent_gid,
                    subject.uid,
                    subject.groups,
                    need,
                    is_dir=True,
                    acl=acl,
                    caps=caps,
                )
                if retry.allowed:
                    decision = retry
        detail = (
            f"{ctx.op.value} in a directory needs w+x on the directory itself: {parent_path} is "
            f"{oct(parent_mode)[2:].zfill(4)} ({decision.effective_letters} effective); {decision.reason}"
        )
        parent_fixes = (
            []
            if decision.allowed
            else [f"sudo chmod o+wx {parent_path}   # or: sudo setfacl -m u:{subject.uid}:rwx {parent_path}"]
        )
        status = Status.OK if decision.allowed else Status.DENY
        return LayerResult(
            id="mode",
            index=index,
            title="Permission bits",
            status=status,
            confidence=Confidence.DECISIVE,
            detail=detail,
            fix=parent_fixes[0] if parent_fixes else None,
            data={"class": decision.klass, "effective": decision.effective, "bypass": decision.bypass},
        )

    if not target.exists or target.mode is None:
        return LayerResult(
            id="mode",
            index=index,
            title="Permission bits",
            status=Status.SKIP,
            detail="no object to check permission bits on",
        )

    need = OP_NEEDS[ctx.op]
    decision = dac_check(
        target.mode,
        target.uid,
        target.gid,
        subject.uid,
        subject.groups,
        need,
        is_dir=target.is_dir,
        acl=ctx.acl,
        caps=caps,
    )
    mask_note = f" {decision.mask_note}" if decision.mask_note else ""
    detail = f"need {perm_letters(need)}; {decision.reason}{mask_note}"

    fixes: List[str] = []
    if not decision.allowed:
        fixes = suggested_grant(subject, need, target.path, is_dir=target.is_dir)
    return LayerResult(
        id="mode",
        index=index,
        title="Permission bits",
        status=Status.OK if decision.allowed else Status.DENY,
        confidence=Confidence.DECISIVE,
        detail=detail,
        fix=fixes[0] if fixes else None,
        data={
            "class": decision.klass,
            "effective": decision.effective,
            "source": decision.source,
            "bypass": decision.bypass,
            "alternatives": fixes[1:],
        },
    )


# --------------------------------------------------------------------------- #
# 6. sticky
# --------------------------------------------------------------------------- #


def layer_sticky(ctx: CheckContext, index: int) -> LayerResult:
    if ctx.op is not Op.DELETE:
        return LayerResult(
            id="sticky",
            index=index,
            title="Sticky-bit delete rule",
            status=Status.SKIP,
            detail="only checked for --op delete",
        )
    target = ctx.target
    if not target.ancestors:
        return LayerResult(
            id="sticky",
            index=index,
            title="Sticky-bit delete rule",
            status=Status.SKIP,
            detail="the parent directory could not be inspected",
        )
    parent_path, parent_mode, parent_uid, _parent_gid = target.ancestors[-1]
    allowed, why = sticky_allows_delete(
        parent_mode, parent_uid, target.uid if target.uid is not None else -1, ctx.subject.uid
    )
    fix = None
    if not allowed:
        fix = f"sudo rm {target.path}   # or make {ctx.subject.name_of(ctx.subject.uid)} the owner of {parent_path}"
    return LayerResult(
        id="sticky",
        index=index,
        title="Sticky-bit delete rule",
        status=Status.OK if allowed else Status.DENY,
        confidence=Confidence.DECISIVE,
        detail=f"{parent_path}: {why}",
        fix=fix,
        data={"parent": parent_path, "parent_mode": parent_mode},
    )


DAC_LAYERS = (
    layer_exists,
    layer_ownership,
    layer_acl,
    layer_traverse,
    layer_mode,
    layer_sticky,
)

__all__ = [
    "DAC_LAYERS",
    "first_missing_component",
    "layer_acl",
    "layer_exists",
    "layer_mode",
    "layer_ownership",
    "layer_sticky",
    "layer_traverse",
]
