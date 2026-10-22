"""System layers: mount flags, file attributes, capabilities, sandbox, SELinux, AppArmor."""

from __future__ import annotations

import os
from typing import List, Optional

from ..dac import CAP_LINUX_IMMUTABLE, immutable_blocks
from ..model import Confidence, LayerResult, Op, Status
from ..parsers import describe_userns
from .context import CheckContext


def _matches(name: Optional[str], path: str) -> bool:
    if not name:
        return False
    return name == path or name == path.rstrip("/").split("/")[-1]


def _subject_object(ctx: CheckContext) -> str:
    """CREATE/DELETE act on the parent directory; everything else on the object."""
    if ctx.op in (Op.CREATE, Op.DELETE) and ctx.target.ancestors:
        return ctx.target.ancestors[-1][0]
    return ctx.target.path


# --------------------------------------------------------------------------- #
# 7. mount flags
# --------------------------------------------------------------------------- #

_NETWORK_FS = {"nfs", "nfs4", "cifs", "smb3", "sshfs", "9p", "ceph", "glusterfs", "afs", "fuse.sshfs"}
_FUSE_FS = ("fuse",)

#: Attributes that are worth a warning even when they do not block this access.
NOTABLE_FLAGS = frozenset(
    {
        "immutable",
        "append_only",
        "encrypted",
        "no_cow",
        "topdir",
        "projinherit",
        "casefold",
        "verity",
        "compress",
        "no_compress",
        "no_tail_merge",
        "dax",
    }
)


def layer_mount(ctx: CheckContext, index: int) -> LayerResult:
    object_path = _subject_object(ctx)
    mount = ctx.mount_for(object_path)
    if mount is None:
        return LayerResult(
            id="mount",
            index=index,
            title="Mount options",
            status=Status.UNKNOWN,
            detail=f"could not find the mount backing {object_path} (mountinfo unavailable?)",
        )
    wrote = ctx.op in (Op.WRITE, Op.CREATE, Op.DELETE)
    data = {
        "mount_point": mount.mount_point,
        "fstype": mount.fstype,
        "source": mount.source,
        "options": sorted(mount.options),
    }

    if wrote and mount.has("ro"):
        return LayerResult(
            id="mount",
            index=index,
            title="Mount options",
            status=Status.DENY,
            confidence=Confidence.DECISIVE,
            detail=(
                f"the filesystem at {mount.mount_point} ({mount.source}, {mount.fstype}) is mounted read-only, "
                "so writes fail with EROFS — this is not a permission problem"
            ),
            fix=f"sudo mount -o remount,rw {mount.mount_point}   # or write somewhere else",
            data=data,
        )
    if ctx.op is Op.EXEC and mount.has("noexec"):
        return LayerResult(
            id="mount",
            index=index,
            title="Mount options",
            status=Status.DENY,
            confidence=Confidence.DECISIVE,
            detail=(
                f"{mount.mount_point} is mounted noexec, so executing {ctx.target.path} returns EACCES "
                "even when the x bit is set"
            ),
            fix=(
                f"run it through an interpreter instead (e.g. bash {ctx.target.path} / python3 {ctx.target.path}), "
                f"or remount: sudo mount -o remount,exec {mount.mount_point}"
            ),
            data=data,
        )

    notes: List[str] = []
    if wrote and mount.has("rw"):
        notes.append(f"{mount.mount_point} is mounted rw")
    if ctx.op is Op.EXEC and "noexec" not in mount.options:
        notes.append("noexec is not set")
    if mount.has("nosuid") and ctx.target.mode is not None and (ctx.target.mode & 0o6000):
        notes.append(
            "nosuid is set, so setuid/setgid bits on this mount are ignored (relevant to privilege, not to access)"
        )
    if mount.fstype in _NETWORK_FS:
        notes.append(
            f"{mount.fstype} is a network filesystem: the server can deny you independently "
            "(root_squash maps root to nobody; all_squash maps everyone)"
        )
    if any(mount.fstype.startswith(prefix) for prefix in _FUSE_FS):
        notes.append(
            f"{mount.fstype} is a FUSE filesystem: it may enforce its own permission model "
            "(allow_other, default_permissions)"
        )
    status = Status.WARN if mount.has("nosuid") and (ctx.target.mode or 0) & 0o6000 else Status.OK
    return LayerResult(
        id="mount",
        index=index,
        title="Mount options",
        status=status,
        confidence=Confidence.DECISIVE,
        detail=f"{object_path} is on {mount.mount_point} ({mount.source}, {mount.fstype}, "
        f"rw={'rw' if mount.has('rw') else 'ro'})" + ("; " + "; ".join(notes) if notes else ""),
        data=data,
    )


# --------------------------------------------------------------------------- #
# 8. file attributes (chattr)
# --------------------------------------------------------------------------- #


def layer_attrs(ctx: CheckContext, index: int) -> LayerResult:
    object_path = _subject_object(ctx)
    if ctx.fs_flags is None:
        return LayerResult(
            id="attrs",
            index=index,
            title="File attributes (chattr)",
            status=Status.UNKNOWN,
            detail=f"file attributes could not be read ({ctx.fs_flags_reason or 'unknown reason'})",
        )
    flags = set(ctx.flag_names)
    has_cap = CAP_LINUX_IMMUTABLE in ctx.subject.caps_eff
    blocked, why = immutable_blocks(ctx.op, flags, has_cap)
    printable = ", ".join(sorted(flags)) if flags else "none"
    fix = None
    if blocked:
        if "immutable" in flags:
            fix = f"sudo chattr -i {object_path}   # needs CAP_LINUX_IMMUTABLE, i.e. usually root"
        else:
            fix = f"sudo chattr -a {object_path}   # append-only: remove the flag first, then write, then set it back"
    extra = []
    if "encrypted" in flags:
        extra.append("fscrypt-encrypted: the key must be in your keyring")
    if "no_cow" in flags:
        extra.append("btrfs no_cow")
    if "append_only" in flags and ctx.op is Op.WRITE:
        extra.append("appending with >> still works; overwriting does not")
    if blocked:
        status = Status.DENY
    elif flags & NOTABLE_FLAGS:
        status = Status.WARN
    else:
        status = Status.INFO
    detail = f"attributes on {object_path}: {printable}"
    if blocked:
        detail = f"{why} [{printable}]"
    if extra:
        detail += "; " + "; ".join(extra)
    return LayerResult(
        id="attrs",
        index=index,
        title="File attributes (chattr)",
        status=status,
        confidence=Confidence.DECISIVE if blocked else Confidence.ADVISORY,
        detail=detail,
        fix=fix,
        data={"flags": sorted(flags), "raw": ctx.fs_flags},
    )


# --------------------------------------------------------------------------- #
# 9. capabilities
# --------------------------------------------------------------------------- #


def layer_capabilities(ctx: CheckContext, index: int) -> LayerResult:
    subject = ctx.subject
    caps = set(subject.caps_eff)
    data = {"caps_eff": sorted(caps), "uid": subject.uid}
    if not caps:
        if subject.uid == 0:
            return LayerResult(
                id="capabilities",
                index=index,
                title="Capabilities",
                status=Status.WARN,
                confidence=Confidence.ADVISORY,
                detail=(
                    "you are uid 0 but no effective capabilities are reported (typical of "
                    "--cap-drop=ALL, rootless containers or systemd CapabilityBoundingSet=): "
                    "the normal root bypass does NOT apply, so the DAC bits decide"
                ),
                fix="check CapEff with: grep Cap /proc/self/status",
                data=data,
            )
        return LayerResult(
            id="capabilities",
            index=index,
            title="Capabilities",
            status=Status.OK,
            confidence=Confidence.DECISIVE,
            detail="no capabilities that bypass DAC are held, so the permission bits decide",
            data=data,
        )
    overrides = sorted(caps & {"CAP_DAC_OVERRIDE", "CAP_DAC_READ_SEARCH", "CAP_FOWNER"})
    if overrides:
        detail = f"effective capabilities include {', '.join(overrides)}, which bypass parts of the DAC check"
        if "CAP_DAC_OVERRIDE" in caps:
            detail += " (read/write/extend; execute still needs one x bit set)"
        elif "CAP_DAC_READ_SEARCH" in caps:
            detail += " (read and directory search; not write, not execute of files)"
        return LayerResult(
            id="capabilities",
            index=index,
            title="Capabilities",
            status=Status.OK,
            confidence=Confidence.DECISIVE,
            detail=detail,
            data=data,
        )
    return LayerResult(
        id="capabilities",
        index=index,
        title="Capabilities",
        status=Status.INFO,
        confidence=Confidence.DECISIVE,
        detail=f"effective capabilities ({', '.join(sorted(caps))}) do not bypass path permission checks",
        data=data,
    )


# --------------------------------------------------------------------------- #
# 10. sandbox
# --------------------------------------------------------------------------- #


def layer_sandbox(ctx: CheckContext, index: int) -> LayerResult:
    env = ctx.env
    subject = ctx.subject
    bits: List[str] = []
    warnings: List[str] = []
    fixes: List[str] = []

    if env.container:
        bits.append(f"container: {env.container}")
    else:
        bits.append("no container detected")

    if ctx.uid_map:
        description = describe_userns(ctx.uid_map, 0)
        bits.append(f"user namespace: {description}")
        mapped = None
        from ..parsers import map_id

        if subject.uid == 0:
            mapped = map_id(ctx.uid_map, 0)
        if subject.uid == 0 and mapped is not None and mapped != 0:
            warnings.append(
                f"root inside this namespace is uid {mapped} on the host, so files owned by real root "
                "(host uid 0) are not yours to read"
            )
            fixes.append("bind-mount or chown the data to the mapped id, or run with --userns=host")

    if subject.seccomp_mode:
        if subject.seccomp_mode == 1:
            bits.append("seccomp: strict")
            warnings.append("seccomp is in strict mode: most syscalls fail (often EPERM, not EACCES)")
        elif subject.seccomp_mode == 2:
            bits.append("seccomp: filter")
    if subject.no_new_privs:
        bits.append("no_new_privs is set (setuid bits cannot raise privileges)")
    if env.landlock_abi:
        bits.append(f"Landlock ABI {env.landlock_abi}")
        warnings.append(
            "Landlock is available: a process can sandbox itself below its normal permissions, and "
            "why cannot inspect another process's ruleset"
        )
    if subject.apparmor_profile:
        bits.append(f"AppArmor profile: {subject.apparmor_profile}")
    if env.root_fs_read_only:
        bits.append("/ is mounted read-only")
    if env.selinux_enforcing:
        bits.append("SELinux is enforcing")

    status = Status.WARN if warnings else Status.INFO
    return LayerResult(
        id="sandbox",
        index=index,
        title="Namespace and sandbox context",
        status=status,
        confidence=Confidence.ADVISORY,
        detail="; ".join(bits + warnings) if (bits or warnings) else "no sandbox signals detected",
        fix=fixes[0] if fixes else None,
        data={"container": env.container, "landlock_abi": env.landlock_abi},
    )


# --------------------------------------------------------------------------- #
# 11. SELinux
# --------------------------------------------------------------------------- #


def layer_selinux(ctx: CheckContext, index: int) -> LayerResult:
    env = ctx.env
    if env.selinux_enforcing is None and not ctx.avc:
        return LayerResult(
            id="selinux",
            index=index,
            title="SELinux policy",
            status=Status.SKIP,
            detail="SELinux does not appear to be active on this system",
        )
    file_context = None
    prefix = ctx.target.fs_root
    try:
        raw = os.getxattr((prefix + ctx.target.path) if prefix else ctx.target.path, "security.selinux")
        file_context = raw.decode("utf-8", errors="replace").strip("\x00").strip()
    except (OSError, AttributeError):
        file_context = None

    from ..parsers import match_avc_for_path

    hits = match_avc_for_path(ctx.avc, ctx.target.path)
    if hits:
        denial = hits[-1]
        fix = (
            f"sudo restorecon -v {ctx.target.path}   # fix a wrong file context; then re-check the label maps"
            f" to the right type"
        )
        if denial.tcontext:
            fix += f"\n  expected target type: {denial.tcontext}"
        return LayerResult(
            id="selinux",
            index=index,
            title="SELinux policy",
            status=Status.DENY,
            confidence=Confidence.EVIDENCE,
            detail=(
                f"an AVC denial matches this path: {' '.join(denial.perms)} on class {denial.target_class}"
                f"{' by ' + denial.comm if denial.comm else ''}"
                f"{' (permissive mode: logged but not enforced)' if denial.permissive else ''}"
                "; contexts: " + f"{denial.scontext} -> {denial.tcontext}"
            ),
            fix=fix,
            data=denial.as_dict(),
        )
    if env.selinux_enforcing:
        return LayerResult(
            id="selinux",
            index=index,
            title="SELinux policy",
            status=Status.WARN,
            confidence=Confidence.ADVISORY,
            detail=(
                "SELinux is enforcing but no matching AVC record was found in the available logs"
                + (f" (file context: {file_context})" if file_context else "")
                + ". If every DAC check above passes and you are still denied, this is the likely culprit"
            ),
            fix="grep -i 'avc:.*denied' /var/log/audit/audit.log | tail   # then: sudo ausearch -m AVC -ts recent",
            data={"file_context": file_context},
        )
    detail = "SELinux is permissive: denials are logged but not enforced"
    if file_context:
        detail += f" (file context: {file_context})"
    return LayerResult(
        id="selinux",
        index=index,
        title="SELinux policy",
        status=Status.INFO,
        confidence=Confidence.DECISIVE,
        detail=detail,
        data={"file_context": file_context},
    )


# --------------------------------------------------------------------------- #
# 12. AppArmor
# --------------------------------------------------------------------------- #


def layer_apparmor(ctx: CheckContext, index: int) -> LayerResult:
    env = ctx.env
    profile = ctx.subject.apparmor_profile
    hits = [item for item in ctx.apparmor if _matches(item.name, ctx.target.path)]
    if hits:
        denial = hits[-1]
        return LayerResult(
            id="apparmor",
            index=index,
            title="AppArmor policy",
            status=Status.DENY,
            confidence=Confidence.EVIDENCE,
            detail=(
                f"an AppArmor denial matches this path: {denial.operation or 'access'} "
                f"{denial.requested_mask or ''} by {denial.comm or 'a process'} under profile "
                f"{denial.profile or profile or '?'}"
            ),
            fix=(
                f"sudo aa-status   # list profiles\n"
                f"  temporarily: sudo aa-complain {denial.profile}   # then re-test\n"
                f"  permanently: add a rule to /etc/apparmor.d/{denial.profile} and reload"
            ),
            data=denial.as_dict(),
        )
    if env.apparmor_profiles is not None or profile:
        return LayerResult(
            id="apparmor",
            index=index,
            title="AppArmor policy",
            status=Status.INFO,
            confidence=Confidence.ADVISORY,
            detail=(
                "AppArmor is loaded"
                + (f" ({env.apparmor_profiles} profiles)" if env.apparmor_profiles is not None else "")
                + (f"; subject profile: {profile}" if profile else "; the subject is unconfined")
                + "; no denial record matched this path"
            ),
            data={"profiles": env.apparmor_profiles, "profile": profile},
        )
    return LayerResult(
        id="apparmor",
        index=index,
        title="AppArmor policy",
        status=Status.SKIP,
        detail="AppArmor does not appear to be active on this system",
    )


SYSTEM_LAYERS = (
    layer_mount,
    layer_attrs,
    layer_capabilities,
    layer_sandbox,
    layer_selinux,
    layer_apparmor,
)

__all__ = [
    "SYSTEM_LAYERS",
    "layer_apparmor",
    "layer_attrs",
    "layer_capabilities",
    "layer_mount",
    "layer_sandbox",
    "layer_selinux",
]
