"""Shared fixtures for the test suite and for ``scripts/make_demo.py``.

These helpers build the data structures the real pipeline consumes, so tests can
exercise the attribution layers without needing a specific machine. The ``why``
renderer is the real one — only the collected facts are synthetic.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import List, Optional, Sequence, Tuple

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
for candidate in (str(SRC), str(ROOT / "tests")):
    if candidate not in sys.path:
        sys.path.insert(0, candidate)

from why.checks import collect_fixes, decide, run_layers  # noqa: E402
from why.checks.context import CheckContext  # noqa: E402
from why.collect import Environment  # noqa: E402
from why.model import LayerResult, Op, Report, Subject, Target  # noqa: E402
from why.parsers import Mount, decode_posix_acl  # noqa: E402


def make_subject(
    uid: int = 1000,
    gid: int = 1000,
    groups: Sequence[int] = (1000,),
    caps: Optional[frozenset] = None,
    label: str = "user alice",
    pid: Optional[int] = None,
    caps_eff: Optional[frozenset] = None,
) -> Subject:
    if caps_eff is not None:
        caps = caps_eff
    return Subject(
        uid=uid,
        gid=gid,
        groups=tuple(groups),
        caps_eff=caps if caps is not None else frozenset(),
        label=label,
        pid=pid,
        names={uid: "alice" if uid == 1000 else ("root" if uid == 0 else str(uid))},
    )


def make_target(
    path: str = "/etc/shadow",
    mode: int = 0o640,
    uid: int = 0,
    gid: int = 42,
    is_dir: bool = False,
    exists: bool = True,
    ancestors: Optional[List[Tuple[str, int, int, int]]] = None,
    is_symlink: bool = False,
    symlink_target: Optional[str] = None,
) -> Target:
    if ancestors is None:
        ancestors = [("/", 0o755, 0, 0)]
        parts = [p for p in path.split("/") if p]
        current = ""
        for part in parts[:-1]:
            current = f"{current}/{part}"
            ancestors.append((current, 0o755, 0, 0))
    target = Target(
        path=path,
        exists=exists,
        mode=mode if exists else None,
        uid=uid if exists else None,
        gid=gid if exists else None,
        size=1393 if exists else None,
        is_dir=is_dir,
        is_symlink=is_symlink,
        symlink_target=symlink_target,
        ancestors=list(ancestors),
        parent="/" + "/".join([p for p in path.split("/") if p][:-1]) if "/" in path else "/",
        stat_path=path,
    )
    return target


def make_mount(
    mount_point: str = "/",
    fstype: str = "ext4",
    source: str = "/dev/sda1",
    options: Sequence[str] = ("rw", "relatime"),
) -> Mount:
    return Mount(
        mount_id=1,
        parent_id=0,
        major_minor="8:1",
        root="/",
        mount_point=mount_point,
        options=frozenset(options),
        fstype=fstype,
        source=source,
        super_options=frozenset(options),
    )


def make_env(**kwargs) -> Environment:
    env = Environment(platform="linux", kernel="6.8.0-test", distro="Debian GNU/Linux 12")
    env.lsm = kwargs.pop("lsm", ["lockdown", "capability", "apparmor"])
    for key, value in kwargs.items():
        setattr(env, key, value)
    return env


def make_ctx(
    target: Optional[Target] = None,
    subject: Optional[Subject] = None,
    op: Op = Op.READ,
    mounts: Optional[Sequence[Mount]] = None,
    **kwargs,
) -> CheckContext:
    ctx = CheckContext(
        target=target or make_target(),
        subject=subject or make_subject(),
        op=op,
        env=make_env(),
        mounts=mounts if mounts is not None else [make_mount()],
        **kwargs,
    )
    return ctx


def acl_blob(entries: Sequence[Tuple[int, int, Optional[int]]]) -> bytes:
    """Build a ``system.posix_acl_access`` payload from ``(tag, perm, id)`` triples."""
    out = (2).to_bytes(4, "little")
    for tag, perm, ident in entries:
        out += tag.to_bytes(2, "little")
        out += perm.to_bytes(2, "little")
        out += (0xFFFFFFFF if ident is None else ident).to_bytes(4, "little")
    return out


def extended_acl(mask: int = 0o4, named_user_perm: int = 0o6, named_uid: int = 1000):
    """owner rw-, named user rw-, group r--, mask (default r--), other ---."""
    blob = acl_blob(
        [
            (0x01, 0o6, None),
            (0x02, named_user_perm, named_uid),
            (0x04, 0o4, None),
            (0x10, mask, None),
            (0x20, 0o0, None),
        ]
    )
    return decode_posix_acl(blob)


def denied_report(ctx: Optional[CheckContext] = None) -> Report:
    """Run the real layer pipeline over a fixture and assemble the report.

    Used by the demo-image script and by the renderer tests so that the example
    output is produced by production code, not by a hand-written string.
    """
    ctx = ctx or shadow_ctx()
    layers: List[LayerResult] = run_layers(ctx)
    verdict, deciding, reason = decide(layers, ctx)
    import why

    return Report(
        tool="why",
        version=why.__version__,
        target=ctx.target,
        subject=ctx.subject,
        op=ctx.op,
        layers=layers,
        verdict=verdict,
        deciding_layer=deciding,
        reason=reason,
        fixes=collect_fixes(layers, deciding),
        notes=[
            "SELinux is not active on this system",
            "no container detected",
            "example output generated from a fixture: tests/support.py",
        ],
        platform="linux",
    )


def shadow_ctx() -> CheckContext:
    """The canonical case: alice is not in the shadow group, reading /etc/shadow."""
    target = make_target("/etc/shadow", mode=0o640, uid=0, gid=42)
    subject = make_subject(uid=1000, gid=1000, groups=(1000, 27), label="user alice")
    ctx = make_ctx(target=target, subject=subject, op=Op.READ)
    ctx.acl = None
    ctx.acl_reason = "no ACL present"
    ctx.fs_flags = 0x00040000  # extents: the normal case on ext4
    target.uid_name = "root"
    target.gid_name = "shadow"
    ctx.env.lsm = ["lockdown", "capability", "apparmor"]
    ctx.env.selinux_enforcing = False
    return ctx


__all__ = [
    "ROOT",
    "SRC",
    "acl_blob",
    "denied_report",
    "extended_acl",
    "make_ctx",
    "make_env",
    "make_mount",
    "make_subject",
    "make_target",
    "shadow_ctx",
]
