"""Attribution layers, in the order the kernel applies them.

Layers are grouped by subsystem:

``dac_layers``     exists, ownership, acl, traverse, mode, sticky
``system_layers``  mount, attrs, capabilities, sandbox, selinux, apparmor

A layer never raises: it returns a :class:`~why.model.LayerResult` describing what
it found, why, and how to fix it. ``run_all`` orchestrates them and computes the
final verdict.
"""

from __future__ import annotations

from typing import Callable, List, Optional, Sequence, Tuple

from ..collect import (
    Environment,
    collect_environment,
    is_linux,
    read_acl,
    read_apparmor_denials,
    read_avc_denials,
    read_default_acl,
    read_fs_flags,
    read_mountinfo,
    read_uid_map,
)
from ..model import (
    Confidence,
    LayerResult,
    Op,
    Report,
    Status,
    Subject,
    Target,
    Verdict,
)
from ..parsers import lsm_notes
from .context import CheckContext
from .dac_layers import (
    layer_acl,
    layer_exists,
    layer_mode,
    layer_ownership,
    layer_sticky,
    layer_traverse,
)
from .system_layers import (
    layer_apparmor,
    layer_attrs,
    layer_capabilities,
    layer_mount,
    layer_sandbox,
    layer_selinux,
)

LayerFn = Callable[[CheckContext, int], LayerResult]

#: The canonical order. Index is 1-based and shows up in the report.
PIPELINE: Tuple[LayerFn, ...] = (
    layer_exists,
    layer_sandbox,
    layer_capabilities,
    layer_mount,
    layer_attrs,
    layer_traverse,
    layer_ownership,
    layer_acl,
    layer_mode,
    layer_sticky,
    layer_selinux,
    layer_apparmor,
)

LAYER_META: Tuple[Tuple[str, str], ...] = (
    ("exists", "Does the entry exist?"),
    ("sandbox", "Namespace and sandbox context"),
    ("capabilities", "Capabilities"),
    ("mount", "Mount options"),
    ("attrs", "File attributes (chattr)"),
    ("traverse", "Directory traversal (x on every parent)"),
    ("ownership", "Which permission class applies to you?"),
    ("acl", "POSIX ACL"),
    ("mode", "Permission bits"),
    ("sticky", "Sticky-bit delete rule"),
    ("selinux", "SELinux policy"),
    ("apparmor", "AppArmor policy"),
)


def build_context(
    target: Target,
    subject: Subject,
    op: Op,
    env: Optional[Environment] = None,
    gather_evidence: bool = True,
) -> CheckContext:
    env = env or collect_environment()
    mounts, mount_note = read_mountinfo(subject.pid)

    acl = None
    acl_reason: Optional[str] = "object does not exist"
    if target.exists:
        acl, acl_reason = read_acl(target.stat_path)

    default_acl = None
    default_acl_reason: Optional[str] = None
    if op is Op.CREATE and target.ancestors:
        default_acl, default_acl_reason = read_default_acl(target.ancestors[-1][0])

    object_path = target.path
    if op in (Op.CREATE, Op.DELETE) and target.ancestors:
        object_path = target.ancestors[-1][0]
    stat_object = (target.fs_root + object_path) if target.fs_root else object_path
    fs_flags: Optional[int] = None
    fs_flags_reason: Optional[str] = "object does not exist"
    if target.exists or op in (Op.CREATE, Op.DELETE):
        fs_flags, fs_flags_reason = read_fs_flags(stat_object)

    avc: Sequence = ()
    apparmor: Sequence = ()
    evidence_notes: List[str] = []
    if gather_evidence:
        avc, avc_notes = read_avc_denials()
        apparmor, aa_notes = read_apparmor_denials()
        evidence_notes.extend(avc_notes)
        evidence_notes.extend(aa_notes)
    if mount_note:
        evidence_notes.append(mount_note)

    uid_map, uid_map_reason = read_uid_map(subject.pid)
    if uid_map_reason and uid_map:
        evidence_notes.append(uid_map_reason)

    return CheckContext(
        target=target,
        subject=subject,
        op=op,
        env=env,
        mounts=mounts,
        acl=acl,
        acl_reason=acl_reason,
        default_acl=default_acl,
        default_acl_reason=default_acl_reason,
        fs_flags=fs_flags,
        fs_flags_reason=fs_flags_reason,
        avc=avc,
        apparmor=apparmor,
        uid_map=uid_map,
        evidence_notes=evidence_notes,
    )


def run_layers(ctx: CheckContext) -> List[LayerResult]:
    results: List[LayerResult] = []
    for position, layer in enumerate(PIPELINE, start=1):
        try:
            results.append(layer(ctx, position))
        except Exception as exc:  # pragma: no cover - a layer must never break the run
            results.append(
                LayerResult(
                    id=LAYER_META[position - 1][0],
                    index=position,
                    title=LAYER_META[position - 1][1],
                    status=Status.UNKNOWN,
                    detail=f"this layer failed unexpectedly: {exc.__class__.__name__}: {exc}",
                )
            )
    return results


def decide(layers: Sequence[LayerResult], ctx: CheckContext) -> Tuple[Verdict, Optional[str], str]:
    decisive = next(
        (item for item in layers if item.status is Status.DENY and item.confidence is Confidence.DECISIVE),
        None,
    )
    evidence = next(
        (item for item in layers if item.status is Status.DENY and item.confidence is Confidence.EVIDENCE),
        None,
    )
    if decisive is not None:
        return Verdict.DENIED, decisive.id, decisive.detail
    if evidence is not None:
        return (
            Verdict.DENIED_BY_EVIDENCE,
            evidence.id,
            f"DAC checks pass, but a kernel denial record matches: {evidence.detail}",
        )
    allowed_reason = "no layer in this model denies the operation"
    if not is_linux():
        return (
            Verdict.UNKNOWN,
            None,
            "not running on Linux: only the platform-independent layers are meaningful here",
        )
    mac_layers = [item for item in layers if item.id in ("selinux", "apparmor") and item.status is Status.WARN]
    if mac_layers:
        allowed_reason += (
            f"; however {mac_layers[0].title} is active and could still deny this"
            " (no matching denial record was found in the available logs)"
        )
    unknowns = [item for item in layers if item.status is Status.UNKNOWN]
    if unknowns:
        allowed_reason += "; layers marked unknown could not be evaluated: " + ", ".join(
            item.title for item in unknowns
        )
    return Verdict.ALLOWED, None, allowed_reason


def collect_fixes(layers: Sequence[LayerResult], deciding: Optional[str]) -> List[str]:
    ordered: List[str] = []
    # The fix for the layer that actually decided the outcome comes first.
    by_id = {item.id: item for item in layers}
    primary = by_id.get(deciding) if deciding else None
    candidates: List[LayerResult] = []
    if primary is not None:
        candidates.append(primary)
    for item in layers:
        if item is primary:
            continue
        if item.status in (Status.DENY, Status.WARN):
            candidates.append(item)
    for item in candidates:
        if not item.fix:
            continue
        for line in str(item.fix).splitlines():
            line = line.strip()
            if line and line not in ordered:
                ordered.append(line)
    return ordered


def run_all(
    target: Target,
    subject: Subject,
    op: Op,
    env: Optional[Environment] = None,
    gather_evidence: bool = True,
) -> Report:
    ctx = build_context(target, subject, op, env=env, gather_evidence=gather_evidence)
    layers = run_layers(ctx)
    verdict, deciding, reason = decide(layers, ctx)
    fixes = collect_fixes(layers, deciding)

    notes: List[str] = []
    notes.extend(lsm_notes(ctx.env.lsm))
    notes.extend(ctx.evidence_notes)
    if not target.exists and op is not Op.CREATE:
        notes.append("note: ENOENT and EACCES are different failures; this one is ENOENT")

    import sys

    return Report(
        tool="why",
        version=_version(),
        target=target,
        subject=subject,
        op=op,
        layers=layers,
        verdict=verdict,
        deciding_layer=deciding,
        reason=reason,
        fixes=fixes,
        evidence=[item.raw for item in list(ctx.avc)[-3:]] + [item.raw for item in list(ctx.apparmor)[-3:]],
        notes=notes,
        platform=sys.platform,
        degraded=list(ctx.env.degraded),
    )


def _version() -> str:
    from .. import __version__

    return __version__


__all__ = [
    "LAYER_META",
    "PIPELINE",
    "build_context",
    "collect_fixes",
    "decide",
    "run_all",
    "run_layers",
]
