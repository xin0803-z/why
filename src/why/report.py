"""Rendering: a readable human report, and a stable machine-readable one."""

from __future__ import annotations

import json
import os
import shutil
import sys
from typing import Dict, List, Optional

from .model import Report, Status, Verdict

ANSI = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    "red": "\033[31m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "blue": "\033[34m",
    "cyan": "\033[36m",
    "grey": "\033[90m",
}

UNICODE_ICONS = {
    Status.OK: "✔",
    Status.DENY: "✘",
    Status.WARN: "!",
    Status.INFO: "·",
    Status.SKIP: "-",
    Status.UNKNOWN: "?",
}

ASCII_ICONS = {
    Status.OK: "+",
    Status.DENY: "X",
    Status.WARN: "!",
    Status.INFO: ".",
    Status.SKIP: "-",
    Status.UNKNOWN: "?",
}

STATUS_KEYS = {
    Status.OK: "green",
    Status.DENY: "red",
    Status.WARN: "yellow",
    Status.INFO: "cyan",
    Status.SKIP: "grey",
    Status.UNKNOWN: "yellow",
}

VERDICT_STYLE = {
    Verdict.DENIED: ("red", "DENIED"),
    Verdict.DENIED_BY_EVIDENCE: ("red", "DENIED (kernel evidence)"),
    Verdict.ALLOWED: ("green", "ALLOWED (by every layer why can check)"),
    Verdict.UNKNOWN: ("yellow", "UNKNOWN"),
}


class Style:
    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def __call__(self, text: str, *keys: str) -> str:
        if not self.enabled or not keys:
            return text
        prefix = "".join(ANSI[key] for key in keys if key in ANSI)
        return f"{prefix}{text}{ANSI['reset']}" if prefix else text


def want_color(mode: str) -> bool:
    if mode == "always":
        return True
    if mode == "never":
        return False
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("TERM") == "dumb":
        return False
    return sys.stdout.isatty()


def _terminal_width(default: int = 100) -> int:
    try:
        return min(max(shutil.get_terminal_size((default, 24)).columns, 60), 200)
    except OSError:  # pragma: no cover
        return default


def _truncate(text: str, width: int, ellipsis: str = "…") -> str:
    if width <= len(ellipsis) + 1 or len(text) <= width:
        return text
    return text[: width - len(ellipsis)] + ellipsis


def render_text(
    report: Report,
    color: bool = False,
    verbose: bool = False,
    icons: str = "auto",
    width: Optional[int] = None,
) -> str:
    style = Style(color)
    encoding = (getattr(sys.stdout, "encoding", None) or "utf-8").lower()
    if icons == "ascii":
        use_unicode = False
    elif icons == "unicode":
        use_unicode = True
    else:
        use_unicode = "utf" in encoding or color
    glyphs = UNICODE_ICONS if use_unicode else ASCII_ICONS
    rule_char = "─" if use_unicode else "-"
    ellipsis = "…" if use_unicode else "..."
    width = width or _terminal_width()
    lines: List[str] = []

    head = f"{report.tool} {report.version}"
    lines.append(style(head, "bold") + style(f"{report.platform:>{max(width - len(head), 1)}}", "grey"))
    lines.append(style(rule_char * width, "grey"))

    target = report.target
    kind = "directory" if target.is_dir else ("file" if target.exists else "missing")
    lines.append(f"{style('target ', 'grey')} {target.path}   {style(target.mode_str, 'bold')}  ({kind})")
    if target.exists:
        owner = f"{target.uid_name or target.uid}:{target.gid_name or target.gid}"
        lines.append(
            f"{style('       ', 'grey')} owner {owner}"
            f"{f'  size {target.size}' if target.size is not None else ''}"
            f"{f'  -> symlink to {target.symlink_target}' if target.is_symlink else ''}"
        )
    lines.append(f"{style('subject', 'grey')} {report.subject.describe()}")
    lines.append(f"{style('action ', 'grey')} {report.op.value}")
    lines.append("")

    label_width = max(len(item.title) for item in report.layers) if report.layers else 10
    for item in report.layers:
        icon = glyphs.get(item.status, "?")
        key = STATUS_KEYS.get(item.status, "reset")
        head_col = style(icon, key, "bold")
        title = item.title.ljust(label_width)
        title = style(title, "bold") if item.status is Status.DENY else title
        detail = item.detail
        plain_prefix = f" {item.index:>2} {icon} {title}  "
        styled_prefix = f" {item.index:>2} {head_col} {title}  "
        # Continuation lines line up under the detail column, so the report stays
        # scannable; on very narrow terminals fall back to a short indent.
        indent_len = min(len(plain_prefix), max(width // 3, 20))
        indent = " " * indent_len
        available = width - len(plain_prefix)
        if verbose and len(detail) > available:
            if available < 20:  # too narrow to share the line with the prefix
                lines.append(styled_prefix.rstrip())
                chunks = _wrap(detail, max(width - indent_len, 30))
                lines.extend(indent + chunk for chunk in chunks)
            else:
                chunks = _wrap_with_first(detail, available, max(width - indent_len, 30))
                lines.append(styled_prefix + chunks[0])
                lines.extend(indent + chunk for chunk in chunks[1:])
        else:
            lines.append(styled_prefix + _truncate(detail, available, ellipsis))
        if item.confidence.value == "evidence" and item.status is Status.DENY:
            lines.append(indent + style("(from kernel audit evidence, not a prediction)", "grey"))

    lines.append("")
    key, label = VERDICT_STYLE[report.verdict]
    deciding = ""
    if report.deciding_layer:
        deciding_layer = report.layer(report.deciding_layer)
        if deciding_layer is not None:
            deciding = f" (layer {deciding_layer.index}: {deciding_layer.title})"

    def emit(label_text: str, content: str) -> None:
        """Right-pad the label, wrap long values instead of running off screen."""
        chunks = _wrap(content, max(width - 8, 40)) if verbose else [_truncate(content, max(width - 8, 20), ellipsis)]
        lines.append(style(label_text.ljust(7), "grey") + " " + chunks[0])
        for chunk in chunks[1:]:
            lines.append(" " * 8 + chunk)

    lines.append(style("verdict", "grey") + " " + f"{style(label, key, 'bold')}{deciding}")
    emit("reason", report.reason)
    for index, fix in enumerate(report.fixes):
        emit("fix" if index == 0 else "", fix)
    if report.notes:
        lines.append(style("notes", "grey"))
        for note in report.notes:
            lines.append("        " + _truncate(note, width - 8, ellipsis))
    if verbose and report.evidence:
        lines.append(style("evidence", "grey"))
        for raw in report.evidence:
            for chunk in _wrap(raw, width - 8):
                lines.append("        " + chunk)
    if verbose and report.degraded:
        lines.append(style("degraded", "grey"))
        for reason in report.degraded:
            lines.append("        " + _truncate(reason, width - 8, ellipsis))
    return "\n".join(lines)


def _wrap(text: str, width: int) -> List[str]:
    words = text.split(" ")
    out: List[str] = []
    current = ""
    for word in words:
        if not current:
            current = word
        elif len(current) + 1 + len(word) <= width:
            current += " " + word
        else:
            out.append(current)
            current = word
    if current:
        out.append(current)
    return out or [""]


def _wrap_with_first(text: str, first_width: int, rest_width: int) -> List[str]:
    """Wrap ``text`` where the first line has a different budget than the rest."""
    words = text.split(" ")
    out: List[str] = []
    current = ""
    limit = first_width
    for word in words:
        candidate = word if not current else f"{current} {word}"
        if not current or len(candidate) <= limit:
            current = candidate
        else:
            out.append(current)
            current = word
            limit = rest_width
    if current:
        out.append(current)
    return out or [""]


def render_json(report: Report, indent: int = 2) -> str:
    payload: Dict[str, object] = {
        "tool": report.tool,
        "version": report.version,
        "platform": report.platform,
        "verdict": report.verdict.value,
        "deciding_layer": report.deciding_layer,
        "reason": report.reason,
        "action": report.op.value,
        "subject": {
            "uid": report.subject.uid,
            "gid": report.subject.gid,
            "groups": list(report.subject.groups),
            "label": report.subject.label,
            "pid": report.subject.pid,
            "caps_eff": sorted(report.subject.caps_eff),
            "selinux_context": report.subject.selinux_context,
            "apparmor_profile": report.subject.apparmor_profile,
            "seccomp_mode": report.subject.seccomp_mode,
        },
        "target": {
            "path": report.target.path,
            "exists": report.target.exists,
            "is_dir": report.target.is_dir,
            "is_symlink": report.target.is_symlink,
            "symlink_target": report.target.symlink_target,
            "mode": report.target.mode,
            "mode_string": report.target.mode_str,
            "uid": report.target.uid,
            "gid": report.target.gid,
            "size": report.target.size,
            "ancestors": [{"path": path, "mode": mode} for path, mode, _uid, _gid in report.target.ancestors],
        },
        "layers": [item.as_dict() for item in report.layers],
        "fixes": report.fixes,
        "notes": report.notes,
        "degraded": report.degraded,
    }
    if report.evidence:
        payload["evidence"] = report.evidence
    return json.dumps(payload, indent=indent, ensure_ascii=False)


def layer_catalog() -> str:
    """The output of ``why layers``."""
    from .checks import LAYER_META

    lines = ["why checks these layers, in this order:", ""]
    for index, (layer_id, title) in enumerate(LAYER_META, start=1):
        lines.append(f" {index:>2}. {title}  [{layer_id}]")
    lines.append("")
    lines.append("Deceptive ones worth knowing about:")
    lines.append("  · capabilities can bypass the permission bits entirely (root, containers with --cap-add)")
    lines.append("  · the immutable attribute (chattr +i) denies even root")
    lines.append("  · noexec turns 'is it executable?' into EACCES, not a missing x bit")
    lines.append("  · an extended POSIX ACL turns the group mode bits into a mask")
    lines.append("  · SELinux/AppArmor can deny an access that every DAC check allows")
    return "\n".join(lines)


__all__ = ["Style", "layer_catalog", "render_json", "render_text", "want_color"]
