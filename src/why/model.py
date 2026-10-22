"""Data model shared by the collectors, the attribution layers and the renderer."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Sequence, Tuple


class Status(str, Enum):
    """Outcome of a single attribution layer."""

    OK = "ok"  # this layer allows the operation
    DENY = "deny"  # this layer is the (or a) reason the operation fails
    WARN = "warn"  # suspicious, or a trap that often bites later
    INFO = "info"  # context only
    SKIP = "skip"  # not applicable here
    UNKNOWN = "unknown"  # could not be determined on this system


class Confidence(str, Enum):
    """How much weight a DENY verdict deserves."""

    DECISIVE = "decisive"  # decided by this run: the kernel *must* refuse
    EVIDENCE = "evidence"  # a recent kernel denial record matches this target
    ADVISORY = "advisory"  # a hint, not proof


class Op(str, Enum):
    READ = "read"
    WRITE = "write"
    EXEC = "exec"
    DELETE = "delete"
    CREATE = "create"

    @property
    def letter(self) -> str:
        return {
            Op.READ: "r",
            Op.WRITE: "w",
            Op.EXEC: "x",
            Op.DELETE: "w(x)",
            Op.CREATE: "w(x)",
        }[self]


@dataclass(frozen=True)
class Subject:
    """Who is asking. Either the current process, ``--user`` or ``--pid``."""

    uid: int
    gid: int
    groups: Tuple[int, ...] = ()
    caps_eff: frozenset = frozenset()
    label: str = "current process"
    pid: Optional[int] = None
    names: Dict[int, str] = field(default_factory=dict)
    selinux_context: Optional[str] = None
    apparmor_profile: Optional[str] = None
    seccomp_mode: Optional[int] = None
    no_new_privs: Optional[int] = None

    @property
    def is_root(self) -> bool:
        return self.uid == 0

    def has_cap(self, name: str) -> bool:
        return name in self.caps_eff

    def name_of(self, uid: int) -> str:
        return self.names.get(uid, str(uid))

    def describe(self) -> str:
        bits = [f"uid={self.uid}({self.name_of(self.uid)})", f"gid={self.gid}"]
        if self.groups:
            bits.append("groups=" + ",".join(str(g) for g in self.groups))
        return " ".join(bits) + f"  [{self.label}]"


@dataclass
class Target:
    """What is being accessed."""

    path: str  # absolute, as the *subject* sees it
    exists: bool = False
    mode: Optional[int] = None
    uid: Optional[int] = None
    gid: Optional[int] = None
    uid_name: Optional[str] = None
    gid_name: Optional[str] = None
    size: Optional[int] = None
    is_dir: bool = False
    is_symlink: bool = False
    symlink_target: Optional[str] = None
    # ancestor directories from / down to the parent, as (path, mode, uid, gid)
    ancestors: List[Tuple[str, int, int, int]] = field(default_factory=list)
    parent: Optional[str] = None
    # prefix actually used for stat() — /proc/<pid>/root for --pid, else ""
    fs_root: str = ""
    # for the paths we stat'd: the prefix-qualified real path
    stat_path: str = ""

    @property
    def mode_str(self) -> str:
        import stat as _stat

        if self.mode is None:
            return "?"
        mode = self.mode
        if _stat.S_IFMT(mode) == 0:
            # `stat.filemode` needs the type bits; fixtures and 4-digit octal
            # values only carry the permission bits.
            mode |= _stat.S_IFREG
        return _stat.filemode(mode)


@dataclass
class LayerResult:
    id: str
    index: int
    title: str
    status: Status
    confidence: Confidence = Confidence.ADVISORY
    detail: str = ""
    fix: Optional[str] = None
    data: Dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> Dict[str, object]:
        out: Dict[str, object] = {
            "id": self.id,
            "index": self.index,
            "title": self.title,
            "status": self.status.value,
            "confidence": self.confidence.value,
            "detail": self.detail,
        }
        if self.fix:
            out["fix"] = self.fix
        if self.data:
            out["data"] = self.data
        return out


class Verdict(str, Enum):
    DENIED = "denied"
    DENIED_BY_EVIDENCE = "denied-by-evidence"
    ALLOWED = "allowed"
    UNKNOWN = "unknown"


@dataclass
class Report:
    tool: str
    version: str
    target: Target
    subject: Subject
    op: Op
    layers: List[LayerResult]
    verdict: Verdict
    deciding_layer: Optional[str]
    reason: str
    fixes: List[str] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    platform: str = ""
    degraded: List[str] = field(default_factory=list)

    def layer(self, layer_id: str) -> Optional[LayerResult]:
        for item in self.layers:
            if item.id == layer_id:
                return item
        return None

    def by_status(self, status: Status) -> Sequence[LayerResult]:
        return [item for item in self.layers if item.status == status]
