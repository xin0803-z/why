"""Pure parsers: text/blob in, structured data out. No OS access, no side effects.

Everything in this module is deliberately free of ``fcntl``/``/proc`` access so it
can be unit-tested on any platform (including Windows and macOS) with fixtures.
``why.collect`` is the only module allowed to touch the live system.
"""

from __future__ import annotations

import re
import stat as statmod
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Tuple, Union

# --------------------------------------------------------------------------- #
# UNIX mode bits
# --------------------------------------------------------------------------- #

PERM_MASK = 0o777
MODE_R, MODE_W, MODE_X = 0o4, 0o2, 0o1

CLASS_USER, CLASS_GROUP, CLASS_OTHER = "user", "group", "other"


def perm_letters(bits: int) -> str:
    """0o5 -> ``"r-x"``."""
    out = ""
    for bit, letter in ((MODE_R, "r"), (MODE_W, "w"), (MODE_X, "x")):
        out += letter if bits & bit else "-"
    return out


def bits_of(mode: int, klass: str) -> int:
    """Extract the permission triad for one class from a full st_mode."""
    shift = {"user": 6, "group": 3, "other": 0}[klass]
    return (mode >> shift) & 0o7


def special_bits(mode: int) -> str:
    """Return the setuid/setgid/sticky suffix such as ``s``, ``t`` or ``-``."""
    out = ""
    out += "s" if mode & statmod.S_ISUID else "-"
    out += "s" if mode & statmod.S_ISGID else "-"
    out += "t" if mode & statmod.S_ISVTX else "-"
    return out


def mode_string(mode: int) -> str:
    """``0o104640`` -> ``"-rw-r-----"`` (like ``stat -c %A``)."""
    kind = statmod.S_IFMT(mode)
    if kind == statmod.S_IFDIR:
        first = "d"
    elif kind == statmod.S_IFLNK:
        first = "l"
    elif kind == statmod.S_IFCHR:
        first = "c"
    elif kind == statmod.S_IFBLK:
        first = "b"
    elif kind == statmod.S_IFIFO:
        first = "p"
    elif kind == statmod.S_IFSOCK:
        first = "s"
    else:
        first = "-"
    body = perm_letters(bits_of(mode, CLASS_USER)) + perm_letters(bits_of(mode, CLASS_GROUP))
    body += perm_letters(bits_of(mode, CLASS_OTHER))
    letters = list(body)
    if mode & statmod.S_ISUID:
        letters[2] = "s" if letters[2] == "x" else "S"
    if mode & statmod.S_ISGID:
        letters[5] = "s" if letters[5] == "x" else "S"
    if mode & statmod.S_ISVTX:
        letters[8] = "t" if letters[8] == "x" else "T"
    return first + "".join(letters)


# --------------------------------------------------------------------------- #
# POSIX ACLs — binary xattr decoder (system.posix_acl_access)
# --------------------------------------------------------------------------- #

ACL_XATTR_VERSION = 0x0002
ACL_TAG_USER_OBJ = 0x01
ACL_TAG_USER = 0x02
ACL_TAG_GROUP_OBJ = 0x04
ACL_TAG_GROUP = 0x08
ACL_TAG_MASK = 0x10
ACL_TAG_OTHER = 0x20
ACL_UNDEFINED_ID = 0xFFFFFFFF

ACL_TAG_NAMES = {
    ACL_TAG_USER_OBJ: "user::",
    ACL_TAG_USER: "user",
    ACL_TAG_GROUP_OBJ: "group::",
    ACL_TAG_GROUP: "group",
    ACL_TAG_MASK: "mask::",
    ACL_TAG_OTHER: "other::",
}


@dataclass(frozen=True)
class AclEntry:
    tag: int
    perm: int
    qualifier: Union[int, str, None] = None

    @property
    def perms(self) -> str:
        return perm_letters(self.perm)

    def label(self) -> str:
        if self.tag == ACL_TAG_USER_OBJ:
            return "user::"
        if self.tag == ACL_TAG_GROUP_OBJ:
            return "group::"
        if self.tag == ACL_TAG_MASK:
            return "mask::"
        if self.tag == ACL_TAG_OTHER:
            return "other::"
        kind = "user" if self.tag == ACL_TAG_USER else "group"
        return f"{kind}:{self.qualifier}"


@dataclass
class Acl:
    entries: List[AclEntry] = field(default_factory=list)
    source: str = "xattr"
    # Set when a getfacl text dump used symbolic names we cannot resolve to ids.
    unresolved_names: bool = False

    # -- convenience accessors -------------------------------------------- #
    def _find(self, tag: int, qualifier: Optional[int] = None) -> Optional[AclEntry]:
        for entry in self.entries:
            if entry.tag != tag:
                continue
            if qualifier is not None and entry.qualifier != qualifier:
                continue
            return entry
        return None

    @property
    def owner_entry(self) -> Optional[AclEntry]:
        return self._find(ACL_TAG_USER_OBJ)

    @property
    def group_entry(self) -> Optional[AclEntry]:
        return self._find(ACL_TAG_GROUP_OBJ)

    @property
    def other_entry(self) -> Optional[AclEntry]:
        return self._find(ACL_TAG_OTHER)

    @property
    def mask_entry(self) -> Optional[AclEntry]:
        return self._find(ACL_TAG_MASK)

    @property
    def named_users(self) -> Dict[Union[int, str], int]:
        return {e.qualifier: e.perm for e in self.entries if e.tag == ACL_TAG_USER and e.qualifier is not None}

    @property
    def named_groups(self) -> Dict[Union[int, str], int]:
        return {e.qualifier: e.perm for e in self.entries if e.tag == ACL_TAG_GROUP and e.qualifier is not None}

    @property
    def is_extended(self) -> bool:
        """A POSIX ACL is 'extended' iff it has a mask or any named entry."""
        return bool(self.mask_entry) or bool(self.named_users) or bool(self.named_groups)

    def lines(self) -> List[str]:
        """Render the ACL the way ``getfacl`` does, one entry per line."""
        out = []
        for entry in self.entries:
            if entry.qualifier is None:
                out.append(f"{entry.label()}{entry.perms}")
            else:
                out.append(f"{entry.label()}:{entry.perms}")
        return out


def decode_posix_acl(blob: bytes) -> Acl:
    """Decode the raw ``system.posix_acl_access`` xattr payload.

    Layout (little endian): ``u32 version`` followed by 8-byte entries of
    ``u16 tag, u16 perm, u32 id``.
    """
    if len(blob) < 4:
        raise ValueError("ACL blob too short")
    version = int.from_bytes(blob[0:4], "little")
    if version != ACL_XATTR_VERSION:
        raise ValueError(f"unsupported ACL xattr version: {version}")
    body = blob[4:]
    if len(body) % 8:
        raise ValueError("ACL blob is not a multiple of 8 bytes")
    entries: List[AclEntry] = []
    for offset in range(0, len(body), 8):
        tag = int.from_bytes(body[offset : offset + 2], "little")
        perm = int.from_bytes(body[offset + 2 : offset + 4], "little")
        ident = int.from_bytes(body[offset + 4 : offset + 8], "little")
        qualifier: Union[int, str, None] = None
        if tag in (ACL_TAG_USER, ACL_TAG_GROUP) and ident != ACL_UNDEFINED_ID:
            qualifier = ident
        entries.append(AclEntry(tag=tag, perm=perm & 0o7, qualifier=qualifier))
    return Acl(entries=entries, source="xattr")


_GETFACL_RE = re.compile(r"^(user|group|mask|other):([^:]*):([-r-x]+)\s*$")


def parse_getfacl(text: str) -> Acl:
    """Parse ``getfacl -n``-style output (a fallback when xattr access is denied)."""
    entries: List[AclEntry] = []
    unresolved = False
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = _GETFACL_RE.match(line)
        if not match:
            continue
        kind, qualifier_text, perms = match.groups()
        perm = 0
        for letter, bit in (("r", MODE_R), ("w", MODE_W), ("x", MODE_X)):
            if letter in perms:
                perm |= bit
        if kind == "user" and not qualifier_text:
            tag: int = ACL_TAG_USER_OBJ
            qualifier: Union[int, str, None] = None
        elif kind == "group" and not qualifier_text:
            tag = ACL_TAG_GROUP_OBJ
            qualifier = None
        elif kind == "mask":
            tag = ACL_TAG_MASK
            qualifier = None
        elif kind == "other":
            tag = ACL_TAG_OTHER
            qualifier = None
        elif kind == "user":
            tag = ACL_TAG_USER
            qualifier = qualifier_text
        else:
            tag = ACL_TAG_GROUP
            qualifier = qualifier_text
        if qualifier is not None:
            if isinstance(qualifier, str) and qualifier.isdigit():
                qualifier = int(qualifier)
            else:
                unresolved = True
        entries.append(AclEntry(tag=tag, perm=perm, qualifier=qualifier))
    return Acl(entries=entries, source="getfacl", unresolved_names=unresolved)


def acl_perms_for(
    acl: Optional[Acl],
    uid: int,
    groups: Iterable[int],
    file_uid: Optional[int],
    file_gid: Optional[int],
) -> Tuple[Optional[int], str]:
    """POSIX ACL evaluation. Returns ``(perm_bits_or_None, human explanation)``.

    ``None`` means "no extended ACL applies, fall back to the mode bits".
    Named entries are only matched when they carry numeric ids; unresolved
    symbolic names yield an explicit explanation instead of a wrong answer.
    """
    if acl is None or not acl.is_extended:
        return None, "no extended ACL"
    groups = tuple(groups)
    if acl.unresolved_names:
        return None, "ACL has symbolic names that could not be resolved to ids (rerun as root)"

    if uid == file_uid and acl.owner_entry:
        return acl.owner_entry.perm, "matched the ACL owner (user::) entry, which ignores the mask"

    named_users = acl.named_users
    if uid in named_users:
        perm = named_users[uid]
        mask = acl.mask_entry.perm if acl.mask_entry else 0o7
        return perm & mask, f"matched ACL entry user:{uid}={perm_letters(perm)} & mask={perm_letters(mask)}"

    group_perm: Optional[int] = None
    reasons: List[str] = []
    if file_gid is not None and file_gid in groups and acl.group_entry:
        group_perm = acl.group_entry.perm
        reasons.append(f"in owning group (group::={perm_letters(group_perm)})")
    named_groups = acl.named_groups
    for gid in groups:
        if gid in named_groups:
            entry_perm = named_groups[gid]
            group_perm = entry_perm if group_perm is None else (group_perm | entry_perm)
            reasons.append(f"ACL group:{gid}={perm_letters(entry_perm)}")
    if group_perm is not None:
        mask = acl.mask_entry.perm if acl.mask_entry else 0o7
        effective = group_perm & mask
        return effective, " + ".join(reasons) + f" & mask={perm_letters(mask)} -> {perm_letters(effective)}"

    if acl.other_entry:
        return acl.other_entry.perm, "matched other:: (no user/group entry applies)"
    return None, "ACL present but no entry applies"


# --------------------------------------------------------------------------- #
# /proc/self/mountinfo
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Mount:
    mount_id: int
    parent_id: int
    major_minor: str
    root: str
    mount_point: str
    options: frozenset
    fstype: str
    source: str
    super_options: frozenset
    optional: Tuple[str, ...] = ()

    def has(self, option: str) -> bool:
        return option in self.options or option in self.super_options


_ESCAPES = {
    "\\040": " ",
    "\\011": "\t",
    "\\012": "\n",
    "\\134": "\\",
}


def decode_mountinfo_escapes(text: str) -> str:
    for key, value in _ESCAPES.items():
        text = text.replace(key, value)
    return text


def parse_mountinfo(text: str) -> List[Mount]:
    """Parse ``/proc/self/mountinfo`` (or ``/proc/<pid>/mountinfo``)."""
    mounts: List[Mount] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if " - " not in line:
            continue
        left, right = line.split(" - ", 1)
        lfields = left.split()
        rfields = right.split()
        if len(lfields) < 6 or len(rfields) < 3:
            continue
        try:
            mount_id = int(lfields[0])
            parent_id = int(lfields[1])
        except ValueError:
            continue
        optional: List[str] = []
        # Fields after mount options up to the separator are optional tags
        # such as shared:5, master:1, propagate_from:2.
        idx = 6
        while idx < len(lfields) and ":" in lfields[idx]:
            optional.append(lfields[idx])
            idx += 1
        mounts.append(
            Mount(
                mount_id=mount_id,
                parent_id=parent_id,
                major_minor=lfields[2],
                root=decode_mountinfo_escapes(lfields[3]),
                mount_point=decode_mountinfo_escapes(lfields[4]),
                options=frozenset(lfields[5].split(",")),
                optional=tuple(optional),
                fstype=rfields[0],
                source=decode_mountinfo_escapes(rfields[1]),
                super_options=frozenset(rfields[2].split(",")),
            )
        )
    return mounts


def find_mount(mounts: Sequence[Mount], path: str) -> Optional[Mount]:
    """Longest-prefix mount lookup, respecting path-component boundaries."""
    best: Optional[Mount] = None
    best_len = -1
    for mount in mounts:
        point = mount.mount_point.rstrip("/") or "/"
        if path == point or path.startswith(point.rstrip("/") + "/") or point == "/":
            if point == "/" and path != "/":
                length = 0
            else:
                length = len(point)
            if length > best_len:
                best, best_len = mount, length
    return best


# --------------------------------------------------------------------------- #
# /proc/<pid>/status, uid_map
# --------------------------------------------------------------------------- #


def _split_kv(line: str) -> Tuple[str, str]:
    if ":" not in line:
        return line.strip(), ""
    key, value = line.split(":", 1)
    return key.strip(), value.strip()


def parse_proc_status(text: str) -> Dict[str, object]:
    """Parse ``/proc/<pid>/status`` into a small, typed dictionary."""
    out: Dict[str, object] = {}
    for line in text.splitlines():
        key, value = _split_kv(line)
        if not key:
            continue
        if key in ("Name", "State", "Seccomp", "NoNewPrivs"):
            out[key] = value
        elif key in ("Uid", "Gid"):
            parts = value.split()
            out[key] = [int(p) for p in parts if p.isdigit()]
        elif key == "Groups":
            out[key] = [int(p) for p in value.split() if p.isdigit()]
        elif key in ("CapEff", "CapPrm", "CapBnd", "CapInh", "CapAmb"):
            out[key] = value
    return out


def parse_uid_map(text: str) -> List[Tuple[int, int, int]]:
    """Parse ``/proc/<pid>/uid_map`` into ``(inside, outside, length)`` triples."""
    maps: List[Tuple[int, int, int]] = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) != 3:
            continue
        try:
            maps.append((int(parts[0]), int(parts[1]), int(parts[2])))
        except ValueError:
            continue
    return maps


def map_id(maps: Sequence[Tuple[int, int, int]], ident: int) -> Optional[int]:
    """Translate an *inside* id to the *outside* id, or ``None`` if unmapped."""
    for inside, outside, length in maps:
        if inside <= ident < inside + length:
            return outside + (ident - inside)
    return None


def describe_userns(maps: Sequence[Tuple[int, int, int]], uid: int = 0) -> str:
    if not maps:
        return "no user namespace mapping found"
    outside = map_id(maps, uid)
    if outside is None:
        return f"uid {uid} is not mapped in this namespace"
    if outside != uid:
        return f"uid {uid} inside the namespace is uid {outside} on the host"
    return f"uid {uid} maps 1:1"


# --------------------------------------------------------------------------- #
# Capabilities
# --------------------------------------------------------------------------- #

CAP_NAMES: Tuple[str, ...] = (
    "CAP_CHOWN",
    "CAP_DAC_OVERRIDE",
    "CAP_DAC_READ_SEARCH",
    "CAP_FOWNER",
    "CAP_FSETID",
    "CAP_KILL",
    "CAP_SETGID",
    "CAP_SETUID",
    "CAP_SETPCAP",
    "CAP_LINUX_IMMUTABLE",
    "CAP_NET_BIND_SERVICE",
    "CAP_NET_BROADCAST",
    "CAP_NET_ADMIN",
    "CAP_NET_RAW",
    "CAP_IPC_LOCK",
    "CAP_IPC_OWNER",
    "CAP_SYS_MODULE",
    "CAP_SYS_RAWIO",
    "CAP_SYS_CHROOT",
    "CAP_SYS_PTRACE",
    "CAP_SYS_PACCT",
    "CAP_SYS_ADMIN",
    "CAP_SYS_BOOT",
    "CAP_SYS_NICE",
    "CAP_SYS_RESOURCE",
    "CAP_SYS_TIME",
    "CAP_SYS_TTY_CONFIG",
    "CAP_MKNOD",
    "CAP_LEASE",
    "CAP_AUDIT_WRITE",
    "CAP_AUDIT_CONTROL",
    "CAP_SETFCAP",
    "CAP_MAC_OVERRIDE",
    "CAP_MAC_ADMIN",
    "CAP_SYSLOG",
    "CAP_WAKE_ALARM",
    "CAP_BLOCK_SUSPEND",
    "CAP_AUDIT_READ",
    "CAP_PERFMON",
    "CAP_BPF",
    "CAP_CHECKPOINT_RESTORE",
)


def decode_cap_mask(mask: Union[str, int]) -> frozenset:
    """``"000001ffffffffff"`` -> ``frozenset({"CAP_CHOWN", ...})``."""
    if isinstance(mask, str):
        text = mask.strip()
        if not text:
            return frozenset()
        try:
            value = int(text, 16)
        except ValueError:
            return frozenset()
    else:
        value = mask
    names = set()
    for bit, name in enumerate(CAP_NAMES):
        if value & (1 << bit):
            names.add(name)
    if value >> len(CAP_NAMES):
        names.add(f"CAP_UNKNOWN_BITS(0x{value:x})")
    return frozenset(names)


# --------------------------------------------------------------------------- #
# File flags (FS_IOC_GETFLAGS) and lsattr output
# --------------------------------------------------------------------------- #

FS_FLAG_NAMES: Tuple[Tuple[int, str], ...] = (
    (0x00000001, "secure_delete"),
    (0x00000002, "undelete"),
    (0x00000004, "compress"),
    (0x00000008, "sync"),
    (0x00000010, "immutable"),
    (0x00000020, "append_only"),
    (0x00000040, "no_dump"),
    (0x00000080, "no_atime"),
    (0x00000100, "dirty"),
    (0x00000200, "compressed_blocks"),
    (0x00000400, "no_compress"),
    (0x00000800, "encrypted"),
    (0x00001000, "indexed_dir"),
    (0x00002000, "imagic"),
    (0x00004000, "journal_data"),
    (0x00008000, "no_tail_merge"),
    (0x00010000, "dirsync"),
    (0x00020000, "topdir"),
    (0x00040000, "extents"),
    (0x00080000, "ea_inode"),
    (0x00100000, "eofblocks"),
    (0x00200000, "no_cow"),
    (0x00400000, "dax"),
    (0x00800000, "inline_data"),
    (0x01000000, "projinherit"),
    (0x02000000, "casefold"),
    (0x04000000, "verity"),
)

# lsattr prints one character per flag in this order.
LSATTR_ORDER: Tuple[Tuple[str, int, str], ...] = (
    ("s", 0x00000001, "secure_delete"),
    ("u", 0x00000002, "undelete"),
    ("c", 0x00000004, "compress"),
    ("S", 0x00000008, "sync"),
    ("i", 0x00000010, "immutable"),
    ("a", 0x00000020, "append_only"),
    ("d", 0x00000040, "no_dump"),
    ("A", 0x00000080, "no_atime"),
    ("Z", 0x00000100, "dirty"),
    ("B", 0x00000200, "compressed_blocks"),
    ("X", 0x00000400, "no_compress"),
    ("E", 0x00000800, "encrypted"),
    ("I", 0x00001000, "indexed_dir"),
    ("j", 0x00002000, "imagic"),
    ("J", 0x00004000, "journal_data"),
    ("t", 0x00008000, "no_tail_merge"),
    ("D", 0x00010000, "dirsync"),
    ("T", 0x00020000, "topdir"),
    ("e", 0x00040000, "extents"),
    ("C", 0x00200000, "no_cow"),
    ("P", 0x01000000, "projinherit"),
    ("x", 0x00400000, "dax"),
    ("F", 0x02000000, "casefold"),
    ("V", 0x04000000, "verity"),
)


def decode_fs_flags(value: int) -> frozenset:
    """Numeric FS_IOC_GETFLAGS value -> set of human-readable flag names."""
    names = {name for bit, name in FS_FLAG_NAMES if value & bit}
    known = 0
    for bit, _ in FS_FLAG_NAMES:
        known |= bit
    if value & ~known:
        names.add(f"unknown_flags(0x{value & ~known:x})")
    return frozenset(names)


def parse_lsattr(text: str) -> Dict[str, frozenset]:
    """Parse ``lsattr`` output, returning ``{path: {flag names}}``."""
    out: Dict[str, frozenset] = {}
    for line in text.splitlines():
        line = line.rstrip("\n")
        if not line or line.startswith("lsattr:") or " " not in line:
            continue
        flags_text, path = line.split(None, 1)
        path = path.strip()
        value = 0
        for index, char in enumerate(flags_text):
            if index >= len(LSATTR_ORDER) or char == "-":
                continue
            if char == LSATTR_ORDER[index][0]:
                value |= LSATTR_ORDER[index][1]
        out[path] = decode_fs_flags(value)
    return out


def flags_to_lsattr_string(flags: Iterable[str]) -> str:
    flags = set(flags)
    return "".join(char if name in flags else "-" for char, _bit, name in LSATTR_ORDER)


# --------------------------------------------------------------------------- #
# SELinux AVC records
# --------------------------------------------------------------------------- #


@dataclass
class AvcDenial:
    perms: Tuple[str, ...]
    target_class: str
    path: Optional[str]
    comm: Optional[str]
    pid: Optional[int]
    scontext: Optional[str]
    tcontext: Optional[str]
    permissive: Optional[bool]
    raw: str

    def as_dict(self) -> Dict[str, object]:
        return {
            "perms": list(self.perms),
            "class": self.target_class,
            "path": self.path,
            "comm": self.comm,
            "pid": self.pid,
            "scontext": self.scontext,
            "tcontext": self.tcontext,
            "permissive": self.permissive,
        }


_KV_RE = re.compile(r'(\w+)=("(?:[^"\\]|\\.)*"|\S+)')


def _kv_pairs(text: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for key, value in _KV_RE.findall(text):
        if value.startswith('"') and value.endswith('"'):
            value = value[1:-1]
        out[key] = value
    return out


_AVC_PERMS_RE = re.compile(r"avc:\s+(denied|granted)\s+\{([^}]*)\}")


def parse_avc_lines(text: str) -> List[AvcDenial]:
    """Extract ``type=AVC ... avc: denied { ... } for ...`` records from audit logs."""
    denials: List[AvcDenial] = []
    for line in text.splitlines():
        if "avc:" not in line:
            continue
        match = _AVC_PERMS_RE.search(line)
        if not match:
            continue
        decision, perms_text = match.groups()
        if decision != "denied":
            continue
        pairs = _kv_pairs(line)
        pid_text = pairs.get("pid")
        permissive_text = pairs.get("permissive")
        denials.append(
            AvcDenial(
                perms=tuple(perms_text.split()),
                target_class=pairs.get("tclass", "?"),
                path=pairs.get("name") or pairs.get("path"),
                comm=pairs.get("comm"),
                pid=int(pid_text) if pid_text and pid_text.isdigit() else None,
                scontext=pairs.get("scontext"),
                tcontext=pairs.get("tcontext"),
                permissive=None if permissive_text is None else permissive_text == "1",
                raw=line.strip(),
            )
        )
    return denials


def match_avc_for_path(denials: Sequence[AvcDenial], path: str, basename: bool = True) -> List[AvcDenial]:
    """Best-effort match: AVC records carry a bare ``name=``, not a full path."""
    base = path.rstrip("/").split("/")[-1]
    hits = []
    for denial in denials:
        if not denial.path:
            continue
        if denial.path == path:
            hits.append(denial)
        elif basename and denial.path == base:
            hits.append(denial)
    return hits


# --------------------------------------------------------------------------- #
# AppArmor denials (kernel printk records)
# --------------------------------------------------------------------------- #


@dataclass
class AppArmorDenial:
    operation: Optional[str]
    profile: Optional[str]
    name: Optional[str]
    comm: Optional[str]
    pid: Optional[int]
    requested_mask: Optional[str]
    denied_mask: Optional[str]
    raw: str

    def as_dict(self) -> Dict[str, object]:
        return {
            "operation": self.operation,
            "profile": self.profile,
            "name": self.name,
            "comm": self.comm,
            "pid": self.pid,
            "requested_mask": self.requested_mask,
            "denied_mask": self.denied_mask,
        }


def parse_apparmor_denials(text: str) -> List[AppArmorDenial]:
    out: List[AppArmorDenial] = []
    for line in text.splitlines():
        if 'apparmor="DENIED"' not in line and "apparmor=DENIED" not in line:
            continue
        pairs = _kv_pairs(line)
        pid_text = pairs.get("pid")
        out.append(
            AppArmorDenial(
                operation=pairs.get("operation"),
                profile=pairs.get("profile"),
                name=pairs.get("name"),
                comm=pairs.get("comm"),
                pid=int(pid_text) if pid_text and pid_text.isdigit() else None,
                requested_mask=pairs.get("requested_mask"),
                denied_mask=pairs.get("denied_mask"),
                raw=line.strip(),
            )
        )
    return out


# --------------------------------------------------------------------------- #
# LSM list
# --------------------------------------------------------------------------- #


def parse_lsm_list(text: str) -> List[str]:
    """Parse ``/sys/kernel/security/lsm`` (``lockdown,yama,integrity,selinux``)."""
    return [item.strip() for item in text.strip().split(",") if item.strip()]


def lsm_notes(modules: Sequence[str]) -> List[str]:
    notes = []
    if "selinux" in modules:
        notes.append("SELinux is active (a DAC-permitted access can still be denied by policy)")
    if "apparmor" in modules:
        notes.append("AppArmor is active (path-based confinement can still deny you)")
    if "landlock" in modules:
        notes.append("Landlock is active (a process may sandbox itself below its normal permissions)")
    if "bpf" in modules:
        notes.append("BPF LSM hooks are active (policy may live in an eBPF program)")
    if "tomoyo" in modules:
        notes.append("Tomoyo is active")
    if not any(m in modules for m in ("selinux", "apparmor", "landlock", "bpf", "tomoyo")):
        notes.append("no mandatory access control module reported")
    return notes


__all__ = [
    "ACL_TAG_NAMES",
    "Acl",
    "AclEntry",
    "AppArmorDenial",
    "AvcDenial",
    "CAP_NAMES",
    "Mount",
    "acl_perms_for",
    "bits_of",
    "decode_cap_mask",
    "decode_fs_flags",
    "decode_mountinfo_escapes",
    "decode_posix_acl",
    "describe_userns",
    "find_mount",
    "flags_to_lsattr_string",
    "lsm_notes",
    "map_id",
    "match_avc_for_path",
    "mode_string",
    "parse_apparmor_denials",
    "parse_avc_lines",
    "parse_getfacl",
    "parse_lsattr",
    "parse_lsm_list",
    "parse_mountinfo",
    "parse_proc_status",
    "parse_uid_map",
    "perm_letters",
    "special_bits",
]
