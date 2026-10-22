"""Collectors: the only module in ``why`` that touches the live system.

Design rules:

* Every collector is *best effort*. On a non-Linux host, in a container with a
  stripped ``/proc``, or without root, it degrades and records *why* in
  ``Environment.degraded`` instead of raising.
* Nothing here decides anything: collectors gather, ``why.checks`` reasons.
"""

from __future__ import annotations

import os
import platform
import shutil
import stat as statmod
import subprocess
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

try:  # Unix only; guarded so `why` still imports (degraded) on Windows/macOS
    import grp
    import pwd
except ImportError:  # pragma: no cover - exercised on Windows
    grp = None  # type: ignore[assignment]
    pwd = None  # type: ignore[assignment]

from .model import Subject, Target
from .parsers import (
    Acl,
    AppArmorDenial,
    AvcDenial,
    Mount,
    decode_cap_mask,
    decode_posix_acl,
    parse_apparmor_denials,
    parse_avc_lines,
    parse_getfacl,
    parse_lsm_list,
    parse_mountinfo,
    parse_proc_status,
    parse_uid_map,
)

ACL_ACCESS_XATTR = "system.posix_acl_access"
ACL_DEFAULT_XATTR = "system.posix_acl_default"
FS_IOC_GETFLAGS = 0x80086601


def is_linux() -> bool:
    return sys.platform.startswith("linux")


def _read_text(path: str, limit: int = 1 << 20) -> Optional[str]:
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            return handle.read(limit)
    except OSError:
        return None


def _run(argv: Sequence[str], timeout: float = 5.0) -> Optional[str]:
    """Run a helper binary, returning stdout or ``None``. Never raises."""
    if not argv or shutil.which(argv[0]) is None:
        return None
    try:
        proc = subprocess.run(
            list(argv),
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    try:
        return proc.stdout.decode("utf-8", errors="replace")
    except Exception:  # pragma: no cover - defensive
        return None


@dataclass
class Environment:
    """Facts about the host that are not tied to one access attempt."""

    platform: str = ""
    distro: str = ""
    kernel: str = ""
    lsm: List[str] = field(default_factory=list)
    container: Optional[str] = None
    selinux_enforcing: Optional[bool] = None
    apparmor_profiles: Optional[int] = None
    landlock_abi: Optional[int] = None
    root_fs_read_only: Optional[bool] = None
    degraded: List[str] = field(default_factory=list)

    def as_dict(self) -> Dict[str, object]:
        return {
            "platform": self.platform,
            "distro": self.distro,
            "kernel": self.kernel,
            "lsm": list(self.lsm),
            "container": self.container,
            "selinux_enforcing": self.selinux_enforcing,
            "apparmor_profiles": self.apparmor_profiles,
            "landlock_abi": self.landlock_abi,
            "root_fs_read_only": self.root_fs_read_only,
            "degraded": list(self.degraded),
        }


# --------------------------------------------------------------------------- #
# Identity
# --------------------------------------------------------------------------- #


def _own_ids() -> Tuple[int, int, int, int]:
    """``(uid, euid, gid, egid)`` with a safe fallback on non-Unix platforms."""
    uid = getattr(os, "getuid", lambda: 0)()
    euid = getattr(os, "geteuid", lambda: uid)()
    gid = getattr(os, "getgid", lambda: 0)()
    egid = getattr(os, "getegid", lambda: gid)()
    return uid, euid, gid, egid


def _own_groups() -> Tuple[int, ...]:
    getter = getattr(os, "getgroups", None)
    if getter is None:
        return ()
    try:
        return tuple(getter())
    except OSError:  # pragma: no cover
        return ()


def uid_name(uid: int) -> str:
    if pwd is None:
        return str(uid)
    try:
        return pwd.getpwuid(uid).pw_name
    except (KeyError, OSError):
        return str(uid)


def group_name(gid: int) -> str:
    if grp is None:
        return str(gid)
    try:
        return grp.getgrgid(gid).gr_name
    except (KeyError, OSError):
        return str(gid)


def supplementary_groups_of_user(name_or_uid: str) -> Tuple[int, int, Tuple[int, ...]]:
    """Resolve ``--user`` into ``(uid, gid, groups)``."""
    if pwd is None or grp is None:
        raise ValueError("--user requires a Unix host with the pwd/grp modules available")
    entry = None
    try:
        if str(name_or_uid).isdigit():
            entry = pwd.getpwuid(int(name_or_uid))
        else:
            entry = pwd.getpwnam(str(name_or_uid))
    except (KeyError, OSError):
        entry = None
    if entry is None:
        raise ValueError(f"unknown user: {name_or_uid!r}")
    groups = {entry.pw_gid}
    try:
        for group in grp.getgrall():
            if entry.pw_name in group.gr_mem:
                groups.add(group.gr_gid)
    except OSError:
        pass
    return entry.pw_uid, entry.pw_gid, tuple(sorted(groups))


def _int_list(value: object, fallback: Sequence[int]) -> List[int]:
    """Coerce a parsed ``/proc/<pid>/status`` field to a list of ints, or use the fallback."""
    if isinstance(value, list) and value and all(isinstance(item, int) for item in value):
        return [int(item) for item in value]
    return list(fallback)


def _subject_from_proc(pid: Optional[int], label: str) -> Subject:
    prefix = f"/proc/{pid}" if pid else "/proc/self"
    status_text = _read_text(f"{prefix}/status") or ""
    status = parse_proc_status(status_text)
    own_uid, own_euid, own_gid, own_egid = _own_ids()
    uid_list = _int_list(status.get("Uid"), (own_uid, own_euid, own_euid, own_euid))
    gid_list = _int_list(status.get("Gid"), (own_gid, own_egid, own_egid, own_egid))
    groups = tuple(_int_list(status.get("Groups"), _own_groups()))
    cap_eff = status.get("CapEff")
    caps = decode_cap_mask(cap_eff) if isinstance(cap_eff, str) else None

    selinux = _read_text(f"{prefix}/attr/current")
    selinux_context = selinux.strip() if selinux and "apparmor" not in selinux else None
    apparmor = selinux.strip() if selinux and "apparmor" in selinux else None
    if apparmor:
        apparmor = apparmor.split("(")[0].strip()

    seccomp_text = str(status.get("Seccomp", ""))
    seccomp = int(seccomp_text) if seccomp_text.isdigit() else None
    nnp_text = str(status.get("NoNewPrivs", ""))
    nnp = int(nnp_text) if nnp_text.isdigit() else None

    names = {uid_list[1]: uid_name(uid_list[1])}

    return Subject(
        uid=uid_list[1],  # effective uid is what the kernel checks
        gid=gid_list[1],
        groups=groups,
        caps_eff=caps if caps is not None else frozenset(),
        label=label,
        pid=pid,
        names=names,
        selinux_context=selinux_context,
        apparmor_profile=apparmor,
        seccomp_mode=seccomp,
        no_new_privs=nnp,
    )


def resolve_subject(user: Optional[str] = None, pid: Optional[int] = None) -> Subject:
    """Build the subject of the inquiry: current process, ``--user`` or ``--pid``."""
    if pid is not None:
        if not os.path.isdir(f"/proc/{pid}"):
            raise ValueError(f"no such process: {pid}")
        return _subject_from_proc(pid, f"pid {pid}")
    if user is not None:
        uid, gid, groups = supplementary_groups_of_user(user)
        names = {uid: uid_name(uid)}
        names.update({g: group_name(g) for g in groups})
        return Subject(
            uid=uid,
            gid=gid,
            groups=groups,
            caps_eff=frozenset(),
            label=f"user {user}",
            names={uid: uid_name(uid)},
        )
    subject = _subject_from_proc(None, "current process")
    if not is_linux():
        # /proc is absent: fall back to the interpreter's own credentials.
        own_uid, own_euid, own_gid, own_egid = _own_ids()
        return Subject(
            uid=own_euid,
            gid=own_egid,
            groups=_own_groups(),
            caps_eff=frozenset(),
            label="current process (non-Linux fallback)",
            names={own_euid: uid_name(own_euid)},
        )
    return subject


# --------------------------------------------------------------------------- #
# Target
# --------------------------------------------------------------------------- #


def _is_root_privileged() -> bool:
    if os.name == "nt":  # pragma: no cover - windows only
        return False
    try:
        return os.geteuid() == 0
    except AttributeError:  # pragma: no cover
        return False


def _stat_at(real_path: str, follow: bool = True) -> Optional[os.stat_result]:
    try:
        return os.stat(real_path) if follow else os.lstat(real_path)
    except OSError:
        return None


def collect_target(path: str, fs_root: str = "", base_dir: Optional[str] = None) -> Target:
    """Gather stat data for ``path`` as seen through ``fs_root``.

    ``fs_root`` is a prefix such as ``/proc/1234/root`` used for ``--pid`` so that
    path resolution happens inside the target process's mount namespace.
    ``base_dir`` is used for relative paths (the process's cwd for ``--pid``).
    """
    if not os.path.isabs(path):
        path = os.path.join(base_dir or os.getcwd(), path)
    path = os.path.normpath(path)
    real = os.path.realpath(path)
    stat_path = (fs_root + real) if fs_root else real

    target = Target(path=real, fs_root=fs_root, stat_path=stat_path, parent=os.path.dirname(real.rstrip("/")) or "/")

    link_info = _stat_at(stat_path, follow=False)
    if link_info is not None and statmod.S_ISLNK(link_info.st_mode):
        target.is_symlink = True
        try:
            target.symlink_target = os.readlink(stat_path)
        except OSError:
            target.symlink_target = None

    info = _stat_at(stat_path, follow=True)
    if info is None:
        target.exists = False
    else:
        target.exists = True
        target.mode = statmod.S_IMODE(info.st_mode)
        target.uid = info.st_uid
        target.gid = info.st_gid
        target.uid_name = uid_name(info.st_uid)
        target.gid_name = group_name(info.st_gid)
        target.size = info.st_size
        target.is_dir = statmod.S_ISDIR(info.st_mode)

    # Ancestors: every directory the kernel must traverse, from / down to the parent.
    parts = [p for p in real.split("/") if p]
    current = ""
    for part in parts[:-1]:
        current = f"{current}/{part}"
        info = _stat_at((fs_root + current) if fs_root else current, follow=True)
        if info is None:
            break
        target.ancestors.append((current, statmod.S_IMODE(info.st_mode), info.st_uid, info.st_gid))
    root_info = _stat_at((fs_root + "/") if fs_root else "/", follow=True)
    if root_info is not None:
        target.ancestors.insert(0, ("/", statmod.S_IMODE(root_info.st_mode), root_info.st_uid, root_info.st_gid))
    return target


# --------------------------------------------------------------------------- #
# Mounts, ACLs, attributes
# --------------------------------------------------------------------------- #


def read_mountinfo(pid: Optional[int] = None) -> Tuple[List[Mount], Optional[str]]:
    source = f"/proc/{pid}/mountinfo" if pid else "/proc/self/mountinfo"
    text = _read_text(source)
    if text is None:
        return [], f"could not read {source}"
    return parse_mountinfo(text), None


def read_acl(path: str) -> Tuple[Optional[Acl], Optional[str]]:
    """Read the POSIX access ACL from the xattr, falling back to ``getfacl -n``."""
    reason: Optional[str]
    try:
        blob = os.getxattr(path, ACL_ACCESS_XATTR)
    except (OSError, AttributeError) as exc:
        blob = None
        reason = f"xattr read failed ({exc.__class__.__name__})"
    else:
        reason = None
    if blob:
        try:
            return decode_posix_acl(blob), None
        except ValueError as exc:
            return None, f"could not decode ACL xattr: {exc}"
    text = _run(["getfacl", "-n", "-p", "--", path])
    if text:
        parsed = parse_getfacl(text)
        if parsed.entries:
            return parsed, reason
    return None, reason or "no ACL present"


def read_default_acl(directory: str) -> Tuple[Optional[Acl], Optional[str]]:
    """A directory's default ACL decides the mode of files created inside it."""
    try:
        blob = os.getxattr(directory, ACL_DEFAULT_XATTR)
    except (OSError, AttributeError) as exc:
        return None, f"no default ACL ({exc.__class__.__name__})"
    if not blob:
        return None, "no default ACL"
    try:
        return decode_posix_acl(blob), None
    except ValueError as exc:
        return None, f"could not decode default ACL: {exc}"


def read_fs_flags(path: str) -> Tuple[Optional[int], Optional[str]]:
    """Read ``FS_IOC_GETFLAGS``; fall back to parsing ``lsattr`` output."""
    if is_linux():
        try:
            import fcntl
            import struct as structmod

            flags = 0
            fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
            try:
                buf = fcntl.ioctl(fd, FS_IOC_GETFLAGS, structmod.pack("i", 0))
                flags = structmod.unpack("i", buf)[0]
            finally:
                os.close(fd)
            return flags, None
        except (OSError, ImportError, ModuleNotFoundError) as exc:
            reason = f"ioctl FS_IOC_GETFLAGS failed ({exc.__class__.__name__}: {exc})"
    else:
        reason = "not Linux: file attributes unavailable"
    text = _run(["lsattr", "-d", "--", path])
    if text:
        from .parsers import parse_lsattr

        parsed = parse_lsattr(text)
        for value in parsed.values():
            names = set(value)
            flags = 0
            for bit, name in (
                (0x00000010, "immutable"),
                (0x00000020, "append_only"),
                (0x00000040, "no_dump"),
                (0x00200000, "no_cow"),
                (0x00000800, "encrypted"),
                (0x00020000, "topdir"),
                (0x00040000, "extents"),
                (0x01000000, "projinherit"),
                (0x02000000, "casefold"),
            ):
                if name in names:
                    flags |= bit
            return flags, reason
    return None, reason


def read_uid_map(pid: Optional[int]) -> Tuple[List[Tuple[int, int, int]], Optional[str]]:
    prefix = f"/proc/{pid}" if pid else "/proc/self"
    text = _read_text(f"{prefix}/uid_map")
    if text is None:
        return [], f"could not read {prefix}/uid_map"
    return parse_uid_map(text), None


# --------------------------------------------------------------------------- #
# Evidence: recent kernel denials
# --------------------------------------------------------------------------- #


def read_avc_denials(limit: int = 4000, recent_minutes: int = 30) -> Tuple[List[AvcDenial], List[str]]:
    notes: List[str] = []
    text = _run(["ausearch", "-m", "AVC", "-ts", "recent", "--raw"], timeout=8.0)
    if text:
        return parse_avc_lines(text), notes
    for candidate in ("/var/log/audit/audit.log", "/var/log/audit/audit.log.1"):
        if os.path.exists(candidate):
            data = _read_text(candidate)
            if data is None:
                notes.append(f"{candidate} exists but is not readable (try root)")
                continue
            lines = data.splitlines()[-limit:]
            if candidate.endswith(".log") and len(data.splitlines()) == limit:
                notes.append(f"only the last {limit} lines of {candidate} were inspected")
            return parse_avc_lines("\n".join(lines)), notes
    notes.append("no audit log available (install auditd, or run with root, for SELinux evidence)")
    return [], notes


def read_apparmor_denials(limit: int = 4000) -> Tuple[List[AppArmorDenial], List[str]]:
    notes: List[str] = []
    text = _run(["dmesg", "--ctime"], timeout=5.0)
    if not text:
        text = _run(["journalctl", "-k", "-n", str(limit), "--no-pager"], timeout=8.0)
    if not text:
        notes.append("could not read kernel messages (dmesg/journalctl unavailable or restricted)")
        return [], notes
    lines = "\n".join(text.splitlines()[-limit:])
    return parse_apparmor_denials(lines), notes


# --------------------------------------------------------------------------- #
# Environment
# --------------------------------------------------------------------------- #


def collect_environment() -> Environment:
    env = Environment(
        platform=platform.platform(),
        kernel=platform.release(),
        distro=_distro_name(),
    )
    lsm_text = _read_text("/sys/kernel/security/lsm")
    env.lsm = parse_lsm_list(lsm_text) if lsm_text else []
    if not env.lsm:
        env.degraded.append("could not read /sys/kernel/security/lsm (LSM modules unknown)")

    selinux_path = "/sys/fs/selinux/enforce"
    if os.path.exists(selinux_path):
        value = _read_text(selinux_path)
        env.selinux_enforcing = value is not None and value.strip() == "1"
    else:
        env.selinux_enforcing = None

    profiles = "/sys/kernel/security/apparmor/profiles"
    if os.path.exists(profiles):
        text = _read_text(profiles) or ""
        env.apparmor_profiles = len([line for line in text.splitlines() if line.strip()])
    else:
        env.apparmor_profiles = None

    abi = "/sys/kernel/security/landlock/abi_version"
    if os.path.exists(abi):
        value = _read_text(abi)
        if value and value.strip().isdigit():
            env.landlock_abi = int(value.strip())

    env.container = _detect_container()
    mounts, _ = read_mountinfo()
    for mount in mounts:
        if mount.mount_point == "/":
            env.root_fs_read_only = mount.has("ro")
            break
    if not is_linux():
        env.degraded.append("not running on Linux: only the platform-independent checks are meaningful")
    return env


def _distro_name() -> str:
    text = _read_text("/etc/os-release")
    if not text:
        return platform.system()
    for line in text.splitlines():
        if line.startswith("PRETTY_NAME="):
            return line.split("=", 1)[1].strip().strip('"')
    return platform.system()


def _detect_container() -> Optional[str]:
    if os.path.exists("/run/.containerenv"):
        return "podman"
    if os.path.exists("/.dockerenv"):
        return "docker"
    version = _read_text("/proc/version") or ""
    if "microsoft" in version.lower():
        return "wsl"
    cgroup = _read_text("/proc/self/cgroup") or ""
    if "kubepods" in cgroup:
        return "kubernetes"
    if "docker" in cgroup:
        return "docker"
    if "lxc" in cgroup:
        return "lxc"
    if "libpod" in cgroup:
        return "podman"
    return None


__all__ = [
    "ACL_ACCESS_XATTR",
    "ACL_DEFAULT_XATTR",
    "Environment",
    "collect_environment",
    "collect_target",
    "group_name",
    "is_linux",
    "read_acl",
    "read_apparmor_denials",
    "read_avc_denials",
    "read_default_acl",
    "read_fs_flags",
    "read_mountinfo",
    "read_uid_map",
    "resolve_subject",
    "supplementary_groups_of_user",
    "uid_name",
]
