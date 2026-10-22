# The 12 layers, in the order the kernel applies them

This is the document `why` is built on. Each section explains what the kernel
actually does, the classic failure that hides there, how to reproduce the check by
hand, and what `why` does about it.

A useful mental model: a `Permission denied` (`EACCES`) is the *end* of a decision
chain, and different layers can end it long before the mode bits are ever
consulted.

---

## 1. Does the entry exist?

`ENOENT` and `EACCES` are different failures with the same user-visible shrug. A
dangling symlink is the classic confusion: `ls -l` shows a link, the target is
gone, and the error text talks about permissions.

```bash
stat /path/to/thing        # "No such file or directory" is NOT a permission problem
readlink -f /path/to/link  # resolve a symlink chain by hand
```

**What `why` does:** reports the deepest missing component, and distinguishes a
missing target from a dangling symlink. For `--op create` it reports `EEXIST` when
the entry already exists.

## 2. Namespace and sandbox context

Since Linux 3.8, uid 0 inside a user namespace is not the host's uid 0. In
rootless containers (`podman`, `docker --userns`, `systemd-nspawn`) the mapping is
usually `0 -> 100000`: the file you are staring at is owned by the *host's* root,
which is not you.

```bash
cat /proc/self/uid_map          # 0  100000  65536  means "my root is host uid 100000"
cat /proc/self/status | grep -E 'Cap|Seccomp|NoNewPrivs'
cat /sys/kernel/security/lsm    # lockdown,yama,integrity,selinux,landlock,bpf
```

**What `why` does:** reports the mapping, seccomp mode, `no_new_privs`, the
Landlock ABI and the container flavour. If uid 0 maps to a non-zero host id, it
says so, because that single fact explains a whole class of "permission denied in
a container" tickets.

## 3. Capabilities

The kernel does not have a "root bypass"; it has `CAP_DAC_OVERRIDE`,
`CAP_DAC_READ_SEARCH` and `CAP_FOWNER`. A root process with
`--cap-drop=ALL` or a restrictive `CapabilityBoundingSet=` is *not* privileged for
file access:

```bash
grep Cap /proc/self/status     # CapEff is what matters, not uid 0
capsh --decode=$(grep CapEff /proc/self/status | awk '{print $2}')
```

Two details that surprise people:

* `CAP_DAC_OVERRIDE` still does not grant execute when **no** `x` bit is set on the
  file. The kernel requires at least one execute bit.
* `CAP_DAC_READ_SEARCH` grants read and directory search (`x` on directories) but
  never write.

**What `why` does:** decodes `CapEff`, explains which DAC decisions are bypassed
and which are not, and warns when uid 0 has no capabilities at all.

## 4. Mount options

Some denials never reach the permission bits:

| Option | Failure | Notes |
| ------ | ------- | ----- |
| `ro` | `EROFS` | not a permission problem at all |
| `noexec` | `EACCES` | the `x` bit is set and it still will not run |
| `nosuid` | (no denial) | silently ignores setuid/setgid |
| `nodev` | `EACCES` | device nodes on this mount do not work |

Network filesystems add a second authority: with NFS `root_squash`, root on the
client is `nobody` on the server; `all_squash` does that to everyone. FUSE
filesystems may implement their own permission model (`allow_other`,
`default_permissions`).

```bash
findmnt -T /path/to/thing      # which mount backs this path, and with what options
cat /proc/self/mountinfo
```

**What `why` does:** resolves the longest-prefix mount for the target (or for the
parent, when creating or deleting), and reports `ro`/`noexec` as decisive denials.
For `noexec` it suggests the workaround that actually works:
`bash script.sh` / `python3 tool.py`.

## 5. File attributes (`chattr`)

`chattr +i` makes a file unwritable **even for root**, and undeletable, and
unrenamable — until the flag is removed with `CAP_LINUX_IMMUTABLE`. Append-only
(`+a`) permits `>>` but not overwriting or deletion. `lsattr` is the only
user-visible clue, and only if you thought to run it.

```bash
lsattr /path/to/thing
sudo chattr -i /path/to/thing     # needs CAP_LINUX_IMMUTABLE
```

**What `why` does:** reads the flags directly with `FS_IOC_GETFLAGS` (no `lsattr`
binary needed), decodes them, and denies decisively on `immutable`/`append_only`
when the operation is blocked.

## 6. Directory traversal

To open `/a/b/c`, the kernel needs `x` (search) on `/a` **and** `/a/b`. Nothing
about `/a/b/c`'s own mode matters if a parent refuses traversal. This is the single
most common cause of a denial that `ls -l` on the file cannot explain.

```bash
namei -l /a/b/c          # modes of every component (no ACLs, no root rules)
namei -mo /a/b/c         # as another user, if you have namei from util-linux
```

**What `why` does:** walks every component down to the parent, checks `x` with the
subject's real identity **and with each directory's ACL consulted** — because
`setfacl -m u:alice:x /home` is a legitimate way to grant traversal, and ignoring
it would produce a confidently wrong answer. It reports the first component that
refuses, by name.

## 7. Which permission class applies to you?

The mode bits are three triads: owner, group, other. Exactly one of them applies,
chosen in that order:

1. `uid == st_uid` → user bits
2. `st_gid` in your groups (effective gid or supplementary) → group bits
3. otherwise → other bits

The trap: a file with `-rw-r-----  root:shadow` looks "readable" if you assume you
are in the group. You are not; group membership is resolved at **login time**, so
`usermod -aG` requires a new session.

```bash
id                       # your real group list, as the kernel sees it
stat -c '%U %G %A' file
```

**What `why` does:** names the class that applies and why, and when the group bits
*would* have allowed the access, it says so explicitly and suggests the `usermod`
line. That one message resolves a large share of real tickets.

## 8. POSIX ACLs, and the mask trap

An extended ACL adds named users/groups, and — crucially — a **mask**. When a
mask exists, the group triad in the mode bits *is* the mask. So this innocent line

```bash
chmod g-w file        # on a file with an ACL
```

does not only change the group; it rewrites the mask to `r--` and silently strips
the write permission from every named user entry and the owning group. The ACL
entries still *look* correct in `getfacl`.

```bash
getfacl -n file       # look at mask::, then remember that `ls -l`'s group triad prints it
setfacl -m m::rw file # repair the mask
```

POSIX evaluation order (simplified): owner entry (mask ignored) → named user
(masked) → union of matching group-class entries (masked) → other (mask ignored).

**What `why` does:** decodes the raw `system.posix_acl_access` xattr itself (a
16-byte-per-entry little-endian structure — no `getfacl` dependency), evaluates the
ACL for your uid/groups, applies the mask, and warns when the mode's group triad
and the ACL mask disagree. Symbolic names it cannot resolve to ids are reported as
unresolvable instead of being guessed.

## 9. Permission bits

Now the ordinary decision, with the two rules people forget:

* **root:** `CAP_DAC_OVERRIDE` bypasses read/write, but execute still needs one `x`
  bit; `CAP_DAC_READ_SEARCH` bypasses read and directory search.
* **write vs create:** writing *to* a file needs `w` on the file; creating,
  renaming or deleting an entry needs `w`+`x` on the **parent directory**.

```bash
stat -c '%A %a %U:%G' file
namei -l path
```

**What `why` does:** computes the decision from the mode, the applying class, the
ACL (if extended) and the capabilities — and picks the operation-appropriate object
(the parent directory for `create`/`delete`). It prints a least-privilege fix first
(`setfacl -m u:<uid>:<perms>`) and the blunt one second (`chmod o+…`).

## 10. The sticky-bit delete rule

In a sticky directory (`/tmp`, mode `1777`) only the file's owner, the directory's
owner, or root may delete or rename an entry — regardless of `w` on the directory.

```bash
stat -c '%A %U' /tmp
```

**What `why` does:** applies the rule for `--op delete` and explains which of the
three conditions failed.

## 11. SELinux

SELinux can deny an access that every DAC check allows. Denials appear as `AVC`
records; without `auditd` (or root) you may not be able to read them.

```bash
getenforce
sudo ausearch -m AVC -ts recent
ls -Z /path/to/thing        # the file's context
restorecon -v /path/to/thing
```

**What `why` does:** reads the enforcement state, the file's `security.selinux`
context, and recent AVC records (`ausearch`, or the tail of
`/var/log/audit/audit.log`), then matches them against the target by full path or
basename. A match is reported as **evidence**, never as a prediction: it labels the
finding `denied-by-evidence` so scripts and humans know the difference.

## 12. AppArmor

Path-based confinement. Denials show up in the kernel ring buffer, not in an audit
log:

```bash
sudo aa-status
sudo dmesg | grep -i 'apparmor.*DENIED'
cat /proc/self/attr/current     # the profile this process runs under
```

**What `why` does:** reads the subject's profile, scans `dmesg` (falling back to
`journalctl -k`) for `apparmor="DENIED"` records, matches the path, and reports the
denied mask together with `aa-complain` for triage.

---

## Why the order matters

The layers are printed in kernel order, so the report reads causally: the first
decisive `DENY` is the reason. Layers 11 and 12 come last because they are the only
ones that cannot be decided from user space — they can only be *evidenced*.

## What `why` still cannot see

* Landlock and BPF LSM rulesets inside another process.
* The server side of a network filesystem.
* Whether a denial you saw ten minutes ago is the one you are hitting now.
* Anything that happens between its `stat()` calls and your next command (no tool
  can close that race).

It reports these gaps rather than filling them with a guess.