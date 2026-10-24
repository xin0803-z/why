# why

**Permission denied — but which layer denied you, and how do you fix it?**

[![CI](https://github.com/xin0803-z/why/actions/workflows/ci.yml/badge.svg)](https://github.com/xin0803-z/why/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](pyproject.toml)
[![Zero dependencies](https://img.shields.io/badge/dependencies-0-brightgreen.svg)](pyproject.toml)
[![Platform: Linux](https://img.shields.io/badge/platform-linux-lightgrey.svg)](#limits-stated-plainly)

`why` walks an access attempt through every layer the Linux kernel checks — path traversal, ownership, mode bits, POSIX ACLs and their mask, capabilities, `chattr` attributes, mount options, namespaces, SELinux and AppArmor — and tells you which one said no.

Most "permission denied" tickets are not about the mode bits you can see with `ls -l`. They are about the `x` bit on a grandparent directory, an ACL mask that a `chmod` silently rewrote, a container whose root is not root, or a file marked immutable. `why` checks them in the order the kernel applies them.

![why denied /etc/shadow](docs/demo.png)

<sub>Example output — regenerate it with `python scripts/make_demo.py`.</sub>

```console
$ why denied /etc/shadow
verdict DENIED (layer 9: Permission bits)
reason  need r--; effective --- via mode:other (uid 1000 is not the owner and none of
        groups [27, 1000] is gid 42; other bits are ---)
fix     sudo setfacl -m u:1000:r-- /etc/shadow   # grants only uid 1000
        sudo usermod -aG 42 alice   # then log out and back in, or use a fresh login shell
```

---

## Install

Two ways, both straight from this repository (the distribution is **not on PyPI yet**):

```bash
# 1. the installer - fetches the release wheel, then hands it to pipx, uv or pip
curl -fsSL https://raw.githubusercontent.com/xin0803-z/why/main/scripts/install.sh | bash

# 2. or take the wheel yourself, so you can see exactly what you are installing
#    https://github.com/xin0803-z/why/releases/latest
pip install --user ./why_linux-<version>-py3-none-any.whl
```

From source (no dependencies beyond the standard library):

```bash
git clone https://github.com/xin0803-z/why && cd why
pipx install .
```

> The distribution is named `why-linux` because `why` was taken on PyPI; the command is always `why`.
> `pipx install why-linux` and friends will work the moment it is published there — until then the
> installer and the release wheel above are the supported routes, and `scripts/install.sh --dry-run`
> shows every command it would run.

Requires Python 3.9+ (RHEL 9's Python is fine). **Zero runtime dependencies.** Runs read-only: `why` never changes a permission, a label or a file — it only prints the commands you could run.

## Quick start

```bash
why denied /etc/shadow                      # why can't I read this?
why denied /etc/shadow --op write           # ... or write it?
why denied /var/www/html/new.txt --op create  # can I create this? (missing paths switch to create)
why denied /srv/data --user www-data        # explain it as another user
why denied /srv/data --pid 1234             # explain it for a running process, in its own namespace
why denied /etc/hosts --json | jq .deciding_layer
why denied /srv/data --check                # silent; exit 1 when denied, for scripts
why layers                                  # the 12 layers, in kernel order
```

### As a script

```bash
if why denied /backup/dump.sql --check; then
  echo "backup is readable"
else
  echo "backup would be denied"; why denied /backup/dump.sql   # prints the full story
fi
```

`--check` fails closed: an undetermined verdict (exit `11` normally) also returns `1`,
because a gate should not pass on a question it could not answer. It reports `unknown`
on stderr rather than claiming a denial.

| Exit code | Meaning |
| --------- | ------- |
| `0` | a denial was explained (`denied`, or `denied-by-evidence` from kernel audit records) |
| `1` | usage error, or `--check` found the access denied |
| `2` | internal error |
| `10` | no layer in the model denies this access |
| `11` | verdict could not be established (e.g. not a Linux host) |

## The 12 layers

| # | Layer | The trap it catches |
| - | ----- | ------------------- |
| 1 | Does the entry exist? | `ENOENT` dressed up as a permission problem; dangling symlinks |
| 2 | Namespace and sandbox context | container root that is not host root, `no_new_privs`, seccomp, Landlock |
| 3 | Capabilities | `--cap-drop=ALL` removes root's bypass; `CAP_DAC_READ_SEARCH` grants read but not write |
| 4 | Mount options | `ro` (that's `EROFS`, not `EACCES`), `noexec` (that *is* `EACCES`), `nosuid`, NFS `root_squash` |
| 5 | File attributes | `chattr +i` denies **even root**; `+a` allows append but not overwrite |
| 6 | Directory traversal | the missing `x` on a grandparent directory |
| 7 | Which permission class applies? | you are in the wrong group — the group bits *would* have allowed it |
| 8 | POSIX ACL | a `chmod` silently rewrote the ACL mask and stripped the grant |
| 9 | Permission bits | the plain mode/owner decision, root rules included |
| 10 | Sticky-bit delete rule | `/tmp` semantics: only the file owner, the directory owner or root may delete |
| 11 | SELinux policy | an AVC `denied` record that matches your target |
| 12 | AppArmor policy | a `DENIED` record from the profile the subject runs under |

Every layer reports its evidence, and the verdict names the deciding layer.
[docs/LAYERS.md](docs/LAYERS.md) explains the kernel behaviour behind each one — and
the failure each layer exists to catch.

### Honesty about confidence

`why` distinguishes what it *knows* from what it *suspects*:

* **decisive** — decided by this run. The kernel must refuse (mode bits, `x` on a parent, `ro`, immutable, sticky).
* **evidence** — a recent kernel denial record (SELinux AVC, AppArmor) matches this path. Reported as `denied-by-evidence`, never as a prediction.
* **advisory** — context worth knowing, such as "SELinux is enforcing and could still deny this; no record found".

`why` cannot see inside another process's Landlock ruleset, or on the server side of an NFS mount. It says so instead of guessing.

## JSON output

```console
$ why denied /etc/shadow --json
{
  "tool": "why",
  "version": "0.1.0",
  "verdict": "denied",
  "deciding_layer": "mode",
  "reason": "need r--; effective --- via mode:other (...)",
  "subject": { "uid": 1000, "gid": 1000, "groups": [1000, 27], "caps_eff": [] },
  "target": { "path": "/etc/shadow", "mode": 416, "mode_string": "-rw-r-----", "uid": 0, "gid": 42 },
  "layers": [ { "id": "exists", "index": 1, "status": "ok", "confidence": "decisive", ... } ],
  "fixes": ["sudo setfacl -m u:1000:r-- /etc/shadow"]
}
```

Stable field names, one object per layer, suitable for CI gates and for handing to an AI agent.

## How it compares

| Tool | What it answers |
| ---- | --------------- |
| `ls -l`, `stat` | what the mode bits are |
| `namei -l` | the modes of every path component (no ACLs, no roots, no mounts) |
| `getfacl` | the ACL entries (you evaluate the mask yourself) |
| `lsattr` | the file attributes (only if you thought to run it) |
| `ausearch`, `audit2why` | SELinux denials (only SELinux) |
| `strace` | which syscall failed (not why) |
| **`why`** | **which of the 12 layers denied you, with evidence and a fix** |

## Limits, stated plainly

* MAC prediction is not possible from user space: `why` decides DAC and cites MAC evidence.
* Landlock/BPF policies inside another process cannot be read.
* ACLs are read from the raw `system.posix_acl_access` xattr (no `getfacl` needed), falling back to `getfacl -n` when the xattr is unavailable.
* Symbolic ACL names that cannot be resolved to ids are reported as unresolvable rather than guessed.
* Kernel-facing behaviour is verified by the CI integration matrix (Ubuntu, Debian, Fedora, Rocky, Arch containers, as root). The unit suite runs everywhere.

## Roadmap

`why` is designed as a family of "explain the failure" subcommands. `denied` is the first:

* `why slow` — boot/reload regression attribution (`systemd-analyze blame` does not explain causality)
* `why port` — who holds this port, plumbed back to the unit/container that started it
* `why disk` — what grew, and what owns it

Vote with a 👍 on the issue or open a PR.

## Contributing

Bug reports that include `why denied ... --json --verbose` output are the most useful thing you can send. See [CONTRIBUTING.md](CONTRIBUTING.md); the CI workflow runs the unit suite on Python 3.9–3.13 and the kernel-facing tests inside five distro containers.

## License

MIT — see [LICENSE](LICENSE).

<sub>中文说明见 [README.zh-CN.md](README.zh-CN.md)。</sub>