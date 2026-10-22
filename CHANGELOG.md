# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

_Nothing yet._

## [0.1.0] - 2026-10-22

First release: `why denied`.

### Added

* `why denied PATH` — attribute an access denial to one of 12 layers, in kernel order:
  existence, namespace/sandbox context, capabilities, mount options, `chattr`
  attributes, directory traversal, permission class, POSIX ACL, mode bits, sticky-bit
  delete rule, SELinux policy, AppArmor policy.
* `--op read|write|exec|delete|create` — including the parent-directory semantics of
  create/delete, and automatic `create` when the path does not exist.
* `--user USER` and `--pid PID` — explain an access as another identity, or for a
  running process inside its own mount and user namespace.
* `--json` — stable machine-readable report, one object per layer.
* `--check` — silent mode with a scriptable exit code.
* `--verbose`, `--color`, `--no-color`, `--ascii`, `--no-evidence`.
* Pure-standard-library POSIX ACL decoding from the raw `system.posix_acl_access`
  xattr, including mask evaluation and the `chmod`-rewrites-the-mask trap.
* Capability decoding from `CapEff`, including the container case where uid 0 has no
  privileges and the rule that execute needs one `x` bit.
* File attributes read via `FS_IOC_GETFLAGS` (immutable, append-only, and friends).
* SELinux AVC and AppArmor `DENIED` evidence matching, reported as
  `denied-by-evidence` rather than as a prediction.
* `why layers` — explain the model itself.
* Exit-code contract: `0` explained, `1` usage/`--check` denied, `2` internal,
  `10` allowed, `11` unknown.
* Test suite: 118 unit tests that run on any platform, plus a root-only Linux
  integration suite executed in CI inside Ubuntu, Debian, Fedora, Rocky and Arch
  containers.
* `docs/LAYERS.md` — the kernel behaviour behind each layer.
* `scripts/make_demo.py` — regenerates the README screenshot from the real renderer.

[Unreleased]: https://github.com/xin0803-z/why/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/xin0803-z/why/releases/tag/v0.1.0