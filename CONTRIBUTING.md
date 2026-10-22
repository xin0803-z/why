# Contributing to why

Thanks for helping. This project has one job — explain an access denial correctly —
so correctness beats features, and an honest "I cannot tell" beats a confident guess.

## Development setup

```bash
git clone https://github.com/xin0803-z/why && cd why
python3 -m venv .venv && . .venv/bin/activate     # Windows: .venv\Scripts\activate
python -m pip install -e .                        # no runtime dependencies
python -m unittest discover -s tests -v           # 119 tests, ~0.2s
```

Optional, what CI runs as well:

```bash
python -m pip install ruff mypy pyyaml
ruff check .
ruff format --check .
mypy                                              # configured in pyproject.toml
python scripts/check_configs.py                    # workflows, issue templates, devcontainer
```

The kernel-facing integration tests need root on Linux (they create files, ACLs and
mounts in a temp directory):

```bash
sudo python3 -m unittest discover -s tests -p "test_linux_integration.py" -v
```

They skip themselves everywhere else, so you can run the whole suite on macOS or
Windows and still get a clean result.

### Developing on Windows or macOS

The kernel-facing behaviour can only be verified on Linux. Two easy options:

* **Dev container** — open the repo in VS Code and "Reopen in Container"
  (`.devcontainer/` is configured with `acl`, `e2fsprogs` and `util-linux`).
* **CI** — push a branch; the `integration` job runs the suite as root inside
  Ubuntu, Debian, Fedora, Rocky and Arch containers.

On non-Linux hosts `why` still runs and reports which layers it could not evaluate
(`why denied /some/path -v` lists them under `degraded`).

## Design rules

1. **Read-only.** `why` never modifies a permission, a label, an ACL or a file. It
   prints the commands a human could run. Any PR that `chmod`s something is rejected.
2. **Never crash.** Collectors degrade (missing `/proc`, no root, no `getfacl`, not
   Linux) and record *why* in `Environment.degraded`. A layer must return a
   `LayerResult`, never raise — `run_layers()` wraps them, but do not rely on it.
3. **Honest confidence.** `Confidence.DECISIVE` means "this run proves the kernel
   refuses". Anything inferred from logs is `EVIDENCE`; context is `ADVISORY`.
   Never label a guess as decisive.
4. **Pure logic goes in `parsers.py` / `dac.py`.** Those modules must not touch the
   filesystem, so they stay unit-testable on any platform. Only `collect.py` talks
   to the live system.
5. **Zero runtime dependencies.** Standard library only. Pillow is allowed in
   `scripts/` (development tooling).
6. **Explain, do not dump.** Every layer ends with a sentence a human can act on,
   and a `fix` when there is one.

## Adding a layer

1. Write the function in `checks/dac_layers.py` (DAC) or `checks/system_layers.py`
   (system/MAC) with the signature `layer_x(ctx: CheckContext, index: int) -> LayerResult`.
2. Register it in `PIPELINE` and add `(id, title)` to `LAYER_META` in
   `checks/__init__.py` — the index in the report, the `why layers` output and the
   tests all derive from those two tuples.
3. Add a fixture-based test in `tests/test_layers.py`. Use `tests/support.py`
   builders instead of the real filesystem.
4. If it depends on kernel behaviour, add a case to
   `tests/test_linux_integration.py` (skipped unless root on Linux).
5. Document it in `docs/LAYERS.md` and in both READMEs' layer table.

## Adding a parser

Parsers are pure and heavily tested, which is where most of the risk lives:

1. Add the function to `src/why/parsers.py`, with a docstring describing the exact
   input format (kernel header, man page, or the tool that produced it).
2. Export it in `__all__`.
3. Add tests with **real** input samples in `tests/test_parsers.py`, including a
   malformed-input case. Real `mountinfo`/`getfacl`/`audit.log` snippets are best;
   note where the sample came from.

## Commit and PR style

* Conventional-commit prefixes: `feat:`, `fix:`, `docs:`, `test:`, `chore:`.
* One logical change per PR; update `CHANGELOG.md` under `## [Unreleased]`.
* A PR that changes behaviour needs a test that fails before it and passes after.

GitHub Actions runs `unit` (Python 3.9–3.13), `integration` (5 distro containers as
root), `lint` (ruff check + format) and `package` (build the wheel, install it, run
`why --version`, `why layers` and a JSON round-trip).

## Reporting a bug

The single most useful thing to attach:

```bash
why denied /the/path/that/fails --json --verbose > why-report.json
```

plus your distro, `uname -a`, and whether you run in a container. Please redact
paths you consider sensitive — the report includes them verbatim.