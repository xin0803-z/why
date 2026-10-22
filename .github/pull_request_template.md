## What this changes

<!-- One paragraph. What behaviour is different after this PR? -->

## Why

<!-- The failure mode or gap it addresses. Link the issue: Fixes #123 -->

## How it was verified

- [ ] `python -m unittest discover -s tests` passes
- [ ] `ruff check .` and `ruff format --check .` pass
- [ ] New behaviour has a test that fails without the change
- [ ] If it touches kernel behaviour: added a case to `tests/test_linux_integration.py`

<!-- Paste the relevant output, especially for a changed verdict:

$ why denied /path --op write --no-color
...
-->

## Checklist

- [ ] Read-only: nothing in this PR modifies permissions, ACLs, labels or files
- [ ] No new runtime dependency (standard library only)
- [ ] Confidence is labelled honestly (`decisive` only when this run proves it)
- [ ] Collectors degrade instead of raising when the host is not Linux, or lacks root
- [ ] Docs updated: `docs/LAYERS.md` and both README layer tables if a layer changed
- [ ] `CHANGELOG.md` updated under `## [Unreleased]`