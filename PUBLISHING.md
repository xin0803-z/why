# Publishing checklist

> **Status: published.** This repository lives at
> <https://github.com/xin0803-z/why>. The `OWNER` placeholder was replaced with
> `xin0803-z` everywhere, and the repository was created and pushed with the GitHub
> REST API on 2026-10-22. The generic steps below are kept as a reference for
> publishing future repositories.

Everything in this repository is ready to push, except for one placeholder:
`OWNER` (in `pyproject.toml` URLs, both READMEs, `CHANGELOG.md`,
`.github/ISSUE_TEMPLATE/config.yml`). Replace it with your GitHub username before
the first push.

> **Watch out when automating this.** `OWNER` is a substring of `CAP_FOWNER` and
> `CAP_IPC_OWNER`, which appear in `src/why/dac.py`, `src/why/parsers.py`,
> `docs/LAYERS.md` and `src/why/checks/system_layers.py`. A naive
> search-and-replace corrupts them (`CAP_Fxin0803-z`) and the capability checks stop
> matching. Replace only the standalone token — in PowerShell,
> `[regex]'\bOWNER\b'`; with `sed`, `s/\bOWNER\b/<you>/g` — and then review
> `git diff` before committing.

## 1. Replace OWNER

PowerShell, from the repository root:

```powershell
$me = "your-github-username"
Get-ChildItem -Recurse -File -Include *.md,*.toml,*.yml,*.json |
  Where-Object { $_.FullName -notmatch '\\\.git\\' } |
  ForEach-Object {
    $t = Get-Content -Raw $_.FullName
    if ($t -match 'OWNER') { Set-Content -NoNewline $_.FullName ($t -replace 'OWNER', $me) }
  }
```

Or on Linux/macOS:

```bash
grep -rl OWNER --exclude-dir=.git . | xargs sed -i "s/OWNER/your-github-username/g"
```

Sanity check afterwards: `grep -rn OWNER --exclude-dir=.git .` should print nothing.

## 2. Create the repository and push

Git is not installed on the machine this project was authored on, so the first push
has to happen after installing it ([Git for Windows](https://git-scm.com/download/win)):

```bash
cd why
git init -b main
git add -A
git commit -m "feat: why denied — attribute a Linux access denial to one of 12 layers"
git remote add origin https://github.com/<you>/why.git
git push -u origin main
```

Verify the line endings survived (the shell script and the workflow files must stay
LF): `git ls-files --eol scripts/install.sh` should show `w/lf`.

With the GitHub CLI the same thing is one command:

```bash
gh repo create why --public --source=. --push
```

## 3. Repository settings worth setting before announcing

| Setting | Value | Why |
| ------- | ----- | --- |
| Description | `Explain a Linux "Permission denied": which of 12 layers denied you, with evidence and a fix.` | it is the search result |
| Topics | `linux`, `permissions`, `acl`, `capabilities`, `selinux`, `apparmor`, `sysadmin`, `troubleshooting`, `cli`, `devops` | topic pages are real discovery traffic |
| Website | the repo README anchor for install | keeps the top of the page tidy |
| Discussions | enabled | gives `why slow` / `why port` debates a home |
| Releases | tag `v0.1.0` on the first commit | triggers `.github/workflows/release.yml` |

```bash
gh repo edit <you>/why --description "Explain a Linux \"Permission denied\": which of 12 layers denied you, with evidence and a fix." \
  --add-topic linux --add-topic permissions --add-topic acl --add-topic capabilities \
  --add-topic selinux --add-topic apparmor --add-topic sysadmin --add-topic cli
gh release create v0.1.0 --generate-notes
```

## 4. Confirm CI is green

The first push runs four jobs: `unit` (3.9–3.13), `integration` (Ubuntu, Debian,
Fedora, Rocky, Arch containers, as root), `lint` and `package`. The integration job
is the real Linux test bed — check it before telling anyone about the project.
The CI badge in the README starts working at the same moment.

## 5. Optional: publish to PyPI

`pyproject.toml` is already a valid PEP 621 metadata file, and `.github/workflows/release.yml`
contains a commented-out `publish-pypi` job that uses Trusted Publishing (no API
token stored anywhere):

1. Create the `why-linux` project on PyPI as a *pending publisher* for
   `<you>/why` / workflow `release.yml` / environment `pypi`.
2. Create an environment named `pypi` in the repository settings.
3. Uncomment the `publish-pypi` job, then push a tag: `git tag v0.1.0 && git push --tags`.

After that, `pipx install why-linux` works for everyone and the install section of
the README becomes one line.

## 6. Launch notes (what actually earns stars)

The project's advantage is that the output *is* the marketing: every screenshot
answers a question people have already typed into a search engine. In rough order of
return:

1. **A gif or screenshot in the first screen** — already in `docs/demo.png`; record a
   real terminal gif before posting anywhere, since a live denial is more convincing
   than a fixture.
2. **Answer real questions with it.** Search the `permission denied` questions on
   Server Fault, Stack Overflow, r/linuxquestions, r/sysadmin and the Fedora/Ubuntu
   forums. Post the tool only where its output actually answers the question.
3. **One long-form post** based on `docs/LAYERS.md` ("the 12 places a Linux permission
   denial hides"), with the repo linked at the end — this is the piece that gets
   shared.
4. **Timing**: Hacker News (Show HN) on a weekday morning US time; cross-post to
   r/linux and r/sysadmin the same week, then Fedora Magazine / LWN tips / the
   `#linux` communities for the second wave.
5. **Ask for the failure that is still unexplained.** The `why slow` / `why port` /
   `why disk` roadmap is the hook for a second wave of attention — an issue asking
   for one of them is the signal to build it.

## 7. Ground rules to keep the project credible

* Never claim a MAC denial that was not matched against a real audit record — the
  `denied-by-evidence` label exists exactly for this.
* Keep the layer order in `docs/LAYERS.md`, the README table and `checks/__init__.py`
  in sync; a reviewer will notice.
* Keep the test count honest in the docs (currently 119 unit tests plus the
  root-only integration suite).
* Re-run `python scripts/make_demo.py` after any change to the renderer so the
  screenshot never lies about the output.