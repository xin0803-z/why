#!/usr/bin/env bash
# Install `why` without the ceremony.
#
#   curl -fsSL https://raw.githubusercontent.com/xin0803-z/why/main/scripts/install.sh | bash
#   curl -fsSL .../install.sh | bash -s -- --version 0.1.1
#   curl -fsSL .../install.sh | bash -s -- --method pip --prefix "$HOME/.local"
#
# It prefers pipx, then uv, then `pip install --user`. It never uses sudo and never
# touches system Python. There is no index to trust: the wheel is fetched from this
# project's GitHub release (the fallback to PyPI only matters once it is published).
set -euo pipefail

PACKAGE="why-linux"
REPO="${WHY_REPO:-xin0803-z/why}"
VERSION=""
METHOD="auto"
PREFIX="${HOME}/.local"
DRY_RUN=0

usage() {
    cat <<'EOF'
Install why (the `why-linux` distribution).

Usage: install.sh [options]

Options:
  --version VERSION   Install a specific version (default: latest release)
  --method METHOD     auto | pipx | uv | pip   (default: auto)
  --prefix DIR        Where pip puts it (default: ~/.local); pipx/uv put their
                      launcher in DIR/bin
  --dry-run           Print what would happen, change nothing
  -h, --help          This message

Environment:
  WHY_REPO            GitHub owner/repo to download from (default: xin0803-z/why)
EOF
}

log()  { printf '\033[1m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[33mwarning:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
    case "$1" in
        --version) VERSION="${2:-}"; shift 2 ;;
        --version=*) VERSION="${1#*=}"; shift ;;
        --method) METHOD="${2:-}"; shift 2 ;;
        --method=*) METHOD="${1#*=}"; shift ;;
        --prefix) PREFIX="${2:-}"; shift 2 ;;
        --prefix=*) PREFIX="${1#*=}"; shift ;;
        --dry-run) DRY_RUN=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) die "unknown option: $1 (try --help)" ;;
    esac
done

[ -n "$VERSION" ] || VERSION="latest"

# ---------------------------------------------------------------- sanity checks

case "$(uname -s 2>/dev/null || echo unknown)" in
    Linux) : ;;
    *) warn "why explains Linux access checks; this host is $(uname -s). Installing anyway." ;;
esac

PY=""
for candidate in python3 python; do
    if command -v "$candidate" >/dev/null 2>&1; then
        if "$candidate" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 9) else 1)' 2>/dev/null; then
            PY="$candidate"; break
        fi
    fi
done
[ -n "$PY" ] || die "Python 3.9 or newer is required, and was not found in PATH."
log "Using $PY ($("$PY" -c 'import platform; print(platform.python_version())'))"

run() {
    if [ "$DRY_RUN" = "1" ]; then
        printf '    [dry-run] %s\n' "$*"
    else
        "$@"
    fi
}

has() { command -v "$1" >/dev/null 2>&1; }

# ---------------------------------------------------------------- artifact source
# The package is not on PyPI yet, so the artifact comes from the GitHub release: the
# API names the tag, and the wheel name follows from it. Anything that downloads is
# done with curl when it exists and with the standard library otherwise, so the
# installer needs nothing beyond Python and a shell.

BASE="https://github.com/${REPO}"
API="https://api.github.com/repos/${REPO}"

api_tag() {
    if [ "$VERSION" = "latest" ]; then
        url="${API}/releases/latest"
    else
        url="${API}/releases/tags/v${VERSION}"
    fi
    if has curl; then
        curl -fsSL "$url" 2>/dev/null |
            sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1
    else
        "$PY" - "$url" <<'PYEOF' 2>/dev/null || true
import json, sys, urllib.request
try:
    with urllib.request.urlopen(sys.argv[1], timeout=20) as response:
        print(json.load(response).get("tag_name", ""))
except Exception:
    pass
PYEOF
    fi
}

fetch() {
    if has curl; then
        curl -fsSL -o "$2" "$1"
    else
        "$PY" -c 'import sys, urllib.request; urllib.request.urlretrieve(sys.argv[1], sys.argv[2])' "$1" "$2"
    fi
}

index_spec() {
    if [ "$VERSION" = "latest" ]; then printf '%s' "$PACKAGE"; else printf '%s==%s' "$PACKAGE" "$VERSION"; fi
}

tmpdir=""
# Must not return non-zero: a failing command in the EXIT trap would become the
# script's exit status (a --dry-run run sets no tmpdir and exited 1 because of it).
cleanup() {
    if [ -n "$tmpdir" ]; then
        rm -rf "$tmpdir"
    fi
    return 0
}
trap cleanup EXIT INT TERM

SPEC=""
tag="$(api_tag || true)"
if [ -n "$tag" ]; then
    url="${BASE}/releases/download/${tag}/why_linux-${tag#v}-py3-none-any.whl"
    log "Release ${tag}"
    if [ "$DRY_RUN" = "1" ]; then
        printf '    [dry-run] download %s\n' "$url"
        SPEC="$url"
    else
        tmpdir="$(mktemp -d)"
        wheel="${tmpdir}/why_linux-${tag#v}-py3-none-any.whl"
        if fetch "$url" "$wheel"; then
            SPEC="$wheel"
        else
            warn "could not download $url"
            warn "falling back to the package index"
            SPEC="$(index_spec)"
        fi
    fi
else
    warn "no release found for ${REPO} (offline, rate-limited, or no releases yet)"
    warn "falling back to the package index"
    SPEC="$(index_spec)"
fi

# ---------------------------------------------------------------- installation

installed_with=""
if [ "$METHOD" = "auto" ]; then
    if has pipx;  then METHOD="pipx"
    elif has uv;  then METHOD="uv"
    else               METHOD="pip"
    fi
fi

case "$METHOD" in
    pipx)
        has pipx || die "pipx not found. Install it, or use --method pip."
        log "pipx install $SPEC"
        run env PIPX_BIN_DIR="${PREFIX}/bin" pipx install "$SPEC" --force
        installed_with="pipx"
        ;;
    uv)
        has uv || die "uv not found. Install it, or use --method pip."
        log "uv tool install $SPEC"
        run env UV_TOOL_BIN_DIR="${PREFIX}/bin" uv tool install "$SPEC" --force
        installed_with="uv"
        ;;
    pip)
        # PYTHONUSERBASE is what makes --prefix mean something: pip writes the package
        # into $PREFIX/lib/pythonX.Y/site-packages and the `why` script into $PREFIX/bin.
        log "pip install --user $SPEC  (PYTHONUSERBASE=$PREFIX)"
        if [ "$DRY_RUN" = "1" ]; then
            printf '    [dry-run] PYTHONUSERBASE=%s %s -m pip install --user --upgrade %s\n' "$PREFIX" "$PY" "$SPEC"
        else
            PYTHONUSERBASE="$PREFIX" "$PY" -m pip install --user --upgrade "$SPEC"
        fi
        installed_with="pip"
        ;;
    *) die "unknown --method: $METHOD (auto | pipx | uv | pip)" ;;
esac

# ---------------------------------------------------------------- verification

if [ "$DRY_RUN" = "1" ]; then
    log "Dry run complete; nothing was installed."
    exit 0
fi

# Where this Python puts packages relative to a prefix ("lib/pythonX.Y/site-packages"
# on Linux, "Lib/site-packages" on Windows). The launcher itself is located by search
# rather than by guessing: pip nests it differently on some platforms.
purelibdir="$("$PY" -c 'import sysconfig; print(sysconfig.get_path("purelib", vars={"base": "", "platbase": ""}))')"

installed_as=""
launcher=""
if command -v why >/dev/null 2>&1; then
    installed_as="$(why --version)"
else
    launcher="$(find "$PREFIX" -maxdepth 4 \( -type f -o -type l \) \( -name why -o -name why.exe \) 2>/dev/null | head -n 1)"
    if [ -n "$launcher" ]; then
        # Prove the installed command actually runs before claiming success: with a
        # custom --prefix the package may not be on the interpreter's default path yet.
        if version="$(PYTHONPATH="${PREFIX}/${purelibdir}${PYTHONPATH:+:$PYTHONPATH}" "$launcher" --version 2>/dev/null)" && [ -n "$version" ]; then
            installed_as="${version} (${launcher}, not on PATH yet)"
        elif version="$("$launcher" --version 2>/dev/null)" && [ -n "$version" ]; then
            installed_as="${version} (${launcher}, not on PATH yet)"
        fi
    fi
fi

if [ -n "$installed_as" ]; then
    log "Installed: ${installed_as}"
else
    warn "The \`why\` command is not on your PATH yet, and no launcher was found under ${PREFIX}."
    warn "Check the pip output above for where it went."
fi

if [ -n "$launcher" ] && ! command -v why >/dev/null 2>&1; then
    warn "To use it from your shell:"
    warn "  export PATH=\"$(dirname "$launcher"):\$PATH\""
    if [ "$installed_with" = "pip" ] && [ "$PREFIX" != "${HOME}/.local" ]; then
        warn "A custom --prefix is outside Python's default path, so in that shell also:"
        warn "  export PYTHONPATH=\"${PREFIX}/${purelibdir}\${PYTHONPATH:+:\$PYTHONPATH}\""
    fi
fi

cat <<'EOF'

Next steps:
  why layers                     # see the 12 layers, in kernel order
  why denied /etc/shadow         # try it on a real denial
  why denied /srv/data --json    # machine-readable, for scripts and agents

EOF