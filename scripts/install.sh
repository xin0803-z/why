#!/usr/bin/env bash
# Install `why` without the ceremony.
#
#   curl -fsSL https://raw.githubusercontent.com/xin0803-z/why/main/scripts/install.sh | bash
#   curl -fsSL .../install.sh | bash -s -- --version 0.1.1
#   curl -fsSL .../install.sh | bash -s -- --method pip --prefix "$HOME/.local"
#
# It prefers pipx, then uv, then `pip install --user`. It never uses sudo and never
# touches system Python.
set -euo pipefail

PACKAGE="why-linux"
VERSION=""
METHOD="auto"
PREFIX="${HOME}/.local"
DRY_RUN=0

usage() {
    cat <<'EOF'
Install why (the `why-linux` distribution).

Usage: install.sh [options]

Options:
  --version VERSION   Install a specific version (default: latest)
  --method METHOD     auto | pipx | uv | pip   (default: auto)
  --prefix DIR        Installation prefix for the pip method (default: ~/.local)
  --dry-run           Print what would happen, change nothing
  -h, --help          This message
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
SPEC="${PACKAGE}"
[ "$VERSION" = "latest" ] || SPEC="${PACKAGE}==${VERSION}"

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
        run pipx install "$SPEC" --force
        installed_with="pipx"
        ;;
    uv)
        has uv || die "uv not found. Install it, or use --method pip."
        log "uv tool install $SPEC"
        run uv tool install "$SPEC" --force
        installed_with="uv"
        ;;
    pip)
        log "pip install --user $SPEC  (prefix: $PREFIX)"
        if [ "$DRY_RUN" = "1" ]; then
            printf '    [dry-run] %s -m pip install --user --upgrade %s\n' "$PY" "$SPEC"
        else
            "$PY" -m pip install --user --upgrade "$SPEC"
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

if command -v why >/dev/null 2>&1; then
    log "Installed: $(why --version)"
else
    warn "The \`why\` command is not on your PATH yet."
    case "$installed_with" in
        pip)
            warn "Add pip's user bin directory, then restart your shell:"
            warn "  export PATH=\"\$($PY -m site --user-base)/bin:\$PATH\""
            ;;
        *) warn "Restart your shell so the tool directory is picked up." ;;
    esac
fi

cat <<'EOF'

Next steps:
  why layers                     # see the 12 layers, in kernel order
  why denied /etc/shadow         # try it on a real denial
  why denied /srv/data --json    # machine-readable, for scripts and agents

EOF