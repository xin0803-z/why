"""Command line interface for ``why``.

Exit-code contract (documented in the README, relied on by scripts):

===  ==================================================================
0    a denial was explained (``denied`` or ``denied-by-evidence``)
1    usage error, or ``--check`` found the access denied
2    an unexpected internal error occurred
10   no layer in the model denies this access (``allowed``)
11   the verdict could not be established (e.g. not a Linux host)
===  ==================================================================
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import List, Optional, Sequence

from . import __version__
from .checks import run_all
from .collect import collect_environment, collect_target, resolve_subject
from .model import Op, Report, Verdict
from .report import layer_catalog, render_json, render_text, want_color

EXIT_EXPLAINED_DENIED = 0
EXIT_USAGE = 1
EXIT_INTERNAL = 2
EXIT_ALLOWED = 10
EXIT_UNKNOWN = 11

KNOWN_COMMANDS = ("denied", "layers", "version")
DENIED_FLAGS = {"-h", "--help"}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="why",
        description="Explain Linux access denials layer by layer: which layer said no, and why.",
        epilog=(
            "examples:\n"
            "  why denied /etc/shadow\n"
            "  why denied /var/www/html --op write\n"
            "  why denied /srv/data --user www-data\n"
            "  why denied /srv/data --pid 1234\n"
            "  why denied /etc/hosts --json | jq .deciding_layer\n"
            "  why layers\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"why {__version__}")
    sub = parser.add_subparsers(dest="command")

    denied = sub.add_parser(
        "denied",
        help="explain why an access is denied",
        description="Explain why an access is denied, layer by layer.",
    )
    denied.add_argument("path", nargs="?", help="path to inspect (defaults to the cwd of --pid)")
    denied.add_argument(
        "--op",
        choices=[op.value for op in Op],
        default=None,
        help="operation to explain (default: read, or create when the path does not exist)",
    )
    who = denied.add_mutually_exclusive_group()
    who.add_argument("--user", "-u", help="explain the access as this user instead of yourself")
    who.add_argument("--pid", type=int, help="explain the access as this running process, in its own namespace")
    denied.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    denied.add_argument("--check", action="store_true", help="print nothing, only set the exit code")
    denied.add_argument("--no-evidence", action="store_true", help="skip reading audit logs and dmesg")
    denied.add_argument("--color", choices=["auto", "always", "never"], default="auto")
    denied.add_argument("--no-color", action="store_true", help="alias for --color never")
    denied.add_argument("--ascii", action="store_true", help="use ASCII glyphs for terminals without Unicode support")
    denied.add_argument("--verbose", "-v", action="store_true", help="do not truncate the report")

    sub.add_parser("layers", help="list the layers why checks, in order")
    sub.add_parser("version", help="print the version")
    return parser


def _normalize_argv(argv: Sequence[str]) -> List[str]:
    """``why /etc/shadow`` should work like ``why denied /etc/shadow``."""
    args = list(argv)
    if not args:
        return args
    if args[0] in KNOWN_COMMANDS or args[0].startswith("-") or args[0] in DENIED_FLAGS:
        return args
    return ["denied"] + args


def _resolve_view(args: argparse.Namespace) -> tuple:
    """Return ``(subject, base_dir, fs_root, path)`` for the chosen subject."""
    if args.pid is not None:
        if not os.path.isdir(f"/proc/{args.pid}"):
            raise ValueError(f"no such process: {args.pid}")
        subject = resolve_subject(pid=args.pid)
        fs_root = f"/proc/{args.pid}/root"
        try:
            cwd = os.readlink(f"/proc/{args.pid}/cwd")
        except OSError:
            cwd = "/"
        path = args.path or cwd
        return subject, cwd, fs_root, path
    subject = resolve_subject(user=args.user)
    return subject, os.getcwd(), "", args.path


def cmd_denied(args: argparse.Namespace) -> int:
    if not args.path and args.pid is None:
        print("why: a path is required (or use --pid)", file=sys.stderr)
        return EXIT_USAGE
    try:
        subject, base_dir, fs_root, path = _resolve_view(args)
    except ValueError as exc:
        print(f"why: {exc}", file=sys.stderr)
        return EXIT_USAGE

    target = collect_target(path, fs_root=fs_root, base_dir=base_dir)
    if args.op is not None:
        op = Op(args.op)
    else:
        op = Op.CREATE if not target.exists else Op.READ
    env = collect_environment()
    report = run_all(target, subject, op, env=env, gather_evidence=not args.no_evidence)
    if args.op is None and not target.exists:
        report.notes.insert(
            0,
            "the path does not exist, so --op create was assumed: why checked whether you could create it",
        )

    if args.check:
        return _check_exit_code(report)

    if args.json:
        print(render_json(report))
    else:
        color = want_color("never" if args.no_color else args.color)
        print(
            render_text(
                report,
                color=color,
                verbose=args.verbose,
                icons="ascii" if args.ascii else "auto",
            )
        )
    return _exit_code(report)


def _exit_code(report: Report) -> int:
    if report.verdict in (Verdict.DENIED, Verdict.DENIED_BY_EVIDENCE):
        return EXIT_EXPLAINED_DENIED
    if report.verdict is Verdict.ALLOWED:
        return EXIT_ALLOWED
    return EXIT_UNKNOWN


def _check_exit_code(report: Report) -> int:
    """Scriptable gate: 0 when the access is allowed, 1 otherwise (fail closed)."""
    if report.verdict is Verdict.ALLOWED:
        return 0
    if report.verdict is Verdict.UNKNOWN:
        print(
            f"unknown: {report.reason} (could not be established; --check fails closed, "
            "drop --check for the full report)",
            file=sys.stderr,
        )
        return 1
    layer = report.layer(report.deciding_layer) if report.deciding_layer else None
    where = f" (layer {layer.index}: {layer.title})" if layer else ""
    print(f"denied{where}: {report.reason}", file=sys.stderr)
    return 1


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    raw = list(sys.argv[1:] if argv is None else argv)
    args = parser.parse_args(_normalize_argv(raw))

    try:
        if args.command == "layers":
            print(layer_catalog())
            return 0
        if args.command == "version":
            print(f"why {__version__}")
            return 0
        if args.command == "denied":
            return cmd_denied(args)
        parser.print_help()
        return EXIT_USAGE
    except BrokenPipeError:  # pragma: no cover - piping into head
        try:
            sys.stdout.close()
        except OSError:
            pass
        return 0
    except KeyboardInterrupt:  # pragma: no cover
        print("why: interrupted", file=sys.stderr)
        return 130
    except Exception as exc:  # pragma: no cover - defensive
        print(f"why: internal error: {exc.__class__.__name__}: {exc}", file=sys.stderr)
        if os.environ.get("WHY_DEBUG"):
            raise
        return EXIT_INTERNAL


__all__ = [
    "EXIT_ALLOWED",
    "EXIT_EXPLAINED_DENIED",
    "EXIT_INTERNAL",
    "EXIT_UNKNOWN",
    "EXIT_USAGE",
    "build_parser",
    "main",
]
