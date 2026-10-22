#!/usr/bin/env python3
"""Regenerate ``docs/demo.png``: a terminal-style screenshot of the real renderer.

The image is produced by :func:`why.report.render_text` (production code) fed with
the fixture from ``tests/support.py``, so the layout, colours and wording in the
README are exactly what the tool prints. Pillow is a development-only dependency:

    python -m pip install Pillow
    python scripts/make_demo.py

Run it from the repository root.
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path
from typing import List, Sequence, Tuple

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

os.environ["COLUMNS"] = "118"  # harmless fallback when stdout is not a terminal

import support  # noqa: E402

from why.report import render_text  # noqa: E402

WIDTH = 118  # the report wraps to this many columns in the generated image

try:
    from PIL import Image, ImageDraw, ImageFont
except ImportError:  # pragma: no cover
    print("Pillow is required: python -m pip install Pillow", file=sys.stderr)
    raise SystemExit(1) from None

FONT_CANDIDATES = (
    "C:/Windows/Fonts/consola.ttf",
    "C:/Windows/Fonts/cour.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
    "/usr/share/fonts/TTF/DejaVuSansMono.ttf",
    "/usr/share/fonts/truetype/liberation/LiberationMono-Regular.ttf",
    "/System/Library/Fonts/Menlo.ttc",
)

ANSI_RE = re.compile(r"\x1b\[([0-9;]*)m")
CODE_MAP = {
    "0": "reset",
    "1": "bold",
    "2": "dim",
    "31": "red",
    "32": "green",
    "33": "yellow",
    "34": "blue",
    "36": "cyan",
    "90": "grey",
}

BACKGROUND = (15, 18, 22)
TITLE_BAR = (27, 31, 39)
DEFAULT_FG = (214, 216, 220)
COLORS = {
    "red": (255, 106, 106),
    "green": (94, 214, 130),
    "yellow": (240, 200, 90),
    "cyan": (110, 200, 235),
    "blue": (128, 168, 255),
    "grey": (128, 136, 148),
    "dim": (128, 136, 148),
}
BOLD = (255, 255, 255)

TITLE = "why denied /etc/shadow"
FOOTER = "example output - regenerate with: python scripts/make_demo.py"

Run = Tuple[str, Tuple[str, ...]]


def load_font(size: int) -> ImageFont.FreeTypeFont:
    for candidate in FONT_CANDIDATES:
        if Path(candidate).exists():
            try:
                return ImageFont.truetype(candidate, size)
            except OSError:
                continue
    print("warning: no TrueType monospace font found, using the bitmap default", file=sys.stderr)
    return ImageFont.load_default()


def parse_ansi(text: str) -> List[List[Run]]:
    lines: List[List[Run]] = []
    for raw in text.split("\n"):
        runs: List[Run] = []
        keys: Tuple[str, ...] = ()
        position = 0
        for match in ANSI_RE.finditer(raw):
            if match.start() > position:
                runs.append((raw[position : match.start()], keys))
            for code in [item for item in match.group(1).split(";") if item]:
                key = CODE_MAP.get(code)
                if key == "reset":
                    keys = ()
                elif key:
                    keys = tuple(sorted(set(keys + (key,))))
            position = match.end()
        if position < len(raw):
            runs.append((raw[position:], keys))
        lines.append(runs)
    return lines


def pick_color(keys: Sequence[str]) -> Tuple[int, int, int]:
    for key in ("red", "green", "yellow", "cyan", "blue", "grey", "dim"):
        if key in keys:
            return COLORS[key]
    if "bold" in keys:
        return BOLD
    return DEFAULT_FG


def main() -> int:
    report = support.denied_report()
    report.notes = [
        "SELinux is permissive: denials are logged, not enforced",
        "no container detected; no user namespace mapping",
    ]
    text = render_text(report, color=True, verbose=True, icons="ascii", width=WIDTH)
    lines = parse_ansi(text)

    font = load_font(15)
    bold_title_font = load_font(13)
    line_height = 21
    padding = 18
    title_height = 38

    char_width = max(font.getlength("M"), 1.0)
    columns = max(len(line_text(raw)) for raw in text.split("\n"))
    body_width = int(columns * char_width) + 2 * padding
    width = max(body_width, 760)
    body_height = line_height * len(lines)
    footer_height = int(line_height * 1.6)
    height = title_height + padding + body_height + footer_height + padding

    image = Image.new("RGB", (width, height), BACKGROUND)
    draw = ImageDraw.Draw(image)
    draw.rectangle([0, 0, width, title_height], fill=TITLE_BAR)

    for index, color in enumerate(((255, 95, 86), (255, 189, 46), (39, 201, 63))):
        cx = padding + 8 + index * 20
        cy = title_height // 2
        draw.ellipse([cx - 6, cy - 6, cx + 6, cy + 6], fill=color)
    draw.text((padding + 80, title_height // 2 - 10), TITLE, font=bold_title_font, fill=(196, 200, 208))

    y = title_height + padding
    for runs in lines:
        x = float(padding)
        for chunk, keys in runs:
            if not chunk:
                continue
            draw.text((x, y), chunk, font=font, fill=pick_color(keys))
            x += font.getlength(chunk)
        y += line_height

    draw.text(
        (padding, height - padding - 6),
        FOOTER,
        font=bold_title_font,
        fill=(104, 112, 124),
    )

    target = ROOT / "docs" / "demo.png"
    target.parent.mkdir(parents=True, exist_ok=True)
    image.save(target)
    print(f"wrote {target.relative_to(ROOT)} ({width}x{height}, {columns} columns)")
    return 0


def line_text(raw: str) -> str:
    return ANSI_RE.sub("", raw)


if __name__ == "__main__":
    raise SystemExit(main())
