"""Packaging invariants: the version has one source of truth and is documented.

The 0.1.0 wheel reported ``why 0.1.0`` while its metadata said 0.1.1, because the
version was written in both ``pyproject.toml`` and ``src/why/__init__.py``. These
tests keep the second copy from coming back, and keep the changelog in step.
"""

from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import why  # noqa: E402


def _project_table(text: str) -> str:
    """The ``[project]`` table of a pyproject.toml, as text."""
    match = re.search(r"^\[project\]$(.*?)(?=^\[)", text, re.MULTILINE | re.DOTALL)
    assert match is not None, "[project] table not found"
    return match.group(1)


class VersionTests(unittest.TestCase):
    def setUp(self):
        self.pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")

    def test_the_project_table_does_not_restate_the_version(self):
        table = _project_table(self.pyproject)
        self.assertNotRegex(table, r"^version\s*=", "the version belongs in src/why/__init__.py only")
        self.assertIn('dynamic = ["version"]', table)

    def test_the_build_backend_reads_the_version_from_the_package(self):
        self.assertIn('version = { attr = "why.__version__" }', self.pyproject)

    def test_the_version_is_not_empty_and_looks_like_a_release(self):
        self.assertRegex(why.__version__, r"^\d+\.\d+\.\d+$")

    def test_the_changelog_documents_the_current_version(self):
        released = re.findall(r"^## \[(\d+\.\d+\.\d+)\]", self.changelog, re.MULTILINE)
        self.assertTrue(released, "no released version headings in CHANGELOG.md")
        self.assertEqual(
            released[0],
            why.__version__,
            f"CHANGELOG.md's newest release is {released[0]} but the code says {why.__version__}",
        )

    def test_the_changelog_keeps_an_unreleased_section_on_top(self):
        headings = re.findall(r"^## \[([^\]]+)\]", self.changelog, re.MULTILINE)
        self.assertEqual(headings[0], "Unreleased")

    def test_every_changelog_release_has_a_link_reference(self):
        for version in re.findall(r"^## \[(\d+\.\d+\.\d+)\]", self.changelog, re.MULTILINE):
            self.assertIn(f"[{version}]:", self.changelog, f"{version} has no link reference")

    def test_the_readme_pins_no_version(self):
        """`pip install why-linux` and the installer both follow the latest release."""
        for name in ("README.md", "README.zh-CN.md"):
            text = (ROOT / name).read_text(encoding="utf-8")
            self.assertNotRegex(text, r"why-linux==", f"{name} pins a version")


class MetadataTests(unittest.TestCase):
    def test_the_console_script_points_at_the_cli(self):
        self.assertIn('why = "why.cli:main"', (ROOT / "pyproject.toml").read_text(encoding="utf-8"))

    def test_the_package_ships_its_type_marker(self):
        self.assertTrue((ROOT / "src" / "why" / "py.typed").is_file())

    def test_license_and_readme_are_present_for_the_index(self):
        pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn('license = "MIT"', pyproject)
        self.assertIn('readme = "README.md"', pyproject)
        self.assertTrue((ROOT / "LICENSE").is_file())


if __name__ == "__main__":
    unittest.main()
