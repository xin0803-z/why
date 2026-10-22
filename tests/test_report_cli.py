"""Tests for the renderers, the CLI contract and the end-to-end path."""

from __future__ import annotations

import io
import json
import os
import re
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

import support  # noqa: E402

from why import __version__, cli  # noqa: E402
from why import report as report_mod


class TextRenderTests(unittest.TestCase):
    def test_report_mentions_the_verdict_and_the_deciding_layer(self):
        text = report_mod.render_text(support.denied_report(), color=False)
        self.assertIn("verdict", text)
        self.assertIn("DENIED", text)
        self.assertIn("Permission bits", text)
        self.assertIn("setfacl", text)

    def test_color_can_be_disabled(self):
        text = report_mod.render_text(support.denied_report(), color=False)
        self.assertNotIn("\033[", text)

    def test_color_output_is_styled(self):
        text = report_mod.render_text(support.denied_report(), color=True)
        self.assertIn("\033[", text)

    def test_long_details_are_truncated_unless_verbose(self):
        short = report_mod.render_text(support.denied_report(), color=False, verbose=False)
        long = report_mod.render_text(support.denied_report(), color=False, verbose=True)
        self.assertLessEqual(len(short), len(long))

    def test_no_line_exceeds_the_requested_width(self):
        ansi = re.compile(r"\033\[[0-9;]*m")
        for verbose in (False, True):
            for width in (80, 100, 120):
                text = report_mod.render_text(support.denied_report(), color=True, verbose=verbose, width=width)
                for line in text.split("\n"):
                    plain = ansi.sub("", line)
                    self.assertLessEqual(
                        len(plain),
                        width,
                        f"line exceeds width {width} (verbose={verbose}): {plain!r}",
                    )

    def test_ascii_mode_avoids_unicode_glyphs(self):
        text = report_mod.render_text(support.denied_report(), color=False, verbose=True, icons="ascii", width=100)
        self.assertNotIn("─", text)
        self.assertNotIn("✘", text)
        self.assertIn("X", text)

    def test_unicode_mode_uses_the_icons(self):
        text = report_mod.render_text(support.denied_report(), color=False, verbose=True, icons="unicode", width=100)
        self.assertIn("✘", text)

    def test_layer_catalog_lists_every_layer(self):
        catalog = report_mod.layer_catalog()
        numbered = [
            line for line in catalog.splitlines() if line.strip() and line.strip().split(".")[0].strip().isdigit()
        ]
        self.assertEqual(len(numbered), 12)
        self.assertIn("[mode]", catalog)


class JsonRenderTests(unittest.TestCase):
    def test_json_is_stable_and_complete(self):
        payload = json.loads(report_mod.render_json(support.denied_report()))
        self.assertEqual(payload["tool"], "why")
        self.assertEqual(payload["version"], __version__)
        self.assertEqual(payload["verdict"], "denied")
        self.assertEqual(payload["deciding_layer"], "mode")
        self.assertEqual(len(payload["layers"]), 12)
        self.assertEqual(payload["target"]["path"], "/etc/shadow")
        self.assertEqual(payload["target"]["mode_string"], "-rw-r-----")
        self.assertIn("fixes", payload)
        self.assertTrue(payload["fixes"])

    def test_every_layer_has_id_status_and_confidence(self):
        payload = json.loads(report_mod.render_json(support.denied_report()))
        for item in payload["layers"]:
            self.assertIn("id", item)
            self.assertIn(item["status"], {"ok", "deny", "warn", "info", "skip", "unknown"})
            self.assertIn(item["confidence"], {"decisive", "evidence", "advisory"})


class ArgvNormalizationTests(unittest.TestCase):
    def test_bare_path_becomes_the_denied_subcommand(self):
        self.assertEqual(cli._normalize_argv(["/etc/shadow"]), ["denied", "/etc/shadow"])

    def test_known_commands_pass_through(self):
        for command in ("denied", "layers", "version"):
            self.assertEqual(cli._normalize_argv([command]), [command])

    def test_flags_pass_through(self):
        self.assertEqual(cli._normalize_argv(["--version"]), ["--version"])
        self.assertEqual(cli._normalize_argv([]), [])


class ExitCodeTests(unittest.TestCase):
    def test_denied_maps_to_zero(self):
        self.assertEqual(cli._exit_code(support.denied_report()), cli.EXIT_EXPLAINED_DENIED)

    def test_allowed_maps_to_ten(self):
        from why.model import Verdict

        report = support.denied_report()
        report.verdict = Verdict.ALLOWED
        report.deciding_layer = None
        self.assertEqual(cli._exit_code(report), cli.EXIT_ALLOWED)

    def test_unknown_maps_to_eleven(self):
        from why.model import Verdict

        report = support.denied_report()
        report.verdict = Verdict.UNKNOWN
        self.assertEqual(cli._exit_code(report), cli.EXIT_UNKNOWN)

    def test_check_mode_is_silent_when_allowed(self):
        from why.model import Verdict

        report = support.denied_report()
        report.verdict = Verdict.ALLOWED
        buffer = io.StringIO()
        with redirect_stderr(buffer):
            self.assertEqual(cli._check_exit_code(report), 0)
        self.assertEqual(buffer.getvalue(), "")

    def test_check_mode_explains_on_stderr_when_denied(self):
        buffer = io.StringIO()
        with redirect_stderr(buffer):
            self.assertEqual(cli._check_exit_code(support.denied_report()), 1)
        self.assertIn("Permission bits", buffer.getvalue())

    def test_check_mode_fails_closed_on_an_unknown_verdict(self):
        from why.model import Verdict

        report = support.denied_report()
        report.verdict = Verdict.UNKNOWN
        report.deciding_layer = None
        buffer = io.StringIO()
        with redirect_stderr(buffer):
            self.assertEqual(cli._check_exit_code(report), 1)
        message = buffer.getvalue()
        self.assertIn("unknown", message)
        # It must not claim a denial it could not establish.
        self.assertNotIn("denied", message)


class CliEndToEndTests(unittest.TestCase):
    def test_layers_command(self):
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            self.assertEqual(cli.main(["layers"]), 0)
        self.assertIn("Permission bits", buffer.getvalue())

    def test_version_command(self):
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            self.assertEqual(cli.main(["version"]), 0)
        self.assertIn(__version__, buffer.getvalue())

    def test_version_flag_exits_zero(self):
        with self.assertRaises(SystemExit) as caught, redirect_stdout(io.StringIO()):
            cli.main(["--version"])
        self.assertEqual(caught.exception.code, 0)

    def test_missing_path_is_a_usage_error(self):
        buffer = io.StringIO()
        with redirect_stderr(buffer):
            self.assertEqual(cli.main(["denied"]), cli.EXIT_USAGE)
        self.assertIn("path is required", buffer.getvalue())

    def test_unknown_pid_is_a_usage_error(self):
        buffer = io.StringIO()
        with redirect_stderr(buffer):
            code = cli.main(["denied", "/etc/hosts", "--pid", "99999999"])
        self.assertEqual(code, cli.EXIT_USAGE)

    def test_json_output_is_valid_for_a_real_path(self):
        """Runs the real collectors; the verdict itself is platform dependent."""
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as handle:
            handle.write("hello\n")
            path = handle.name
        try:
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                code = cli.main(["denied", path, "--json", "--no-evidence"])
            self.assertIn(code, (cli.EXIT_EXPLAINED_DENIED, cli.EXIT_ALLOWED, cli.EXIT_UNKNOWN))
            payload = json.loads(buffer.getvalue())
            self.assertEqual(len(payload["layers"]), 12)
            self.assertEqual(payload["target"]["path"], os.path.realpath(path))
        finally:
            os.unlink(path)

    def test_create_op_on_a_missing_path(self):
        missing = os.path.join(tempfile.gettempdir(), "why-does-not-exist-42", "file.txt")
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            cli.main(["denied", missing, "--op", "create", "--no-evidence"])
        self.assertIn("why", buffer.getvalue())


if __name__ == "__main__":
    unittest.main()
