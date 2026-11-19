import contextlib
import io
import json
import unittest
from pathlib import Path

from prom_alert_lint.cli import format_json, format_markdown, format_text, main, should_fail
from prom_alert_lint.rules import Finding

SAMPLES_DIR = Path(__file__).resolve().parent.parent / "samples"


class TestCli(unittest.TestCase):
    def test_clean_files_exit_zero(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = main(
                [
                    str(SAMPLES_DIR / "prometheus-rules-clean.yml"),
                    str(SAMPLES_DIR / "alertmanager-clean.yml"),
                ]
            )
        self.assertEqual(code, 0)
        self.assertIn("0 issues found", buf.getvalue())

    def test_broken_file_exits_one_on_default_fail_on_error(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = main([str(SAMPLES_DIR / "prometheus-rules-broken.yml")])
        self.assertEqual(code, 1)

    def test_fail_on_none_exits_zero_even_with_critical(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = main(
                [
                    str(SAMPLES_DIR / "alertmanager-broken.yml"),
                    "--fail-on",
                    "none",
                ]
            )
        self.assertEqual(code, 0)

    def test_json_output_is_valid_json(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = main(
                [
                    str(SAMPLES_DIR / "alertmanager-broken.yml"),
                    "--format",
                    "json",
                    "--fail-on",
                    "none",
                ]
            )
        self.assertEqual(code, 0)
        payload = json.loads(buf.getvalue())
        self.assertEqual(payload["files_scanned"], 1)
        self.assertGreater(payload["total_findings"], 0)
        self.assertIsInstance(payload["findings"], list)

    def test_markdown_output_contains_table(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            main(
                [
                    str(SAMPLES_DIR / "prometheus-rules-broken.yml"),
                    "--format",
                    "markdown",
                    "--fail-on",
                    "none",
                ]
            )
        out = buf.getvalue()
        self.assertIn("# Prometheus & Alertmanager Lint Report", out)
        self.assertIn("| Severity | Rule | File | Target | Message |", out)

    def test_should_fail_thresholds(self):
        warn = [Finding("PROM001", "warning", "a.yml", "g/a", "msg")]
        self.assertFalse(should_fail(warn, "error"))
        self.assertTrue(should_fail(warn, "warning"))
        self.assertTrue(should_fail(warn, "info"))
        self.assertFalse(should_fail(warn, "none"))

    def test_format_text_empty(self):
        self.assertEqual(format_text([], 2), "OK: 2 file(s) scanned, 0 issues found.")

    def test_format_markdown_empty(self):
        out = format_markdown([], 1)
        self.assertIn("No issues found.", out)


if __name__ == "__main__":
    unittest.main()
