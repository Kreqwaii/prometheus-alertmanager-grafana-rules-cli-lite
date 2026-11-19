import unittest
from pathlib import Path

from prom_alert_lint.rules import (
    lint_alertmanager_config,
    lint_file,
    lint_paths,
    lint_prometheus_rules,
)

SAMPLES_DIR = Path(__file__).resolve().parent.parent / "samples"


class TestPrometheusLinter(unittest.TestCase):
    def test_clean_prometheus_rules_have_zero_findings(self):
        findings = lint_file(SAMPLES_DIR / "prometheus-rules-clean.yml")
        self.assertEqual(findings, [])

    def test_broken_prometheus_rules_detect_all_expected_rules(self):
        findings = lint_file(SAMPLES_DIR / "prometheus-rules-broken.yml")
        rule_ids = {f.rule_id for f in findings}
        self.assertIn("PROM001", rule_ids)
        self.assertIn("PROM002", rule_ids)
        self.assertIn("PROM003", rule_ids)
        self.assertIn("PROM004", rule_ids)
        self.assertIn("PROM005", rule_ids)
        self.assertIn("PROM006", rule_ids)

    def test_recording_rules_are_skipped(self):
        data = {
            "groups": [
                {
                    "name": "rec",
                    "rules": [{"record": "job:http_requests:rate5m", "expr": "rate(http_requests[5m])"}],
                }
            ]
        }
        self.assertEqual(lint_prometheus_rules(data, "rec.yml"), [])

    def test_rate_window_2m_is_accepted(self):
        data = {
            "groups": [
                {
                    "name": "g",
                    "rules": [
                        {
                            "alert": "OkRate",
                            "expr": "rate(req_total[2m]) > 1",
                            "for": "5m",
                            "labels": {"severity": "warning"},
                            "annotations": {"summary": "ok", "runbook_url": "https://rb"},
                        }
                    ],
                }
            ]
        }
        self.assertEqual(lint_prometheus_rules(data, "ok.yml"), [])

    def test_irate_30s_is_flagged(self):
        data = {
            "groups": [
                {
                    "name": "g",
                    "rules": [
                        {
                            "alert": "ShortIrate",
                            "expr": "irate(req_total[30s]) > 1",
                            "for": "5m",
                            "labels": {"severity": "warning"},
                            "annotations": {"summary": "ok", "runbook_url": "https://rb"},
                        }
                    ],
                }
            ]
        }
        findings = lint_prometheus_rules(data, "short.yml")
        self.assertEqual([f.rule_id for f in findings], ["PROM005"])

    def test_duplicate_alert_across_files(self):
        p1 = SAMPLES_DIR / "prometheus-rules-clean.yml"
        findings, count = lint_paths([p1, p1])
        self.assertEqual(count, 2)
        self.assertTrue(any(f.rule_id == "PROM006" for f in findings))


class TestAlertmanagerLinter(unittest.TestCase):
    def test_clean_alertmanager_has_zero_findings(self):
        findings = lint_file(SAMPLES_DIR / "alertmanager-clean.yml")
        self.assertEqual(findings, [])

    def test_broken_alertmanager_detects_am001_am002_am003(self):
        findings = lint_file(SAMPLES_DIR / "alertmanager-broken.yml")
        rule_ids = {f.rule_id for f in findings}
        self.assertIn("AM001", rule_ids)
        self.assertIn("AM002", rule_ids)
        self.assertIn("AM003", rule_ids)

    def test_env_substitution_not_flagged_as_secret(self):
        data = {
            "route": {"receiver": "slack", "group_by": ["alertname"], "repeat_interval": "1h"},
            "receivers": [{"name": "slack", "slack_configs": [{"api_url": "${SLACK_URL}"}]}],
        }
        self.assertEqual(lint_alertmanager_config(data, "am.yml"), [])

    def test_undefined_receiver_in_route_flagged(self):
        data = {
            "route": {"receiver": "missing-rec", "group_by": ["alertname"], "repeat_interval": "1h"},
            "receivers": [],
        }
        findings = lint_alertmanager_config(data, "am.yml")
        self.assertEqual([f.rule_id for f in findings], ["AM002"])

    def test_missing_file_returns_io001(self):
        findings = lint_file(Path("nonexistent_file_12345.yml"))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "IO001")

    def test_lint_paths_directory_scan(self):
        findings, count = lint_paths([SAMPLES_DIR])
        self.assertEqual(count, 4)
        self.assertGreater(len(findings), 0)


if __name__ == "__main__":
    unittest.main()
