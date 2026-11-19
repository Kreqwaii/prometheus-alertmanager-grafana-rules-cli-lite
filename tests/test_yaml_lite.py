import unittest

from prom_alert_lint.yaml_lite import YamlParseError, parse_yaml


class TestYamlLite(unittest.TestCase):
    def test_empty_input(self):
        self.assertEqual(parse_yaml(""), {})
        self.assertEqual(parse_yaml("   \n# just a comment\n"), {})

    def test_simple_mapping(self):
        data = parse_yaml("name: test\ncount: 42\nratio: 0.5\nenabled: true\n")
        self.assertEqual(data, {"name": "test", "count": 42, "ratio": 0.5, "enabled": True})

    def test_null_and_booleans(self):
        data = parse_yaml("a: null\nb: ~\nc: false\nd: TRUE\n")
        self.assertIsNone(data["a"])
        self.assertIsNone(data["b"])
        self.assertIs(data["c"], False)
        self.assertIs(data["d"], True)

    def test_quoted_strings_and_comments(self):
        data = parse_yaml('url: "https://example.com/#frag" # trailing\nsingle: \'it\'\'s ok\'\n')
        self.assertEqual(data["url"], "https://example.com/#frag")
        self.assertEqual(data["single"], "it's ok")

    def test_inline_list_and_dict(self):
        data = parse_yaml("tags: [a, b, 3]\nmeta: {env: prod, active: true}\n")
        self.assertEqual(data["tags"], ["a", "b", 3])
        self.assertEqual(data["meta"], {"env": "prod", "active": True})

    def test_sequence_of_scalars(self):
        data = parse_yaml("items:\n  - alpha\n  - beta\n")
        self.assertEqual(data, {"items": ["alpha", "beta"]})

    def test_sequence_of_mappings(self):
        yaml_text = (
            "groups:\n"
            "  - name: g1\n"
            "    rules:\n"
            "      - alert: A1\n"
            "        expr: up == 0\n"
        )
        data = parse_yaml(yaml_text)
        self.assertEqual(data["groups"][0]["name"], "g1")
        self.assertEqual(data["groups"][0]["rules"][0]["alert"], "A1")

    def test_block_scalar_literal_and_folded(self):
        yaml_text = (
            "expr: |\n"
            "  sum(rate(x[5m]))\n"
            "  > 10\n"
            "desc: >\n"
            "  line one\n"
            "  line two\n"
        )
        data = parse_yaml(yaml_text)
        self.assertEqual(data["expr"], "sum(rate(x[5m]))\n> 10")
        self.assertEqual(data["desc"], "line one line two")

    def test_document_markers_ignored(self):
        data = parse_yaml("---\nkey: value\n...\n")
        self.assertEqual(data, {"key": "value"})

    def test_invalid_line_raises(self):
        with self.assertRaises(YamlParseError):
            parse_yaml("not_a_key_value_pair\n")


if __name__ == "__main__":
    unittest.main()
