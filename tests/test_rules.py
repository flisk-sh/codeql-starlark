import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import starlark_analyze as sa  # noqa: E402

FIXTURES = os.path.join(ROOT, "tests", "fixtures")


def rules_for(source):
    findings, error = sa.analyze_source(source, "t.star")
    assert error is None, error
    return sorted(f["rule"] for f in findings)


class RuleTests(unittest.TestCase):
    def test_unpinned_remote_load_is_flagged(self):
        self.assertEqual(rules_for('load("https://x.example/a.star", "a")'), ["unpinned-remote-load"])

    def test_pinned_remote_load_passes(self):
        src = 'load("https://x.example/a.star@0123456789abcdef0123456789abcdef01234567", "a")'
        self.assertEqual(rules_for(src), [])

    def test_local_load_passes(self):
        self.assertEqual(rules_for('load("//tools:a.star", "a")'), [])

    def test_string_built_cmd_is_flagged_for_concat_format_and_fstring(self):
        self.assertEqual(rules_for('local_resource("b", cmd="make " + t)'), ["string-built-local-resource-cmd"])
        self.assertEqual(rules_for('local_resource("b", cmd="make {}".format(t))'), ["string-built-local-resource-cmd"])
        self.assertEqual(rules_for('local_resource("b", cmd=f"make {t}")'), ["string-built-local-resource-cmd"])

    def test_list_cmd_passes(self):
        self.assertEqual(rules_for('local_resource("b", cmd=["make", t])'), [])

    def test_literal_secret_by_keyword_and_assignment(self):
        self.assertEqual(rules_for('API_TOKEN = "abc"'), ["literal-secret"])
        self.assertEqual(rules_for('k8s_yaml(password="hunter2")'), ["literal-secret"])

    def test_empty_or_env_secret_passes(self):
        self.assertEqual(rules_for('API_TOKEN = ""'), [])
        self.assertEqual(rules_for('API_TOKEN = os.environ["API_TOKEN"]'), [])

    def test_read_outside_root_flags_absolute_and_parent_paths(self):
        self.assertEqual(rules_for('read_file("/etc/passwd")'), ["read-outside-root"])
        self.assertEqual(rules_for('read_yaml("../../x.yaml")'), ["read-outside-root"])

    def test_read_inside_root_passes(self):
        self.assertEqual(rules_for('read_file("deploy/config.yaml")'), [])


class FixtureTests(unittest.TestCase):
    def test_bad_fixture_reports_every_rule(self):
        with open(os.path.join(FIXTURES, "bad", "Tiltfile"), encoding="utf-8") as handle:
            found = rules_for(handle.read())
        for rule in sa.RULES:
            self.assertIn(rule, found)

    def test_good_fixture_is_clean(self):
        with open(os.path.join(FIXTURES, "good", "Tiltfile"), encoding="utf-8") as handle:
            self.assertEqual(rules_for(handle.read()), [])

    def test_unparseable_file_becomes_notification_not_crash(self):
        with open(os.path.join(FIXTURES, "bad", "broken.star"), encoding="utf-8") as handle:
            findings, error = sa.analyze_source(handle.read(), "broken.star")
        self.assertEqual(findings, [])
        self.assertIsNotNone(error)


class SarifTests(unittest.TestCase):
    def test_end_to_end_writes_valid_sarif_shape(self):
        out = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, out)
        sarif_path = os.path.join(out, "r.sarif")
        code = sa.main(["--root", FIXTURES, "--output", sarif_path])
        self.assertEqual(code, 0)
        with open(sarif_path, encoding="utf-8") as handle:
            doc = json.load(handle)
        run = doc["runs"][0]
        self.assertEqual(doc["version"], "2.1.0")
        self.assertEqual(run["tool"]["driver"]["name"], "codeql-starlark (unofficial)")
        self.assertTrue(run["results"])
        for result in run["results"]:
            self.assertIn("starlarkFindingHash/v1", result["partialFingerprints"])
            region = result["locations"][0]["physicalLocation"]["region"]
            self.assertGreaterEqual(region["startLine"], 1)
        notes = run["invocations"][0]["toolExecutionNotifications"]
        self.assertTrue(any("broken.star" in n["message"]["text"] for n in notes))

    def test_fail_on_findings_exits_nonzero(self):
        out = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, out)
        code = sa.main(["--root", os.path.join(FIXTURES, "bad"), "--output", os.path.join(out, "x.sarif"), "--fail-on-findings"])
        self.assertEqual(code, 1)


if __name__ == "__main__":
    unittest.main()
