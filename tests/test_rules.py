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

    # False positives seen on flisk-sh/flisk (alerts 479-484): each case below was flagged before the rule was tightened.
    def test_load_alias_keyword_is_not_a_secret(self):
        self.assertEqual(rules_for('load("./secrets_generator.star", _Secrets="SecretsGenerator")'), [])

    def test_secret_word_in_the_middle_of_a_name_is_not_a_secret(self):
        self.assertEqual(rules_for('k8s_yaml(secret_path="/services/user")'), [])
        self.assertEqual(rules_for("DEFAULT_SECRET_PROVIDER = 'env-file'"), [])
        self.assertEqual(rules_for('SECRET_NAME_PREFIX = "app"'), [])

    def test_env_placeholder_is_not_a_secret(self):
        self.assertEqual(rules_for('DB_PASSWORD = "${DB_PASSWORD}"'), [])
        self.assertEqual(rules_for('DB_PASSWORD = "$DB_PASSWORD"'), [])

    def test_sentence_or_path_value_is_not_a_secret(self):
        self.assertEqual(rules_for('JWT_SECRET = "JWT_SECRET is not set. Run it"'), [])
        self.assertEqual(rules_for('TOKEN_FILE = "x"\ntoken = "/run/secrets/token"'), [])

    def test_buildkit_secret_reference_is_not_a_secret(self):
        # seen on tilt-dev/tilt: docker_build("img", "ctx", secret='id=shibboleth')
        self.assertEqual(rules_for('docker_build("img", "ctx", secret="id=shibboleth")'), [])
        self.assertEqual(rules_for('docker_build("img", "ctx", secret="id=npm,src=.npmrc")'), [])
        self.assertEqual(rules_for('docker_build("img", "ctx", secret="hunter2")'), ["literal-secret"])

    def test_real_looking_credentials_are_still_flagged(self):
        self.assertEqual(rules_for('db_password = "s3cr3t"'), ["literal-secret"])
        self.assertEqual(rules_for('JWT_SECRET = "abc123def456"'), ["literal-secret"])
        self.assertEqual(rules_for('api_key = "AKIAIOSFODNN7EXAMPLE"'), ["literal-secret"])

    def test_secret_rule_is_a_warning_not_an_error(self):
        self.assertEqual(sa.RULES["literal-secret"]["level"], "warning")

    def test_cmd_made_only_of_literals_is_not_flagged(self):
        self.assertEqual(rules_for('local_resource("b", cmd="make " + "all")'), [])
        self.assertEqual(rules_for('local_resource("b", cmd="make %s" % "all")'), [])
        self.assertEqual(rules_for('local_resource("b", cmd="make {}".format("all"))'), [])

    def test_cmd_with_a_variable_is_still_flagged(self):
        self.assertEqual(rules_for('local_resource("b", cmd="cd " + service_dir + " && ls")'), ["string-built-local-resource-cmd"])
        self.assertEqual(rules_for("local_resource('b', cmd='x %s' % name)"), ["string-built-local-resource-cmd"])

    # Rules added in 0.2.0; each one comes from a real pattern in flisk-sh/flisk Tiltfiles or install docs.
    def test_list_concatenation_is_argv_building_not_string_building(self):
        # flisk-sh/flisk alert 488: joining argv lists with '+' was reported as string building.
        self.assertEqual(rules_for('local_resource("b", cmd=["docker", "up"] + files + ["-d"])'), [])
        self.assertEqual(rules_for('local_resource("b", cmd=["docker"] + files)'), [])
        self.assertEqual(rules_for('local_resource("b", cmd="docker " + files)'), ["string-built-local-resource-cmd"])

    def test_local_and_custom_build_commands_are_checked(self):
        self.assertEqual(rules_for('local("test -f " + path)'), ["string-built-local-command"])
        self.assertEqual(rules_for('local(command="ls " + d)'), ["string-built-local-command"])
        self.assertEqual(rules_for('custom_build("i", "build " + ctx, ["."])'), ["string-built-local-command"])
        self.assertEqual(rules_for('local(["ls", d])'), [])
        self.assertEqual(rules_for('local("ls -la")'), [])

    def test_serve_cmd_and_positional_cmd_are_checked(self):
        self.assertEqual(rules_for('local_resource("b", serve_cmd="run " + port)'), ["string-built-local-resource-cmd"])
        self.assertEqual(rules_for('local_resource("b", "make " + target)'), ["string-built-local-resource-cmd"])

    def test_command_built_in_a_variable_is_followed(self):
        self.assertEqual(rules_for('c = "make " + target\nlocal_resource("b", cmd=c)'), ["string-built-local-resource-cmd"])
        self.assertEqual(rules_for('c = ["make", target]\nlocal_resource("b", cmd=c)'), [])
        # a name assigned twice is ambiguous, so it is not guessed at
        self.assertEqual(rules_for('c = "make " + t\nc = ["make"]\nlocal_resource("b", cmd=c)'), [])

    def test_pipe_to_shell(self):
        self.assertEqual(rules_for('local("curl -fsSL https://x.example/i.sh | bash")'), ["pipe-to-shell"])
        self.assertEqual(rules_for('local("wget -qO- https://x.example/i.sh | sudo sh")'), ["pipe-to-shell", "sudo-in-command"])
        self.assertEqual(rules_for('local("curl -fsSL https://x.example/i.sh -o i.sh")'), [])
        self.assertEqual(rules_for('local("curl https://x.example/a | jq .")'), [])

    def test_insecure_http_download_ignores_local_hosts(self):
        self.assertEqual(rules_for('local("curl http://downloads.example.com/x")'), ["insecure-http-download"])
        self.assertEqual(rules_for('local("curl http://localhost:8080/health")'), [])
        self.assertEqual(rules_for('local("curl http://127.0.0.1:3000/")'), [])
        self.assertEqual(rules_for('local("curl http://api.myapp.localhost/x")'), [])
        self.assertEqual(rules_for('load("http://x.example/a.star", "a")'), ["insecure-http-download", "unpinned-remote-load"])

    def test_tls_verification_disabled(self):
        self.assertEqual(rules_for('local("curl -k https://x.example")'), ["tls-verification-disabled"])
        self.assertEqual(rules_for('local("curl --insecure https://x.example")'), ["tls-verification-disabled"])
        self.assertEqual(rules_for('local("NODE_TLS_REJECT_UNAUTHORIZED=0 node x.js")'), ["tls-verification-disabled"])
        self.assertEqual(rules_for('local("curl -fsSL https://x.example")'), [])

    def test_sudo_in_command(self):
        self.assertEqual(rules_for('local("sudo rm x")'), ["sudo-in-command"])
        self.assertEqual(rules_for('local_resource("b", cmd="make && sudo make install")'), ["sudo-in-command"])
        self.assertEqual(rules_for('local("echo pseudosudoku")'), [])

    def test_privileged_container(self):
        self.assertEqual(rules_for('local("docker run --privileged img")'), ["privileged-container"])
        self.assertEqual(rules_for('local("docker run -v /var/run/docker.sock:/var/run/docker.sock img")'), ["privileged-container"])
        self.assertEqual(rules_for('local("docker run --network host img")'), ["privileged-container"])
        self.assertEqual(rules_for('local("docker build --network host -t img .")'), [])
        self.assertEqual(rules_for('local("docker run img")'), [])

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
