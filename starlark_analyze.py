"""Static checks for Starlark files (Tiltfiles, *.star) that write SARIF 2.1.0.

Starlark is a restricted subset of Python, so Python's ``ast`` module parses it
without a Starlark engine. Files that use syntax outside that overlap are
reported as parse notifications instead of being skipped silently.
"""

import argparse
import ast
import glob
import hashlib
import json
import os
import re
import sys

TOOL_NAME = "codeql-starlark"
TOOL_VERSION = "0.2.2"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
DEFAULT_PATTERNS = ["**/*.star", "**/Tiltfile"]

RULES = {
    "unpinned-remote-load": {
        "name": "UnpinnedRemoteLoad",
        "text": "load() fetches a remote URL that is not pinned to a commit or checksum.",
        "level": "warning",
    },
    "string-built-local-resource-cmd": {
        "name": "StringBuiltLocalResourceCmd",
        "text": "local_resource() builds its cmd from string concatenation or formatting.",
        "level": "warning",
    },
    "string-built-local-command": {
        "name": "StringBuiltLocalCommand",
        "text": "local() or custom_build() builds its command from string concatenation or formatting.",
        # A note: local() helpers such as `test -f` are common and low risk, so they must not drown the warnings.
        "level": "note",
    },
    "pipe-to-shell": {
        "name": "PipeToShell",
        "text": "A command downloads a script and pipes it straight into a shell.",
        "level": "error",
    },
    "insecure-http-download": {
        "name": "InsecureHttpDownload",
        "text": "A command downloads over plain http:// from a non-local host.",
        "level": "error",
    },
    "tls-verification-disabled": {
        "name": "TlsVerificationDisabled",
        "text": "A command turns off TLS certificate verification.",
        "level": "error",
    },
    "sudo-in-command": {
        "name": "SudoInCommand",
        "text": "A command runs sudo, so a Tiltfile can change the host with elevated rights.",
        "level": "warning",
    },
    "privileged-container": {
        "name": "PrivilegedContainer",
        "text": "A command starts a container with host-level access (--privileged, the Docker socket or the host network/PID namespace).",
        "level": "warning",
    },
    "literal-secret": {
        "name": "LiteralSecret",
        "text": "A name ending in password, secret, token or api key is assigned a string literal that looks like a credential.",
        "level": "warning",
    },
    "read-outside-root": {
        "name": "ReadOutsideRoot",
        "text": "A file read targets an absolute path or climbs above the project root.",
        "level": "warning",
    },
}

# Keyword arguments that are executed by a shell (string) or exec'd directly (list).
LOCAL_RESOURCE_CMD_KWARGS = {"cmd", "serve_cmd", "cmd_bat", "serve_cmd_bat"}
# Calls whose command argument is a sink: (call name, keyword, positional index or None).
COMMAND_CALLS = {"local": ("command", 0), "custom_build": ("command", 1)}

PIPE_TO_SHELL = re.compile(r"\b(curl|wget)\b[^|]*\|\s*(sudo\s+)?(ba|z|da|k)?sh\b")
LOCAL_HOST = r"(localhost|127\.|0\.0\.0\.0|\[::1\]|host\.docker\.internal|([a-z0-9-]+\.)*localhost|([a-z0-9-]+\.)+local\b)"
HTTP_DOWNLOAD = re.compile(r"\b(curl|wget)\b[^|;&]*\bhttp://(?!" + LOCAL_HOST + ")", re.IGNORECASE)
TLS_OFF = re.compile(
    r"(\bcurl\b[^|;&]*\s(-k|--insecure)\b|--no-check-certificate|--tlsv1(\.0|\.1)?\b|NODE_TLS_REJECT_UNAUTHORIZED=0"
    r"|GIT_SSL_NO_VERIFY|\bnpm\s+config\s+set\s+strict-ssl\s+false|--trusted-host|PYTHONHTTPSVERIFY=0)"
)
SUDO = re.compile(r"(^|[\s;&|(])sudo(\s|$)")
# `docker build --network host` only shares the network for the build, so host networking counts for run/create only.
PRIVILEGED = re.compile(
    r"(--privileged\b|/var/run/docker\.sock|\b(run|create)\b[^|;&]*--(network|net)[= ]host\b|--pid[= ]host\b)"
)

FILE_READERS = {"read_file", "read_yaml", "read_json", "read_csv", "listdir"}
# The secret word must END the name: API_TOKEN and db_password match, SECRET_PATH, SECRET_PROVIDER and
# JWT_SECRET_MISSING_MESSAGE do not (they name a path, a provider and a message).
SECRET_NAME = re.compile(r"(password|passwd|secret|token|api[_-]?key|private[_-]?key)$", re.IGNORECASE)
COMMIT_PIN = re.compile(r"[0-9a-f]{40}|sha256[=:][0-9a-f]{64}", re.IGNORECASE)
REMOTE_PREFIXES = ("http://", "https://", "git://", "ssh://")


def looks_like_credential(expr):
    """A string literal that could be a credential, not a placeholder, path or sentence."""
    if not (isinstance(expr, ast.Constant) and isinstance(expr.value, str)):
        return False
    value = expr.value
    if value == "" or any(ch.isspace() for ch in value):
        return False  # empty, or prose such as an error message
    if re.match(r"(id|src|source|env)=", value):
        return False  # docker_build(secret='id=npm') names a BuildKit secret, it is not the secret
    if "$" in value or value.startswith(("/", "./", "../", "<", "{{", "%(")):
        return False  # env placeholder like ${DB_PASSWORD}, a path, or a template
    return True


def is_shell_quoted(expr):
    """shlex.quote(x) / quote(x) makes one shell word out of x, so splicing it into a command is safe."""
    return isinstance(expr, ast.Call) and call_name(expr) == "quote" and not expr.keywords and len(expr.args) == 1


def has_dynamic_part(expr):
    """True when a string expression mixes in anything that is not a plain string literal."""
    if isinstance(expr, ast.Constant):
        return False
    if is_shell_quoted(expr):
        return False
    if isinstance(expr, ast.JoinedStr):
        return any(isinstance(v, ast.FormattedValue) and has_dynamic_part(v.value) for v in expr.values)
    if isinstance(expr, ast.BinOp):
        return has_dynamic_part(expr.left) or has_dynamic_part(expr.right)
    if isinstance(expr, (ast.Tuple, ast.List)):
        return any(has_dynamic_part(e) for e in expr.elts)
    if isinstance(expr, ast.Call) and isinstance(expr.func, ast.Attribute) and expr.func.attr == "format":
        parts = list(expr.args) + [kw.value for kw in expr.keywords]
        return any(has_dynamic_part(e) for e in parts)
    return True


def call_name(node):
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    return None


def is_string_built(expr):
    """True for '+' concatenation, '%' or str.format() that mixes in a non-literal piece."""
    return _builds_string(expr) and has_dynamic_part(expr)


def contains_list(expr):
    """True when a '+' chain joins argument lists, which is argv building and not string building."""
    if isinstance(expr, (ast.List, ast.Tuple)):
        return True
    if isinstance(expr, ast.BinOp) and isinstance(expr.op, ast.Add):
        return contains_list(expr.left) or contains_list(expr.right)
    return False


def string_pieces(expr):
    """Every string literal inside an expression, so a rule can read the command text it ends up in."""
    return " ".join(n.value for n in ast.walk(expr) if isinstance(n, ast.Constant) and isinstance(n.value, str))


def _builds_string(expr):
    if isinstance(expr, ast.JoinedStr):
        return True
    if isinstance(expr, ast.BinOp) and isinstance(expr.op, (ast.Add, ast.Mod)):
        return not (isinstance(expr.op, ast.Add) and contains_list(expr))
    if isinstance(expr, ast.Call) and isinstance(expr.func, ast.Attribute) and expr.func.attr == "format":
        return True
    return False


class Checker(ast.NodeVisitor):
    def __init__(self, relpath, assignments=None):
        self.relpath = relpath
        self.findings = []
        # name -> value, only for names assigned exactly once in the file, so `cmd = "x " + y` is followed into local_resource(cmd=cmd).
        self.assignments = assignments or {}

    def resolve(self, expr):
        """Follow a single-assignment variable one step to the expression it was built from."""
        if isinstance(expr, ast.Name) and expr.id in self.assignments:
            return self.assignments[expr.id]
        return expr

    def check_command(self, node, string_rule, label):
        """Run every command rule on one command expression (the argument a shell or exec will run)."""
        expr = self.resolve(node)
        if is_string_built(expr):
            self.report(string_rule, node, f"{label} is built from a string; pass a list of arguments instead.")
        text = string_pieces(expr)
        if PIPE_TO_SHELL.search(text):
            self.report("pipe-to-shell", node, f"{label} pipes a download into a shell; download, verify a checksum, then run.")
        if HTTP_DOWNLOAD.search(text):
            self.report("insecure-http-download", node, f"{label} downloads over http://; use https:// and verify a checksum.")
        if TLS_OFF.search(text):
            self.report("tls-verification-disabled", node, f"{label} disables TLS certificate verification.")
        if SUDO.search(text):
            self.report("sudo-in-command", node, f"{label} runs sudo; print the command for the user to run instead.")
        if PRIVILEGED.search(text):
            self.report("privileged-container", node, f"{label} starts a container with host-level access.")

    def report(self, rule_id, node, message):
        self.findings.append(
            {
                "rule": rule_id,
                "message": message,
                "line": node.lineno,
                "column": node.col_offset + 1,
            }
        )

    def visit_Call(self, node):
        name = call_name(node)
        args = node.args
        first = args[0] if args else None

        if name == "load" and isinstance(first, ast.Constant) and isinstance(first.value, str):
            label = first.value
            if label.startswith("http://"):
                self.report("insecure-http-download", node, f"load('{label}') fetches over http://; use https://.")
            if label.startswith(REMOTE_PREFIXES) and not COMMIT_PIN.search(label):
                self.report("unpinned-remote-load", node, f"load('{label}') is not pinned to a commit or sha256.")

        if name == "local_resource":
            for kw in node.keywords:
                if kw.arg in LOCAL_RESOURCE_CMD_KWARGS:
                    self.check_command(kw.value, "string-built-local-resource-cmd", f"{kw.arg}")
            if len(args) > 1:
                self.check_command(args[1], "string-built-local-resource-cmd", "cmd")

        if name in COMMAND_CALLS:
            keyword, index = COMMAND_CALLS[name]
            for kw in node.keywords:
                if kw.arg == keyword:
                    self.check_command(kw.value, "string-built-local-command", f"{name}() {keyword}")
            if len(args) > index and not any(kw.arg == keyword for kw in node.keywords):
                self.check_command(args[index], "string-built-local-command", f"{name}() {keyword}")

        if name in FILE_READERS and isinstance(first, ast.Constant) and isinstance(first.value, str):
            target = first.value
            if target.startswith("/") or ".." in target.replace("\\", "/").split("/"):
                self.report("read-outside-root", node, f"{name}('{target}') reads outside the project root.")

        # load("f.star", _Secrets="Secrets") binds an alias; the keyword is a symbol name, not a value.
        for kw in node.keywords if name != "load" else []:
            if kw.arg and SECRET_NAME.search(kw.arg) and looks_like_credential(kw.value):
                self.report("literal-secret", kw.value, f"'{kw.arg}' is set to a string literal.")

        self.generic_visit(node)

    def visit_Assign(self, node):
        if looks_like_credential(node.value):
            for target in node.targets:
                if isinstance(target, ast.Name) and SECRET_NAME.search(target.id):
                    self.report("literal-secret", node.value, f"'{target.id}' is assigned a string literal.")
        self.generic_visit(node)



def single_assignments(tree):
    """Map each name that is assigned exactly once (anywhere in the file) to its value."""
    counts = {}
    values = {}
    for node in ast.walk(tree):
        targets = []
        if isinstance(node, ast.Assign):
            targets = [(t.id, node.value) for t in node.targets if isinstance(t, ast.Name)]
        elif isinstance(node, ast.AugAssign) and isinstance(node.target, ast.Name):
            counts[node.target.id] = counts.get(node.target.id, 0) + 2
        for name, value in targets:
            counts[name] = counts.get(name, 0) + 1
            values[name] = value
    return {name: values[name] for name, count in counts.items() if count == 1 and name in values}


def analyze_source(source, relpath):
    """Return (findings, parse_error). parse_error is a string or None."""
    try:
        tree = ast.parse(source, filename=relpath)
    except SyntaxError as err:
        return [], f"{err.msg} at line {err.lineno}"
    checker = Checker(relpath, single_assignments(tree))
    checker.visit(tree)
    return checker.findings, None


def discover(root, patterns, excludes=()):
    seen = set()
    for pattern in patterns:
        for path in glob.glob(os.path.join(root, pattern), recursive=True):
            if os.path.isfile(path):
                seen.add(os.path.relpath(path, root).replace(os.sep, "/"))
    skipped = set()
    for pattern in excludes:
        for path in glob.glob(os.path.join(root, pattern), recursive=True):
            skipped.add(os.path.relpath(path, root).replace(os.sep, "/"))
    return sorted(seen - skipped)


def fingerprint(rule_id, relpath, message):
    digest = hashlib.sha256(f"{rule_id}|{relpath}|{message}".encode("utf-8")).hexdigest()
    return digest


def build_sarif(root, files):
    rules = []
    rule_index = {}
    for rule_id, meta in RULES.items():
        rule_index[rule_id] = len(rules)
        rules.append(
            {
                "id": rule_id,
                "name": meta["name"],
                "shortDescription": {"text": meta["text"]},
                "defaultConfiguration": {"level": meta["level"]},
            }
        )

    results = []
    notifications = []
    for relpath in files:
        with open(os.path.join(root, relpath), encoding="utf-8") as handle:
            source = handle.read()
        findings, parse_error = analyze_source(source, relpath)
        if parse_error:
            notifications.append(
                {
                    "level": "note",
                    "message": {"text": f"Could not parse {relpath}: {parse_error}"},
                    "locations": [{"physicalLocation": {"artifactLocation": {"uri": relpath}}}],
                }
            )
            continue
        for item in findings:
            results.append(
                {
                    "ruleId": item["rule"],
                    "ruleIndex": rule_index[item["rule"]],
                    "level": RULES[item["rule"]]["level"],
                    "message": {"text": item["message"]},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": relpath},
                                "region": {"startLine": item["line"], "startColumn": item["column"]},
                            }
                        }
                    ],
                    "partialFingerprints": {
                        "starlarkFindingHash/v1": fingerprint(item["rule"], relpath, item["message"]),
                    },
                }
            )

    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": TOOL_NAME, "version": TOOL_VERSION, "rules": rules}},
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "toolExecutionNotifications": notifications,
                    }
                ],
                "results": results,
            }
        ],
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description="Check Starlark files and write SARIF.")
    parser.add_argument("--root", default=".", help="project root to scan (default: current directory)")
    parser.add_argument("--pattern", action="append", dest="patterns", help="glob relative to root; repeatable")
    parser.add_argument("--exclude", action="append", dest="excludes", help="glob relative to root to skip (for example generated golden files); repeatable")
    parser.add_argument("--output", default="starlark-analyze.sarif", help="SARIF file to write")
    parser.add_argument("--fail-on-findings", action="store_true", help="exit 1 when any result is reported")
    args = parser.parse_args(argv)

    root = os.path.abspath(args.root)
    files = discover(root, args.patterns or DEFAULT_PATTERNS, args.excludes or [])
    sarif = build_sarif(root, files)
    with open(args.output, "w", encoding="utf-8") as handle:
        json.dump(sarif, handle, indent=2)
        handle.write("\n")

    results = sarif["runs"][0]["results"]
    print(f"Scanned {len(files)} file(s), {len(results)} finding(s). SARIF written to {args.output}.")
    if args.fail_on_findings and results:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
