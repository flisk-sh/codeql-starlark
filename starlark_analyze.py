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

TOOL_NAME = "codeql-starlark (unofficial)"
TOOL_VERSION = "0.1.0"
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
    if "$" in value or value.startswith(("/", "./", "../", "<", "{{", "%(")):
        return False  # env placeholder like ${DB_PASSWORD}, a path, or a template
    return True


def has_dynamic_part(expr):
    """True when a string expression mixes in anything that is not a plain string literal."""
    if isinstance(expr, ast.Constant):
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


def _builds_string(expr):
    if isinstance(expr, ast.JoinedStr):
        return True
    if isinstance(expr, ast.BinOp) and isinstance(expr.op, (ast.Add, ast.Mod)):
        return True
    if isinstance(expr, ast.Call) and isinstance(expr.func, ast.Attribute) and expr.func.attr == "format":
        return True
    return False


class Checker(ast.NodeVisitor):
    def __init__(self, relpath):
        self.relpath = relpath
        self.findings = []

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
            if label.startswith(REMOTE_PREFIXES) and not COMMIT_PIN.search(label):
                self.report("unpinned-remote-load", node, f"load('{label}') is not pinned to a commit or sha256.")

        if name == "local_resource":
            for kw in node.keywords:
                if kw.arg == "cmd" and is_string_built(kw.value):
                    self.report("string-built-local-resource-cmd", kw.value, "cmd is built from a string; pass a list of arguments instead.")

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



def analyze_source(source, relpath):
    """Return (findings, parse_error). parse_error is a string or None."""
    try:
        tree = ast.parse(source, filename=relpath)
    except SyntaxError as err:
        return [], f"{err.msg} at line {err.lineno}"
    checker = Checker(relpath)
    checker.visit(tree)
    return checker.findings, None


def discover(root, patterns):
    seen = set()
    for pattern in patterns:
        for path in glob.glob(os.path.join(root, pattern), recursive=True):
            if os.path.isfile(path):
                seen.add(os.path.relpath(path, root).replace(os.sep, "/"))
    return sorted(seen)


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
    parser.add_argument("--output", default="starlark-analyze.sarif", help="SARIF file to write")
    parser.add_argument("--fail-on-findings", action="store_true", help="exit 1 when any result is reported")
    args = parser.parse_args(argv)

    root = os.path.abspath(args.root)
    files = discover(root, args.patterns or DEFAULT_PATTERNS)
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
