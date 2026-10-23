# codeql-starlark

> **Unofficial community project.** Not made, endorsed or supported by GitHub or the CodeQL team. It does not use CodeQL: it parses Starlark itself and reports through SARIF.

Static checks for Starlark files (`Tiltfile`, `*.star`) that write [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html), so the results appear under Code scanning next to CodeQL.

CodeQL does not analyze Starlark. This project fills that gap.

## Rules

| Rule | Level | What it flags |
| --- | --- | --- |
| `unpinned-remote-load` | warning | `load()` of a `http(s)`, `git` or `ssh` URL with no commit SHA or `sha256` in it |
| `string-built-local-resource-cmd` | warning | `local_resource(cmd=...)` built with `+`, `%`, `.format()` or an f-string |
| `literal-secret` | error | a `password`, `secret`, `token` or `api_key` name set to a non-empty string literal |
| `read-outside-root` | warning | `read_file`, `read_yaml`, `read_json`, `read_csv` or `listdir` on an absolute path or one containing `..` |

Starlark is a restricted subset of Python, so the analyzer parses files with Python's `ast` module. It needs no Starlark engine and no dependencies. A file the parser rejects is reported as a notification, not skipped.

## Use it in a repository

Add a job that checks out your repository and runs the action, pinned to a full commit SHA:

```yaml
name: 🔬 Starlark

on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read

jobs:
  starlark:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v7
        with:
          persist-credentials: false
      - uses: flisk-sh/codeql-starlark@<full commit SHA>
```

Inputs:

- `patterns`: space-separated globs. Default `**/*.star **/Tiltfile`.
- `category`: SARIF category in Code scanning. Default `/language:starlark`.
- `fail-on-findings`: set to `"true"` to fail the step on any result. Default `"false"`, report only.

## Run it locally

```bash
python3 starlark_analyze.py --root path/to/project --output starlark-analyze.sarif
python3 -m unittest tests.test_rules -v
```

Python 3.9 or newer is enough. There are no dependencies.

## Status

Early. The rule set is small and each rule has a fixture. Expect false positives on code that builds commands dynamically on purpose.

## License

MIT. See [LICENSE](LICENSE).
