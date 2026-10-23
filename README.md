# codeql-starlark

> **Community project.** Not made, endorsed or supported by GitHub or the CodeQL team. It does not use CodeQL: it parses Starlark itself and reports through SARIF.

Static checks for Starlark files (`Tiltfile`, `*.star`) that write [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html), so the results appear under Code scanning next to CodeQL.

**Published on the GitHub Marketplace:** [Starlark Analyzer for Code Scanning](https://github.com/marketplace/actions/starlark-analyzer-for-code-scanning). Current release: [v0.2.1](https://github.com/flisk-sh/codeql-starlark/releases/tag/v0.2.1).

CodeQL does not analyze Starlark. This project fills that gap.

## Rules

| Rule | Level | What it flags |
| --- | --- | --- |
| `unpinned-remote-load` | warning | `load()` of a `http(s)`, `git` or `ssh` URL with no commit SHA or `sha256` in it |
| `string-built-local-resource-cmd` | warning | `local_resource(cmd=, serve_cmd=, cmd_bat=)` (or the positional command) built with `+`, `%`, `.format()` or an f-string that mixes in a non-literal value. A name assigned once is followed (`c = "make " + t` then `cmd=c`). Joining argument **lists** with `+` is argv building and is not flagged. Joining two literals is not flagged |
| `string-built-local-command` | note | the same pattern in `local()` and `custom_build()` commands |
| `pipe-to-shell` | error | `curl ... \| sh` or `wget ... \| bash` in a command |
| `insecure-http-download` | error | `curl`/`wget` of an `http://` URL on a non-local host, or `load("http://...")` |
| `tls-verification-disabled` | error | `curl -k`, `--insecure`, `--no-check-certificate`, `NODE_TLS_REJECT_UNAUTHORIZED=0`, `GIT_SSL_NO_VERIFY` and similar |
| `sudo-in-command` | warning | `sudo` in a command |
| `privileged-container` | warning | `--privileged`, the Docker socket, `docker run --network host` or `--pid host` in a command |
| `literal-secret` | warning | a name that **ends** in `password`, `secret`, `token`, `api_key` or `private_key` set to a credential-looking string. Not flagged: empty values, values with spaces, env placeholders such as `${DB_PASSWORD}`, paths, `load()` aliases, and names like `SECRET_PATH` or `SECRET_PROVIDER` |
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
      - uses: flisk-sh/codeql-starlark@d7626243e510170baf13c53d2895c12576823b0a # v0.2.1
```

Inputs:

- `patterns`: space-separated globs. Default `**/*.star **/Tiltfile`.
- `exclude`: space-separated globs to skip, for example generated golden files (`**/__tests__/**`). Default none.
- `category`: SARIF category in Code scanning. Default `/language:starlark`.
- `fail-on-findings`: set to `"true"` to fail the step on any result. Default `"false"`, report only.

## Run it locally

```bash
python3 starlark_analyze.py --root path/to/project --exclude '**/__tests__/**' --output starlark-analyze.sarif
python3 -m unittest tests.test_rules -v
```

Python 3.9 or newer is enough. There are no dependencies.

## Status

Early. Each rule has a unit test and a fixture. 0.2.0 added the command rules above after the first release found only four alerts on a real repository. Expect false positives on code that builds commands dynamically on purpose.

## License

MIT. See [LICENSE](LICENSE).
