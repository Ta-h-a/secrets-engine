# SecretLens

High-performance secret and vulnerability detection engine, written in Rust. Drop-in replacement for the original C# engine with identical JSON pipe protocol, plus an optional HTTP server mode.

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Installation](#installation)
- [Usage](#usage)
  - [Pipe Mode](#pipe-mode)
  - [Serve Mode](#serve-mode)
- [CLI Reference](#cli-reference)
- [Exit Codes](#exit-codes)
- [Detection Rules](#detection-rules)
- [JSON Pipe Protocol](#json-pipe-protocol)
- [HTTP API](#http-api)
- [Analysis Pipeline](#analysis-pipeline)
- [Output Formats](#output-formats)
- [AI Enrichment](#ai-enrichment)
- [Pre-commit Hook](#pre-commit-hook)
- [Custom Rules](#custom-rules)
- [Building from Source](#building-from-source)
- [Contributing](#contributing)

---

## Overview

SecretLens scans source code for secrets, credentials, and security vulnerabilities. It ships with 20 built-in rules covering AWS keys, API tokens, private keys, weak cryptography, injection risks, and more.

**Key properties:**

- Parallel analysis via Rayon — scales linearly with CPU cores
- Two analyzers: regex-based and AST-based (Python via `rustpython-parser`, JS/TS via `oxc`)
- Four-stage pipeline: analysis → redaction → deduplication → optional AI enrichment
- Three output formats: JSON, plain text, SARIF 2.1.0 (GitHub Advanced Security compatible)
- Stdout is reserved for JSON protocol output; all logs go to stderr
- Full drop-in compatibility with the C# engine pipe protocol

---

## Architecture

SecretLens is a Cargo workspace with one binary crate and six library crates:

```
secretlens (binary)
│
├── secretlens-core          Protocol types, Finding, Rule, AstPattern
├── secretlens-rules         YAML rule loader, RuleRegistry, 20 compiled-in defaults
├── secretlens-analyzers     RegexAnalyzer (DashMap cache) + AstAnalyzer (rustpython + oxc)
├── secretlens-pipeline      4-stage pipeline, SARIF serializer
├── secretlens-ai            AiProvider trait; Null, Local (Ollama), Cloud (OpenAI-compatible)
└── secretlens-http          Axum HTTP server, 4 routes, RotationForwarder → code-guard
```

### Crate responsibilities

| Crate | Responsibility |
|---|---|
| `secretlens-core` | Shared data types: `Finding`, `Rule`, `AstPattern`, `ProtocolRequest`, `ProtocolResponse` |
| `secretlens-rules` | Loads rules from a YAML directory; falls back to 20 compiled-in defaults if the directory is missing |
| `secretlens-analyzers` | `RegexAnalyzer` compiles patterns once into a `DashMap` cache; `AstAnalyzer` dispatches to language-specific walkers |
| `secretlens-pipeline` | Orchestrates the four pipeline stages; exposes `run_pipeline()` and `to_sarif()` |
| `secretlens-ai` | Async AI enrichment; provider selected at runtime via `aiProviderConfig` in the request |
| `secretlens-http` | Axum router; `RotationForwarder` proxies AWS key findings to the code-guard rotation service |

---

## Installation

### Pre-built binary

Download a release binary from the releases page and place it on your `PATH`:

```sh
chmod +x secretlens
sudo mv secretlens /usr/local/bin/
```

### Build from source

See [Building from Source](#building-from-source).

---

## Usage

### Pipe Mode

Pipe mode is the default. The engine reads newline-delimited JSON requests from stdin and writes newline-delimited JSON responses to stdout. All diagnostic output goes to stderr.

```sh
echo '{"command":"analyze","payload":{"files":[{"filePath":"main.py","content":"password=\"hunter2\""}]}}' \
  | secretlens
```

This is the protocol used by the pre-commit hook and by the original C# engine integration.

#### Output format

Control the format of findings in pipe mode with `--format`:

```sh
echo '...' | secretlens --format text
echo '...' | secretlens --format sarif
echo '...' | secretlens --format json   # default
```

### Serve Mode

Serve mode starts an Axum HTTP server. Use this for editor integrations, CI pipelines, or any client that prefers HTTP over stdin/stdout.

```sh
secretlens --mode serve
# Listening on 0.0.0.0:8080

secretlens --mode serve --bind 127.0.0.1:9000
```

---

## CLI Reference

```
USAGE:
    secretlens [OPTIONS]

OPTIONS:
    --mode <MODE>
        Operating mode [default: pipe]
        Values: pipe, serve

    --rules-dir <PATH>
        Directory containing YAML rule files
        [env: SECRETLENS_RULES_DIR]
        [default: ./rules/ relative to the binary]

    --format <FORMAT>
        Output format for pipe mode findings [default: json]
        Values: json, text, sarif

    --bind <ADDR>
        Address to bind in serve mode [default: 0.0.0.0:8080]

    --rotation-endpoint <URL>
        Base URL of the code-guard key rotation service
        [env: CODEGUARD_ENDPOINT]
        [default: http://localhost:8000]

    --log-level <LEVEL>
        Log verbosity [default: warn]
        [env: RUST_LOG]
        Values: off, error, warn, info, debug, trace
```

`RUST_LOG` overrides `--log-level` when both are set.

---

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | Success — no findings |
| `1` | Success — one or more findings detected |
| `2` | Engine error (bad input, rule load failure, etc.) |

Exit code `1` is intentional and allows shell scripts and CI pipelines to distinguish "clean scan" from "findings present" without parsing JSON.

---

## Detection Rules

SecretLens ships with 20 built-in rules. Rules are loaded from the `--rules-dir` directory at startup; the compiled-in defaults are used as a fallback if the directory is absent.

### Built-in rules

| Rule ID | Name | Severity | Language | Analyzer |
|---|---|---|---|---|
| SEC-001 | AWS Access Key Exposed | critical | * | regex |
| SEC-002 | Generic API Key Detected | high | * | regex |
| SEC-003 | Google API Key Detected | high | * | regex |
| SEC-004 | Hardcoded Password | high | * | regex |
| SEC-005 | Stripe API Key Detected | critical | * | regex |
| SEC-006 | SendGrid API Key Detected | high | * | regex |
| SEC-007 | Slack Webhook URL Detected | high | * | regex |
| SEC-008 | Twilio Credentials Detected | high | * | regex |
| SEC-009 | Cloudflare Token Detected | high | * | regex |
| SEC-010 | GitHub Token Detected | critical | * | regex |
| SEC-011 | OpenAI API Key Detected | critical | * | regex |
| SEC-012 | Anthropic API Key Detected | critical | * | regex |
| SEC-013 | PEM Private Key Detected | critical | * | regex |
| SEC-014 | JWT Token Detected | medium | * | regex |
| SEC-015 | SQL Injection Risk | high | * | regex |
| PERF-001 | Synchronous File I/O | medium | javascript/typescript | regex |
| AST-PY-001 | Python eval() Usage | critical | python | ast |
| AST-PY-002 | Python exec() Usage | critical | python | ast |
| AST-JS-001 | JavaScript eval() Usage | critical | javascript | ast |
| AST-JS-002 | JavaScript Weak Crypto | high | javascript | ast |

Rules marked `*` for language apply to all file types.

---

## JSON Pipe Protocol

The pipe protocol is line-delimited JSON: one request per line in, one response per line out.

### Request envelope

```json
{
  "command": "analyze",
  "payload": { ... }
}
```

`command` is either `"analyze"` or `"resolve"`.

### Analyze request payload

```json
{
  "files": [
    {
      "filePath": "src/config.py",
      "content": "<full file content as a string>"
    }
  ],
  "aiProviderConfig": {
    "provider": "none"
  }
}
```

`aiProviderConfig` is optional. See [AI Enrichment](#ai-enrichment) for provider options.

### Response envelope

```json
{
  "status": "success",
  "payload": {
    "findings": [ ... ]
  }
}
```

`status` is `"success"` or `"error"`. On error, `payload` contains a `"message"` field instead of `"findings"`.

### Finding object

| Field | Type | Description |
|---|---|---|
| `id` | string (UUIDv4) | Unique finding identifier |
| `filePath` | string | Path as provided in the request |
| `lineNumber` | integer | 1-indexed line of the match |
| `ruleId` | string | Rule that triggered (e.g. `SEC-001`) |
| `type` | string | Finding category |
| `severity` | string | `critical`, `high`, `medium`, `low` |
| `title` | string | Short human-readable title |
| `message` | string | Description of the finding |
| `description` | string | Extended explanation |
| `rawFindingData` | string | Redacted match text |
| `recommendations` | string[] | Suggested remediation steps |
| `references` | string[] | External links |
| `tags` | string[] | Categorization tags |
| `impact` | string \| null | AI-generated impact assessment (optional) |
| `suggestedFix` | string \| null | AI-generated fix suggestion (optional) |

### Example: clean scan

```sh
$ echo '{"command":"analyze","payload":{"files":[{"filePath":"hello.py","content":"print(\"hello\")"}]}}' \
    | secretlens
{"status":"success","payload":{"findings":[]}}
$ echo $?
0
```

### Example: finding detected

```sh
$ echo '{"command":"analyze","payload":{"files":[{"filePath":"cfg.py","content":"AWS_KEY=\"AKIAIOSFODNN7EXAMPLE\""}]}}' \
    | secretlens
{"status":"success","payload":{"findings":[{"id":"...","filePath":"cfg.py","lineNumber":1,"ruleId":"SEC-001",...}]}}
$ echo $?
1
```

---

## HTTP API

Start the server with `--mode serve`, then use the following endpoints.

### `GET /health`

Liveness check.

**Response:**
```json
{ "status": "ok", "version": "1.0.0" }
```

### `POST /analyze`

Analyze one or more files. Request and response bodies are identical to the pipe protocol payload (no command envelope needed).

**Request body:**
```json
{
  "files": [
    { "filePath": "src/app.js", "content": "..." }
  ],
  "aiProviderConfig": { "provider": "none" }
}
```

**Response body:** same structure as the pipe protocol response.

### `POST /resolve`

Resolve a finding by ID. Accepts a finding `id` and returns additional context.

### `POST /forward-to-rotation`

Forward an AWS key finding to the code-guard rotation service. The server proxies the request to `POST {rotation-endpoint}/api/v1/rotate`.

**Request body:**
```json
{
  "iam_user": "deploy-bot",
  "access_key_id": "AKIAIOSFODNN7EXAMPLE",
  "incident_id": "...",
  "risk_level": "critical"
}
```

The rotation endpoint base URL is configured with `--rotation-endpoint` or the `CODEGUARD_ENDPOINT` environment variable.

---

## Analysis Pipeline

Every scan runs through four sequential stages:

```
Input files
    │
    ▼
1. Parallel Analysis
   ├── RegexAnalyzer  — Rayon parallel iterator; patterns compiled once into DashMap cache
   └── AstAnalyzer    — Language-specific AST walkers (Python: rustpython-parser, JS/TS: oxc)
    │
    ▼
2. Redaction
   Per-rule redact flag; matched text replaced before storing in rawFindingData
    │
    ▼
3. Deduplication
   Keyed on (filePath, lineNumber, ruleId) — eliminates duplicate matches
    │
    ▼
4. AI Enrichment  (optional, async)
   Adds impact and suggestedFix fields to each finding
    │
    ▼
Output findings
```

### Line number resolution

The regex analyzer builds a byte-offset-to-line lookup table once per file (O(n)), then resolves each match position with a binary search (O(log n)).

### AST analysis

**Python** (`rustpython-parser 0.3`): walks the AST for `Call` nodes (detecting `eval`, `exec`) and `Import`/`ImportFrom` nodes (detecting dangerous modules like `subprocess`).

**JavaScript / TypeScript** (`oxc_parser 0.29`): walks the AST via a custom visitor, detecting `CallExpression` nodes, `StaticMemberExpression` nodes, and weak cryptography string arguments (e.g. `"md5"`, `"sha1"`).

AST pattern syntax used in rule YAML:

| Pattern | Matches |
|---|---|
| `call:eval` | Any call to `eval()` |
| `member_call:fs.readFileSync` | Member call `fs.readFileSync(...)` |
| `crypto_weak:md5` | Weak algorithm string passed to a crypto function |
| `import:subprocess` | Import of the `subprocess` module |

---

## Output Formats

### JSON (default)

Standard pipe protocol response. Machine-readable, suitable for downstream tooling.

### Text

Human-readable table printed to stdout. Useful for local development:

```sh
echo '...' | secretlens --format text
```

### SARIF 2.1.0

GitHub Advanced Security compatible. Upload to GitHub Code Scanning:

```sh
echo '...' | secretlens --format sarif > results.sarif
```

Then in your GitHub Actions workflow:

```yaml
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

---

## AI Enrichment

AI enrichment is opt-in. It adds `impact` and `suggestedFix` fields to each finding. Configure it via `aiProviderConfig` in the request payload.

### No AI (default)

```json
{ "provider": "none" }
```

### Local model (Ollama)

Requires a running Ollama instance with `llama3` pulled.

```json
{
  "provider": "local",
  "endpoint": "http://localhost:11434",
  "model": "llama3"
}
```

### Cloud model (OpenAI-compatible)

Uses `gpt-4o-mini` by default. Compatible with any OpenAI-compatible API.

```json
{
  "provider": "cloud",
  "endpoint": "https://api.openai.com/v1",
  "apiKey": "sk-...",
  "model": "gpt-4o-mini"
}
```

---

## Pre-commit Hook

The `hooks/pre-commit` script integrates SecretLens into your Git workflow. It scans staged files before every commit and blocks the commit if findings are present.

### Installation

Copy the hook into your repository:

```sh
cp /path/to/secretlens/hooks/pre-commit .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

Or symlink it for automatic updates:

```sh
ln -sf /path/to/secretlens/hooks/pre-commit .git/hooks/pre-commit
```

### How it works

1. Collects staged files via `git diff --cached --name-only --diff-filter=ACM`
2. Reads the content of each staged file
3. Builds a JSON analyze request and pipes it to the SecretLens binary
4. Parses the response with Python 3
5. Prints a colored findings table to the terminal
6. Exits with code `1` (blocking the commit) if any findings are present

### Binary resolution

The hook locates the engine binary in this order:

1. `$SECRETLENS_BIN` environment variable
2. `secretlens` on `PATH`
3. `../projectInRust/target/debug/secretlens` relative to the repository

### Bypassing the hook

```sh
git commit --no-verify
```

Use sparingly. Prefer fixing the finding or adding an inline suppression comment.

---

## Custom Rules

Rules are YAML files in the `--rules-dir` directory. Each file defines one rule.

### Rule schema

```yaml
id: "MY-RULE-001"
name: "My Custom Rule"
description: "Detects a dangerous pattern."
severity: "high"          # critical | high | medium | low
language: "*"             # * | python | javascript | typescript | ...
analyzer: "regex"         # regex | ast
pattern: "dangerous_fn\\("
redact: true
redact_replacement: "[REDACTED]"
tags:
  - security
  - custom
recommendations:
  - "Replace dangerous_fn() with a safe alternative."
references:
  - "https://example.com/security-advisory"
```

### AST rule example

```yaml
id: "AST-PY-003"
name: "Python subprocess Usage"
description: "Detects import of the subprocess module."
severity: "medium"
language: "python"
analyzer: "ast"
pattern: "import:subprocess"
redact: false
tags:
  - security
```

Place YAML files in the rules directory and restart the engine. Compiled-in defaults are still active unless you explicitly replace them with rules of the same ID.

---

## Building from Source

### Prerequisites

- Rust 1.75 or later (`rustup update stable`)
- `git`

### Debug build

```sh
git clone <repo-url>
cd projectInRust
cargo build
./target/debug/secretlens --help
```

### Release build

```sh
cargo build --release
./target/release/secretlens --help
```

The release profile uses `opt-level=3`, `lto="thin"`, `codegen-units=1`, and `strip=true` for a compact, optimized binary.

### Running tests

```sh
cargo test --workspace
```

All 48 unit tests should pass.

### Workspace layout

```
projectInRust/
├── Cargo.toml              Workspace manifest
├── src/
│   └── main.rs             CLI entry point, pipe loop, serve dispatch
├── hooks/
│   └── pre-commit          Git pre-commit hook script
├── rules/                  Built-in YAML rule files (20 rules)
└── crates/
    ├── secretlens-core/
    ├── secretlens-rules/
    ├── secretlens-analyzers/
    ├── secretlens-pipeline/
    ├── secretlens-ai/
    └── secretlens-http/
```

---

## Contributing

1. Fork the repository and create a feature branch.
2. Make your changes; add tests for new behavior.
3. Run `cargo test --workspace` and ensure all tests pass.
4. Run `cargo clippy --workspace -- -D warnings` and fix any lints.
5. Open a pull request with a clear description of the change.

### Adding a new rule

1. Create a YAML file in `rules/` following the schema above.
2. If the rule should be a compiled-in default, add it to `crates/secretlens-rules/src/defaults.rs`.
3. Add a unit test in `crates/secretlens-analyzers/src/` that exercises the pattern.

### Adding a new analyzer

1. Implement the `Analyzer` trait in `crates/secretlens-analyzers/src/`.
2. Register it in the pipeline in `crates/secretlens-pipeline/src/pipeline.rs`.
3. Add an `analyzer` key value to the rule schema and handle it in the rule loader.
