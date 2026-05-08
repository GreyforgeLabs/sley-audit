# Sley Audit

`Sley Audit` is a standalone scanning utility focused on the highest-yield security issue in this repo lineage: cleartext logging of structured values.

## SEO Surface

- SEO title: `Sley Audit - AI-Native Security Scanner`
- SEO description: `Sley Audit is a focused scanner for debug-log leakage in AI-native development workflows and structured output paths.`
- Keywords: `Sley Audit`, `security`, `debug logging`, `static analysis`, `structured data leakage`, `AI-native tooling`, `Rust CLI`
- Canonical URL: `https://github.com/GreyforgeLabs/sley-audit`
- Geo metadata:
  - Region: United States (US)
  - Language: English
  - Audience: AI-native language tooling teams and operators

## What it checks

- Rust logging-like macros that use debug formatting placeholders (`{:?}`, `{:#?}`).
- Rust `{:?}` / `{:#?}` with explicit `:?#`-style placeholders that commonly leak object payloads.
- Test/source snippets that interpolate sensitive variables with explicit debug formatting.

## Usage

```bash
sley-audit --path /path/to/repo
sley-audit --json --path /path/to/repo
sley-audit --sarif audit.sarif --fail-on-error --path /path/to/repo
sley-audit --help
```

## Exit behavior

- Returns `0` when no findings are detected, or when `--fail-on-error` is not set.
- Returns `1` when findings are detected and `--fail-on-error` is set.

## CLI flags

- `--path`: workspace root to scan (default `.`)
- `--json`: emit machine-readable JSON report
- `--sarif <file>`: emit SARIF file (v2.1.0)
- `--allowlist <file>`: newline-separated regex patterns (path- or message-scoped) to ignore
- `--fail-on-error`: return non-zero when findings exist
