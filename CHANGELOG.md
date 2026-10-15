# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/) and the project uses [Semantic Versioning](https://semver.org/).

## [1.1.0] - 2026-10-15

### Changed
- **Licence changes are reported, not judged.** The `copyleft-license` rule and `--copyleft` are removed (passing `--copyleft` / `copyleft` now only adds an info warning). `license-changed` findings carry license-sentinel categories (`fromCategory`, `toCategory`); put licence policy in license-sentinel. Depends on license-sentinel ^1.1.0.
- `--offline` now uses cached OSV results instead of skipping the lookup, and reports components missing from the cache.

### Added
- VEX: `--vex` takes CycloneDX VEX or OpenVEX documents, and VEX embedded in the head CycloneDX SBOM is applied automatically. `not_affected`, `false_positive`, `fixed` and `resolved` vulnerabilities are suppressed and listed under `vulnerabilities.vex`; other statuses are noted on the finding.
- On-disk OSV cache (`--cache-dir`, `--cache-ttl`, default 24 h, `--no-cache`), one file per OSV endpoint.
- `--pr-comment <file>` writes a short sticky PR comment (verdict, new vulnerabilities, licence changes, downgrades). The Action gains `pr-comment`, `github-token` and `vex` inputs and posts or updates the comment. Markdown output stays under GitHub's 65,000-character comment limit.
- Dual ESM + CommonJS build with generated type declarations; CI checks `require` and `import` from the packed tarball.

## [1.0.0] - 2026-10-13

### Added
- Reads CycloneDX 1.4–1.6 JSON (nested components, root excluded, licenses/expressions, hashes, supplier/publisher/authors) and SPDX 2.3 JSON (purl external refs, NOASSERTION handling, supplier prefixes, checksums).
- Generates CycloneDX 1.5 SBOMs from npm, pnpm and yarn lockfiles using the published `license-sentinel` library (`--generate`, `--include-dev`).
- Compares two SBOM files, a file against the project, or a git ref against the working tree (`--base origin/main`), including projects in subdirectories of a repo.
- Reports added, removed, upgraded and downgraded components (multi-version aware, semver-ish ordering), license changes, supplier changes and same-version hash changes.
- OSV.dev batch vulnerability lookup (`/v1/querybatch` with pagination plus detail fetches) for added/changed components; new vs fixed vs persisting vulnerabilities with alias matching; severity from CVSS v3 vectors or advisory ratings; `--offline`, `--osv-url`.
- Policy rules: `new-vulnerability`, `copyleft-license` (weak/strong/network levels), `hash-changed`, `too-many-changes` (`--max-changes`), `downgrade` (`--deny-downgrades`), `supplier-changed`, `license-changed`, `osv-error`, `allowlist-expired`, `unscanned-component`, `sbom-warning`; per-rule severity overrides and an allowlist (vuln id/alias, package glob, rule) with reasons and expiry.
- Text, JSON, SARIF 2.1.0 and Markdown output (PR-comment marker, collapsible sections, job summary); `--fail-on`; exit codes 0/1/2.
- Composite GitHub Action (auto base ref on pull requests), programmatic API and TypeScript types. One runtime dependency (`license-sentinel`, itself zero-dependency).
