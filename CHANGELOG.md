# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/) and the project uses [Semantic Versioning](https://semver.org/).

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
