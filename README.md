# sbom-diff-sentinel

[![npm version](https://img.shields.io/npm/v/sbom-diff-sentinel.svg)](https://www.npmjs.com/package/sbom-diff-sentinel) [![CI](https://github.com/MrLouisWright/sbom-diff-sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/MrLouisWright/sbom-diff-sentinel/actions/workflows/ci.yml) [![Node](https://img.shields.io/node/v/sbom-diff-sentinel.svg)](https://nodejs.org) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> See exactly what a pull request changes in your software bill of materials, and block the risky changes.

`sbom-diff-sentinel` compares two SBOMs, or your project at a git ref against the working tree. It reports components that were **added, removed, upgraded or downgraded**, plus **license, supplier and hash changes**. It checks the added and changed components against **[OSV.dev](https://osv.dev)** and splits the results into **new** and **fixed** vulnerabilities, each with a severity. Then it applies a policy: fail on new vulnerabilities at or above a severity, downgrades, new copyleft licenses or oversized changes.

- Reads **CycloneDX 1.4–1.6 JSON** and **SPDX 2.3 JSON**
- Generates SBOMs from npm, pnpm and yarn lockfiles with [license-sentinel](https://www.npmjs.com/package/license-sentinel)
- Text, JSON, SARIF and Markdown output (the Markdown suits PR comments and job summaries)
- CLI, library and GitHub Action. Node.js 18+, one zero-dependency runtime dependency

## Quick start

```bash
npx sbom-diff-sentinel --base origin/main             # project at origin/main vs working tree
npx sbom-diff-sentinel base.cdx.json head.spdx.json   # two SBOM files (formats can be mixed)
npx sbom-diff-sentinel base.cdx.json                  # SBOM file vs the current project
npx sbom-diff-sentinel --generate bom.cdx.json        # write a CycloneDX 1.5 SBOM for the project
```

```text
SBOM diff: base.cdx.json (8) → head.spdx.json (10)

Added (3)
  + axios@0.21.0 MIT
  + copyleft-lib@1.0.0 AGPL-3.0-only
  + dual@2.0.0 MIT OR GPL-3.0-only

Removed (1)
  - left-pad@1.3.0

Upgraded (1)
  ↑ lodash 4.17.20 → 4.17.21

Downgraded (1)
  ↓ minimist 1.2.8 → 1.2.5

License changes (1)
  chalk: MIT → GPL-3.0-only

Supplier changes (1)
  debug: TJ Holowaychuk → Evil Corp

Hash changes (1)
  ! express@4.18.2

Fixed vulnerabilities (1)
  ✓ GHSA-29mw-wpgm-hmr9 lodash@4.17.20 (medium)

Policy findings (32)
  critical minimist@1.2.5: GHSA-xvch-5gv4-984h (CVE-2021-44906) Prototype Pollution in minimist [new-vulnerability]
           ↳ See https://osv.dev/vulnerability/GHSA-xvch-5gv4-984h for fixed versions
  high     axios@0.21.0: GHSA-cph5-m8f7-6c5x (CVE-2021-3749) axios Inefficient Regular Expression Complexity vulnerability [new-vulnerability]
  …
  high     chalk license changed MIT → GPL-3.0-only (strong-copyleft) [copyleft-license]
  high     New dependency copyleft-lib@1.0.0 is AGPL-3.0-only (network-copyleft) [copyleft-license]
  high     express@4.18.2: hash changed for the same version [hash-changed]
  medium   debug: supplier "TJ Holowaychuk" → "Evil Corp" [supplier-changed]
  medium   minimist downgraded 1.2.8 → 1.2.5 [downgrade]
  low      chalk: license MIT → GPL-3.0-only [license-changed]

6 change(s): +3 -1 ↑1 ↓1; vulns: 26 new, 1 fixed (checked); 1 critical, 15 high, 14 medium, 2 low
```

## Rules

| Rule | Default severity | What it catches |
|---|---|---|
| `new-vulnerability` | the advisory's severity | An added or changed component has an OSV advisory that the base didn't have (matched by ID and aliases) |
| `copyleft-license` | high | A new dependency, or a license change, brings in copyleft (`--copyleft weak\|strong\|network\|none`, default `strong`). `MIT OR GPL-3.0` counts as permissive |
| `hash-changed` | high | Same name and version, different hash: a republished or tampered package, or a different mirror |
| `too-many-changes` | high | More component changes than `--max-changes` |
| `osv-error` | high | The OSV lookup failed, so the check can't silently pass. Use `--offline` to skip it on purpose |
| `downgrade` | medium (`--deny-downgrades` raises it to high) | A component moved to a lower version |
| `supplier-changed` | medium | The supplier or publisher changed |
| `license-changed` | low | Any license change |
| `allowlist-expired` | low | An allowlist entry is past its `expires` date |
| `unscanned-component` | info | No purl or version, so it couldn't be checked on OSV |
| `sbom-warning` | info | Spec version outside CycloneDX 1.4–1.6 or SPDX 2.3 (parsed anyway) |

Vulnerability severity comes from the CVSS v3 base score (computed from the vector), then the advisory's rating (GHSA `MODERATE` maps to medium). Advisories without either are rated medium and marked as estimated.

## How components are matched

Components are matched by package URL without the version (`pkg:npm/lodash`, `pkg:maven/org.example/core`), falling back to the name. Qualifiers such as `?type=jar` are ignored. When a package appears in several versions, versions on both sides are unchanged, the rest are paired highest-to-highest as upgrades or downgrades, and any leftovers count as added or removed. Hashes are compared only when both sides share an algorithm.

## Options

```
--base <file|ref>      Base SBOM file, or a git ref to generate it from (e.g. origin/main, HEAD~1, v1.2.0)
--head <file|dir>      Head SBOM file or project directory (default: --project)
-C, --project <dir>    Project directory (default: .); may be a subdirectory of the repo
--include-dev          Include devDependencies when generating
--offline              Skip the OSV.dev lookup
--osv-url <url>        OSV API base URL (default: https://api.osv.dev)
--timeout <ms>         OSV request timeout (default: 15000)
--fail-on <sev>        critical | high | medium | low | info | none (default: high)
--copyleft <level>     weak | strong | network | none (default: strong)
--max-changes <n>      Fail when more than n components change
--deny-downgrades      Treat downgrades as high severity
--config <file>        Config file (default: .sbom-diff-sentinel.json or package.json "sbom-diff-sentinel")
--format <fmt>         text | json | sarif | markdown (default: text)
--json/--sarif/--markdown <file>   Also write that report to a file
--generate [file]      Write a CycloneDX 1.5 SBOM for the project (stdout if no file)
-q, --quiet            Only print the summary line
```

**Exit codes:** `0` pass, `1` findings at or above `--fail-on`, `2` usage or runtime error (bad SBOM, unknown git ref and so on).

With `--base <ref>`, the tool reads `package.json` and the lockfile at that ref with `git show` and builds both sides from lockfiles, so they're generated the same way. Your working tree is never checked out or changed.

## Config

`.sbom-diff-sentinel.json` (or a `"sbom-diff-sentinel"` key in `package.json`):

```json
{
  "failOn": "high",
  "copyleft": "strong",
  "maxChanges": 40,
  "rules": { "downgrade": "high", "license-changed": "off" },
  "allowlist": [
    { "id": "CVE-2021-3749", "reason": "server-side only, not reachable", "expires": "2027-01-31" },
    { "package": "@internal/*", "rule": "supplier-changed", "reason": "registry migration" },
    { "package": "copyleft-lib", "rule": "copyleft-license", "reason": "legal approved LEGAL-123" }
  ]
}
```

An allowlist entry matches a vulnerability ID or alias (`id`), a package name glob (`package`) and/or a `rule`. Matching findings are suppressed and reported as allowlisted. After `expires`, the finding comes back with a note, and unused expired entries are flagged.

## GitHub Action

```yaml
on: pull_request
permissions:
  contents: read
jobs:
  sbom-diff:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0, persist-credentials: false }
      - uses: MrLouisWright/sbom-diff-sentinel@v1
        id: sbom
        with:
          fail-on: high          # base defaults to origin/<PR base branch>
          max-changes: '50'
```

The Markdown report is written to the job summary. Its path is in `steps.sbom.outputs.markdown-file`, so you can post it as a sticky PR comment (it starts with `<!-- sbom-diff-sentinel -->`). Inputs: `base`, `head`, `project`, `fail-on`, `copyleft`, `max-changes`, `include-dev`, `offline`, `config`, `sarif`, `json`, `job-summary` and `args`.

## Library

```js
import { readSbom, generateSbomAtRef, generateSbom, analyze, formatMarkdown, exitCode } from 'sbom-diff-sentinel';

const report = await analyze(generateSbomAtRef('.', 'origin/main'), generateSbom('.'), { maxChanges: 50 });
console.log(report.diff.upgraded, report.vulnerabilities.new);
process.exitCode = exitCode(report);
```

TypeScript types are included.

## Support

If this project is useful to you, you can support its development with a donation: [Buy me a coffee](https://donate.stripe.com/aFa00lek3cvX4Ds2Fk9EI0b). It helps keep these tools maintained, documented and free for everyone.

## License

MIT © Louis Wright ([Louis Wright](https://github.com/MrLouisWright))
