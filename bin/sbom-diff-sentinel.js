#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { readSbom, generateSbom, generateSbomAtRef, generateCycloneDX, analyze, exitCode, formatText, formatJson, formatSarif, formatMarkdown, formatPrSummary, SEVERITIES } from '../src/index.js';
import { loadConfig } from '../src/config.js';

const pkg = JSON.parse(fs.readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
const HELP = `sbom-diff-sentinel ${pkg.version} — diff two SBOMs and gate on new vulnerabilities, downgrades and licenses

Usage:
  sbom-diff-sentinel <base.json> [head.json]   compare two SBOMs (head defaults to the project)
  sbom-diff-sentinel --base <git-ref>          compare the project at a git ref with the working tree
  sbom-diff-sentinel --generate [out.json]     write a CycloneDX SBOM for the project

SBOMs: CycloneDX 1.4–1.6 JSON or SPDX 2.3 JSON. Projects: npm, pnpm or yarn lockfiles
(SBOMs are generated with license-sentinel).

Options:
  --base <file|ref>      Base SBOM file, or a git ref (e.g. origin/main) to generate it from
  --head <file|dir>      Head SBOM file or project directory (default: --project)
  -C, --project <dir>    Project directory for generation and git refs (default: .)
  --include-dev          Include devDependencies when generating
  --offline              No network: use cached OSV results only (skipped if the cache is empty)
  --vex <file>           CycloneDX VEX or OpenVEX document (repeatable); not_affected/fixed vulns are suppressed.
                         VEX embedded in the head CycloneDX SBOM is applied automatically
  --cache-dir <dir>      OSV cache directory (default: ~/.cache/sbom-diff-sentinel)
  --cache-ttl <s>        Reuse cached OSV results for s seconds (default: 86400)
  --no-cache             Don't read or write the OSV cache
  --osv-url <url>        OSV API base URL (default: https://api.osv.dev)
  --timeout <ms>         OSV request timeout (default: 15000)
  --fail-on <sev>        critical | high | medium | low | info | none (default: high)
  --max-changes <n>      Fail when more than n components change
  --deny-downgrades      Treat downgrades as high severity
  --config <file>        Config file (default: .sbom-diff-sentinel.json or package.json "sbom-diff-sentinel")
  --format <fmt>         Stdout format: text | json | sarif | markdown (default: text)
  --json <file>          Also write a JSON report
  --sarif <file>         Also write a SARIF 2.1.0 report
  --markdown <file>      Also write a Markdown report (job summary)
  --pr-comment <file>    Also write a short PR comment (verdict, new vulns, licence changes, downgrades)
  --no-fixes             Hide fix suggestions     --no-color   Disable colours
  -q, --quiet            Only print the summary line
  -h, --help | -v, --version

Exit codes: 0 pass, 1 findings at or above --fail-on, 2 usage or runtime error.
`;

function parseArgs(argv) {
  const o = { positional: [], format: 'text', color: (process.stdout.isTTY && !process.env.NO_COLOR) || !!process.env.FORCE_COLOR, fixes: true, project: '.' };
  argv = argv.flatMap((a) => (a.startsWith('--') && a.includes('=') ? [a.slice(0, a.indexOf('=')), a.slice(a.indexOf('=') + 1)] : [a]));
  const need = (i) => { const val = argv[i + 1]; if (val === undefined || (val.startsWith('-') && val.length > 1)) throw new Error(`${argv[i]} needs a value`); return val; };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    switch (a) {
      case '-h': case '--help': o.help = true; break;
      case '-v': case '--version': o.version = true; break;
      case '--base': o.base = need(i); i++; break;
      case '--head': o.head = need(i); i++; break;
      case '-C': case '--project': o.project = need(i); i++; break;
      case '--generate': { const n = argv[i + 1]; o.generate = n && !n.startsWith('-') ? (i++, n) : '-'; break; }
      case '--include-dev': o.includeDev = true; break;
      case '--offline': o.offline = true; break;
      case '--vex': (o.vex ||= []).push(need(i)); i++; break;
      case '--cache-dir': o.cacheDir = need(i); i++; break;
      case '--cache-ttl': o.cacheTtl = Number(need(i)); i++; if (!(o.cacheTtl >= 0)) throw new Error('Invalid --cache-ttl'); break;
      case '--no-cache': o.noCache = true; break;
      case '--pr-comment': o.prComment = need(i); i++; break;
      case '--osv-url': o.osvUrl = need(i); i++; break;
      case '--timeout': o.timeout = Number(need(i)); i++; if (!(o.timeout > 0)) throw new Error('Invalid --timeout'); break;
      case '--fail-on': o.failOn = need(i); i++; if (![...SEVERITIES, 'none'].includes(o.failOn)) throw new Error(`Invalid --fail-on ${o.failOn}`); break;
      case '--copyleft': o.copyleft = need(i); i++; break;
      case '--max-changes': o.maxChanges = Number(need(i)); i++; if (!Number.isInteger(o.maxChanges) || o.maxChanges < 0) throw new Error('Invalid --max-changes'); break;
      case '--deny-downgrades': o.denyDowngrades = true; break;
      case '--config': o.config = need(i); i++; break;
      case '--format': o.format = need(i); i++; if (!['text', 'json', 'sarif', 'markdown'].includes(o.format)) throw new Error(`Invalid --format ${o.format}`); break;
      case '--json': o.json = need(i); i++; break;
      case '--sarif': o.sarif = need(i); i++; break;
      case '--markdown': o.markdown = need(i); i++; break;
      case '--no-fixes': o.fixes = false; break;
      case '--no-color': o.color = false; break;
      case '-q': case '--quiet': o.quiet = true; break;
      default: if (a.startsWith('-')) throw new Error(`Unknown option ${a}`); o.positional.push(a);
    }
  }
  if (o.positional.length > 2) throw new Error('Too many arguments');
  if (o.positional[0]) { if (o.base) throw new Error('Give the base either positionally or with --base'); o.base = o.positional[0]; }
  if (o.positional[1]) { if (o.head) throw new Error('Give the head either positionally or with --head'); o.head = o.positional[1]; }
  if (!o.base && !o.generate && !o.help && !o.version) throw new Error('Missing base SBOM or --base <git-ref>');
  return o;
}

function loadSide(spec, project, opts, isBase) {
  if (fs.existsSync(spec)) {
    if (fs.statSync(spec).isDirectory()) return generateSbom(spec, opts);
    return readSbom(spec);
  }
  if (!isBase) throw new Error(`No such file or directory: ${spec}`);
  if (/\.(json|spdx|cdx)$/i.test(spec)) throw new Error(`No such file: ${spec}`);
  return generateSbomAtRef(project, spec, opts);
}

async function main() {
  let o;
  try { o = parseArgs(process.argv.slice(2)); } catch (e) { process.stderr.write(`sbom-diff-sentinel: ${e.message}\n\n${HELP}`); return 2; }
  if (o.help) { process.stdout.write(HELP); return 0; }
  if (o.version) { process.stdout.write(pkg.version + '\n'); return 0; }
  const gen = { includeDev: !!o.includeDev };
  if (o.generate) {
    const doc = JSON.stringify(generateCycloneDX(o.project, gen), null, 2) + '\n';
    if (o.generate === '-') process.stdout.write(doc); else { fs.writeFileSync(o.generate, doc); process.stderr.write(`Wrote ${o.generate}\n`); }
    return 0;
  }
  const cfg = loadConfig(o.project, o.config);
  const base = loadSide(o.base, o.project, gen, true);
  const head = loadSide(o.head || o.project, o.project, gen, false);
  const rules = { ...(cfg.rules || {}) };
  if (o.denyDowngrades) rules.downgrade = 'high';
  const copyleft = o.copyleft ? (o.copyleft === 'none' ? false : o.copyleft) : cfg.copyleft;
  const report = await analyze(base, head, { ...cfg, rules, copyleft, vex: [...(cfg.vex || []), ...(o.vex || [])], cache: o.noCache ? false : o.cacheDir || cfg.cache, cacheTtl: o.cacheTtl ?? cfg.cacheTtl, failOn: o.failOn || cfg.failOn, maxChanges: o.maxChanges ?? cfg.maxChanges, offline: o.offline || cfg.offline, osvUrl: o.osvUrl || cfg.osvUrl, timeout: o.timeout || cfg.timeout });
  const out = { text: () => formatText(report, { color: o.color, fixes: o.fixes }), json: () => formatJson(report), sarif: () => formatSarif(report, pkg.version), markdown: () => formatMarkdown(report), prComment: () => formatPrSummary(report) };
  process.stdout.write(o.quiet && o.format === 'text' ? formatText(report, { color: o.color, summaryOnly: true }) : out[o.format]());
  for (const [k, f] of [['json', o.json], ['sarif', o.sarif], ['markdown', o.markdown], ['prComment', o.prComment]]) if (f) { fs.mkdirSync(path.dirname(path.resolve(f)), { recursive: true }); fs.writeFileSync(f, out[k]()); }
  return exitCode(report);
}

main().then((c) => { process.exitCode = c; }, (e) => { process.stderr.write(`sbom-diff-sentinel: ${e.message}\n`); process.exitCode = 2; });
