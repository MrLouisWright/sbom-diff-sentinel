import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { spawnSync } from 'node:child_process';
import { parseSbom, analyze, parseVex, vexFor, formatPrSummary, formatMarkdown, formatText, OsvCache, RULES } from '../src/index.js';
import { mockOsv, rec, fx } from './helpers.js';

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'sds-f-'));
process.env.SBOM_DIFF_SENTINEL_CACHE = tmp();
const BIN = new URL('../bin/sbom-diff-sentinel.js', import.meta.url).pathname;
const cdx = (comps, extra = {}) => parseSbom({ bomFormat: 'CycloneDX', specVersion: '1.6', components: comps.map(([name, version, x = {}]) => ({ type: 'library', 'bom-ref': `${name}@${version}`, name, version, purl: `pkg:npm/${name}@${version}`, ...x })), ...extra });
const VULNS = { 'pkg:npm/axios@0.21.0': ['GHSA-ax'], 'pkg:npm/lodash@4.17.20': ['GHSA-lo'], 'pkg:npm/qs@6.0.0': ['GHSA-qs'] };
const RECS = { 'GHSA-ax': rec('high', { aliases: ['CVE-2021-3749'] }), 'GHSA-lo': rec('critical'), 'GHSA-qs': rec('medium') };
const head = () => cdx([['axios', '0.21.0'], ['lodash', '4.17.20'], ['qs', '6.0.0']]);

test('licence changes are reported, not judged', async () => {
  assert.equal(RULES['copyleft-license'], undefined);
  const r = await analyze(cdx([['a', '1.0.0', { licenses: [{ license: { id: 'MIT' } }] }]]), cdx([['a', '1.0.0', { licenses: [{ license: { id: 'AGPL-3.0-only' } }] }], ['b', '1.0.0', { licenses: [{ license: { id: 'GPL-3.0-only' } }] }]]), { offline: true, cache: false });
  assert.deepEqual(r.findings.map((f) => f.rule), ['license-changed']);
  assert.equal(r.findings[0].toCategory, 'network-copyleft'); assert.equal(r.findings[0].severity, 'low');
});

test('VEX: OpenVEX, CycloneDX VEX file and embedded VEX suppress not_affected vulnerabilities', async () => {
  const osv = await mockOsv({ vulns: VULNS, records: RECS });
  try {
    const d = tmp();
    fs.writeFileSync(path.join(d, 'open.json'), JSON.stringify({ '@context': 'https://openvex.dev/ns/v0.2.0', statements: [
      { vulnerability: { name: 'CVE-2021-3749' }, products: [{ '@id': 'pkg:npm/axios' }], status: 'not_affected', justification: 'vulnerable_code_not_in_execute_path' },
      { vulnerability: { name: 'GHSA-qs' }, products: [{ '@id': 'pkg:npm/qs@6.0.0' }], status: 'under_investigation' },
    ] }));
    fs.writeFileSync(path.join(d, 'cdx-vex.json'), JSON.stringify({ bomFormat: 'CycloneDX', specVersion: '1.6', vulnerabilities: [{ id: 'GHSA-lo', analysis: { state: 'false_positive', detail: 'only used at build time' }, affects: [{ ref: 'pkg:npm/lodash@4.17.20' }] }] }));
    const r = await analyze(cdx([]), head(), { osvUrl: osv.url, vex: [path.join(d, 'open.json'), path.join(d, 'cdx-vex.json')], cache: false });
    assert.deepEqual(r.vulnerabilities.new.map((v) => v.id), ['GHSA-qs']);
    assert.deepEqual(r.vulnerabilities.vex.map((v) => [v.id, v.vex.status]).sort(), [['GHSA-ax', 'not_affected'], ['GHSA-lo', 'false_positive']]);
    assert.match(r.findings.find((f) => f.rule === 'new-vulnerability').message, /\[VEX: under_investigation\]/);
    assert.deepEqual(r.vex, { statements: 3, suppressed: 2 });
    assert.match(formatMarkdown(r), /Not affected \(VEX\)/); assert.match(formatText(r, { summaryOnly: true }), /2 not affected \(VEX\)/);
    // embedded in head SBOM (bom-ref)
    const embedded = cdx([['axios', '0.21.0']], { vulnerabilities: [{ id: 'GHSA-ax', analysis: { state: 'not_affected', justification: 'code_not_reachable' }, affects: [{ ref: 'axios@0.21.0' }] }] });
    assert.equal(embedded.vex.length, 1);
    const e = await analyze(cdx([]), embedded, { osvUrl: osv.url, cache: false });
    assert.equal(e.vulnerabilities.new.length, 0); assert.equal(e.vulnerabilities.vex.length, 1);
    // wrong product does not match
    const st = parseVex({ statements: [{ vulnerability: 'GHSA-ax', products: ['pkg:npm/other'], status: 'not_affected' }] });
    assert.equal(vexFor(st, { ids: ['GHSA-ax'], package: 'axios', version: '0.21.0', purl: 'pkg:npm/axios@0.21.0' }), null);
    assert.ok(vexFor(parseVex({ statements: [{ vulnerability: 'ghsa-ax', status: 'fixed' }] }), { ids: ['GHSA-ax'], package: 'axios', version: '0.21.0' }));
    await assert.rejects(analyze(cdx([]), head(), { vex: [path.join(d, 'missing.json')], offline: true, cache: false }), /VEX/);
  } finally { await osv.close(); }
});

test('OSV cache: reuse, TTL and offline mode', async () => {
  const osv = await mockOsv({ vulns: VULNS, records: RECS });
  try {
    const dir = tmp();
    const a = await analyze(cdx([]), head(), { osvUrl: osv.url, cache: dir, now: '2026-10-15T10:00:00Z' });
    assert.equal(a.vulnerabilities.new.length, 3); assert.equal(osv.log.batches.length, 1); assert.equal(osv.log.details.length, 3);
    const b = await analyze(cdx([]), head(), { osvUrl: osv.url, cache: dir, now: '2026-10-15T12:00:00Z' });
    assert.equal(b.vulnerabilities.new.length, 3); assert.equal(osv.log.batches.length, 1, 'served from cache'); assert.equal(b.cache.hits, 3);
    const c = await analyze(cdx([]), head(), { osvUrl: osv.url, cache: dir, now: '2026-10-17T12:00:00Z' });
    assert.equal(osv.log.batches.length, 2, 'expired after the TTL'); assert.equal(c.vulnerabilities.status, 'checked');
    await osv.close();
    const off = await analyze(cdx([]), cdx([['axios', '0.21.0'], ['new-pkg', '1.0.0']]), { osvUrl: osv.url, cache: dir, offline: true, now: '2030-01-01' });
    assert.equal(off.vulnerabilities.status, 'checked (offline, from cache)');
    assert.deepEqual(off.vulnerabilities.new.map((v) => v.id), ['GHSA-ax']);
    assert.match(off.findings.find((f) => f.rule === 'unscanned-component').message, /new-pkg@1\.0\.0 is not in the OSV cache/);
    const empty = await analyze(cdx([]), head(), { osvUrl: osv.url, cache: tmp(), offline: true });
    assert.equal(empty.vulnerabilities.status, 'skipped (offline)');
    const mem = new OsvCache(null); mem.setQuery('p', ['x']); assert.deepEqual(mem.getQuery('p'), ['x']); mem.save();
  } finally { await osv.close().catch(() => {}); }
});

test('PR summary comment', async () => {
  const osv = await mockOsv({ vulns: VULNS, records: RECS });
  try {
    const r = await analyze(cdx([['minimist', '1.2.8', { licenses: [{ license: { id: 'MIT' } }] }]]), cdx([['minimist', '1.2.5', { licenses: [{ license: { id: 'GPL-3.0-only' } }] }], ['axios', '0.21.0']]), { osvUrl: osv.url, cache: false });
    const s = formatPrSummary(r);
    assert.match(s, /^<!-- sbom-diff-sentinel -->\n### ❌ SBOM diff: failing at `high`/);
    assert.match(s, /\[GHSA-ax\]\(https:\/\/osv\.dev\/vulnerability\/GHSA-ax\) in `axios@0\.21\.0`/);
    assert.match(s, /\*\*Licence changes\*\*\n\n- `minimist`: MIT → GPL-3\.0-only/);
    assert.match(s, /\*\*Downgrades\*\*/);
    assert.match(formatPrSummary(r, { failOn: 'none' }), /✅ SBOM diff: passing/);
    const many = { ...r, vulnerabilities: { ...r.vulnerabilities, new: Array.from({ length: 40 }, (_, i) => ({ ...r.vulnerabilities.new[0], id: `GHSA-${i}` })) } };
    assert.match(formatPrSummary(many), /…and 25 more/);
    const huge = { ...r, findings: Array.from({ length: 3000 }, () => ({ severity: 'high', rule: 'hash-changed', message: 'x'.repeat(100) })) };
    assert.ok(formatPrSummary(huge, { maxRows: 5000 }).length <= 65000); assert.ok(formatMarkdown(huge, { maxRows: 5000 }).length <= 65000);
  } finally { await osv.close(); }
});

test('CLI: --vex, --pr-comment, --no-cache, --cache-dir', () => {
  const d = tmp();
  fs.writeFileSync(path.join(d, 'vex.json'), JSON.stringify({ statements: [{ vulnerability: 'X', status: 'not_affected' }] }));
  const run = (args) => spawnSync(process.execPath, [BIN, ...args], { cwd: path.dirname(fx('base.cdx.json')), encoding: 'utf8', env: { ...process.env, NO_COLOR: '1' } });
  const r = run(['base.cdx.json', 'head.spdx.json', '--offline', '--vex', path.join(d, 'vex.json'), '--pr-comment', path.join(d, 'pr.md'), '--cache-dir', path.join(d, 'c'), '--format', 'json']);
  assert.equal(r.status, 1, r.stderr); assert.equal(JSON.parse(r.stdout).vex.statements, 1);
  assert.match(fs.readFileSync(path.join(d, 'pr.md'), 'utf8'), /^<!-- sbom-diff-sentinel -->/);
  assert.equal(run(['base.cdx.json', 'head.spdx.json', '--offline', '--no-cache', '-q']).status, 1);
  assert.equal(run(['base.cdx.json', 'head.spdx.json', '--cache-ttl', '-5']).status, 2);
  assert.match(run(['--help']).stdout, /--vex <file>[\s\S]*--pr-comment/);
});
