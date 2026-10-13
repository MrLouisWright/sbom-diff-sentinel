import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readSbom, parseSbom, diffSboms, analyze, exitCode, lookupVulns } from '../src/index.js';
import { fx, mockOsv, rec } from './helpers.js';

const base = () => readSbom(fx('base.cdx.json'));
const head = () => readSbom(fx('head.spdx.json'));
const cdx = (comps) => parseSbom({ bomFormat: 'CycloneDX', specVersion: '1.5', components: comps.map(([name, version, extra = {}]) => ({ type: 'library', name, version, purl: `pkg:npm/${name}@${version}`, ...extra })) });

test('diff: added, removed, upgraded, downgraded, license/supplier/hash changes', () => {
  const d = diffSboms(base(), head());
  assert.deepEqual(d.added.map((x) => x.name), ['axios', 'copyleft-lib', 'dual']);
  assert.deepEqual(d.removed.map((x) => x.name), ['left-pad']);
  assert.deepEqual(d.upgraded.map((x) => [x.name, x.from, x.to]), [['lodash', '4.17.20', '4.17.21']]);
  assert.deepEqual(d.downgraded.map((x) => [x.name, x.from, x.to]), [['minimist', '1.2.8', '1.2.5']]);
  assert.deepEqual(d.licenseChanged.map((x) => [x.name, x.from, x.to]), [['chalk', 'MIT', 'GPL-3.0-only']]);
  assert.deepEqual(d.supplierChanged.map((x) => [x.name, x.to]), [['debug', 'Evil Corp']]);
  assert.deepEqual(d.hashChanged.map((x) => x.name), ['express']);
  assert.equal(d.totals.changes, 6);
  assert.equal(d.unchanged, 5);
});

test('diff: multiple versions of one package pair highest-to-highest; identical SBOMs have no changes', () => {
  const d = diffSboms(cdx([['a', '1.0.0'], ['a', '2.0.0']]), cdx([['a', '2.1.0'], ['a', '1.0.0'], ['a', '3.0.0']]));
  assert.deepEqual(d.upgraded.map((x) => [x.from, x.to]), [['2.0.0', '3.0.0']]);
  assert.deepEqual(d.added.map((x) => x.version), ['2.1.0']);
  assert.equal(diffSboms(base(), base()).totals.changes, 0);
  assert.equal(diffSboms(cdx([['x', '1.0.0', { hashes: [{ alg: 'SHA-256', content: 'AA' }] }]]), cdx([['x', '1.0.0', { hashes: [{ alg: 'SHA-1', content: 'BB' }] }]])).hashChanged.length, 0, 'no common algorithm: unknown, not changed');
});

test('analyze with mocked OSV: new vs fixed vs persisting, severities, policy findings', async () => {
  const osv = await mockOsv({
    vulns: {
      'pkg:npm/axios@0.21.0': ['GHSA-axios-high', 'GHSA-axios-low'],
      'pkg:npm/minimist@1.2.5': ['GHSA-mini-crit', 'GHSA-shared'],
      'pkg:npm/minimist@1.2.8': ['GHSA-shared-alias'],
      'pkg:npm/lodash@4.17.20': ['GHSA-lodash-old'],
      'pkg:npm/left-pad@1.3.0': ['GHSA-leftpad'],
    },
    records: {
      'GHSA-axios-high': rec('high', { aliases: ['CVE-2021-1'] }), 'GHSA-axios-low': rec('low'), 'GHSA-mini-crit': rec('critical'),
      'GHSA-shared': rec('medium', { aliases: ['CVE-SHARED'] }), 'GHSA-shared-alias': rec('medium', { aliases: ['CVE-SHARED'] }),
      'GHSA-lodash-old': { database_specific: { severity: 'HIGH' } }, 'GHSA-leftpad': rec('low'),
    },
  });
  try {
    const r = await analyze(base(), head(), { osvUrl: osv.url, now: '2026-10-13' });
    assert.equal(r.vulnerabilities.status, 'checked');
    assert.deepEqual(r.vulnerabilities.new.map((v) => `${v.id}:${v.severity}`).sort(), ['GHSA-axios-high:high', 'GHSA-axios-low:low', 'GHSA-mini-crit:critical']);
    assert.deepEqual(r.vulnerabilities.persisting.map((v) => v.id), ['GHSA-shared'], 'matched through alias');
    assert.deepEqual(r.vulnerabilities.fixed.map((v) => [v.id, v.removed]).sort(), [['GHSA-leftpad', true], ['GHSA-lodash-old', false]]);
    assert.equal(osv.log.batches.length, 1, 'one batch request');
    assert.equal(osv.log.batches[0].length, 8, 'added(3) + changed heads(2) + removed(1) + changed bases(2)');
    const rules = r.findings.map((f) => `${f.rule}:${f.severity}`);
    for (const x of ['new-vulnerability:critical', 'new-vulnerability:high', 'new-vulnerability:low', 'copyleft-license:high', 'hash-changed:high', 'downgrade:medium', 'supplier-changed:medium', 'license-changed:low']) assert.ok(rules.includes(x), x);
    assert.equal(r.findings.filter((f) => f.rule === 'copyleft-license').length, 2, 'chalk license change + copyleft-lib; dual-licensed MIT OR GPL is fine');
    assert.equal(r.findings[0].severity, 'critical', 'sorted by severity');
    assert.equal(exitCode(r), 1);
    assert.equal(exitCode(r, 'none'), 0);
  } finally { await osv.close(); }
});

test('allowlist with expiry, rule overrides, copyleft level, maxChanges, offline', async () => {
  const osv = await mockOsv({ vulns: { 'pkg:npm/axios@0.21.0': ['GHSA-a'] }, records: { 'GHSA-a': rec('critical', { aliases: ['CVE-2099-1'] }) } });
  try {
    const opts = {
      osvUrl: osv.url, now: '2026-10-13', copyleft: false, maxChanges: 3,
      rules: { 'hash-changed': 'off', 'supplier-changed': 'low', downgrade: 'high' },
      allow: [{ id: 'CVE-2099-1', reason: 'not reachable', expires: '2027-01-01' }, { package: 'chalk', rule: 'license-changed', expires: '2020-01-01', reason: 'old' }, { package: 'nothing', expires: '2020-01-01' }],
    };
    const r = await analyze(base(), head(), opts);
    assert.equal(r.suppressed.length, 1);
    assert.equal(r.suppressed[0].allow.reason, 'not reachable');
    const by = (rule) => r.findings.filter((f) => f.rule === rule);
    assert.equal(by('new-vulnerability').length, 0);
    assert.equal(by('copyleft-license').length, 0);
    assert.equal(by('hash-changed').length, 0);
    assert.equal(by('supplier-changed')[0].severity, 'low');
    assert.equal(by('downgrade')[0].severity, 'high');
    assert.match(by('license-changed')[0].message, /allowlist entry expired 2020-01-01/);
    assert.equal(by('allowlist-expired').length, 1);
    assert.match(by('too-many-changes')[0].message, /6 component changes exceed the maximum of 3/);
    const weak = await analyze(cdx([]), cdx([['lgpl', '1.0.0', { licenses: [{ license: { id: 'LGPL-2.1-only' } }] }]]), { offline: true, copyleft: 'weak' });
    assert.equal(weak.findings[0].rule, 'copyleft-license');
    const off = await analyze(base(), head(), { offline: true });
    assert.equal(off.vulnerabilities.status, 'skipped (offline)');
    assert.equal(off.findings.filter((f) => f.rule === 'new-vulnerability').length, 0);
  } finally { await osv.close(); }
});

test('OSV failures become osv-error findings; pagination tokens are followed; unscanned components reported', async () => {
  const down = await mockOsv({ fail: true });
  try {
    const r = await analyze(base(), head(), { osvUrl: down.url });
    assert.equal(r.findings.find((f) => f.rule === 'osv-error').severity, 'high');
    assert.match(r.vulnerabilities.status, /^error: OSV querybatch HTTP 503/);
  } finally { await down.close(); }
  const pg = await mockOsv({ paginate: true, vulns: { 'pkg:npm/x@1.0.0': ['A', 'B', 'C'] }, records: { A: rec('low'), B: rec('low'), C: rec('high') } });
  try {
    const comp = cdx([['x', '1.0.0']]).components[0];
    const { byComponent } = await lookupVulns([comp, { name: 'np', version: '1', purl: null }], { url: pg.url + '/' });
    assert.deepEqual(byComponent.get(comp).map((v) => v.id), ['A', 'B', 'C']);
    assert.equal(pg.log.batches.length, 2);
    assert.equal(pg.log.batches[1][0].page_token, 'p2');
    const r = await analyze(cdx([]), parseSbom({ bomFormat: 'CycloneDX', specVersion: '1.5', components: [{ type: 'library', name: 'nopurl', version: '1' }] }), { osvUrl: pg.url });
    assert.equal(r.findings[0].rule, 'unscanned-component');
  } finally { await pg.close(); }
});

test('SBOM version warnings are surfaced', async () => {
  const r = await analyze(readSbom(fx('v13.cdx.json')), readSbom(fx('v14.cdx.json')), { offline: true });
  assert.ok(r.findings.some((f) => f.rule === 'sbom-warning' && /Base: CycloneDX specVersion 1.3/.test(f.message)));
  await assert.rejects(analyze(base(), head(), { failOn: 'bad' }), /Invalid failOn/);
  await assert.rejects(analyze(base(), head(), { rules: { nope: 'high' } }), /Unknown rule/);
  await assert.rejects(analyze(base(), head(), { allow: [{ reason: 'x' }] }), /needs "id"/);
});
