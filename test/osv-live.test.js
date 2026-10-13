import { test } from 'node:test';
import assert from 'node:assert/strict';
import { lookupVulns, parseSbom } from '../src/index.js';

// One real query against api.osv.dev. Set OSV_OFFLINE=1 to skip (e.g. no network).
test('real OSV.dev batch query finds the minimist prototype pollution advisory', { skip: process.env.OSV_OFFLINE === '1' && 'OSV_OFFLINE=1', timeout: 60000 }, async () => {
  const s = parseSbom({ bomFormat: 'CycloneDX', specVersion: '1.5', components: [
    { type: 'library', name: 'minimist', version: '1.2.5', purl: 'pkg:npm/minimist@1.2.5' },
    { type: 'library', name: 'minimist', version: '1.2.8', purl: 'pkg:npm/minimist@1.2.8' },
  ] });
  const { byComponent } = await lookupVulns(s.components, { timeout: 30000 });
  const old = byComponent.get(s.components[0]);
  const fixed = byComponent.get(s.components[1]);
  const hit = old.find((v) => v.id === 'GHSA-xvch-5gv4-984h' || v.aliases.includes('CVE-2021-44906'));
  assert.ok(hit, `expected CVE-2021-44906 in ${old.map((v) => v.id)}`);
  assert.equal(hit.severity, 'critical');
  assert.ok(!fixed.some((v) => v.id === hit.id), '1.2.8 is fixed');
});
