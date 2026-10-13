import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { readSbom, parseSbom, parsePurl, compareVersions, categoryOf, cvss3Score, osvSeverity, osvQuery } from '../src/index.js';
import { fx, CVSS } from './helpers.js';

test('CycloneDX 1.5: nested components, root excluded, licenses, hashes, supplier', () => {
  const s = readSbom(fx('base.cdx.json'));
  assert.equal(s.format, 'CycloneDX');
  assert.equal(s.specVersion, '1.5');
  assert.deepEqual(s.warnings, []);
  assert.equal(s.components.length, 8);
  assert.ok(s.components.some((c) => c.name === 'qs'), 'nested component found');
  const lodash = s.components.find((c) => c.name === 'lodash');
  assert.equal(lodash.key, 'pkg:npm/lodash');
  assert.equal(lodash.license, 'MIT');
  assert.equal(lodash.hashes['SHA-512'].length, 128);
  assert.equal(s.components.find((c) => c.name === 'debug').supplier, 'TJ Holowaychuk');
  assert.equal(s.components.find((c) => c.name === '@types/node').key, 'pkg:npm/%40types/node'.replace('%40', '@'));
});

test('SPDX 2.3: described root skipped, NOASSERTION, supplier prefix, checksums', () => {
  const s = readSbom(fx('head.spdx.json'));
  assert.equal(s.format, 'SPDX');
  assert.equal(s.specVersion, '2.3');
  assert.equal(s.components.length, 10);
  assert.ok(!s.components.some((c) => c.name === 'demo-app'));
  assert.equal(s.components.find((c) => c.name === 'debug').supplier, 'Evil Corp');
  assert.equal(s.components.find((c) => c.name === 'express').hashes['SHA-512'][0], 'd');
  const noPurl = parseSbom({ spdxVersion: 'SPDX-2.3', packages: [{ SPDXID: 'x', name: 'thing', versionInfo: 'NOASSERTION', licenseConcluded: 'NOASSERTION', licenseDeclared: 'Apache-2.0' }] });
  assert.equal(noPurl.components[0].version, null);
  assert.equal(noPurl.components[0].license, 'Apache-2.0');
  assert.equal(noPurl.components[0].key, 'name:thing');
});

test('CycloneDX 1.4 and 1.6, maven groups, qualifiers, authors; 1.3 warns; bad input errors', () => {
  const a = readSbom(fx('v14.cdx.json')); const b = readSbom(fx('v16.cdx.json'));
  assert.equal(a.components[0].key, b.components[0].key);
  assert.equal(a.components[0].name, 'org.example:core');
  assert.equal(a.components[0].supplier, 'Example Inc');
  assert.equal(a.components[0].license, 'Custom');
  assert.equal(b.components[1].supplier, 'Kenneth');
  assert.equal(b.components[2].key, 'name:nopurl');
  assert.match(readSbom(fx('v13.cdx.json')).warnings[0], /outside the supported/);
  assert.throws(() => readSbom(fx('bogus.json')), /unrecognised SBOM format/);
  assert.throws(() => parseSbom('{nope'), /not valid JSON/);
  assert.equal(parseSbom({ bomFormat: 'CycloneDX', specVersion: '1.5', components: [{ type: 'library', name: 'x', licenses: [{ license: { id: 'MIT' } }, { license: { id: 'ISC' } }] }] }).components[0].license, 'MIT AND ISC');
});

test('parsePurl', () => {
  assert.deepEqual(parsePurl('pkg:npm/%40scope/name@1.0.0?x=1#sub'), { type: 'npm', namespace: '@scope', name: 'name', version: '1.0.0' });
  assert.deepEqual(parsePurl('pkg:maven/org.a/b'), { type: 'maven', namespace: 'org.a', name: 'b', version: null });
  assert.equal(parsePurl('nope'), null);
});

test('compareVersions', () => {
  const cases = [['1.0.0', '1.0.1', -1], ['1.10.0', '1.9.0', 1], ['1.0.0-rc.1', '1.0.0', -1], ['1.0.0-alpha', '1.0.0-beta', -1], ['1.0.0-rc.2', '1.0.0-rc.10', -1], ['v2', '1.9', 1], ['1.0', '1.0.0', 0], ['1.0.0+b1', '1.0.0', 0], ['2.0.0.Final', '2.0.0.1', -1]];
  for (const [a, b, r] of cases) assert.equal(compareVersions(a, b), r, `${a} vs ${b}`);
});

test('license categories via license-sentinel', () => {
  assert.equal(categoryOf('MIT'), 'permissive');
  assert.equal(categoryOf('GPL-3.0-only'), 'strong-copyleft');
  assert.equal(categoryOf('MIT OR GPL-3.0-only'), 'permissive');
  assert.equal(categoryOf('MIT AND LGPL-2.1-only'), 'weak-copyleft');
  assert.equal(categoryOf('AGPL-3.0-only'), 'network-copyleft');
  assert.equal(categoryOf('((('), 'unknown');
});

test('CVSS v3 scoring and OSV severity fallbacks', () => {
  assert.equal(cvss3Score(CVSS.critical), 9.8);
  assert.equal(cvss3Score(CVSS.medium), 6.1);
  assert.equal(cvss3Score(CVSS.low), 1.8);
  assert.equal(cvss3Score('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N'), 0);
  assert.equal(cvss3Score('garbage'), null);
  assert.deepEqual(osvSeverity({ severity: [{ type: 'CVSS_V3', score: CVSS.high }] }), { severity: 'high', score: 7.5 });
  assert.equal(osvSeverity({ database_specific: { severity: 'MODERATE' } }).severity, 'medium');
  assert.equal(osvSeverity({ affected: [{ ecosystem_specific: { severity: 'LOW' } }] }).severity, 'low');
  assert.equal(osvSeverity({}).estimated, true);
});

test('osvQuery builds versioned purls without qualifiers', () => {
  assert.deepEqual(osvQuery({ purl: 'pkg:maven/org.a/b@1.2?type=jar', version: '1.2' }), { package: { purl: 'pkg:maven/org.a/b@1.2' } });
  assert.deepEqual(osvQuery({ purl: 'pkg:npm/%40s/x', version: '1.0.0' }), { package: { purl: 'pkg:npm/%40s/x@1.0.0' } });
  assert.equal(osvQuery({ purl: null, version: '1' }), null);
  assert.equal(osvQuery({ purl: 'pkg:npm/x', version: null }), null);
  assert.ok(fs.existsSync(fx('base.cdx.json')));
});
