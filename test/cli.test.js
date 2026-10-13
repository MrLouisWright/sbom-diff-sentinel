import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { generateSbom, generateSbomAtRef } from '../src/index.js';
import { fx, FIX, mockOsv, rec, tmpdir } from './helpers.js';

const BIN = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'bin', 'sbom-diff-sentinel.js');
const run = (args, cwd = FIX) => new Promise((resolve) => {
  const p = spawn(process.execPath, [BIN, ...args], { cwd, env: { ...process.env, NO_COLOR: '1', FORCE_COLOR: '' } });
  let stdout = ''; let stderr = '';
  p.stdout.on('data', (d) => { stdout += d; }); p.stderr.on('data', (d) => { stderr += d; });
  p.on('close', (status) => resolve({ status, stdout, stderr }));
});
const git = (cwd, ...args) => execFileSync('git', args, { cwd, stdio: 'pipe', env: { ...process.env, GIT_AUTHOR_NAME: 't', GIT_AUTHOR_EMAIL: 't@t', GIT_COMMITTER_NAME: 't', GIT_COMMITTER_EMAIL: 't@t' } });

let osv;
before(async () => { osv = await mockOsv({ vulns: { 'pkg:npm/axios@0.21.0': ['GHSA-a'], 'pkg:npm/pad@1.0.2': ['GHSA-pad'] }, records: { 'GHSA-a': rec('high'), 'GHSA-pad': rec('critical') } }); });
after(() => osv.close());

test('generateSbom uses license-sentinel on lockfiles (prod by default, dev opt-in)', () => {
  const prod = generateSbom(fx('project'));
  assert.deepEqual(prod.components.map((c) => `${c.name}@${c.version}`).sort(), ['copyleft@2.0.0', 'left@1.2.0', 'pad@1.0.1']);
  assert.equal(prod.components.find((c) => c.name === 'copyleft').license, 'GPL-3.0-only');
  assert.equal(prod.doc.specVersion, '1.5');
  assert.equal(generateSbom(fx('project'), { includeDev: true }).components.length, 6);
});

test('--base <git-ref> generates both sides and diffs the working tree', async () => {
  const dir = tmpdir();
  for (const f of ['package.json', 'package-lock.json']) fs.copyFileSync(fx(`project/${f}`), path.join(dir, f));
  git(dir, 'init', '-q'); git(dir, 'add', '-A'); git(dir, 'commit', '-qm', 'base');
  const lock = JSON.parse(fs.readFileSync(path.join(dir, 'package-lock.json'), 'utf8'));
  lock.packages['node_modules/pad'].version = '1.0.2';
  delete lock.packages['node_modules/copyleft'];
  lock.packages['node_modules/axios'] = { version: '0.21.0', license: 'MIT' };
  fs.writeFileSync(path.join(dir, 'package-lock.json'), JSON.stringify(lock));
  const atRef = generateSbomAtRef(dir, 'HEAD');
  assert.equal(atRef.components.find((c) => c.name === 'pad').version, '1.0.1');
  const r = await run(['--base', 'HEAD', '--osv-url', osv.url, '--format', 'json'], dir);
  assert.equal(r.status, 1, r.stderr);
  const j = JSON.parse(r.stdout);
  assert.deepEqual(j.diff.added.map((x) => x.name), ['axios']);
  assert.deepEqual(j.diff.removed.map((x) => x.name), ['copyleft']);
  assert.deepEqual(j.diff.upgraded.map((x) => `${x.name}:${x.from}->${x.to}`), ['pad:1.0.1->1.0.2']);
  assert.deepEqual(j.vulnerabilities.new.map((v) => v.id).sort(), ['GHSA-a', 'GHSA-pad']);
  // subdirectory project inside a repo
  const mono = tmpdir(); fs.mkdirSync(path.join(mono, 'app'));
  for (const f of ['package.json', 'package-lock.json']) fs.copyFileSync(fx(`project/${f}`), path.join(mono, 'app', f));
  git(mono, 'init', '-q'); git(mono, 'add', '-A'); git(mono, 'commit', '-qm', 'x');
  const r2 = await run(['--base', 'HEAD', '-C', 'app', '--offline'], mono);
  assert.equal(r2.status, 0, r2.stderr);
  assert.match(r2.stdout, /0 change\(s\)/);
  const bad = await run(['--base', 'no-such-ref', '--offline'], dir);
  assert.equal(bad.status, 2);
  assert.match(bad.stderr, /unknown ref "no-such-ref"/);
  assert.equal((await run(['--base', '--upload-pack=x', '--offline'], dir)).status, 2);
});

test('file vs file: text, markdown, sarif, json outputs and report files', async () => {
  const out = tmpdir();
  const r = await run(['base.cdx.json', 'head.spdx.json', '--osv-url', osv.url, '--markdown', path.join(out, 'r.md'), '--sarif', path.join(out, 'r.sarif'), '--json', path.join(out, 'r.json')]);
  assert.equal(r.status, 1);
  assert.match(r.stdout, /Added \(3\)/);
  assert.match(r.stdout, /↓ minimist 1\.2\.8 → 1\.2\.5/);
  assert.match(r.stdout, /high {5}axios@0\.21\.0: GHSA-a/);
  const md = fs.readFileSync(path.join(out, 'r.md'), 'utf8');
  assert.match(md, /^<!-- sbom-diff-sentinel -->/);
  assert.match(md, /\*\*6\*\* change\(s\)/);
  assert.match(md, /\[GHSA-a\]\(https:\/\/osv.dev\/vulnerability\/GHSA-a\)/);
  assert.match(md, /<details open><summary><b>Downgraded<\/b> \(1\)/);
  const sarif = JSON.parse(fs.readFileSync(path.join(out, 'r.sarif'), 'utf8'));
  assert.equal(sarif.version, '2.1.0');
  assert.ok(sarif.runs[0].results.some((x) => x.ruleId === 'new-vulnerability' && x.level === 'error'));
  assert.equal(sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri, 'head.spdx.json');
  assert.equal(JSON.parse(fs.readFileSync(path.join(out, 'r.json'), 'utf8')).tool, 'sbom-diff-sentinel');
  assert.match((await run(['base.cdx.json', 'head.spdx.json', '--offline', '--format', 'markdown'])).stdout, /Vulnerabilities: \*\*0 new\*\*, 0 fixed \(skipped \(offline\)\)/);
  assert.match((await run(['base.cdx.json', 'head.spdx.json', '--offline', '-q'])).stdout, /^6 change\(s\): \+3 -1 ↑1 ↓1; vulns: 0 new, 0 fixed \(skipped \(offline\)\); 3 high, 2 medium, 1 low\n$/);
});

test('--fail-on, --copyleft, --max-changes, --deny-downgrades, config file', async () => {
  assert.equal((await run(['base.cdx.json', 'head.spdx.json', '--offline', '--fail-on', 'critical'])).status, 0);
  assert.equal((await run(['base.cdx.json', 'head.spdx.json', '--offline', '--fail-on', 'none'])).status, 0);
  assert.equal((await run(['base.cdx.json', 'base.cdx.json', '--offline', '--fail-on', 'info'])).status, 0, 'identical SBOMs pass');
  const dir = tmpdir();
  for (const f of ['base.cdx.json', 'head.spdx.json']) fs.copyFileSync(fx(f), path.join(dir, f));
  fs.writeFileSync(path.join(dir, '.sbom-diff-sentinel.json'), JSON.stringify({ copyleft: false, rules: { 'hash-changed': 'off' }, allowlist: [] }));
  assert.equal((await run(['base.cdx.json', 'head.spdx.json', '--offline'], dir)).status, 0, 'config disables high findings');
  assert.equal((await run(['base.cdx.json', 'head.spdx.json', '--offline', '--deny-downgrades'], dir)).status, 1);
  assert.equal((await run(['base.cdx.json', 'head.spdx.json', '--offline', '--max-changes', '2'], dir)).status, 1);
  assert.equal((await run(['base.cdx.json', 'head.spdx.json', '--offline', '--copyleft', 'strong'], dir)).status, 1);
  fs.writeFileSync(path.join(dir, 'bad.json'), '{');
  assert.equal((await run(['base.cdx.json', 'head.spdx.json', '--config', 'bad.json'], dir)).status, 2);
});

test('--generate, usage errors and runtime errors', async () => {
  const g = await run(['--generate', '-C', 'project']);
  assert.equal(g.status, 0);
  assert.equal(JSON.parse(g.stdout).bomFormat, 'CycloneDX');
  const out = path.join(tmpdir(), 'bom.json');
  assert.equal((await run(['--generate', out, '--include-dev', '-C', 'project'])).status, 0);
  assert.equal(JSON.parse(fs.readFileSync(out, 'utf8')).components.length, 6);
  for (const args of [[], ['--nope'], ['a', 'b', 'c'], ['--fail-on', 'x', 'base.cdx.json'], ['--copyleft', 'x', 'base.cdx.json'], ['--max-changes', '-1', 'base.cdx.json'], ['--format', 'xml', 'base.cdx.json'], ['missing.json', '--offline'], ['bogus.json', 'head.spdx.json', '--offline'], ['base.cdx.json', 'nope.json', '--offline']]) {
    const r = await run(args);
    assert.equal(r.status, 2, `${args.join(' ')}: ${r.stderr}`);
    assert.match(r.stderr, /sbom-diff-sentinel:/);
  }
  assert.equal((await run(['--help'])).status, 0);
  assert.match((await run(['--version'])).stdout, /^\d+\.\d+\.\d+\n$/);
});
