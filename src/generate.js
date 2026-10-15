import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { collectProject, auditCollected, toCycloneDX } from 'license-sentinel';
import { parseCycloneDX } from './sbom.js';

export const LOCKFILES = ['package-lock.json', 'npm-shrinkwrap.json', 'pnpm-lock.yaml', 'yarn.lock'];

/**
 * Generate a CycloneDX SBOM (spec version from license-sentinel) (as an object) for an npm project directory using license-sentinel.
 * Lockfiles are preferred over node_modules so both sides of a diff are built the same way.
 */
export function generateCycloneDX(dir, { includeDev = false, source } = {}) {
  const hasLock = LOCKFILES.some((f) => fs.existsSync(path.join(dir, f)));
  const collected = collectProject(dir, { source: source || (hasLock ? 'lockfile' : 'auto') });
  const report = auditCollected(collected, { includeDev, now: '2000-01-01T00:00:00Z' });
  const doc = JSON.parse(toCycloneDX(report, { reproducible: true }));
  delete doc.metadata.timestamp;
  doc.metadata.tools.components.push({ type: 'application', name: 'sbom-diff-sentinel', author: 'Louis Wright' });
  return doc;
}

export function generateSbom(dir, opts = {}) {
  const doc = generateCycloneDX(dir, opts);
  return { ...parseCycloneDX(doc), file: `${path.resolve(dir)} (generated)`, doc };
}

const git = (cwd, args) => execFileSync('git', args, { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], maxBuffer: 256 * 1024 * 1024 });

/** Generate an SBOM for the project as it was at a git ref (reads package.json + lockfile with git show). */
export function generateSbomAtRef(dir, ref, opts = {}) {
  if (!/^[\w./@^~{}:-]+$/.test(ref) || ref.startsWith('-')) throw new Error(`Invalid git ref: ${ref}`);
  let prefix;
  try {
    git(dir, ['rev-parse', '--verify', '--quiet', `${ref}^{commit}`]);
    prefix = git(dir, ['rev-parse', '--show-prefix']).trim();
  } catch { throw new Error(`Not a git repository or unknown ref "${ref}" in ${dir}`); }
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sbom-diff-'));
  try {
    let found = 0;
    for (const f of ['package.json', ...LOCKFILES]) {
      try { fs.writeFileSync(path.join(tmp, f), git(dir, ['show', `${ref}:${prefix}${f}`])); if (f !== 'package.json') found++; } catch { /* absent at ref */ }
    }
    if (!found) throw new Error(`No lockfile (${LOCKFILES.join(', ')}) found at ${ref}:${prefix || './'}`);
    const doc = generateCycloneDX(tmp, { ...opts, source: 'lockfile' });
    return { ...parseCycloneDX(doc), file: `${ref} (generated)`, doc };
  } finally { fs.rmSync(tmp, { recursive: true, force: true }); }
}
