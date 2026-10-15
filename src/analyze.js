import { diffSboms } from './diff.js';
import { lookupVulns, OSV_URL } from './osv.js';
import { categoryOf } from './license.js';
import { readVex, vexFor, SUPPRESSING } from './vex.js';
import { OsvCache, defaultCacheDir } from './osvcache.js';
import { RULES, SEVERITIES, RANK } from './rules.js';

export const DEFAULTS = { failOn: 'high', maxChanges: null, rules: {}, allow: [], offline: false, osvUrl: OSV_URL, timeout: 15000, vex: [], cache: undefined, cacheTtl: 86400 };

const globRe = (g) => new RegExp('^' + String(g).replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.') + '$', 'i');

export function validateConfig(cfg) {
  if (![...SEVERITIES, 'none'].includes(cfg.failOn)) throw new Error(`Invalid failOn: ${cfg.failOn}`);
  if (cfg.cacheTtl !== undefined && !(Number(cfg.cacheTtl) >= 0)) throw new Error(`Invalid cacheTtl: ${cfg.cacheTtl}`);
  if (cfg.maxChanges !== null && cfg.maxChanges !== undefined && !(Number.isInteger(cfg.maxChanges) && cfg.maxChanges >= 0)) throw new Error(`Invalid maxChanges: ${cfg.maxChanges}`);
  for (const [k, v] of Object.entries(cfg.rules || {})) {
    if (!RULES[k]) throw new Error(`Unknown rule in config: ${k}`);
    if (v !== 'off' && !SEVERITIES.includes(v)) throw new Error(`Invalid level for ${k}: ${v}`);
  }
  for (const [i, a] of (cfg.allow || []).entries()) {
    if (!a || typeof a !== 'object' || !(a.id || a.package || a.rule)) throw new Error(`allow[${i}] needs "id", "package" or "rule"`);
    if (a.expires && Number.isNaN(Date.parse(a.expires))) throw new Error(`allow[${i}] has an invalid "expires" date`);
  }
  return cfg;
}

const vulnKeys = (v) => [v.id, ...(v.aliases || [])];

/**
 * Compare two parsed SBOMs, look up vulnerabilities on OSV and apply the policy.
 * @returns {Promise<object>} report
 */
export async function analyze(base, head, options = {}) {
  const cfg = validateConfig({ ...DEFAULTS, ...Object.fromEntries(Object.entries(options).filter(([, v]) => v !== undefined)) });
  const now = cfg.now ? new Date(cfg.now) : new Date();
  const diff = diffSboms(base, head);
  const findings = [];
  const suppressed = [];
  const allow = (cfg.allow || []).map((a) => ({ ...a, expired: !!(a.expires && Date.parse(a.expires) < now.getTime()), used: false }));

  const add = (rule, f) => {
    let severity = RULES[rule].severity === 'vuln' ? f.severity : RULES[rule].severity;
    const o = cfg.rules[rule];
    if (o === 'off') return;
    if (o) severity = o;
    const finding = { rule, severity, ...f, severity };
    const match = allow.find((a) => (!a.rule || a.rule === rule) && (!a.package || (finding.package && globRe(a.package).test(finding.package))) && (!a.id || (finding.ids || []).some((x) => x.toLowerCase() === String(a.id).toLowerCase())));
    if (match) {
      match.used = true;
      if (!match.expired) { suppressed.push({ ...finding, allow: { reason: match.reason || null, expires: match.expires || null } }); return; }
      finding.message += ` (allowlist entry expired ${match.expires})`;
    }
    findings.push(finding);
  };

  for (const w of base.warnings || []) add('sbom-warning', { package: null, message: `Base: ${w}`, fix: 'Regenerate the SBOM with a supported tool version' });
  for (const w of head.warnings || []) add('sbom-warning', { package: null, message: `Head: ${w}`, fix: 'Regenerate the SBOM with a supported tool version' });
  if (options.copyleft !== undefined && options.copyleft !== false) add('sbom-warning', { package: null, message: 'The copyleft option was removed in 1.1.0: sbom-diff-sentinel reports licence changes but no longer applies licence policy', fix: 'Gate licences with license-sentinel (npx license-sentinel --policy ...)' });
  let vex;
  try { vex = [...(head.vex || []), ...(cfg.vexStatements || []), ...readVex(cfg.vex)]; } catch (e) { throw new Error(`VEX: ${e.message}`); }
  const vexed = [];

  // Vulnerabilities
  const changed = [...diff.upgraded, ...diff.downgraded];
  const headTargets = [...diff.added.map((a) => a.component), ...changed.map((c) => c.component)];
  const baseTargets = [...diff.removed.map((r) => r.component), ...changed.map((c) => c.base)];
  const newVulns = []; const fixedVulns = []; const persistingVulns = [];
  let vulnStatus = 'skipped (offline)';
  const cache = cfg.cache === false ? null : new OsvCache(cfg.cache || defaultCacheDir(), { ttl: Number(cfg.cacheTtl ?? 86400), now: () => now.getTime(), url: cfg.osvUrl });
  const useCacheOffline = cfg.offline && cache && cache.size > 0;
  if ((!cfg.offline || useCacheOffline) && (headTargets.length || baseTargets.length)) {
    try {
      const { byComponent, unscanned, uncached } = await lookupVulns([...headTargets, ...baseTargets], { url: cfg.osvUrl, fetchImpl: cfg.fetchImpl, timeout: cfg.timeout, cache, offline: !!cfg.offline });
      vulnStatus = cfg.offline ? 'checked (offline, from cache)' : 'checked';
      for (const c of unscanned.filter((u) => headTargets.includes(u))) add('unscanned-component', { package: c.name, version: c.version, message: `${c.name}@${c.version ?? '?'} has no purl/version, so it was not checked on OSV`, fix: 'Generate the SBOM with package URLs (purl)' });
      for (const c of uncached.filter((u) => headTargets.includes(u))) add('unscanned-component', { package: c.name, version: c.version, message: `${c.name}@${c.version ?? '?'} is not in the OSV cache, so it was not checked (offline)`, fix: 'Run once online to fill the cache, or drop --offline' });
      const byKey = (list) => { const m = new Map(); for (const c of list) { if (!m.has(c.key)) m.set(c.key, []); m.get(c.key).push(...(byComponent.get(c) || []).map((v) => ({ v, c }))); } return m; };
      const H = byKey(headTargets); const B = byKey(baseTargets);
      for (const key of new Set([...H.keys(), ...B.keys()])) {
        const hv = H.get(key) || []; const bv = B.get(key) || [];
        const bKeys = new Set(bv.flatMap(({ v }) => vulnKeys(v)));
        const hKeys = new Set(hv.flatMap(({ v }) => vulnKeys(v)));
        const seen = new Set();
        for (const { v, c } of hv) {
          if (seen.has(v.id)) continue; seen.add(v.id);
          const entry = { ...v, package: c.name, version: c.version };
          if (vulnKeys(v).some((k) => bKeys.has(k))) { persistingVulns.push(entry); continue; }
          const vs = vex.length ? vexFor(vex, { ids: vulnKeys(v), package: c.name, version: c.version, purl: c.purl, ref: c.ref }) : null;
          if (vs && SUPPRESSING.has(vs.status)) { vexed.push({ ...entry, vex: { status: vs.status, justification: vs.justification, detail: vs.detail, source: vs.source } }); continue; }
          newVulns.push(vs ? { ...entry, vex: { status: vs.status, justification: vs.justification, source: vs.source } } : entry);
          add('new-vulnerability', { severity: v.severity, package: c.name, version: c.version, id: v.id, ids: vulnKeys(v), url: v.url, message: `${c.name}@${c.version}: ${v.id}${v.aliases.length ? ` (${v.aliases.slice(0, 2).join(', ')})` : ''} ${v.summary || ''}${vs ? ` [VEX: ${vs.status}]` : ''}`.trim(), fix: `See ${v.url} for fixed versions` });
        }
        const seenB = new Set();
        for (const { v, c } of bv) {
          if (seenB.has(v.id) || vulnKeys(v).some((k) => hKeys.has(k))) continue; seenB.add(v.id);
          fixedVulns.push({ ...v, package: c.name, version: c.version, removed: diff.removed.some((r) => r.component === c) });
        }
      }
    } catch (e) {
      vulnStatus = `error: ${e.message}`;
      add('osv-error', { package: null, message: `OSV lookup failed: ${e.message}`, fix: 'Retry, check network access to api.osv.dev, or run with --offline' });
    }
  } else if (!cfg.offline) vulnStatus = 'checked';
  else if (!headTargets.length && !baseTargets.length) vulnStatus = 'checked';

  // Downgrades
  for (const d of diff.downgraded) add('downgrade', { package: d.name, version: d.to, from: d.from, message: `${d.name} downgraded ${d.from} → ${d.to}`, fix: 'Confirm the downgrade is intended; older versions may lack security fixes' });

  // Licences: report changes only; policy lives in license-sentinel
  for (const l of diff.licenseChanged) add('license-changed', { package: l.name, version: l.version, from: l.from, to: l.to, fromCategory: categoryOf(l.from), toCategory: categoryOf(l.to), message: `${l.name}: license ${l.from || '(none)'} (${categoryOf(l.from)}) → ${l.to || '(none)'} (${categoryOf(l.to)})`, fix: 'Review the new license terms' });
  for (const s of diff.supplierChanged) add('supplier-changed', { package: s.name, version: s.version, from: s.from, to: s.to, message: `${s.name}: supplier "${s.from}" → "${s.to}"`, fix: 'Verify the new maintainer/publisher is legitimate' });
  for (const h of diff.hashChanged) add('hash-changed', { package: h.name, version: h.version, message: `${h.name}@${h.version}: hash changed for the same version`, fix: 'Investigate: a republished or tampered package, or a different registry/mirror' });
  if (cfg.maxChanges !== null && cfg.maxChanges !== undefined && diff.totals.changes > cfg.maxChanges) add('too-many-changes', { package: null, message: `${diff.totals.changes} component changes exceed the maximum of ${cfg.maxChanges}`, fix: 'Split the change, or raise maxChanges' });
  for (const a of allow.filter((x) => x.expired && !x.used)) add('allowlist-expired', { package: a.package || null, message: `Allowlist entry ${a.id || a.package || a.rule} expired on ${a.expires}${a.reason ? ` ("${a.reason}")` : ''}`, fix: 'Re-review and extend "expires", or remove the entry' });

  findings.sort((a, b) => RANK[b.severity] - RANK[a.severity] || String(a.package).localeCompare(String(b.package)));
  const counts = Object.fromEntries(SEVERITIES.map((s) => [s, findings.filter((f) => f.severity === s).length]));
  const strip = (x) => { const { component, base: b, ...rest } = x; return { ...rest, ...(component?.purl ? { purl: component.purl } : {}), ...(component?.license && rest.license === undefined ? { license: component.license } : {}) }; };
  return {
    tool: 'sbom-diff-sentinel', generatedAt: now.toISOString(),
    base: { file: base.file || null, format: base.format, specVersion: base.specVersion, components: base.components.length },
    head: { file: head.file || null, format: head.format, specVersion: head.specVersion, components: head.components.length },
    diff: { added: diff.added.map(strip), removed: diff.removed.map(strip), upgraded: diff.upgraded.map(strip), downgraded: diff.downgraded.map(strip), licenseChanged: diff.licenseChanged.map(strip), supplierChanged: diff.supplierChanged.map(strip), hashChanged: diff.hashChanged.map(strip), unchanged: diff.unchanged, totals: diff.totals },
    vulnerabilities: { status: vulnStatus, new: newVulns, fixed: fixedVulns, persisting: persistingVulns, vex: vexed }, vex: { statements: vex.length, suppressed: vexed.length }, cache: cache ? { dir: cache.dir, ...cache.stats } : null,
    findings, suppressed, counts, config: { failOn: cfg.failOn, maxChanges: cfg.maxChanges, offline: !!cfg.offline },
  };
}

export function exitCode(report, failOn = report.config?.failOn || 'high') {
  if (failOn === 'none') return 0;
  return report.findings.some((f) => RANK[f.severity] >= RANK[failOn]) ? 1 : 0;
}
