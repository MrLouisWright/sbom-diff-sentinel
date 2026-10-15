import { RULES, SEVERITIES } from './rules.js';

const C = { critical: '\x1b[35m', high: '\x1b[31m', medium: '\x1b[33m', low: '\x1b[36m', info: '\x1b[90m', dim: '\x1b[2m', bold: '\x1b[1m', green: '\x1b[32m', red: '\x1b[31m', reset: '\x1b[0m' };
const v = (x) => (x === null || x === undefined || x === '' ? '?' : x);

export function formatText(r, { color = false, fixes = true, summaryOnly = false } = {}) {
  const k = (c, s) => (color ? C[c] + s + C.reset : s);
  const d = r.diff;
  const out = [];
  if (!summaryOnly) {
    out.push(k('bold', `SBOM diff: ${r.base.file || 'base'} (${r.base.components}) → ${r.head.file || 'head'} (${r.head.components})`), '');
    const sec = (title, list, fmt) => { if (!list.length) return; out.push(k('bold', `${title} (${list.length})`)); for (const x of list) out.push('  ' + fmt(x)); out.push(''); };
    sec('Added', d.added, (x) => `${k('green', '+')} ${x.name}@${v(x.version)}${x.license ? k('dim', ` ${x.license}`) : ''}`);
    sec('Removed', d.removed, (x) => `${k('red', '-')} ${x.name}@${v(x.version)}`);
    sec('Upgraded', d.upgraded, (x) => `↑ ${x.name} ${v(x.from)} → ${v(x.to)}`);
    sec('Downgraded', d.downgraded, (x) => `${k('medium', '↓')} ${x.name} ${v(x.from)} → ${v(x.to)}`);
    sec('License changes', d.licenseChanged, (x) => `${x.name}: ${v(x.from)} → ${v(x.to)}`);
    sec('Supplier changes', d.supplierChanged, (x) => `${x.name}: ${x.from} → ${x.to}`);
    sec('Hash changes', d.hashChanged, (x) => `${k('high', '!')} ${x.name}@${x.version}`);
    const vs = r.vulnerabilities;
    sec('Fixed vulnerabilities', vs.fixed, (x) => `${k('green', '✓')} ${x.id} ${x.package}@${x.version} (${x.severity})${x.removed ? k('dim', ' — package removed') : ''}`);
    if (r.findings.length) {
      out.push(k('bold', `Policy findings (${r.findings.length})`));
      for (const f of r.findings) {
        out.push(`  ${k(f.severity, f.severity.padEnd(8))} ${f.message} ${k('dim', `[${f.rule}]`)}`);
        if (fixes && f.fix) out.push(`           ${k('dim', '↳ ' + f.fix)}`);
      }
      out.push('');
    }
  }
  const t = d.totals;
  const c = r.counts;
  out.push(`${t.changes} change(s): +${d.added.length} -${d.removed.length} ↑${d.upgraded.length} ↓${d.downgraded.length}; vulns: ${r.vulnerabilities.new.length} new, ${r.vulnerabilities.fixed.length} fixed${r.vulnerabilities.vex?.length ? `, ${r.vulnerabilities.vex.length} not affected (VEX)` : ''} (${r.vulnerabilities.status}); ` +
    (r.findings.length ? SEVERITIES.filter((s) => c[s]).map((s) => k(s, `${c[s]} ${s}`)).join(', ') : k('green', 'no policy findings')) + (r.suppressed.length ? `; ${r.suppressed.length} allowlisted` : ''));
  return out.join('\n') + '\n';
}

export function formatJson(r) { return JSON.stringify(r, null, 2) + '\n'; }

const SEC = { critical: '9.5', high: '8.0', medium: '5.5', low: '3.0', info: '0.0' };
const LEVEL = { critical: 'error', high: 'error', medium: 'warning', low: 'note', info: 'note' };

export function formatSarif(r, version = '0.0.0') {
  const uri = r.head.file && !/\(generated\)$/.test(r.head.file) ? r.head.file : 'package.json';
  const rules = Object.entries(RULES).map(([id, x]) => ({ id, name: id, shortDescription: { text: x.title }, defaultConfiguration: { level: LEVEL[x.severity] || 'error' }, properties: { tags: ['security', 'sbom', 'supply-chain'], ...(SEC[x.severity] ? { 'security-severity': SEC[x.severity] } : {}) } }));
  return JSON.stringify({
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json', version: '2.1.0',
    runs: [{
      tool: { driver: { name: 'sbom-diff-sentinel', version, informationUri: 'https://github.com/MrLouisWright/sbom-diff-sentinel', rules } },
      results: r.findings.map((f) => ({
        ruleId: f.rule, level: LEVEL[f.severity], message: { text: `${f.message}. ${f.fix || ''}`.trim() },
        locations: [{ physicalLocation: { artifactLocation: { uri: uri.replace(/\\/g, '/') }, region: { startLine: 1 } } }],
        partialFingerprints: { primary: `${f.rule}:${f.package || ''}:${f.id || f.version || ''}` },
        properties: { severity: f.severity, 'security-severity': f.score ? String(f.score) : SEC[f.severity], ...(f.package ? { package: f.package } : {}) },
      })),
    }],
  }, null, 2) + '\n';
}

const md = (s) => String(s ?? '').replace(/\|/g, '\\|').replace(/\n/g, ' ');
const ICON = { critical: '🟣', high: '🔴', medium: '🟠', low: '🔵', info: '⚪' };

/** Markdown report for PR comments and the GitHub job summary. Starts with a stable marker for comment updates. */
export function formatMarkdown(r, { maxRows = 50 } = {}) {
  const d = r.diff; const vs = r.vulnerabilities;
  const out = ['<!-- sbom-diff-sentinel -->', '## 📦 SBOM diff', ''];
  out.push(`**${d.totals.changes}** change(s): ➕ ${d.added.length} added · ➖ ${d.removed.length} removed · ⬆️ ${d.upgraded.length} upgraded · ⬇️ ${d.downgraded.length} downgraded`);
  out.push(`Vulnerabilities: **${vs.new.length} new**, ${vs.fixed.length} fixed${vs.status === 'checked' ? '' : ` (${md(vs.status)})`}`, '');
  if (r.findings.length) {
    out.push('### Policy findings', '', '| | Severity | Rule | Finding |', '|---|---|---|---|');
    for (const f of r.findings.slice(0, maxRows)) out.push(`| ${ICON[f.severity]} | ${f.severity} | \`${f.rule}\` | ${md(f.url ? f.message.replace(f.id, `[${f.id}](${f.url})`) : f.message)} |`);
    if (r.findings.length > maxRows) out.push(`| | | | …and ${r.findings.length - maxRows} more |`);
    out.push('');
  } else out.push('✅ No policy findings.', '');
  const table = (title, head, rows, open = false) => {
    if (!rows.length) return;
    out.push(`<details${open ? ' open' : ''}><summary><b>${title}</b> (${rows.length})</summary>`, '', head, head.replace(/[^|]+/g, '---'));
    for (const row of rows.slice(0, maxRows)) out.push(row);
    if (rows.length > maxRows) out.push(`| …and ${rows.length - maxRows} more |`);
    out.push('', '</details>', '');
  };
  table('New vulnerabilities', '| Severity | ID | Package | Summary |', vs.new.map((x) => `| ${ICON[x.severity]} ${x.severity}${x.score ? ` (${x.score})` : ''} | [${x.id}](${x.url}) | \`${md(x.package)}@${md(x.version)}\` | ${md(x.summary)} |`), true);
  table('Fixed vulnerabilities', '| Severity | ID | Package |', vs.fixed.map((x) => `| ${x.severity} | [${x.id}](${x.url}) | \`${md(x.package)}@${md(x.version)}\`${x.removed ? ' (removed)' : ''} |`));
  table('Added', '| Package | Version | License |', d.added.map((x) => `| \`${md(x.name)}\` | ${md(v(x.version))} | ${md(x.license || '')} |`));
  table('Removed', '| Package | Version |', d.removed.map((x) => `| \`${md(x.name)}\` | ${md(v(x.version))} |`));
  table('Upgraded', '| Package | From | To |', d.upgraded.map((x) => `| \`${md(x.name)}\` | ${md(v(x.from))} | ${md(v(x.to))} |`));
  table('Downgraded', '| Package | From | To |', d.downgraded.map((x) => `| \`${md(x.name)}\` | ${md(v(x.from))} | ${md(v(x.to))} |`), true);
  table('License changes', '| Package | From | To |', d.licenseChanged.map((x) => `| \`${md(x.name)}\` | ${md(v(x.from))} | ${md(v(x.to))} |`));
  table('Supplier changes', '| Package | From | To |', d.supplierChanged.map((x) => `| \`${md(x.name)}\` | ${md(x.from)} | ${md(x.to)} |`));
  table('Hash changes', '| Package | Version |', d.hashChanged.map((x) => `| \`${md(x.name)}\` | ${md(x.version)} |`), true);
  if (r.suppressed.length) out.push(`<sub>${r.suppressed.length} finding(s) allowlisted.</sub>`, '');
  table('Not affected (VEX)', '| ID | Package | Status | Justification |', (vs.vex || []).map((x) => `| [${x.id}](${x.url}) | \`${md(x.package)}@${md(x.version)}\` | ${md(x.vex.status)} | ${md(x.vex.justification || x.vex.detail || '')} |`));
  out.push(`<sub>Generated by [sbom-diff-sentinel](https://github.com/MrLouisWright/sbom-diff-sentinel) · base: ${md(r.base.format)} ${md(r.base.specVersion)} (${r.base.components}) · head: ${md(r.head.format)} ${md(r.head.specVersion)} (${r.head.components})</sub>`);
  let s = out.join('\n') + '\n';
  if (s.length > GH_COMMENT_LIMIT) s = `${s.slice(0, GH_COMMENT_LIMIT - 60)}\n\n_…truncated: see the JSON report for everything_\n`;
  return s;
}

const GH_COMMENT_LIMIT = 65000;
/**
 * Short PR comment: verdict, counts, new vulnerabilities, licence changes and downgrades.
 * Starts with the same `<!-- sbom-diff-sentinel -->` marker so it can replace a previous comment, and stays under GitHub's comment size limit.
 * @param {object} r report
 * @param {{ failOn?: string, maxRows?: number, detailsUrl?: string }} [opts]
 */
export function formatPrSummary(r, { failOn = r.config?.failOn || 'high', maxRows = 15, detailsUrl } = {}) {
  const RANKS = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
  const failing = failOn !== 'none' && r.findings.some((f) => RANKS[f.severity] >= RANKS[failOn]);
  const d = r.diff; const vs = r.vulnerabilities;
  const out = ['<!-- sbom-diff-sentinel -->', `### ${failing ? '❌' : '✅'} SBOM diff: ${failing ? `failing at \`${failOn}\`` : 'passing'}`, ''];
  out.push(`${d.totals.changes} change(s): ➕ ${d.added.length} · ➖ ${d.removed.length} · ⬆️ ${d.upgraded.length} · ⬇️ ${d.downgraded.length} · vulnerabilities **${vs.new.length} new** / ${vs.fixed.length} fixed${vs.vex?.length ? ` / ${vs.vex.length} not affected (VEX)` : ''}${/^checked/.test(vs.status) && vs.status !== 'checked' ? ` _(${md(vs.status)})_` : vs.status === 'checked' ? '' : ` _(${md(vs.status)})_`}`, '');
  const list = (title, rows) => { if (!rows.length) return; out.push(`**${title}**`, ''); for (const x of rows.slice(0, maxRows)) out.push(`- ${x}`); if (rows.length > maxRows) out.push(`- …and ${rows.length - maxRows} more`); out.push(''); };
  list('New vulnerabilities', vs.new.map((x) => `${ICON[x.severity] || ''} ${x.severity} [${x.id}](${x.url}) in \`${md(x.package)}@${md(x.version)}\`${x.summary ? `: ${md(x.summary).slice(0, 120)}` : ''}`));
  list('Licence changes', d.licenseChanged.map((x) => `\`${md(x.name)}\`: ${md(v(x.from))} → ${md(v(x.to))}`));
  list('Downgrades', d.downgraded.map((x) => `\`${md(x.name)}\` ${md(v(x.from))} → ${md(v(x.to))}`));
  const other = r.findings.filter((f) => !['new-vulnerability', 'license-changed', 'downgrade'].includes(f.rule) && RANKS[f.severity] >= RANKS.medium);
  list('Other findings', other.map((f) => `${f.severity} \`${f.rule}\`: ${md(f.message)}`));
  if (detailsUrl) out.push(`[Full report](${detailsUrl})`, '');
  out.push(`<sub>sbom-diff-sentinel · ${r.suppressed.length ? `${r.suppressed.length} allowlisted · ` : ''}base ${r.base.components} → head ${r.head.components} components</sub>`);
  let s = out.join('\n') + '\n';
  if (s.length > GH_COMMENT_LIMIT) s = `${s.slice(0, GH_COMMENT_LIMIT - 40)}\n\n_…truncated_\n`;
  return s;
}
