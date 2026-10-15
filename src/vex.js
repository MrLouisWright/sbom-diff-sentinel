// VEX (Vulnerability Exploitability eXchange): CycloneDX VEX and OpenVEX statements, used to suppress
// vulnerabilities that a supplier or your team has declared not exploitable.
import { readFileSync } from 'node:fs';

/** Statuses that suppress a vulnerability. */
export const SUPPRESSING = new Set(['not_affected', 'false_positive', 'fixed', 'resolved', 'resolved_with_pedigree']);
const stripPurl = (p) => String(p).replace(/[?#].*$/, '').toLowerCase();
const stripPurlVersion = (p) => stripPurl(p).replace(/@[^/@]*$/, '');

/**
 * Parse a VEX document (CycloneDX JSON with vulnerabilities[].analysis, or OpenVEX).
 * @returns {{ vulnerability: string, aliases: string[], products: string[], status: string, justification: string|null, detail: string|null, source: string }[]}
 */
export function parseVex(doc, source = 'VEX') {
  if (typeof doc === 'string') doc = JSON.parse(doc);
  const out = [];
  if (Array.isArray(doc.statements) && (String(doc['@context'] || '').includes('openvex') || doc.statements.some((s) => s.vulnerability))) {
    for (const s of doc.statements) {
      const v = typeof s.vulnerability === 'string' ? { name: s.vulnerability } : s.vulnerability || {};
      const products = (s.products || []).flatMap((p) => (typeof p === 'string' ? [p] : [p['@id'], ...Object.values(p.identifiers || {})]).filter(Boolean));
      out.push({ vulnerability: v.name || v['@id'], aliases: v.aliases || [], products, status: s.status, justification: s.justification || null, detail: s.impact_statement || s.status_notes || null, source });
    }
    return out;
  }
  if (Array.isArray(doc.vulnerabilities)) {
    const refs = new Map();
    const walk = (list) => { for (const c of list || []) { if (c['bom-ref']) refs.set(c['bom-ref'], c.purl || `${c.group ? `${c.group}/` : ''}${c.name}@${c.version}`); walk(c.components); } };
    walk(doc.components); if (doc.metadata?.component) walk([doc.metadata.component]);
    for (const v of doc.vulnerabilities) {
      const state = v.analysis?.state; if (!state) continue;
      const products = (v.affects || []).map((a) => refs.get(a.ref) || a.ref).filter(Boolean);
      out.push({ vulnerability: v.id, aliases: (v.references || []).map((r) => r.id).filter(Boolean), products, status: state, justification: v.analysis.justification || null, detail: v.analysis.detail || null, source });
    }
  }
  return out;
}

/** Read and merge VEX files. */
export function readVex(files) { return [].concat(files || []).flatMap((f) => parseVex(JSON.parse(readFileSync(f, 'utf8')), f)); }

/**
 * Find the VEX statement that applies to a vulnerability in a component. Products match by purl
 * (ignoring qualifiers; a purl without version covers every version), bom-ref, or name@version. No products = every component.
 * @param {ReturnType<typeof parseVex>} statements
 * @param {{ ids: string[], package: string, version: string, purl?: string|null, ref?: string|null }} f
 */
export function vexFor(statements, f) {
  const ids = new Set(f.ids.map((x) => x.toUpperCase()));
  const purl = f.purl ? stripPurl(f.purl) : null;
  const hits = statements.filter((s) => [s.vulnerability, ...s.aliases].some((x) => x && ids.has(String(x).toUpperCase())) && (!s.products.length || s.products.some((p) => {
    const q = String(p);
    if (q.startsWith('pkg:')) return purl && (stripPurl(q) === purl || (!/@/.test(stripPurl(q).split('/').pop()) && stripPurlVersion(purl) === stripPurl(q)));
    return q === f.ref || q === `${f.package}@${f.version}` || q === f.package;
  })));
  return hits.length ? hits[hits.length - 1] : null; // later statements win
}
