// CVSS v3.0/v3.1 base score from a vector string, and severity bands.
const W = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 }, AC: { L: 0.77, H: 0.44 }, UI: { N: 0.85, R: 0.62 },
  C: { H: 0.56, L: 0.22, N: 0 }, I: { H: 0.56, L: 0.22, N: 0 }, A: { H: 0.56, L: 0.22, N: 0 },
};
const roundup = (x) => { const i = Math.round(x * 100000); return i % 10000 === 0 ? i / 100000 : (Math.floor(i / 10000) + 1) / 10; };

export function cvss3Score(vector) {
  const m = {};
  for (const part of String(vector).split('/')) { const [k, v] = part.split(':'); m[k] = v; }
  if (!/^CVSS:3/.test(vector) || !m.AV || !m.AC || !m.PR || !m.UI || !m.S || !m.C || !m.I || !m.A) return null;
  const changed = m.S === 'C';
  const pr = { N: 0.85, L: changed ? 0.68 : 0.62, H: changed ? 0.5 : 0.27 }[m.PR];
  const vals = [W.AV[m.AV], W.AC[m.AC], pr, W.UI[m.UI], W.C[m.C], W.I[m.I], W.A[m.A]];
  if (vals.some((v) => v === undefined)) return null;
  const [av, ac, , ui, c, i, a] = vals;
  const iss = 1 - (1 - c) * (1 - i) * (1 - a);
  const impact = changed ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15) : 6.42 * iss;
  const expl = 8.22 * av * ac * pr * ui;
  if (impact <= 0) return 0;
  return changed ? roundup(Math.min(1.08 * (impact + expl), 10)) : roundup(Math.min(impact + expl, 10));
}

export function bandOf(score) {
  if (score === null || score === undefined) return null;
  if (score >= 9) return 'critical';
  if (score >= 7) return 'high';
  if (score >= 4) return 'medium';
  if (score > 0) return 'low';
  return 'info';
}

const TEXT = { CRITICAL: 'critical', HIGH: 'high', MODERATE: 'medium', MEDIUM: 'medium', LOW: 'low' };

/** Best-effort severity of an OSV vulnerability record. */
export function osvSeverity(v) {
  let score = null;
  for (const s of [...(v.severity || []), ...(v.affected || []).flatMap((a) => a.severity || [])]) {
    if (/^CVSS_V3/.test(s.type)) { const x = cvss3Score(s.score); if (x !== null && (score === null || x > score)) score = x; }
  }
  if (score !== null) return { severity: bandOf(score), score };
  const db = v.database_specific?.severity || (v.affected || []).map((a) => a.database_specific?.severity || a.ecosystem_specific?.severity).find(Boolean);
  if (db && TEXT[String(db).toUpperCase()]) return { severity: TEXT[String(db).toUpperCase()], score: null };
  for (const s of v.severity || []) if (/^CVSS_V4/.test(s.type)) return { severity: 'medium', score: null, estimated: true };
  return { severity: 'medium', score: null, estimated: true };
}
