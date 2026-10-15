import { parsePurl } from './sbom.js';
import { osvSeverity } from './cvss.js';

export const OSV_URL = 'https://api.osv.dev';
const BATCH = 1000;

/** Build an OSV query for a component, or null if it can't be identified. */
export function osvQuery(c) {
  if (!c.purl || !c.version) return null;
  const p = parsePurl(c.purl);
  if (!p) return null;
  const noQ = c.purl.replace(/[?#].*$/, '');
  const base = p.version ? noQ.slice(0, noQ.lastIndexOf('@')) : noQ;
  return { package: { purl: `${base}@${encodeURIComponent(c.version)}` } };
}

async function request(url, { fetchImpl, timeout, body }) {
  const res = await fetchImpl(url, { method: body ? 'POST' : 'GET', headers: body ? { 'content-type': 'application/json' } : {}, body: body ? JSON.stringify(body) : undefined, signal: AbortSignal.timeout(timeout) });
  if (!res.ok) throw new Error(`OSV ${body ? 'querybatch' : 'vulns'} HTTP ${res.status}`);
  return res.json();
}

async function pool(items, n, fn) {
  const out = new Array(items.length);
  let i = 0;
  await Promise.all(Array.from({ length: Math.min(n, items.length) }, async () => { while (i < items.length) { const k = i++; out[k] = await fn(items[k]); } }));
  return out;
}

/**
 * Look up vulnerabilities for components via OSV /v1/querybatch, then fetch details for each id.
 * With a cache, fresh entries are reused; with offline: true only the cache is used (stale entries allowed)
 * and components missing from it come back in `uncached`.
 * @param {object[]} components
 * @param {{ url?: string, fetchImpl?: typeof fetch, timeout?: number, concurrency?: number, cache?: import('./osvcache.js').OsvCache, offline?: boolean }} [opts]
 */
export async function lookupVulns(components, { url = OSV_URL, fetchImpl = globalThis.fetch, timeout = 15000, concurrency = 8, cache = null, offline = false } = {}) {
  url = url.replace(/\/+$/, '');
  const scannable = []; const unscanned = []; const uncached = [];
  for (const c of components) { const q = osvQuery(c); if (q) scannable.push({ c, q }); else unscanned.push(c); }
  const ids = new Map(scannable.map((s) => [s.c, new Set()]));
  const toFetch = [];
  for (const s of scannable) {
    const hit = cache?.getQuery(s.q.package.purl, offline);
    if (hit) for (const id of hit) ids.get(s.c).add(id);
    else if (offline) { uncached.push(s.c); ids.delete(s.c); }
    else toFetch.push(s);
  }
  for (let i = 0; i < toFetch.length; i += BATCH) {
    let pending = toFetch.slice(i, i + BATCH).map((s) => ({ ...s, token: undefined }));
    while (pending.length) {
      const r = await request(`${url}/v1/querybatch`, { fetchImpl, timeout, body: { queries: pending.map((p) => (p.token ? { ...p.q, page_token: p.token } : p.q)) } });
      const results = r.results || [];
      const next = [];
      pending.forEach((p, k) => {
        const res = results[k] || {};
        for (const v of res.vulns || []) ids.get(p.c).add(v.id);
        if (res.next_page_token) next.push({ ...p, token: res.next_page_token });
      });
      pending = next;
    }
    for (const s of toFetch.slice(i, i + BATCH)) cache?.setQuery(s.q.package.purl, [...ids.get(s.c)].sort());
  }
  const allIds = [...new Set([...ids.values()].flatMap((s) => [...s]))].sort();
  const details = new Map();
  await pool(allIds, concurrency, async (id) => {
    let d = cache?.getVuln(id, offline);
    if (!d) {
      if (offline) { d = { id, aliases: [], summary: '(details not cached)', severity: 'high', score: null, url: `https://osv.dev/vulnerability/${id}` }; }
      else {
        const v = await request(`${url}/v1/vulns/${encodeURIComponent(id)}`, { fetchImpl, timeout });
        const sev = osvSeverity(v);
        d = { id, aliases: v.aliases || [], summary: v.summary || (v.details || '').split('\n')[0].slice(0, 200), ...sev, url: `https://osv.dev/vulnerability/${id}` };
        cache?.setVuln(id, d);
      }
    }
    details.set(id, d);
  });
  cache?.save();
  const byComponent = new Map();
  for (const [c, set] of ids) byComponent.set(c, [...set].sort().map((id) => details.get(id)));
  return { byComponent, unscanned, uncached };
}
