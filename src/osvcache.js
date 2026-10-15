// On-disk cache for OSV results so CI re-runs and --offline work without the network.
import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';
import { createHash } from 'node:crypto';

/** Default cache directory ($SBOM_DIFF_SENTINEL_CACHE, $XDG_CACHE_HOME/sbom-diff-sentinel or ~/.cache/sbom-diff-sentinel). */
export function defaultCacheDir() {
  return process.env.SBOM_DIFF_SENTINEL_CACHE || join(process.env.XDG_CACHE_HOME || join(homedir(), '.cache'), 'sbom-diff-sentinel');
}

export class OsvCache {
  /**
   * @param {string|null} dir  null = memory only
   * @param {{ ttl?: number, now?: () => number }} [opts]  ttl in seconds (default 24h); offline mode ignores the TTL
   */
  constructor(dir, { ttl = 86400, now = Date.now, url = 'https://api.osv.dev' } = {}) {
    // one file per OSV endpoint, so a mirror or test server never mixes with api.osv.dev
    const tag = url.replace(/\/+$/, '') === 'https://api.osv.dev' ? '' : `-${createHash('sha256').update(url).digest('hex').slice(0, 12)}`;
    this.dir = dir; this.ttl = ttl; this.now = now; this.file = dir ? join(dir, `osv-cache${tag}.json`) : null;
    this.data = { queries: {}, vulns: {} }; this.dirty = false; this.stats = { hits: 0, misses: 0 };
    if (this.file && existsSync(this.file)) { try { const d = JSON.parse(readFileSync(this.file, 'utf8')); if (d && d.queries && d.vulns) this.data = d; } catch { /* corrupt cache: start fresh */ } }
  }
  fresh(e, stale) { return e && (stale || (this.now() - e.t) / 1000 <= this.ttl); }
  /** Vulnerability ids for a purl query, or undefined if not cached. */
  getQuery(purl, stale = false) { const e = this.data.queries[purl]; if (this.fresh(e, stale)) { this.stats.hits++; return e.ids; } this.stats.misses++; return undefined; }
  setQuery(purl, ids) { this.data.queries[purl] = { t: this.now(), ids }; this.dirty = true; }
  getVuln(id, stale = false) { const e = this.data.vulns[id]; return this.fresh(e, stale) ? e.v : undefined; }
  setVuln(id, v) { this.data.vulns[id] = { t: this.now(), v }; this.dirty = true; }
  get size() { return Object.keys(this.data.queries).length; }
  save() { if (!this.file || !this.dirty) return; mkdirSync(this.dir, { recursive: true }); writeFileSync(this.file, JSON.stringify(this.data)); this.dirty = false; }
}
