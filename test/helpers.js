import http from 'node:http';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const FIX = path.join(path.dirname(fileURLToPath(import.meta.url)), 'fixtures');
export const fx = (f) => path.join(FIX, f);

/** Mock OSV: vulns maps "purl@version" (as queried) -> [ids]; records maps id -> full record. */
export async function mockOsv({ vulns = {}, records = {}, fail = false, paginate = false } = {}) {
  const log = { batches: [], details: [] };
  const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', () => {
      if (fail) { res.statusCode = 503; res.end('down'); return; }
      if (req.method === 'POST' && req.url === '/v1/querybatch') {
        const q = JSON.parse(body);
        log.batches.push(q.queries);
        const results = q.queries.map((x) => {
          const ids = vulns[x.package.purl] || [];
          if (paginate && ids.length > 1 && !x.page_token) return { vulns: [{ id: ids[0] }], next_page_token: 'p2' };
          if (paginate && x.page_token) return { vulns: ids.slice(1).map((id) => ({ id })) };
          return ids.length ? { vulns: ids.map((id) => ({ id, modified: '2026-01-01T00:00:00Z' })) } : {};
        });
        res.setHeader('content-type', 'application/json');
        res.end(JSON.stringify({ results }));
        return;
      }
      const m = /^\/v1\/vulns\/(.+)$/.exec(req.url);
      if (req.method === 'GET' && m) {
        const id = decodeURIComponent(m[1]);
        log.details.push(id);
        const r = records[id];
        if (!r) { res.statusCode = 404; res.end('{}'); return; }
        res.setHeader('content-type', 'application/json');
        res.end(JSON.stringify({ id, ...r }));
        return;
      }
      res.statusCode = 404; res.end();
    });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  return { url: `http://127.0.0.1:${server.address().port}`, log, close: () => new Promise((r) => { server.closeAllConnections?.(); server.close(r); }) };
}

export function tmpdir() { return fs.mkdtempSync(path.join(os.tmpdir(), 'sbomdiff-')); }

export const CVSS = { critical: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', high: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H', medium: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N', low: 'CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N' };
export const rec = (sev, extra = {}) => ({ summary: `${sev} bug`, aliases: [], severity: [{ type: 'CVSS_V3', score: CVSS[sev] }], ...extra });
