import { parseVex } from './vex.js';
import fs from 'node:fs';

const ALG = (a) => String(a || '').toUpperCase().replace(/^SHA(\d)/, 'SHA-$1').replace(/^SHA-?1$/, 'SHA-1');
const noAssert = (v) => (!v || /^(NOASSERTION|NONE)$/i.test(String(v).trim()) ? null : String(v).trim());

/** Parse a package URL into { type, namespace, name, version } (qualifiers/subpath dropped). */
export function parsePurl(purl) {
  const m = /^pkg:([a-zA-Z.+-]+)\/(.+?)(?:\?[^#]*)?(?:#.*)?$/.exec(String(purl || ''));
  if (!m) return null;
  let rest = m[2];
  let version = null;
  const at = rest.lastIndexOf('@');
  if (at > 0 && rest.lastIndexOf('/') < at) { version = decodeURIComponent(rest.slice(at + 1)); rest = rest.slice(0, at); }
  const parts = rest.split('/').map(decodeURIComponent);
  const name = parts.pop();
  return { type: m[1].toLowerCase(), namespace: parts.join('/') || null, name, version };
}

export function purlKey(p) { return `pkg:${p.type}/${p.namespace ? p.namespace + '/' : ''}${p.name}`; }

function cdxLicense(list) {
  if (!Array.isArray(list) || !list.length) return null;
  const parts = list.map((l) => l.expression || l.license?.id || l.license?.name).filter(Boolean);
  if (!parts.length) return null;
  return parts.length === 1 ? parts[0] : parts.map((p) => (/\s/.test(p) ? `(${p})` : p)).join(' AND ');
}

function component({ name, group, version, purl, license, supplier, hashes, scope, ref }) {
  const p = parsePurl(purl);
  const fullName = p ? (p.namespace ? (p.type === 'npm' ? `${p.namespace}/${p.name}` : `${p.namespace}:${p.name}`) : p.name) : group ? `${group}/${name}` : name;
  const key = p ? purlKey(p) : `name:${fullName}`;
  return { key, name: fullName, version: version ?? p?.version ?? null, purl: purl || null, ecosystem: p?.type || null, license: license || null, supplier: supplier || null, hashes: hashes || {}, scope: scope || null, ref: ref || null };
}

export function parseCycloneDX(doc) {
  const spec = String(doc.specVersion || '');
  const warnings = [];
  if (!/^1\.[4-6]$/.test(spec)) warnings.push(`CycloneDX specVersion ${spec || '(missing)'} is outside the supported 1.4–1.6 range; parsing anyway`);
  const out = [];
  const rootRef = doc.metadata?.component?.['bom-ref'];
  const walk = (list) => {
    for (const c of list || []) {
      if (!c || typeof c !== 'object') continue;
      if (c['bom-ref'] && c['bom-ref'] === rootRef) { walk(c.components); continue; }
      if (c.name && !['application', 'operating-system', 'device', 'firmware', 'data'].includes(c.type) || c.purl) {
        const hashes = {};
        for (const h of c.hashes || []) if (h.alg && h.content) hashes[ALG(h.alg)] = String(h.content).toLowerCase();
        out.push(component({ name: c.name, group: c.group, version: c.version, purl: c.purl, license: cdxLicense(c.licenses), supplier: c.supplier?.name || c.publisher || (typeof c.author === 'string' ? c.author : null) || c.authors?.[0]?.name, hashes, scope: c.scope, ref: c['bom-ref'] }));
      }
      walk(c.components);
    }
  };
  walk(doc.components);
  return { format: 'CycloneDX', specVersion: spec, name: doc.metadata?.component?.name || null, components: out, warnings };
}

export function parseSPDX(doc) {
  const spec = String(doc.spdxVersion || '').replace(/^SPDX-/, '');
  const warnings = [];
  if (spec !== '2.3') warnings.push(`SPDX version ${spec || '(missing)'} is not 2.3; parsing anyway`);
  const described = new Set(doc.documentDescribes || []);
  for (const r of doc.relationships || []) if (r.relationshipType === 'DESCRIBES' && r.spdxElementId === 'SPDXRef-DOCUMENT') described.add(r.relatedSpdxElement);
  const out = [];
  for (const p of doc.packages || []) {
    if (described.has(p.SPDXID)) continue;
    const purl = (p.externalRefs || []).find((r) => /purl/i.test(r.referenceType))?.referenceLocator;
    const hashes = {};
    for (const c of p.checksums || []) if (c.algorithm && c.checksumValue) hashes[ALG(c.algorithm)] = String(c.checksumValue).toLowerCase();
    const supplier = noAssert(p.supplier)?.replace(/^(Organization|Person|Tool):\s*/i, '').replace(/\s*\([^)]*@[^)]*\)\s*$/, '') || noAssert(p.originator)?.replace(/^(Organization|Person|Tool):\s*/i, '');
    out.push(component({ name: p.name, version: noAssert(p.versionInfo), purl, license: noAssert(p.licenseConcluded) || noAssert(p.licenseDeclared), supplier, hashes, ref: p.SPDXID }));
  }
  return { format: 'SPDX', specVersion: spec, name: doc.name || null, components: out, warnings };
}

export function parseSbom(input, source = 'SBOM') {
  let doc = input;
  if (typeof input === 'string') {
    try { doc = JSON.parse(input); } catch (e) { throw new Error(`${source}: not valid JSON (${e.message})`); }
  }
  if (!doc || typeof doc !== 'object') throw new Error(`${source}: not a JSON object`);
  if (doc.bomFormat === 'CycloneDX' || (doc.specVersion && Array.isArray(doc.components))) { const r = parseCycloneDX(doc); const vex = Array.isArray(doc.vulnerabilities) ? parseVex(doc, `${source} (embedded VEX)`) : []; return vex.length ? { ...r, vex } : r; }
  if (doc.spdxVersion || doc.SPDXID === 'SPDXRef-DOCUMENT') return parseSPDX(doc);
  throw new Error(`${source}: unrecognised SBOM format (expected CycloneDX JSON or SPDX 2.3 JSON)`);
}

export function readSbom(file) {
  return { ...parseSbom(fs.readFileSync(file, 'utf8'), file), file };
}
