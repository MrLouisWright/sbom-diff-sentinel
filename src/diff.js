import { compareVersions } from './version.js';

const group = (components) => {
  const m = new Map();
  for (const c of components) {
    if (!m.has(c.key)) m.set(c.key, new Map());
    const byVer = m.get(c.key);
    const v = c.version ?? '';
    if (!byVer.has(v)) byVer.set(v, c); // first occurrence wins for duplicates
  }
  return m;
};

const sameHashes = (a, b) => {
  const common = Object.keys(a.hashes || {}).filter((k) => b.hashes && b.hashes[k]);
  if (!common.length) return null; // can't tell
  return common.every((k) => a.hashes[k] === b.hashes[k]);
};

/**
 * Diff two parsed SBOMs. Components are matched by package URL (without version) or name.
 * Several versions of one package are paired highest-to-highest; leftovers are added/removed.
 */
export function diffSboms(base, head) {
  const B = group(base.components);
  const H = group(head.components);
  const added = []; const removed = []; const upgraded = []; const downgraded = []; const unchanged = [];
  const licenseChanged = []; const supplierChanged = []; const hashChanged = [];
  const keys = [...new Set([...B.keys(), ...H.keys()])].sort();
  const compareMeta = (b, h) => {
    if ((b.license || null) !== (h.license || null) && (b.license || h.license)) licenseChanged.push({ name: h.name, key: h.key, version: h.version, fromVersion: b.version, from: b.license, to: h.license, component: h });
    if (b.supplier && h.supplier && b.supplier !== h.supplier) supplierChanged.push({ name: h.name, key: h.key, version: h.version, fromVersion: b.version, from: b.supplier, to: h.supplier, component: h });
  };
  for (const key of keys) {
    const bv = B.get(key) || new Map();
    const hv = H.get(key) || new Map();
    const bOnly = []; const hOnly = [];
    for (const [v, c] of bv) {
      if (hv.has(v)) {
        const h = hv.get(v);
        unchanged.push(h);
        compareMeta(c, h);
        if (sameHashes(c, h) === false) hashChanged.push({ name: h.name, key, version: v, from: c.hashes, to: h.hashes, component: h });
      } else bOnly.push(c);
    }
    for (const [v, c] of hv) if (!bv.has(v)) hOnly.push(c);
    const desc = (a, b) => compareVersions(b.version, a.version);
    bOnly.sort(desc); hOnly.sort(desc);
    while (bOnly.length && hOnly.length) {
      const b = bOnly.shift(); const h = hOnly.shift();
      const c = compareVersions(h.version, b.version);
      const entry = { name: h.name, key, from: b.version, to: h.version, base: b, component: h };
      (c < 0 ? downgraded : upgraded).push(entry);
      compareMeta(b, h);
    }
    for (const c of bOnly) removed.push({ name: c.name, key, version: c.version, component: c });
    for (const c of hOnly) added.push({ name: c.name, key, version: c.version, component: c });
  }
  return {
    added, removed, upgraded, downgraded, licenseChanged, supplierChanged, hashChanged,
    unchanged: unchanged.length,
    totals: { base: base.components.length, head: head.components.length, changes: added.length + removed.length + upgraded.length + downgraded.length },
  };
}
