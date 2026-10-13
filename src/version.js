/** Loose semver-ish comparison: numeric segments, then prerelease (1.0.0-rc < 1.0.0). Returns -1, 0 or 1. */
export function compareVersions(a, b) {
  if (a === b) return 0;
  const split = (v) => {
    const s = String(v ?? '').trim().replace(/^v/i, '').replace(/\+.*$/, '');
    const i = s.search(/-/);
    return { main: (i === -1 ? s : s.slice(0, i)).split(/[._]/), pre: i === -1 ? null : s.slice(i + 1).split('.') };
  };
  const cmpPart = (x, y) => {
    const nx = /^\d+$/.test(x); const ny = /^\d+$/.test(y);
    if (nx && ny) return Math.sign(Number(x) - Number(y));
    if (nx !== ny) return nx ? 1 : -1;
    return x < y ? -1 : x > y ? 1 : 0;
  };
  const A = split(a); const B = split(b);
  for (let i = 0; i < Math.max(A.main.length, B.main.length); i++) {
    const c = cmpPart(A.main[i] ?? '0', B.main[i] ?? '0');
    if (c) return c;
  }
  if (!A.pre && !B.pre) return 0;
  if (!A.pre) return 1;
  if (!B.pre) return -1;
  for (let i = 0; i < Math.max(A.pre.length, B.pre.length); i++) {
    if (A.pre[i] === undefined) return -1;
    if (B.pre[i] === undefined) return 1;
    const c = cmpPart(A.pre[i], B.pre[i]);
    if (c) return c;
  }
  return 0;
}
