import { parseSpdx, spdxOptions, licenseCategory, CATEGORIES } from 'license-sentinel';

const rank = (c) => { const i = CATEGORIES.indexOf(c); return i === -1 ? CATEGORIES.length : i; };

/**
 * Category of an SPDX expression from the licensee's point of view: for OR the most permissive
 * option wins; within an option (AND) the most restrictive license counts.
 */
export function categoryOf(expr) {
  if (!expr) return 'unknown';
  let ast;
  try { ast = parseSpdx(expr).ast; } catch { return 'unknown'; }
  let best = null;
  for (const opt of spdxOptions(ast)) {
    const worst = opt.map((leaf) => licenseCategory(leaf)).reduce((a, c) => (rank(c) > rank(a) ? c : a), 'public-domain');
    if (best === null || rank(worst) < rank(best)) best = worst;
  }
  return best || 'unknown';
}

export const COPYLEFT = { weak: ['weak-copyleft', 'strong-copyleft', 'network-copyleft'], strong: ['strong-copyleft', 'network-copyleft'], network: ['network-copyleft'] };
export const isCopyleft = (expr, level = 'strong') => (COPYLEFT[level] || COPYLEFT.strong).includes(categoryOf(expr));
