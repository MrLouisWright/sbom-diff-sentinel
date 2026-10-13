import fs from 'node:fs';
import path from 'node:path';

export const CONFIG_FILES = ['.sbom-diff-sentinel.json', '.sbom-diff-sentinelrc.json', '.sbom-diff-sentinelrc'];

export function loadConfig(dir = '.', explicit) {
  const f = explicit || CONFIG_FILES.map((c) => path.join(dir, c)).find((p) => fs.existsSync(p));
  let cfg = {};
  if (f) { try { cfg = JSON.parse(fs.readFileSync(f, 'utf8')); } catch (e) { throw new Error(`Config ${f}: ${e.message}`); } }
  else if (fs.existsSync(path.join(dir, 'package.json'))) { try { cfg = JSON.parse(fs.readFileSync(path.join(dir, 'package.json'), 'utf8'))['sbom-diff-sentinel'] || {}; } catch { /* ignore */ } }
  if (cfg.allowlist && !cfg.allow) cfg.allow = cfg.allowlist;
  delete cfg.allowlist;
  return cfg;
}
