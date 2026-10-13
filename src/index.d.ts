export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type RuleId = 'new-vulnerability' | 'copyleft-license' | 'hash-changed' | 'too-many-changes' | 'osv-error' | 'downgrade' | 'supplier-changed' | 'license-changed' | 'allowlist-expired' | 'unscanned-component' | 'sbom-warning';
export interface Component { key: string; name: string; version: string | null; purl: string | null; ecosystem: string | null; license: string | null; supplier: string | null; hashes: Record<string, string>; scope: string | null; ref: string | null }
export interface Sbom { format: 'CycloneDX' | 'SPDX'; specVersion: string; name: string | null; components: Component[]; warnings: string[]; file?: string }
export interface Vuln { id: string; aliases: string[]; summary: string; severity: Severity; score: number | null; estimated?: boolean; url: string }
export interface AllowEntry { id?: string; package?: string; rule?: RuleId; reason?: string; expires?: string }
export interface Options {
  failOn?: Severity | 'none'; copyleft?: 'weak' | 'strong' | 'network' | false; maxChanges?: number | null;
  rules?: Partial<Record<RuleId, Severity | 'off'>>; allow?: AllowEntry[]; offline?: boolean; osvUrl?: string; timeout?: number;
  fetchImpl?: typeof fetch; now?: string | Date;
}
export interface Finding { rule: RuleId; severity: Severity; package: string | null; version?: string | null; message: string; fix?: string; id?: string; ids?: string[]; url?: string; from?: string | null; to?: string | null; license?: string }
export interface Report {
  tool: 'sbom-diff-sentinel'; generatedAt: string;
  base: { file: string | null; format: string; specVersion: string; components: number };
  head: { file: string | null; format: string; specVersion: string; components: number };
  diff: { added: any[]; removed: any[]; upgraded: any[]; downgraded: any[]; licenseChanged: any[]; supplierChanged: any[]; hashChanged: any[]; unchanged: number; totals: { base: number; head: number; changes: number } };
  vulnerabilities: { status: string; new: (Vuln & { package: string; version: string })[]; fixed: (Vuln & { package: string; version: string; removed: boolean })[]; persisting: (Vuln & { package: string; version: string })[] };
  findings: Finding[]; suppressed: (Finding & { allow: { reason: string | null; expires: string | null } })[]; counts: Record<Severity, number>;
}
export function parseSbom(input: string | object, source?: string): Sbom;
export function readSbom(file: string): Sbom;
export function generateSbom(dir: string, options?: { includeDev?: boolean }): Sbom & { doc: object };
export function generateSbomAtRef(dir: string, ref: string, options?: { includeDev?: boolean }): Sbom & { doc: object };
export function generateCycloneDX(dir: string, options?: { includeDev?: boolean }): object;
export function diffSboms(base: Sbom, head: Sbom): Report['diff'] & Record<string, any>;
export function lookupVulns(components: Component[], options?: { url?: string; fetchImpl?: typeof fetch; timeout?: number; concurrency?: number }): Promise<{ byComponent: Map<Component, Vuln[]>; unscanned: Component[] }>;
export function analyze(base: Sbom, head: Sbom, options?: Options): Promise<Report>;
export function exitCode(report: Report, failOn?: Severity | 'none'): 0 | 1;
export function compareVersions(a: string, b: string): -1 | 0 | 1;
export function categoryOf(spdxExpression: string | null): string;
export function cvss3Score(vector: string): number | null;
export function formatText(report: Report, options?: { color?: boolean; fixes?: boolean; summaryOnly?: boolean }): string;
export function formatJson(report: Report): string;
export function formatSarif(report: Report, version?: string): string;
export function formatMarkdown(report: Report, options?: { maxRows?: number }): string;
export const OSV_URL: string;
export const SEVERITIES: Severity[];
export const RULES: Record<RuleId, { severity: Severity | 'vuln'; title: string }>;
