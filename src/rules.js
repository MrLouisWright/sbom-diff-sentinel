export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
export const RANK = { critical: 5, high: 4, medium: 3, low: 2, info: 1, none: 99 };

export const RULES = {
  'new-vulnerability': { severity: 'vuln', title: 'Added or changed component has a known vulnerability not present in the base' },
  'copyleft-license': { severity: 'high', title: 'New component or license change introduces a copyleft license' },
  'hash-changed': { severity: 'high', title: 'Same component version has a different hash (possible tampering or republish)' },
  'too-many-changes': { severity: 'high', title: 'More dependency changes than the configured maximum' },
  'osv-error': { severity: 'high', title: 'Vulnerability lookup failed' },
  downgrade: { severity: 'medium', title: 'Component was downgraded' },
  'supplier-changed': { severity: 'medium', title: 'Component supplier changed' },
  'license-changed': { severity: 'low', title: 'Component license changed' },
  'allowlist-expired': { severity: 'low', title: 'An allowlist entry has expired' },
  'unscanned-component': { severity: 'info', title: 'Component could not be checked for vulnerabilities (no purl or version)' },
  'sbom-warning': { severity: 'info', title: 'SBOM parsing warning' },
};
