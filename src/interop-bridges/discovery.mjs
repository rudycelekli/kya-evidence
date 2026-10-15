import { gate, checkOptions, isQualified, LIMITS, checkUrl } from './gate.mjs';

export const A2A_EXTENSION_URI = 'urn:kya:extension:assessment:v1';
// Unregistered placeholder key for MCP _meta, in the reverse-DNS style the MCP convention asks for. Replace once a registry exists.
export const MCP_META_KEY = 'dev.kya-evidence/assessment';
const CURRENCY_HOW = 'Run the KYA currency check (kya.currency/v1) yourself with your own manifest, policy, incidents and clock. The values here are the exporter result at checkedAt and are not proof.';

export function buildPointer(r, c, url) {
  return {
    assessmentDigest: r.reportDigest, subjectDigest: r.subjectDigest, decision: r.decision, qualified: isQualified(r, c),
    evidenceMode: r.evidenceMode, validUntil: r.validUntil,
    currencyCheck: { schema: 'kya.currency/v1', asOfExport: { checked: c.checked, current: c.current, checkedAt: c.checkedAt, triggerCodes: [...c.triggerCodes], digest: c.digest, overrides: [...c.overrides] }, how: CURRENCY_HOW },
    ...(url ? { assessmentUrl: url } : {}),
    authorizationGranted: false, limits: [...LIMITS]
  };
}
export const buildA2aExtension = (r, c, url) => ({ uri: A2A_EXTENSION_URI, description: 'Pointer to a KYA assessment of this agent configuration and its currency check. Not an authorization grant.', required: false, params: buildPointer(r, c, url) });
export const buildMcpMeta = (r, c, url) => ({ _meta: { [MCP_META_KEY]: buildPointer(r, c, url) } });
const urlOption = options => options.assessmentUrl === undefined ? undefined : checkUrl(options.assessmentUrl, 'assessmentUrl');

/**
 * An entry for the extensions array of an A2A agent card capabilities object (AgentExtension: uri, description, required, params).
 * required is always false so a client that does not understand it is not blocked. The URL, when given, is a hint only; the digest
 * is what binds. Nothing is fetched.
 */
export function exportA2aExtension(assessment, options = {}) {
  checkOptions(options, ['assessmentUrl']);
  const url = urlOption(options);
  const { report, currency } = gate(assessment, options);
  return buildA2aExtension(report, currency, url);
}

/** A members object for MCP server or tool _meta, keyed by MCP_META_KEY. Same pointer content as the A2A extension. */
export function exportMcpMeta(assessment, options = {}) {
  checkOptions(options, ['assessmentUrl']);
  const url = urlOption(options);
  const { report, currency } = gate(assessment, options);
  return buildMcpMeta(report, currency, url);
}
