import { planNextActions } from './aiOrchestrator';
import {
  AIAttackAction,
  AttackNode,
  ScanFinding,
  ScanSession,
} from './types';
import { logger } from './utils/logger';
import { ScanRepository } from './services/db/ScanRepository';

/** Validate an endpoint URL for legitimate attack surface */
function isValidEndpointUrl(url: string): boolean {
  try {
    const urlObj = new URL(url);
    const path = urlObj.pathname;

    // Reject malformed / minified patterns
    const malformedPatterns = [
      /:[a-zA-Z_]\w*[:\/]/, // :variable:remaining or :variable/path (suggests parameter)
      /\([^)]*\)/, // Parentheses - function calls in minified code
      /!0|!1/, // Minified boolean literals
      /\b[a-z]{1,2}\([^)]*\)=>/g, // Minified arrow functions
      /={2,}/,  // Encoded equals signs
    ];

    if (malformedPatterns.some(p => p.test(path))) {
      return false;
    }

    // Reject if suspiciously short path (likely minified bundle reference)
    if (path.length < 2) return false;

    // Accept valid URL
    return true;
  } catch {
    return false;
  }
}

export async function createScanSessionAsync(targetUrl: string, orgId?: string, userId?: string): Promise<ScanSession> {
  logger.info(`Creating scan session for ${targetUrl} (Org: ${orgId || 'None'})`);
  return await ScanRepository.createScan(targetUrl, orgId, userId);
}

// Deprecated synchronous version - kept to avoid breaking imports but will throw
export function createScanSession(targetUrl: string): ScanSession {
  throw new Error("Use createScanSessionAsync instead");
}

export async function getScanSession(id: string): Promise<ScanSession | null> {
  return await ScanRepository.getScan(id);
}

export async function listScanSessions(): Promise<ScanSession[]> {
  return await ScanRepository.getAllScans();
}

export async function addAttackNode(session: ScanSession, node: AttackNode): Promise<void> {
  // Validate endpoint URL before adding
  if (!isValidEndpointUrl(node.url)) {
    logger.debug(`Skipping mal formed endpoint: ${node.url}`, { scanId: session.id });
    return;
  }

  // Optimistically update in-memory object for speed
  if (!session.attackNodes[node.id]) {
    // Calculate Risk Score
    const { RiskAnalyzer } = require('./services/strategy/RiskAnalyzer');
    node.riskScore = RiskAnalyzer.calculateNodeRisk(node);

    session.attackNodes[node.id] = node;
    logger.debug(`New attack node discovered: ${node.url} [Risk: ${node.riskScore}]`, { scanId: session.id });
    // Async persist
    await ScanRepository.addNode(session.id, node);
  }
}

export async function addFinding(session: ScanSession, finding: ScanFinding): Promise<void> {
  session.findings.push(finding);
  logger.warn(`Finding detected: ${finding.type} at ${finding.url}`, { scanId: session.id });
  await ScanRepository.addFinding(session.id, finding);
}

export async function runPlanningStep(
  session: ScanSession,
): Promise<AIAttackAction[]> {
  logger.info(`Starting planning step for scan ${session.id}`);
  const actions = await planNextActions(session);
  session.actions.push(...actions);

  await ScanRepository.addActionLog(session.id, actions);

  return actions;
}

export async function updateAuthContext(
  session: ScanSession,
  context: 'guest' | 'userA' | 'userB',
  headers: Record<string, string>
): Promise<void> {
  session.authHeaders[context] = headers;
  logger.info(`Updating auth headers for ${context}`, { scanId: session.id });
  await ScanRepository.updateAuthContext(session.id, context, headers);
}
