import {
  AIAttackAction,
  ScanSession,
  BudgetUsage,
} from './types';
import { handlers } from './attacks/handlers';
import { logger } from './utils/logger';
import { ScanRepository } from './services/db/ScanRepository';
import { ScanProgressService } from './services/scan/ScanProgressService';

// Type execution registry
type HandlerKey = keyof typeof handlers;

// ─── Budget Enforcement ──────────────────────────────────────────────────────

function getOrInitBudgetUsage(session: ScanSession, nodeId: string): BudgetUsage {
  if (!session.budgetUsage) session.budgetUsage = {};
  if (!session.budgetUsage[nodeId]) {
    session.budgetUsage[nodeId] = {
      mutationsUsed: 0,
      replaysUsed: 0,
      roleTransitionsUsed: 0,
      verificationRetriesUsed: 0,
    };
  }
  return session.budgetUsage[nodeId];
}

/**
 * Returns true if the action is allowed within the node's fuzz budget.
 * Logs a suppression diagnostic and returns false if budget is exhausted.
 */
function checkAndConsumeActionBudget(
  session: ScanSession,
  action: AIAttackAction,
  nodeId: string,
): boolean {
  const node = session.attackNodes[nodeId];
  if (!node?.fuzzBudget) return true; // No budget defined → allow

  const usage = getOrInitBudgetUsage(session, nodeId);
  const budget = node.fuzzBudget;

  // Mutation budget
  if (usage.mutationsUsed >= budget.mutations) {
    logDiagnostic(session, 'warn',
      `Budget exhausted: mutations for ${node.url}`,
      'budget_exhausted',
      { nodeId, mutationsUsed: usage.mutationsUsed, limit: budget.mutations, action: action.actionType }
    );
    incrementSkippedMetric(session, 'budget_exhausted');
    return false;
  }

  // Role transition budget (applies to cross-role attack types)
  const isRoleTransitionAction = ['cross_role_access', 'repeat_as_guest', 'id_tamper'].includes(action.actionType);
  if (isRoleTransitionAction && usage.roleTransitionsUsed >= budget.maxRoleTransitions) {
    logDiagnostic(session, 'warn',
      `Budget exhausted: role transitions for ${node.url}`,
      'role_transition_limit_reached',
      { nodeId, roleTransitionsUsed: usage.roleTransitionsUsed, limit: budget.maxRoleTransitions, action: action.actionType }
    );
    incrementSkippedMetric(session, 'role_transition_limit_reached');
    return false;
  }

  // Consume mutation slot
  usage.mutationsUsed++;
  if (isRoleTransitionAction) usage.roleTransitionsUsed++;

  return true;
}

// ─── Main Execution ──────────────────────────────────────────────────────────

export async function executeAction(
  session: ScanSession,
  action: AIAttackAction,
): Promise<void> {
  const node = session.attackNodes[action.targetNodeId];
  if (!node) return;

  const url = node.url;
  const handlerName = action.actionType as HandlerKey;

  if (!handlers[handlerName]) {
    logDiagnostic(session, 'warn', `No handler found for action type: ${action.actionType}`, 'missing_handler');
    incrementSkippedMetric(session, 'missing_handler');
    return;
  }

  // Guard: low relevance endpoint with exhausted mutation budget
  if (node.priorityScore !== undefined && node.priorityScore < 20 &&
      node.fuzzBudget && node.fuzzBudget.mutations <= 0) {
    logDiagnostic(session, 'info', `Skipping attack ${action.actionType} on ${url}`, 'low_endpoint_relevance');
    incrementSkippedMetric(session, 'low_endpoint_relevance');
    return;
  }

  // Guard: deep probes on shallow-only nodes
  if (action.actionType.includes('probe') && node.attackDepthLevel === 1) {
    logDiagnostic(session, 'info', `Skipping deep probe ${action.actionType} on ${url}`, 'insufficient_depth_level');
    incrementSkippedMetric(session, 'insufficient_depth_level');
    return;
  }

  // Guard: auth propagation check — warn if required role is unconfigured
  const requiresAuth = !['repeat_as_guest', 'cors_probe', 'config_probe', 'anomaly_probe'].includes(action.actionType);
  if (requiresAuth && Object.keys(session.authHeaders['userA'] ?? {}).length === 0) {
    logDiagnostic(session, 'warn', `Auth propagation failure for ${action.actionType} on ${url}`, 'auth_propagation_failure',
      { missingRole: 'userA', action: action.actionType }
    );
  }

  // Guard: budget enforcement
  if (!checkAndConsumeActionBudget(session, action, action.targetNodeId)) {
    return;
  }

  try {
    const shortUrl = url.length > 60 ? `${url.slice(0, 57)}...` : url;
    ScanProgressService.addEvent(
      session.id,
      `⚡ Attack: ${action.actionType} on ${shortUrl}`,
      'attack',
    );

    await handlers[handlerName](session, action, url);

    // Track success metrics
    incrementExecutionMetric(session, true);

    // Persist execution result if available
    if (action.result) {
      await ScanRepository.logExecutionResult(session.id, action.id, action.result);
      logger.debug(`Logged execution result for action ${action.id}`, { scanId: session.id });

      if (action.result.success) {
        ScanProgressService.addEvent(
          session.id,
          `✓ Attack completed: ${action.actionType} (status: ${action.result.status})`,
          'success',
        );
      }
    }

  } catch (error) {
    incrementExecutionMetric(session, false);
    logger.error(`Error executing action ${action.actionType}`, { error, actionId: action.id });
    const msg = error instanceof Error ? error.message.slice(0, 80) : 'Unknown error';
    ScanProgressService.addEvent(
      session.id,
      `✗ Attack failed: ${action.actionType} - ${msg}`,
      'warning',
    );
  }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

export function logDiagnostic(
  session: ScanSession,
  level: 'info' | 'warn' | 'error',
  event: string,
  reason?: string,
  details?: any
) {
  if (!session.diagnosticsLogs) session.diagnosticsLogs = [];
  session.diagnosticsLogs.push({ timestamp: Date.now(), level, event, reason, details });
  if (level === 'error') {
    logger.error(`[DIAGNOSTIC] ${event}`, { reason, details, scanId: session.id });
  } else if (level === 'warn') {
    logger.warn(`[DIAGNOSTIC] ${event}`, { reason, details, scanId: session.id });
  } else {
    logger.info(`[DIAGNOSTIC] ${event}`, { reason, details, scanId: session.id });
  }
}

function incrementSkippedMetric(session: ScanSession, reason: string) {
  if (!session.coverageMetrics) initializeCoverageMetrics(session);
  const metrics = session.coverageMetrics!;
  metrics.skippedAttacks[reason] = (metrics.skippedAttacks[reason] ?? 0) + 1;
}

function incrementExecutionMetric(session: ScanSession, success: boolean) {
  if (!session.coverageMetrics) initializeCoverageMetrics(session);
  const metrics = session.coverageMetrics!;
  if (success) {
    metrics.attackSuccessCount++;
  } else {
    metrics.attackFailureCount++;
  }
}

export function initializeCoverageMetrics(session: ScanSession) {
  if (!session.coverageMetrics) {
    session.coverageMetrics = {
      totalEndpoints: 0,
      endpointsCovered: 0,
      authBoundariesTested: 0,
      rolesTested: 0,
      totalPrivilegeTransitions: 0,
      endpointsDiscovered: Object.keys(session.attackNodes).length,
      endpointsAttacked: 0,
      authenticatedEndpointsTested: 0,
      roleTestedEndpoints: 0,
      parametersFuzzed: 0,
      attackSuccessCount: 0,
      attackFailureCount: 0,
      replayAttempts: 0,
      replaySuccesses: 0,
      skippedAttacks: {},
      failedVerifications: {},
    };
  }
}

/**
 * Increment replay tracking metrics on the session.
 * Called by ExploitVerifier after a replay run.
 */
export function trackReplayMetric(session: ScanSession, success: boolean) {
  if (!session.coverageMetrics) initializeCoverageMetrics(session);
  session.coverageMetrics!.replayAttempts++;
  if (success) session.coverageMetrics!.replaySuccesses++;
}
