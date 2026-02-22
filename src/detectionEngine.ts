import {
  AIAttackAction,
  ScanSession,
} from './types';
import { handlers } from './attacks/handlers';
import { logger } from './utils/logger';
import { ScanRepository } from './services/db/ScanRepository';

// Type execution registry
type HandlerKey = keyof typeof handlers;

export async function executeAction(
  session: ScanSession,
  action: AIAttackAction,
): Promise<void> {
  const node = session.attackNodes[action.targetNodeId];
  if (!node) return;

  const url = node.url;
  const handlerName = action.actionType as HandlerKey;

  if (handlers[handlerName]) {
    try {
      await handlers[handlerName](session, action, url);

      // Persist execution result if available
      if (action.result) {
        await ScanRepository.logExecutionResult(session.id, action.id, action.result);
        logger.debug(`Logged execution result for action ${action.id}`, { scanId: session.id });
      }

    } catch (error) {
      logger.error(`Error executing action ${action.actionType}`, { error, actionId: action.id });
    }
  } else {
    logger.warn(`No handler found for action type: ${action.actionType}`, { scanId: session.id });
  }
}
