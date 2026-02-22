import { AIAttackAction, ScanSession } from './types';
import { AIFactory } from './services/ai/AIFactory';
import { logger } from './utils/logger';

/**
 * Orchestrates AI planning by delegating to the configured provider.
 */
export async function planNextActions(
  session: ScanSession,
  maxActions: number = 3,
): Promise<AIAttackAction[]> {
  try {
    const provider = AIFactory.createProvider();
    return await provider.planNextActions(session, maxActions);
  } catch (error) {
    logger.error('Failed to plan next actions', { error, scanId: session.id });
    return [];
  }
}
