import { AIAttackAction, ScanSession } from '../../types';

export interface AIProvider {
    /**
     * Generates a structural plan for the next attacks.
     */
    planNextActions(session: ScanSession, maxActions?: number): Promise<AIAttackAction[]>;

    /**
     * Returns the provider name and model for logging.
     */
    getMetaData(): { provider: string; model: string };
}
