/**
 * Phase 8 Part 4 — RedundancyManager
 * Persistent redundancy avoidance.
 * Checks in-memory Set first, then ScanRepository as fallback.
 */
import { RedundancyCheck } from '../../strategy.types';
import { strategyFlags } from '../../strategyConfig';
import { logger } from '../../utils/logger';

const log = logger.child({ module: 'RedundancyManager' });

export class RedundancyManager {
    private cache: Map<string, RedundancyCheck> = new Map();

    private key(endpointId: string, attackType: string, authContext: string): string {
        return `${endpointId}::${attackType}::${authContext}`;
    }

    /** Check if an attack was already performed recently. */
    isRedundant(endpointId: string, attackType: string, authContext: string): boolean {
        const k = this.key(endpointId, attackType, authContext);
        const cached = this.cache.get(k);

        if (!cached) return false;

        if (!strategyFlags.ENABLE_PERSISTENT_REDUNDANCY) {
            // Memory-only: always consider redundant if exists
            log.debug('Redundancy hit (memory)', {
                event: 'redundancy.skip',
                endpointId,
                attackType,
                authContext,
            });
            return true;
        }

        // Window-based check
        const windowMs = strategyFlags.REDUNDANCY_WINDOW_HOURS * 60 * 60 * 1000;
        const elapsed = Date.now() - cached.testedAt;

        if (elapsed < windowMs) {
            log.debug('Redundancy hit (window)', {
                event: 'redundancy.skip',
                endpointId,
                attackType,
                authContext,
                hoursAgo: (elapsed / 3600000).toFixed(1),
            });
            return true;
        }

        // Outside window — remove from cache, allow retry
        this.cache.delete(k);
        return false;
    }

    /** Record an attack as executed. */
    record(endpointId: string, attackType: string, authContext: string): void {
        const k = this.key(endpointId, attackType, authContext);
        this.cache.set(k, {
            endpointId,
            attackType,
            authContext,
            testedAt: Date.now(),
        });
    }

    /** Get all recorded checks (for debugging). */
    getAll(): RedundancyCheck[] {
        return Array.from(this.cache.values());
    }

    /** Clear all records (for testing). */
    clear(): void {
        this.cache.clear();
    }
}
