/**
 * RedundancyGuard — Prevents repeating attacks at multiple granularity levels.
 * Checks: endpoint + attack type + payload class + auth role.
 * Uses in-memory Map with configurable time window.
 */
import { strategyFlags } from '../../strategyConfig';
import { logger } from '../../utils/logger';

const log = logger.child({ module: 'RedundancyGuard' });

interface GuardEntry {
    endpointId: string;
    attackType: string;
    payloadClass: string;
    authRole: string;
    testedAt: number;
    findingId?: string;
}

export class RedundancyGuard {
    private entries: Map<string, GuardEntry> = new Map();

    private key(
        endpointId: string,
        attackType: string,
        payloadClass: string,
        authRole: string,
    ): string {
        return `${endpointId}::${attackType}::${payloadClass}::${authRole}`;
    }

    /**
     * Check if this exact attack combination was already tested.
     * Respects REDUNDANCY_WINDOW_HOURS — attacks outside window are allowed.
     */
    isDuplicate(
        endpointId: string,
        attackType: string,
        payloadClass: string,
        authRole: string,
    ): boolean {
        const k = this.key(endpointId, attackType, payloadClass, authRole);
        const entry = this.entries.get(k);

        if (!entry) return false;

        const windowMs = strategyFlags.REDUNDANCY_WINDOW_HOURS * 60 * 60 * 1000;
        const elapsed = Date.now() - entry.testedAt;

        if (elapsed < windowMs) {
            log.debug('Attack skipped — redundant', {
                event: 'redundancy.skip',
                endpointId,
                attackType,
                payloadClass,
                authRole,
                hoursAgo: (elapsed / 3600000).toFixed(1),
            });
            return true;
        }

        // Outside window — remove stale entry, allow retry
        this.entries.delete(k);
        return false;
    }

    /**
     * Record an attack as executed.
     */
    record(
        endpointId: string,
        attackType: string,
        payloadClass: string,
        authRole: string,
        findingId?: string,
    ): void {
        const k = this.key(endpointId, attackType, payloadClass, authRole);
        this.entries.set(k, {
            endpointId,
            attackType,
            payloadClass,
            authRole,
            testedAt: Date.now(),
            findingId,
        });
    }

    /**
     * Check if ANY attack of this type was run on this endpoint (any payload/role).
     * Lighter check for broad dedup.
     */
    hasTestedType(endpointId: string, attackType: string): boolean {
        for (const entry of this.entries.values()) {
            if (entry.endpointId === endpointId && entry.attackType === attackType) {
                const windowMs = strategyFlags.REDUNDANCY_WINDOW_HOURS * 60 * 60 * 1000;
                if (Date.now() - entry.testedAt < windowMs) return true;
            }
        }
        return false;
    }

    /**
     * Get count of tests run on an endpoint (within window).
     */
    getTestCount(endpointId: string): number {
        const windowMs = strategyFlags.REDUNDANCY_WINDOW_HOURS * 60 * 60 * 1000;
        const now = Date.now();
        let count = 0;
        for (const entry of this.entries.values()) {
            if (entry.endpointId === endpointId && now - entry.testedAt < windowMs) {
                count++;
            }
        }
        return count;
    }

    /** Clear all entries (for testing). */
    clear(): void {
        this.entries.clear();
    }

    /** Get total recorded entries. */
    size(): number {
        return this.entries.size;
    }
}
