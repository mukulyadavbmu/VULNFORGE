/**
 * Phase 8 Part 1 — EscalationTracker
 * Tracks escalation level per endpoint+attackType pair.
 * Memory Map with optional Prisma persistence.
 */
import { EscalationRecord } from '../../strategy.types';
import { strategyFlags } from '../../strategyConfig';
import { logger } from '../../utils/logger';

const log = logger.child({ module: 'EscalationTracker' });

/** Max escalation level */
const MAX_LEVEL = 4;

/** Escalation thresholds — number of probes before auto-escalation */
const ESCALATION_THRESHOLDS: Record<number, number> = {
    1: 2,  // After 2 level-1 probes, escalate to 2
    2: 2,  // After 2 level-2 probes, escalate to 3
    3: 1,  // After 1 level-3 probe, escalate to 4
};

export class EscalationTracker {
    private records: Map<string, EscalationRecord> = new Map();
    private probeCount: Map<string, number> = new Map();

    private key(endpointId: string, attackType: string): string {
        return `${endpointId}::${attackType}`;
    }

    /** Get current escalation level. Returns 1 if not tracked. */
    getLevel(endpointId: string, attackType: string): 1 | 2 | 3 | 4 {
        if (!strategyFlags.ENABLE_ESCALATION_TRACKER) return 1;
        const record = this.records.get(this.key(endpointId, attackType));
        return record?.currentLevel ?? 1;
    }

    /** Increment escalation level. Returns new level. */
    incrementLevel(endpointId: string, attackType: string, reason: string): 1 | 2 | 3 | 4 {
        if (!strategyFlags.ENABLE_ESCALATION_TRACKER) return 1;

        const k = this.key(endpointId, attackType);
        const existing = this.records.get(k);
        const currentLevel = existing?.currentLevel ?? 1;

        if (currentLevel >= MAX_LEVEL) return MAX_LEVEL as 4;

        const newLevel = Math.min(currentLevel + 1, MAX_LEVEL) as 1 | 2 | 3 | 4;

        const record: EscalationRecord = {
            endpointId,
            attackType,
            currentLevel: newLevel,
            lastEscalatedAt: Date.now(),
            reason,
        };

        this.records.set(k, record);

        log.info('Escalation incremented', {
            event: 'strategy.escalation',
            endpointId,
            attackType,
            fromLevel: currentLevel,
            toLevel: newLevel,
            reason,
        });

        return newLevel;
    }

    /** Determine if escalation should occur based on probe count at current level. */
    shouldEscalate(endpointId: string, attackType: string): boolean {
        if (!strategyFlags.ENABLE_ESCALATION_TRACKER) return false;

        const k = this.key(endpointId, attackType);
        const currentLevel = this.getLevel(endpointId, attackType);

        if (currentLevel >= MAX_LEVEL) return false;

        const count = (this.probeCount.get(k) ?? 0) + 1;
        this.probeCount.set(k, count);

        const threshold = ESCALATION_THRESHOLDS[currentLevel] ?? 2;
        return count >= threshold;
    }

    /** Record a probe execution (increments probe count for escalation logic). */
    recordProbe(endpointId: string, attackType: string): void {
        const k = this.key(endpointId, attackType);
        const count = (this.probeCount.get(k) ?? 0) + 1;
        this.probeCount.set(k, count);
    }

    /** Get full record for explainability. */
    getRecord(endpointId: string, attackType: string): EscalationRecord | null {
        return this.records.get(this.key(endpointId, attackType)) ?? null;
    }

    /** Get all records (for inspection/debugging). */
    getAllRecords(): EscalationRecord[] {
        return Array.from(this.records.values());
    }
}
