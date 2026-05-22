/**
 * HypothesisRepository — Persistent hypothesis storage via Prisma.
 *
 * Stores, updates, and queries attack hypotheses per scan.
 * Supports confidence updates and testing timestamps.
 * Additive — does not modify existing modules.
 */
import { PrismaClient } from '@prisma/client';
import { logger } from '../../utils/logger';

const log = logger.child({ module: 'HypothesisRepository' });
const prisma = new PrismaClient();

export interface CreateHypothesisInput {
    scanId: string;
    type: string;
    description: string;
    confidence: number;
    status?: string;
}

export interface StoredHypothesis {
    id: string;
    scanId: string;
    type: string;
    description: string;
    confidence: number;
    status: string;
    lastTested: Date | null;
    createdAt: Date;
}

export class HypothesisRepository {
    /**
     * Create a new persistent hypothesis.
     */
    async createHypothesis(input: CreateHypothesisInput): Promise<StoredHypothesis> {
        const hypothesis = await prisma.hypothesis.create({
            data: {
                scanId: input.scanId,
                type: input.type,
                description: input.description,
                confidence: Math.max(0, Math.min(100, input.confidence)),
                status: input.status ?? 'active',
            },
        });

        log.info('Hypothesis persisted', {
            id: hypothesis.id,
            scanId: hypothesis.scanId,
            type: hypothesis.type,
            confidence: hypothesis.confidence,
        });

        return hypothesis;
    }

    /**
     * Update the confidence of an existing hypothesis.
     */
    async updateConfidence(hypothesisId: string, confidence: number): Promise<StoredHypothesis> {
        const clamped = Math.max(0, Math.min(100, confidence));

        const hypothesis = await prisma.hypothesis.update({
            where: { id: hypothesisId },
            data: { confidence: clamped },
        });

        log.debug('Hypothesis confidence updated', {
            id: hypothesisId,
            confidence: clamped,
        });

        return hypothesis;
    }

    /**
     * Mark a hypothesis as tested (sets lastTested and optionally updates status).
     */
    async markTested(
        hypothesisId: string,
        status?: 'confirmed' | 'dismissed' | 'tested',
    ): Promise<StoredHypothesis> {
        const hypothesis = await prisma.hypothesis.update({
            where: { id: hypothesisId },
            data: {
                lastTested: new Date(),
                ...(status ? { status } : {}),
            },
        });

        log.debug('Hypothesis marked tested', {
            id: hypothesisId,
            status: hypothesis.status,
        });

        return hypothesis;
    }

    /**
     * Get all active hypotheses for a scan.
     */
    async getActiveHypotheses(scanId: string): Promise<StoredHypothesis[]> {
        return prisma.hypothesis.findMany({
            where: {
                scanId,
                status: 'active',
            },
            orderBy: { confidence: 'desc' },
        });
    }

    /**
     * Get all hypotheses for a scan (any status).
     */
    async getAllHypotheses(scanId: string): Promise<StoredHypothesis[]> {
        return prisma.hypothesis.findMany({
            where: { scanId },
            orderBy: { createdAt: 'desc' },
        });
    }

    /**
     * Update status of a hypothesis (active → confirmed/dismissed).
     */
    async updateStatus(
        hypothesisId: string,
        status: 'active' | 'confirmed' | 'dismissed' | 'tested',
    ): Promise<StoredHypothesis> {
        return prisma.hypothesis.update({
            where: { id: hypothesisId },
            data: { status },
        });
    }
}
