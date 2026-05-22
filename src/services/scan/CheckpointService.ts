import { PrismaClient } from '@prisma/client';
import { logger } from '../../utils/logger';
import { ScanSession } from '../../types';

const log = logger.child({ module: 'CheckpointService' });
const prisma = new PrismaClient();

export class CheckpointService {
    static async saveCheckpoint(
        scanId: string,
        phase: string,
        phaseIndex: number,
        completedNodes: string[],
        session: ScanSession
    ): Promise<void> {
        try {
            await prisma.scanCheckpoint.create({
                data: {
                    scanId,
                    phase,
                    phaseIndex,
                    completedNodes: JSON.stringify(completedNodes),
                    coverageSnapshot: JSON.stringify(session.coverageMetrics || {}),
                }
            });
            log.info(`Checkpoint saved`, { scanId, phase, phaseIndex });
        } catch (error) {
            log.error(`Failed to save checkpoint`, { scanId, error: error instanceof Error ? error.message : String(error) });
        }
    }

    static async getLatestCheckpoint(scanId: string) {
        return await prisma.scanCheckpoint.findFirst({
            where: { scanId },
            orderBy: { createdAt: 'desc' },
        });
    }
}
