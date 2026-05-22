import { Worker, Job } from 'bullmq';
import { getRedisConnection } from '../services/queue/QueueManager';
import { WorkerCrashContainment } from '../services/system/WorkerCrashContainment';
import { executeAction } from '../detectionEngine';
import { getScanSession } from '../scanOrchestrator';
import { logger } from '../utils/logger';

const log = logger.child({ module: 'AttackWorker' });

export function startAttackWorker() {
    const redis = getRedisConnection();
    if (!redis) return null;

    const worker = new Worker('attack-jobs', async (job: Job) => {
        return WorkerCrashContainment.executeSafe('AttackWorker', job, async () => {
            const { scanId, action } = job.data;
            log.info(`Processing attack job`, { jobId: job.id, actionType: action.actionType });

            const session = await getScanSession(scanId);
            if (!session) throw new Error(`Scan session not found: ${scanId}`);

            // Budget enforcement happens inside executeAction already (Phase 2),
            // but we are executing in an isolated context here.
            await executeAction(session, action);
            
            return { success: true };
        });
    }, {
        connection: redis,
        concurrency: 5, // Bounded concurrency for attacks
    });

    worker.on('failed', (job, err) => {
        log.error(`Attack job failed`, { jobId: job?.id, error: err.message });
    });

    return worker;
}
