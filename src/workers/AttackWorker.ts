import { Worker, Job } from 'bullmq';
import { createWorkerConnection } from '../services/queue/QueueManager';
import { WorkerCrashContainment } from '../services/system/WorkerCrashContainment';
import { executeAction } from '../detectionEngine';
import { getScanSession } from '../scanOrchestrator';
import { logger } from '../utils/logger';

const log = logger.child({ module: 'AttackWorker' });

export function startAttackWorker(): Worker | null {
    // HIGH-2: Dedicated connection per worker
    const redis = createWorkerConnection();
    if (!redis) {
        log.warn('AttackWorker: no Redis connection available, worker not started');
        return null;
    }

    const worker = new Worker('attack-jobs', async (job: Job) => {
        return WorkerCrashContainment.executeSafe('AttackWorker', job, async () => {
            const { scanId, action } = job.data;
            log.info(`AttackWorker: processing job`, { jobId: job.id, actionType: action.actionType });

            const session = await getScanSession(scanId);
            if (!session) throw new Error(`Scan session not found: ${scanId}`);

            await executeAction(session, action);

            return { success: true };
        });
    }, {
        connection: redis,
        concurrency: 5,
    });

    worker.on('completed', (job) => {
        log.info('AttackWorker: job completed', { jobId: job.id, actionType: job.data?.action?.actionType });
    });

    worker.on('failed', (job, err) => {
        log.error('AttackWorker: job failed', {
            jobId: job?.id,
            scanId: job?.data?.scanId,
            actionType: job?.data?.action?.actionType,
            error: err.message,
            stack: err.stack,
        });
    });

    log.info('AttackWorker: started (concurrency=5)');
    return worker;
}
