import { Worker, Job } from 'bullmq';
import { createWorkerConnection } from '../services/queue/QueueManager';
import { WorkerCrashContainment } from '../services/system/WorkerCrashContainment';
import { startPipeline } from '../services/scan/AutoScanPipeline';
import { logger } from '../utils/logger';

const log = logger.child({ module: 'ScanWorker' });

export function startScanWorker(): Worker | null {
    // HIGH-2: Dedicated connection — workers must NOT share the producer connection.
    // BullMQ uses blocking commands (BLPOP) on worker connections that conflict
    // with non-blocking producer commands when sharing a single ioredis instance.
    const redis = createWorkerConnection();
    if (!redis) {
        log.warn('ScanWorker: no Redis connection available, worker not started');
        return null;
    }

    const worker = new Worker('scan-orchestration', async (job: Job) => {
        return WorkerCrashContainment.executeSafe('ScanWorker', job, async () => {
            const { scanId, resume } = job.data;
            log.info(`ScanWorker: processing job`, { jobId: job.id, scanId, resume });
            await startPipeline(scanId);
            return { success: true };
        });
    }, {
        connection: redis,
        concurrency: 3,
    });

    worker.on('completed', (job) => {
        log.info('ScanWorker: job completed', { jobId: job.id, scanId: job.data.scanId });
    });

    worker.on('failed', (job, err) => {
        log.error('ScanWorker: job failed', {
            jobId: job?.id,
            scanId: job?.data?.scanId,
            error: err.message,
            stack: err.stack,
        });
    });

    log.info('ScanWorker: started (concurrency=3)');
    return worker;
}
