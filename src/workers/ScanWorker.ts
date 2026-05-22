import { Worker, Job } from 'bullmq';
import { getRedisConnection } from '../services/queue/QueueManager';
import { WorkerCrashContainment } from '../services/system/WorkerCrashContainment';
import { startPipeline } from '../services/scan/AutoScanPipeline';
import { logger } from '../utils/logger';

const log = logger.child({ module: 'ScanWorker' });

export function startScanWorker() {
    const redis = getRedisConnection();
    if (!redis) return null;

    const worker = new Worker('scan-orchestration', async (job: Job) => {
        return WorkerCrashContainment.executeSafe('ScanWorker', job, async () => {
            const { scanId, resume } = job.data;
            log.info(`Processing scan orchestration job`, { jobId: job.id, scanId, resume });

            // Depending on the logic in AutoScanPipeline, we execute the pipeline.
            // If resume is true, startPipeline needs logic to resume from checkpoint.
            // For now, it delegates back to AutoScanPipeline's startPipeline.
            await startPipeline(scanId); // We assume AutoScanPipeline handles the resume state internally
            
            return { success: true };
        });
    }, {
        connection: redis,
        concurrency: 3, // Global concurrency limit for scans
    });

    worker.on('failed', (job, err) => {
        log.error(`Scan orchestration job failed`, { jobId: job?.id, error: err.message });
    });

    return worker;
}
