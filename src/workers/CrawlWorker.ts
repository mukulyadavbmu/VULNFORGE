import { Worker, Job } from 'bullmq';
import { createWorkerConnection } from '../services/queue/QueueManager';
import { WorkerCrashContainment } from '../services/system/WorkerCrashContainment';
import { crawlTarget } from '../crawler';
import { getScanSession } from '../scanOrchestrator';
import { logger } from '../utils/logger';

const log = logger.child({ module: 'CrawlWorker' });

export function startCrawlWorker(): Worker | null {
    // HIGH-2: Dedicated connection per worker
    const redis = createWorkerConnection();
    if (!redis) {
        log.warn('CrawlWorker: no Redis connection available, worker not started');
        return null;
    }

    const worker = new Worker('crawl-jobs', async (job: Job) => {
        return WorkerCrashContainment.executeSafe('CrawlWorker', job, async () => {
            const { scanId } = job.data;
            log.info(`CrawlWorker: processing job`, { jobId: job.id, scanId });

            const session = await getScanSession(scanId);
            if (!session) throw new Error(`Scan session not found: ${scanId}`);

            await crawlTarget(session, 'guest', { maxPages: 15 });

            return { success: true, nodesFound: Object.keys(session.attackNodes).length };
        });
    }, {
        connection: redis,
        concurrency: 2,
    });

    worker.on('completed', (job) => {
        log.info('CrawlWorker: job completed', { jobId: job.id, scanId: job.data.scanId });
    });

    worker.on('failed', (job, err) => {
        log.error('CrawlWorker: job failed', {
            jobId: job?.id,
            scanId: job?.data?.scanId,
            error: err.message,
            stack: err.stack,
        });
    });

    log.info('CrawlWorker: started (concurrency=2)');
    return worker;
}
