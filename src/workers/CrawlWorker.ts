import { Worker, Job } from 'bullmq';
import { getRedisConnection } from '../services/queue/QueueManager';
import { WorkerCrashContainment } from '../services/system/WorkerCrashContainment';
import { crawlTarget } from '../crawler';
import { getScanSession } from '../scanOrchestrator';
import { logger } from '../utils/logger';

const log = logger.child({ module: 'CrawlWorker' });

export function startCrawlWorker() {
    const redis = getRedisConnection();
    if (!redis) return null;

    const worker = new Worker('crawl-jobs', async (job: Job) => {
        return WorkerCrashContainment.executeSafe('CrawlWorker', job, async () => {
            const { scanId } = job.data;
            log.info(`Processing crawl job for scan ${scanId}`, { jobId: job.id });
            
            const session = await getScanSession(scanId);
            if (!session) throw new Error(`Scan session not found: ${scanId}`);

            // Execute isolated crawl
            await crawlTarget(session, 'guest', { maxPages: 15 }); // config or job data could override
            
            return { success: true, nodesFound: Object.keys(session.attackNodes).length };
        });
    }, {
        connection: redis,
        concurrency: 2, // Bounded concurrency
    });

    worker.on('failed', (job, err) => {
        log.error(`Crawl job failed`, { jobId: job?.id, error: err.message });
    });

    return worker;
}
