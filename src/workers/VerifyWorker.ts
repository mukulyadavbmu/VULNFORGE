import { Worker, Job } from 'bullmq';
import { createWorkerConnection } from '../services/queue/QueueManager';
import { WorkerCrashContainment } from '../services/system/WorkerCrashContainment';
import { ExploitVerifier } from '../services/intelligence/ExploitVerifier';
import { defaultExploitExecutor } from '../services/intelligence/DefaultExploitExecutor';
import { getScanSession } from '../scanOrchestrator';
import { JobFingerprint } from '../services/queue/JobFingerprint';
import { logger } from '../utils/logger';

const log = logger.child({ module: 'VerifyWorker' });

export function startVerifyWorker(): Worker | null {
    // HIGH-2: Dedicated connection per worker
    const redis = createWorkerConnection();
    if (!redis) {
        log.warn('VerifyWorker: no Redis connection available, worker not started');
        return null;
    }

    const verifier = new ExploitVerifier(defaultExploitExecutor);

    const worker = new Worker('verify-jobs', async (job: Job) => {
        return WorkerCrashContainment.executeSafe('VerifyWorker', job, async () => {
            const { scanId, findingId, traceSnapshot, frozenAuth } = job.data;

            // Deduplication check
            const isDup = await JobFingerprint.isReplayDuplicate(scanId, findingId);
            if (isDup) {
                log.info('VerifyWorker: skipping duplicate verification job', { jobId: job.id, findingId });
                return { skipped: true, reason: 'duplicate' };
            }

            log.info('VerifyWorker: processing job', { jobId: job.id, findingId });

            const session = await getScanSession(scanId);
            if (!session) throw new Error(`Scan session not found: ${scanId}`);

            const result = await verifier.verify(traceSnapshot);

            const finding = session.findings.find(f => f.id === findingId);
            if (finding) {
                finding.reliabilityTier = result.reliabilityTier;
                finding.replayStatus = result.reproducible ? 'success' : 'failed';
                finding.verificationHistory = finding.verificationHistory || [];
                finding.verificationHistory.push({
                    timestamp: Date.now(),
                    result: result.reproducible ? 'success' : 'failure',
                    diffScore: result.confidence
                });
            }

            return { success: result.reproducible };
        });
    }, {
        connection: redis,
        concurrency: 2, // Verification is browser-heavy, keep concurrency low
    });

    worker.on('completed', (job) => {
        log.info('VerifyWorker: job completed', { jobId: job.id, findingId: job.data.findingId });
    });

    worker.on('failed', (job, err) => {
        log.error('VerifyWorker: job failed', {
            jobId: job?.id,
            findingId: job?.data?.findingId,
            error: err.message,
            stack: err.stack,
        });
    });

    log.info('VerifyWorker: started (concurrency=2)');
    return worker;
}
