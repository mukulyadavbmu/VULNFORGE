import { Worker, Job } from 'bullmq';
import { getRedisConnection } from '../services/queue/QueueManager';
import { WorkerCrashContainment } from '../services/system/WorkerCrashContainment';
import { ExploitVerifier } from '../services/intelligence/ExploitVerifier';
import { defaultExploitExecutor } from '../services/intelligence/DefaultExploitExecutor';
import { getScanSession } from '../scanOrchestrator';
import { JobFingerprint } from '../services/queue/JobFingerprint';
import { logger } from '../utils/logger';

const log = logger.child({ module: 'VerifyWorker' });

export function startVerifyWorker() {
    const redis = getRedisConnection();
    if (!redis) return null;

    const verifier = new ExploitVerifier(defaultExploitExecutor);

    const worker = new Worker('verify-jobs', async (job: Job) => {
        return WorkerCrashContainment.executeSafe('VerifyWorker', job, async () => {
            const { scanId, findingId, traceSnapshot, frozenAuth } = job.data;
            
            // Deduplication check
            const isDup = await JobFingerprint.isReplayDuplicate(scanId, findingId);
            if (isDup) {
                log.info(`Skipping duplicate verification job`, { jobId: job.id, findingId });
                return { skipped: true, reason: 'duplicate' };
            }

            log.info(`Processing verify job`, { jobId: job.id, findingId });

            const session = await getScanSession(scanId);
            if (!session) throw new Error(`Scan session not found: ${scanId}`);

            // Operate on immutable snapshots
            // The verification runs in an isolated browser context, which was guaranteed in Phase 2.
            const result = await verifier.verify(traceSnapshot);

            // Finding update logic can be dispatched or done here
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

    worker.on('failed', (job, err) => {
        log.error(`Verify job failed`, { jobId: job?.id, error: err.message });
    });

    return worker;
}
