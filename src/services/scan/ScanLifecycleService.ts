import { ScanRepository } from '../db/ScanRepository';
import { queues, isDistributedMode, enqueueJob } from '../queue/QueueManager';
import { logger } from '../../utils/logger';
import { startPipeline } from './AutoScanPipeline';

const log = logger.child({ module: 'ScanLifecycleService' });

export class ScanLifecycleService {

    static async enqueueScan(scanId: string): Promise<void> {
        await ScanRepository.updateStatus(scanId, 'queued');
        log.info(`Scan ${scanId}: status set to 'queued'`);

        const distributed = isDistributedMode();
        const queue = queues.scanOrchestration;

        log.info(`Scan ${scanId}: distributedMode=${distributed}, queueReady=${!!queue}`);

        if (distributed && queue) {
            try {
                await enqueueJob(
                    queue,
                    'orchestrate-scan',
                    { scanId },
                    { jobId: `scan:${scanId}` },
                );
                log.info(`Scan ${scanId}: successfully enqueued to BullMQ (scan-orchestration)`);
            } catch (err) {
                log.error(`Scan ${scanId}: BullMQ enqueue FAILED — falling back to local pipeline`, {
                    error: err instanceof Error ? err.message : String(err),
                    stack: err instanceof Error ? err.stack : undefined,
                });
                // Graceful local fallback: scan still runs, just not distributed
                setImmediate(() => startPipeline(scanId));
            }
        } else {
            log.info(`Scan ${scanId}: starting in local fallback mode (distributed=${distributed}, queue=${!!queue})`);
            setImmediate(() => startPipeline(scanId));
        }
    }

    static async pauseScan(scanId: string): Promise<boolean> {
        await ScanRepository.updateStatus(scanId, 'paused');
        log.info(`Scan ${scanId} paused.`);
        return true;
    }

    static async resumeScan(scanId: string): Promise<boolean> {
        const scan = await ScanRepository.getScan(scanId);
        if (!scan || scan.status !== 'paused') return false;

        await ScanRepository.updateStatus(scanId, 'resumed');

        const distributed = isDistributedMode();
        const queue = queues.scanOrchestration;

        if (distributed && queue) {
            try {
                await enqueueJob(
                    queue,
                    'orchestrate-scan',
                    { scanId, resume: true },
                    { jobId: `scan:${scanId}:resume:${Date.now()}` },
                );
                log.info(`Scan ${scanId}: resume job enqueued to BullMQ`);
            } catch (err) {
                log.error(`Scan ${scanId}: BullMQ resume enqueue FAILED — falling back to local pipeline`, {
                    error: err instanceof Error ? err.message : String(err),
                });
                setImmediate(() => startPipeline(scanId));
            }
        } else {
            setImmediate(() => startPipeline(scanId));
        }

        log.info(`Scan ${scanId} resumed.`);
        return true;
    }

    static async cancelScan(scanId: string): Promise<boolean> {
        await ScanRepository.updateStatus(scanId, 'cancelled');
        log.info(`Scan ${scanId} cancelled.`);
        return true;
    }
}
