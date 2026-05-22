import { ScanRepository } from '../db/ScanRepository';
import { queues, isDistributedMode } from '../queue/QueueManager';
import { logger } from '../../utils/logger';
import { startPipeline } from './AutoScanPipeline';

const log = logger.child({ module: 'ScanLifecycleService' });

export class ScanLifecycleService {
    static async enqueueScan(scanId: string): Promise<void> {
        await ScanRepository.updateStatus(scanId, 'queued');

        if (isDistributedMode() && queues.scanOrchestration) {
            await queues.scanOrchestration.add('orchestrate-scan', { scanId }, {
                jobId: `scan:${scanId}`,
            });
            log.info(`Scan ${scanId} enqueued for distributed execution.`);
        } else {
            log.info(`Scan ${scanId} starting in local fallback mode.`);
            // Run locally in background
            setImmediate(() => startPipeline(scanId));
        }
    }

    static async pauseScan(scanId: string): Promise<boolean> {
        await ScanRepository.updateStatus(scanId, 'paused');
        log.info(`Scan ${scanId} paused.`);
        // In distributed mode, workers should check scan status periodically or before next phase
        return true;
    }

    static async resumeScan(scanId: string): Promise<boolean> {
        const scan = await ScanRepository.getScan(scanId);
        if (!scan || scan.status !== 'paused') return false;

        await ScanRepository.updateStatus(scanId, 'resumed');
        if (isDistributedMode() && queues.scanOrchestration) {
            await queues.scanOrchestration.add('orchestrate-scan', { scanId, resume: true }, {
                jobId: `scan:${scanId}:resume:${Date.now()}`,
            });
        } else {
            setImmediate(() => startPipeline(scanId)); // Need a real resume logic here
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
