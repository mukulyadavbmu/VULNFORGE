import { Worker } from 'bullmq';
import { startScanWorker } from './ScanWorker';
import { startCrawlWorker } from './CrawlWorker';
import { startAttackWorker } from './AttackWorker';
import { startVerifyWorker } from './VerifyWorker';
import { isDistributedMode } from '../services/queue/QueueManager';
import { logger } from '../utils/logger';

const log = logger.child({ module: 'WorkerRegistry' });

export class WorkerRegistry {
    private static workers: Record<string, Worker | null> = {
        scan: null,
        crawl: null,
        attack: null,
        verify: null,
    };
    private static startTimes: Record<string, number> = {};

    static start() {
        if (!isDistributedMode()) {
            log.info('WorkerRegistry: Distributed mode disabled. Workers will not start.');
            return;
        }

        log.info('WorkerRegistry: Starting distributed workers...');
        this.workers.scan = startScanWorker();
        this.workers.crawl = startCrawlWorker();
        this.workers.attack = startAttackWorker();
        this.workers.verify = startVerifyWorker();

        const now = Date.now();
        this.startTimes = {
            scan: now,
            crawl: now,
            attack: now,
            verify: now,
        };
    }

    static async shutdown() {
        log.info('WorkerRegistry: Shutting down all workers gracefully...');
        const promises: Promise<void>[] = [];
        for (const [name, worker] of Object.entries(this.workers)) {
            if (worker) {
                log.info(`Closing worker: ${name}`);
                promises.push(worker.close());
            }
        }
        await Promise.allSettled(promises);
        log.info('WorkerRegistry: All workers shut down.');
    }

    static getStatus() {
        if (!isDistributedMode()) {
            return { mode: 'fallback', workers: null };
        }

        const status: Record<string, any> = {};
        for (const [name, worker] of Object.entries(this.workers)) {
            if (worker) {
                status[name] = {
                    status: worker.isRunning() ? 'running' : (worker.isPaused() ? 'paused' : 'stopped'),
                    uptimeSeconds: Math.floor((Date.now() - (this.startTimes[name] || Date.now())) / 1000),
                    concurrency: worker.opts.concurrency,
                };
            }
        }
        return { mode: 'distributed', workers: status };
    }
}
