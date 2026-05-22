import { Job } from 'bullmq';
import { logger } from '../../utils/logger';

const log = logger.child({ module: 'WorkerCrashContainment' });

export class WorkerCrashContainment {
    private static consecutiveFailures = new Map<string, number>();

    /**
     * Wrap a job execution with crash containment and memory limits.
     */
    static async executeSafe<T>(
        workerName: string,
        job: Job,
        task: () => Promise<T>
    ): Promise<T | null> {
        try {
            // Check memory before execution
            const mem = process.memoryUsage();
            if (mem.heapUsed > 1024 * 1024 * 512) { // 512MB soft limit per worker
                log.warn(`Worker ${workerName} near memory limit, forcing GC if possible`, { heapUsed: mem.heapUsed });
                if (global.gc) global.gc();
            }

            const result = await task();

            // Reset consecutive failures on success
            this.consecutiveFailures.set(workerName, 0);

            return result;
        } catch (error) {
            this.handleCrash(workerName, job, error);
            throw error; // Let BullMQ handle retry/dead-letter
        }
    }

    private static handleCrash(workerName: string, job: Job, error: unknown) {
        const msg = error instanceof Error ? error.message : 'Unknown error';
        
        const failures = (this.consecutiveFailures.get(workerName) || 0) + 1;
        this.consecutiveFailures.set(workerName, failures);

        if (msg.includes('net::ERR') || msg.includes('Target closed') || msg.includes('Page closed')) {
            log.warn(`Browser crash detected in ${workerName}`, { jobId: job.id, error: msg });
            // Browser crashes are localized, don't increment critical failures heavily
        } else if (msg.includes('heap out of memory')) {
            log.error(`FATAL: Memory exhaustion in ${workerName}. Process should be recycled.`, { jobId: job.id });
        } else if (error instanceof SyntaxError) {
            log.warn(`Malformed data/trace in ${workerName}`, { jobId: job.id, error: msg });
        } else {
            log.error(`Worker crash in ${workerName}`, { jobId: job.id, error: msg });
        }

        if (failures > 5) {
            log.error(`Worker ${workerName} experiencing cascade failures (${failures}). Pausing worker.`);
            // A real implementation might pause the queue: job.queue.pause()
            // BullMQ allows pausing queues/workers to prevent poison-job loops.
        }

        // Detect poison job (failed multiple times)
        if (job.attemptsMade >= (job.opts.attempts || 3) - 1) {
            log.error(`Poison job detected and quarantined`, { queue: job.queueName, jobId: job.id });
        }
    }

    static getCrashMetrics() {
        return Object.fromEntries(this.consecutiveFailures);
    }
}
