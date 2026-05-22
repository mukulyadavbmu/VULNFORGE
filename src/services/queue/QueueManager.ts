import { Queue, QueueOptions, Worker, WorkerOptions } from 'bullmq';
import Redis from 'ioredis';
import { config } from '../../config';
import { logger } from '../../utils/logger';

const log = logger.child({ module: 'QueueManager' });

let redisConnection: Redis | null = null;
let isDistributedModeEnabled = false;

if (config.USE_DISTRIBUTED_QUEUE) {
    try {
        const redisUrl = config.REDIS_URL || 'redis://localhost:6379';
        // Use a short timeout to check if Redis is available, so we fallback gracefully
        redisConnection = new Redis(redisUrl, {
            maxRetriesPerRequest: null, // Required by BullMQ
            enableReadyCheck: false,
            connectTimeout: 2000,
            retryStrategy(times) {
                if (times > 3) {
                    return null; // Stop retrying
                }
                return Math.min(times * 50, 2000);
            }
        });

        redisConnection.on('error', (err) => {
            log.warn('Redis connection error (fallback mode may trigger)', { error: err.message });
        });

        redisConnection.on('ready', () => {
            log.info('Redis connected — Distributed Queue Mode ENABLED');
            isDistributedModeEnabled = true;
        });

    } catch (error) {
        log.warn('Failed to initialize Redis. Falling back to in-process pipeline.', { error });
    }
} else {
    log.info('Distributed queue disabled in config. Running in fallback mode.');
}

export function isDistributedMode() {
    return isDistributedModeEnabled;
}

export function getRedisConnection() {
    return redisConnection;
}

const defaultQueueOptions: QueueOptions = {
    connection: redisConnection as Redis,
    defaultJobOptions: {
        attempts: 3,
        backoff: { type: 'exponential', delay: 1000 },
        removeOnComplete: 100,
        removeOnFail: 500,
    }
};

let scanOrchestrationQueue: Queue | null = null;
let crawlJobsQueue: Queue | null = null;
let attackJobsQueue: Queue | null = null;
let verifyJobsQueue: Queue | null = null;

// Initialize queues only if connection exists
export function initializeQueues() {
    if (!redisConnection) return;

    scanOrchestrationQueue = new Queue('scan-orchestration', defaultQueueOptions);
    crawlJobsQueue = new Queue('crawl-jobs', defaultQueueOptions);
    attackJobsQueue = new Queue('attack-jobs', defaultQueueOptions);
    verifyJobsQueue = new Queue('verify-jobs', defaultQueueOptions);
}

// Call after module load
setTimeout(initializeQueues, 500); // Give redis a moment to connect

export const queues = {
    get scanOrchestration() { return scanOrchestrationQueue; },
    get crawlJobs() { return crawlJobsQueue; },
    get attackJobs() { return attackJobsQueue; },
    get verifyJobs() { return verifyJobsQueue; },
};

export async function getQueueHealth() {
    if (!isDistributedModeEnabled || !redisConnection) {
        return { mode: 'fallback', queues: null };
    }

    const health: Record<string, any> = {};
    for (const [name, queue] of Object.entries(queues)) {
        if (queue) {
            const counts = await queue.getJobCounts('wait', 'active', 'completed', 'failed', 'delayed');
            health[name] = counts;
        }
    }
    return { mode: 'distributed', queues: health };
}
