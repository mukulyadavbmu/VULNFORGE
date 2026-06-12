import { Queue, QueueOptions } from 'bullmq';
import Redis from 'ioredis';
import { config } from '../../config';
import { logger } from '../../utils/logger';

const log = logger.child({ module: 'QueueManager' });

// ── Connection state ────────────────────────────────────────────────────────
let redisConnection: Redis | null = null;
let isDistributedModeEnabled = false;

// ── Queue instances – only populated after Redis 'ready' ────────────────────
let scanOrchestrationQueue: Queue | null = null;
let crawlJobsQueue: Queue | null = null;
let attackJobsQueue: Queue | null = null;
let verifyJobsQueue: Queue | null = null;

// ── CRIT-1: Callback so index.ts can start workers after Redis is ready ──────
let _onReadyCallback: (() => void) | null = null;

/**
 * Register a callback to be invoked once Redis emits 'ready'.
 * Use this to start WorkerRegistry AFTER distributed mode is enabled.
 * Must be called before bootstrap() fires the event (i.e. at module load).
 */
export function setOnRedisReady(cb: () => void): void {
    _onReadyCallback = cb;
}

// ── Public accessors ────────────────────────────────────────────────────────
export function isDistributedMode(): boolean {
    return isDistributedModeEnabled;
}

export function getRedisConnection(): Redis | null {
    return redisConnection;
}

export const queues = {
    get scanOrchestration(): Queue | null { return scanOrchestrationQueue; },
    get crawlJobs(): Queue | null { return crawlJobsQueue; },
    get attackJobs(): Queue | null { return attackJobsQueue; },
    get verifyJobs(): Queue | null { return verifyJobsQueue; },
};

// ── HIGH-2: Factory for dedicated worker connections ─────────────────────────
/**
 * Creates a fresh ioredis connection for BullMQ Workers.
 * Workers must NOT share the producer (Queue) connection — BullMQ uses blocking
 * commands (BLPOP/BRPOPLPUSH) on worker connections that interfere with the
 * non-blocking commands the Queue producer uses.
 */
export function createWorkerConnection(): Redis | null {
    const rawUrl = config.REDIS_URL;
    if (!rawUrl) return null;

    return new Redis(rawUrl, {
        family: 4,
        tls: {},
        maxRetriesPerRequest: null,  // mandatory for BullMQ worker blocking commands
        enableReadyCheck: false,
        enableOfflineQueue: false,
        connectTimeout: 10_000,
        retryStrategy(times: number): number {
            return Math.min(times * 200, 30_000);
        },
    });
}

// ── Internal: build BullMQ Queue objects once producer connection is live ────
function initializeQueues(connection: Redis): void {
    const queueOpts: QueueOptions = {
        connection,
        defaultJobOptions: {
            attempts: 3,
            backoff: { type: 'exponential', delay: 1000 },
            removeOnComplete: 100,
            removeOnFail: 500,
        },
    };

    scanOrchestrationQueue = new Queue('scan-orchestration', queueOpts);
    crawlJobsQueue         = new Queue('crawl-jobs',         queueOpts);
    attackJobsQueue        = new Queue('attack-jobs',        queueOpts);
    verifyJobsQueue        = new Queue('verify-jobs',        queueOpts);

    log.info('BullMQ queues initialised: scan-orchestration, crawl-jobs, attack-jobs, verify-jobs');
}

// ── Bootstrap ───────────────────────────────────────────────────────────────
function bootstrap(): void {
    if (!config.USE_DISTRIBUTED_QUEUE) {
        log.info('USE_DISTRIBUTED_QUEUE=false — running in local fallback mode.');
        return;
    }

    const rawUrl = config.REDIS_URL;
    if (!rawUrl) {
        log.warn('REDIS_URL is not set — running in local fallback mode.');
        return;
    }

    // Log the host without credentials for diagnostics
    let safeHost = '(unparseable)';
    try {
        const parsed = new URL(rawUrl);
        safeHost = `${parsed.hostname}:${parsed.port || '6379'}`;
    } catch { /* leave as unparseable */ }

    log.info(`Redis: attempting connection to ${safeHost} …`);

    // ──────────────────────────────────────────────────────────────────────
    // Upstash-safe ioredis configuration (producer connection for Queues)
    //
    // 1. family: 4  — forces IPv4. Render/Node 18+ resolves IPv6 first;
    //    Upstash is IPv4-only → ECONNREFUSED on IPv6.
    // 2. tls: {}    — explicit TLS required even with rediss:// URL.
    // 3. maxRetriesPerRequest: null — BullMQ requirement.
    // 4. retryStrategy — persistent back-off (capped 30 s).
    // 5. Queues initialised inside 'ready' callback — not at module load.
    // ──────────────────────────────────────────────────────────────────────
    try {
        redisConnection = new Redis(rawUrl, {
            family: 4,
            tls: {},
            maxRetriesPerRequest: null,
            enableReadyCheck: false,
            enableOfflineQueue: false,
            connectTimeout: 10_000,
            retryStrategy(times: number): number {
                const delay = Math.min(times * 200, 30_000);
                log.warn(`Redis: reconnecting (attempt ${times}), next try in ${delay}ms …`);
                return delay;
            },
        });

        // ── Event diagnostics ─────────────────────────────────────────────
        redisConnection.on('connect', () => {
            log.info(`Redis: TCP connection established to ${safeHost}`);
        });

        redisConnection.on('ready', () => {
            log.info(`Redis: connection ready — enabling Distributed Queue Mode (host: ${safeHost})`);
            isDistributedModeEnabled = true;
            initializeQueues(redisConnection!);

            // CRIT-1: Notify WorkerRegistry to start now that Redis is live
            if (_onReadyCallback) {
                log.info('Redis: invoking onReady callback (WorkerRegistry.start)');
                _onReadyCallback();
            }
        });

        redisConnection.on('error', (err: Error) => {
            log.warn('Redis: connection error', {
                host: safeHost,
                error: err.message,
                code: (err as any).code ?? 'unknown',
            });
        });

        redisConnection.on('close', () => {
            log.warn(`Redis: connection closed (host: ${safeHost}) — queues suspended`);
            isDistributedModeEnabled = false;
        });

        redisConnection.on('reconnecting', (delay: number) => {
            log.info(`Redis: reconnecting in ${delay}ms …`);
        });

    } catch (err) {
        log.error('Redis: failed to create ioredis client — running in local fallback mode.', {
            error: err instanceof Error ? err.message : String(err),
        });
    }
}

// Run once at module load
bootstrap();

// ── Queue health utility ────────────────────────────────────────────────────
export async function getQueueHealth(): Promise<{ mode: string; queues: Record<string, any> | null }> {
    if (!isDistributedModeEnabled || !redisConnection) {
        return { mode: 'fallback', queues: null };
    }

    const health: Record<string, any> = {};
    for (const [name, queue] of Object.entries(queues)) {
        if (queue) {
            try {
                const counts = await queue.getJobCounts('wait', 'active', 'completed', 'failed', 'delayed');
                health[name] = counts;
            } catch (err) {
                health[name] = { error: err instanceof Error ? err.message : String(err) };
            }
        }
    }
    return { mode: 'distributed', queues: health };
}

// ── Enqueue helper with explicit diagnostics ────────────────────────────────
/**
 * Safe enqueue: logs success/failure with job ID.
 * Throws on failure so callers can fall back.
 */
export async function enqueueJob(
    queue: Queue,
    jobName: string,
    data: Record<string, unknown>,
    opts: { jobId?: string } = {},
): Promise<void> {
    const job = await queue.add(jobName, data, opts);
    log.info('BullMQ: job enqueued', {
        queue: queue.name,
        jobName,
        jobId: job.id,
        data,
    });
}
