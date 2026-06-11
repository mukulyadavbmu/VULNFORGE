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

// ── Internal: build BullMQ Queue objects once connection is live ────────────
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
    // Upstash-safe ioredis configuration
    //
    // Key fixes vs. previous implementation:
    //
    // 1. family: 4  — forces IPv4. On Render (Linux/Node 18+) DNS resolves
    //    to IPv6 (::1) first. Upstash endpoints are IPv4-only, causing
    //    ECONNREFUSED on the IPv6 attempt before IPv4 is tried.
    //
    // 2. tls: {}    — required even when using a rediss:// URL. Passing the
    //    object explicitly ensures ioredis enables TLS regardless of how the
    //    URL was parsed. Without it, connections to port 6380 (Upstash TLS)
    //    are silently attempted over plain TCP and immediately reset.
    //
    // 3. maxRetriesPerRequest: null — mandatory for BullMQ workers/queues.
    //    BullMQ uses blocking commands (BRPOPLPUSH / BLPOP) that must never
    //    time out at the ioredis layer.
    //
    // 4. retryStrategy — persistent exponential back-off (capped 30 s) so
    //    transient network blips don't permanently disable the queue for the
    //    process lifetime. Prior implementation stopped after 3 attempts.
    //
    // 5. Queues are created inside the 'ready' callback (not at module load).
    //    Previously defaultQueueOptions was built synchronously at module
    //    load, capturing the null connection before Redis had connected.
    // ──────────────────────────────────────────────────────────────────────
    try {
        redisConnection = new Redis(rawUrl, {
            // Force IPv4 – Upstash does not support IPv6
            family: 4,

            // Explicit TLS – required for Upstash (rediss:// port 6380)
            tls: {},

            // BullMQ requirement: never abort blocking commands
            maxRetriesPerRequest: null,

            // Skip the PING-based ready check; connect immediately
            enableReadyCheck: false,

            // Production-safe: don't queue commands while offline
            enableOfflineQueue: false,

            connectTimeout: 10_000, // 10 s to establish initial TCP+TLS

            // Persistent reconnect with exponential back-off, capped at 30 s
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
