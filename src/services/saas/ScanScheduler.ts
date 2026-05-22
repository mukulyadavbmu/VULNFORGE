/**
 * Part 9c — ScanScheduler (Enhanced)
 * Cron-based scan scheduling with:
 * - Concurrent scan limits
 * - Domain rate limits
 * - Pause/resume support
 * - Timeout management
 * - Queue prioritization
 *
 * In-memory for MVP. No external cron library.
 */
import { ScheduledScan, EnhancedScheduledScan, ScheduledScanStatus } from '../../strategy.types';
import { logger } from '../../utils/logger';
import crypto from 'crypto';

const log = logger.child({ module: 'ScanScheduler' });

// ─── Constants ──────────────────────────────────────────────────────────────

const DEFAULT_MAX_CONCURRENT = 3;
const DEFAULT_DOMAIN_RATE_LIMIT_MS = 60_000; // 1 min between scans of same domain
const DEFAULT_MAX_SCAN_DURATION_MS = 45 * 60_000; // 45 minutes (hardened from 30)
const DEFAULT_MAX_REQUESTS_PER_ENDPOINT = 40;
const DEFAULT_MAX_TOTAL_REQUESTS = 3000;
const POLL_INTERVAL_MS = 30_000; // Check every 30 seconds

/** Simple cron interval parser — supports: hourly, daily, weekly, every5min */
const CRON_INTERVALS: Record<string, number> = {
    '@every5min': 5 * 60 * 1000,
    '@every15min': 15 * 60 * 1000,
    '@every30min': 30 * 60 * 1000,
    '@hourly': 60 * 60 * 1000,
    '@daily': 24 * 60 * 60 * 1000,
    '@weekly': 7 * 24 * 60 * 60 * 1000,
};

// ─── Types ──────────────────────────────────────────────────────────────────

interface SchedulerConfig {
    maxConcurrentScans: number;
    domainRateLimitMs: number;
    maxScanDurationMs: number;
    maxRequestsPerEndpoint: number;
    maxTotalRequests: number;
}

// ─── Engine ─────────────────────────────────────────────────────────────────

export class ScanScheduler {
    private static schedules: Map<string, EnhancedScheduledScan> = new Map();
    private static pollTimer: ReturnType<typeof setInterval> | null = null;
    private static onScanCallback: ((targetUrl: string, tenantId: string) => void) | null = null;

    // Concurrency tracking
    private static runningScans: Set<string> = new Set();
    private static domainLastScan: Map<string, number> = new Map();

    // Configuration
    private static config: SchedulerConfig = {
        maxConcurrentScans: DEFAULT_MAX_CONCURRENT,
        domainRateLimitMs: DEFAULT_DOMAIN_RATE_LIMIT_MS,
        maxScanDurationMs: DEFAULT_MAX_SCAN_DURATION_MS,
        maxRequestsPerEndpoint: DEFAULT_MAX_REQUESTS_PER_ENDPOINT,
        maxTotalRequests: DEFAULT_MAX_TOTAL_REQUESTS,
    };

    /** Update scheduler configuration. */
    static configure(config: Partial<SchedulerConfig>): void {
        this.config = { ...this.config, ...config };
        log.info('Scheduler configured', { config: this.config });
    }

    /** Register callback to be called when a scan is due. */
    static onScanDue(callback: (targetUrl: string, tenantId: string) => void): void {
        this.onScanCallback = callback;
    }

    /** Schedule a recurring scan with priority. */
    static schedule(
        tenantId: string,
        targetUrl: string,
        cronExpression: string,
        options?: { priority?: number; maxDurationMs?: number },
    ): EnhancedScheduledScan {
        const intervalMs = CRON_INTERVALS[cronExpression];
        if (!intervalMs) {
            throw new Error(`Unsupported cron expression: ${cronExpression}. Use @hourly, @daily, @weekly, @every5min, @every15min, @every30min.`);
        }

        const id = crypto.randomUUID();
        const scan: EnhancedScheduledScan = {
            id,
            tenantId,
            targetUrl,
            cronExpression,
            nextRunAt: Date.now() + intervalMs,
            enabled: true,
            priority: options?.priority ?? 5,
            status: 'queued',
            maxDurationMs: options?.maxDurationMs ?? this.config.maxScanDurationMs,
        };

        this.schedules.set(id, scan);
        log.info('Scan scheduled', { id, tenantId, targetUrl, cronExpression, priority: scan.priority });
        return scan;
    }

    /** Cancel a scheduled scan. */
    static cancel(scheduleId: string): boolean {
        const scan = this.schedules.get(scheduleId);
        if (!scan) return false;
        scan.enabled = false;
        scan.status = 'completed';
        this.runningScans.delete(scheduleId);
        log.info('Scan schedule cancelled', { scheduleId, tenantId: scan.tenantId });
        return true;
    }

    /** Pause a running or queued scan. */
    static pause(scheduleId: string): boolean {
        const scan = this.schedules.get(scheduleId);
        if (!scan) return false;
        if (scan.status !== 'running' && scan.status !== 'queued') return false;

        scan.status = 'paused';
        this.runningScans.delete(scheduleId);
        log.info('Scan paused', { scheduleId, tenantId: scan.tenantId });
        return true;
    }

    /** Resume a paused scan. */
    static resume(scheduleId: string): boolean {
        const scan = this.schedules.get(scheduleId);
        if (!scan) return false;
        if (scan.status !== 'paused') return false;

        scan.status = 'queued';
        // Re-trigger on next tick
        scan.nextRunAt = Date.now();
        log.info('Scan resumed', { scheduleId, tenantId: scan.tenantId });
        return true;
    }

    /** Mark a scan as completed (call after scan finishes). */
    static markCompleted(scheduleId: string): void {
        const scan = this.schedules.get(scheduleId);
        if (!scan) return;
        scan.status = 'queued'; // Back to queued for next run
        this.runningScans.delete(scheduleId);
        const intervalMs = CRON_INTERVALS[scan.cronExpression] ?? 86400000;
        scan.lastRunAt = Date.now();
        scan.nextRunAt = Date.now() + intervalMs;
    }

    /** Mark a scan as failed. */
    static markFailed(scheduleId: string): void {
        const scan = this.schedules.get(scheduleId);
        if (!scan) return;
        scan.status = 'failed';
        this.runningScans.delete(scheduleId);
    }

    /** Start the polling loop. */
    static startPolling(): void {
        if (this.pollTimer) return;

        this.pollTimer = setInterval(() => {
            this.tick();
        }, POLL_INTERVAL_MS);

        log.info('Scheduler polling started', { intervalMs: POLL_INTERVAL_MS });
    }

    /** Stop the polling loop. */
    static stopPolling(): void {
        if (this.pollTimer) {
            clearInterval(this.pollTimer);
            this.pollTimer = null;
            log.info('Scheduler polling stopped');
        }
    }

    /** Get current scheduler stats. */
    static getStats(): {
        totalScheduled: number;
        running: number;
        queued: number;
        paused: number;
        maxConcurrent: number;
    } {
        let queued = 0;
        let paused = 0;
        for (const [, scan] of this.schedules) {
            if (scan.status === 'queued') queued++;
            else if (scan.status === 'paused') paused++;
        }
        return {
            totalScheduled: this.schedules.size,
            running: this.runningScans.size,
            queued,
            paused,
            maxConcurrent: this.config.maxConcurrentScans,
        };
    }

    /** Internal: process due schedules with priority ordering. */
    private static tick(): void {
        const now = Date.now();

        // 1. Check for timed-out scans
        for (const [, scan] of this.schedules) {
            if (scan.status === 'running' && scan.startedAt && scan.maxDurationMs) {
                if (now - scan.startedAt > scan.maxDurationMs) {
                    scan.status = 'timed_out';
                    this.runningScans.delete(scan.id);
                    log.warn('Scan timed out', {
                        scheduleId: scan.id,
                        duration: now - scan.startedAt,
                        maxDuration: scan.maxDurationMs,
                    });
                }
            }
        }

        // 2. Collect due scans and sort by priority
        const dueScans: EnhancedScheduledScan[] = [];
        for (const [, scan] of this.schedules) {
            if (!scan.enabled) continue;
            if (scan.status !== 'queued') continue;
            if (now < scan.nextRunAt) continue;
            dueScans.push(scan);
        }

        // Sort by priority (lower = higher priority)
        dueScans.sort((a, b) => a.priority - b.priority);

        // 3. Execute due scans within concurrency limit
        for (const scan of dueScans) {
            if (this.runningScans.size >= this.config.maxConcurrentScans) {
                log.debug('Concurrency limit reached, deferring scan', {
                    scheduleId: scan.id,
                    running: this.runningScans.size,
                    max: this.config.maxConcurrentScans,
                });
                break;
            }

            // Check domain rate limit
            const domain = this.extractDomain(scan.targetUrl);
            const lastScan = this.domainLastScan.get(domain);
            if (lastScan && now - lastScan < this.config.domainRateLimitMs) {
                log.debug('Domain rate limited', {
                    domain,
                    waitMs: this.config.domainRateLimitMs - (now - lastScan),
                });
                continue;
            }

            // Launch scan
            scan.status = 'running';
            scan.startedAt = now;
            this.runningScans.add(scan.id);
            this.domainLastScan.set(domain, now);

            log.info('Scan due — launching', {
                scheduleId: scan.id,
                targetUrl: scan.targetUrl,
                priority: scan.priority,
            });

            if (this.onScanCallback) {
                this.onScanCallback(scan.targetUrl, scan.tenantId);
            }
        }
    }

    /** List schedules for a tenant. */
    static listForTenant(tenantId: string): EnhancedScheduledScan[] {
        const result: EnhancedScheduledScan[] = [];
        for (const [, scan] of this.schedules) {
            if (scan.tenantId === tenantId) result.push(scan);
        }
        return result;
    }

    /** Extract domain from URL. */
    private static extractDomain(url: string): string {
        try {
            return new URL(url).hostname;
        } catch {
            return url;
        }
    }
}
