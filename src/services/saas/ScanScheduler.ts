/**
 * Part 9c — ScanScheduler
 * Cron-based scan scheduling. In-memory for MVP.
 * No external cron library — uses setInterval-based polling.
 */
import { ScheduledScan } from '../../strategy.types';
import { logger } from '../../utils/logger';
import crypto from 'crypto';

const log = logger.child({ module: 'ScanScheduler' });

/** Simple cron interval parser — supports only: hourly, daily, weekly */
const CRON_INTERVALS: Record<string, number> = {
    '@hourly': 60 * 60 * 1000,
    '@daily': 24 * 60 * 60 * 1000,
    '@weekly': 7 * 24 * 60 * 60 * 1000,
};

export class ScanScheduler {
    private static schedules: Map<string, ScheduledScan> = new Map();
    private static pollTimer: ReturnType<typeof setInterval> | null = null;
    private static onScanCallback: ((targetUrl: string, tenantId: string) => void) | null = null;

    /** Register callback to be called when a scan is due. */
    static onScanDue(callback: (targetUrl: string, tenantId: string) => void): void {
        this.onScanCallback = callback;
    }

    /** Schedule a recurring scan. */
    static schedule(tenantId: string, targetUrl: string, cronExpression: string): ScheduledScan {
        const intervalMs = CRON_INTERVALS[cronExpression];
        if (!intervalMs) {
            throw new Error(`Unsupported cron expression: ${cronExpression}. Use @hourly, @daily, or @weekly.`);
        }

        const id = crypto.randomUUID();
        const scan: ScheduledScan = {
            id,
            tenantId,
            targetUrl,
            cronExpression,
            nextRunAt: Date.now() + intervalMs,
            enabled: true,
        };

        this.schedules.set(id, scan);
        log.info('Scan scheduled', { id, tenantId, targetUrl, cronExpression });
        return scan;
    }

    /** Cancel a scheduled scan. */
    static cancel(scheduleId: string): boolean {
        const scan = this.schedules.get(scheduleId);
        if (!scan) return false;
        scan.enabled = false;
        log.info('Scan schedule cancelled', { scheduleId, tenantId: scan.tenantId });
        return true;
    }

    /** Start the polling loop. Checks every 60 seconds. */
    static startPolling(): void {
        if (this.pollTimer) return; // Already running

        this.pollTimer = setInterval(() => {
            this.tick();
        }, 60_000); // Check every minute

        log.info('Scheduler polling started');
    }

    /** Stop the polling loop. */
    static stopPolling(): void {
        if (this.pollTimer) {
            clearInterval(this.pollTimer);
            this.pollTimer = null;
            log.info('Scheduler polling stopped');
        }
    }

    /** Internal: process due schedules. */
    private static tick(): void {
        const now = Date.now();
        for (const [, scan] of this.schedules) {
            if (!scan.enabled) continue;
            if (now >= scan.nextRunAt) {
                log.info('Scan due', { scheduleId: scan.id, targetUrl: scan.targetUrl });

                // Trigger callback
                if (this.onScanCallback) {
                    this.onScanCallback(scan.targetUrl, scan.tenantId);
                }

                // Update timing
                const intervalMs = CRON_INTERVALS[scan.cronExpression] ?? 86400000;
                scan.lastRunAt = now;
                scan.nextRunAt = now + intervalMs;
            }
        }
    }

    /** List schedules for a tenant. */
    static listForTenant(tenantId: string): ScheduledScan[] {
        const result: ScheduledScan[] = [];
        for (const [, scan] of this.schedules) {
            if (scan.tenantId === tenantId) result.push(scan);
        }
        return result;
    }
}
