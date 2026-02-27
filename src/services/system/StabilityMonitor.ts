/**
 * StabilityMonitor — Track system health during scans.
 *
 * Monitors: memory usage, queue depth, error rate, timeout rate, uptime.
 * Polls every 30 seconds. Safe timers — auto-stop after scan.
 * No external dependencies. Uses process.memoryUsage() only.
 */
import { z } from 'zod';
import { logger } from '../../utils/logger';

const log = logger.child({ module: 'StabilityMonitor' });

// ─── Constants ──────────────────────────────────────────────────────────────

const POLL_INTERVAL_MS = 30_000;
const MAX_HISTORY = 200;
const ERROR_RATE_THRESHOLD = 0.1;    // 10% errors = unstable
const TIMEOUT_RATE_THRESHOLD = 0.15; // 15% timeouts = unstable
const MEMORY_MB_THRESHOLD = 512;     // 512MB = warning

// ─── Types ──────────────────────────────────────────────────────────────────

export interface StabilityStats {
    memoryMB: number;
    queueDepth: number;
    errorRate: number;
    timeoutRate: number;
    uptime: number;
}

export interface InstabilityReport {
    isUnstable: boolean;
    reasons: string[];
    severity: 'healthy' | 'warning' | 'critical';
    recommendation: string;
}

interface Snapshot {
    memoryMB: number;
    queueDepth: number;
    errors: number;
    timeouts: number;
    totalRequests: number;
    timestamp: number;
}

// ─── Engine ─────────────────────────────────────────────────────────────────

export class StabilityMonitor {
    private pollTimer: ReturnType<typeof setInterval> | null = null;
    private startedAt: number = 0;
    private snapshots: Snapshot[] = [];

    // Counters (incremented externally)
    private errorCount = 0;
    private timeoutCount = 0;
    private requestCount = 0;
    private currentQueueDepth = 0;

    /**
     * Start monitoring at 30-second intervals.
     * Safe: calling multiple times is idempotent.
     */
    startMonitoring(): void {
        if (this.pollTimer) return; // Already running

        this.startedAt = Date.now();
        this.errorCount = 0;
        this.timeoutCount = 0;
        this.requestCount = 0;
        this.snapshots = [];

        this.pollTimer = setInterval(() => {
            this.takeSnapshot();
        }, POLL_INTERVAL_MS);

        // Take initial snapshot immediately
        this.takeSnapshot();

        log.info('Stability monitoring started', {
            intervalMs: POLL_INTERVAL_MS,
            memoryThresholdMB: MEMORY_MB_THRESHOLD,
        });
    }

    /**
     * Stop monitoring. Clears timer safely.
     */
    stopMonitoring(): void {
        if (this.pollTimer) {
            clearInterval(this.pollTimer);
            this.pollTimer = null;
            log.info('Stability monitoring stopped', {
                uptimeMs: Date.now() - this.startedAt,
                snapshots: this.snapshots.length,
            });
        }
    }

    /**
     * Get current stability stats.
     */
    getStats(): StabilityStats {
        const mem = process.memoryUsage();
        return {
            memoryMB: Math.round(mem.rss / 1024 / 1024),
            queueDepth: this.currentQueueDepth,
            errorRate: this.requestCount > 0 ? this.errorCount / this.requestCount : 0,
            timeoutRate: this.requestCount > 0 ? this.timeoutCount / this.requestCount : 0,
            uptime: this.startedAt > 0 ? Date.now() - this.startedAt : 0,
        };
    }

    /**
     * Detect instability from current and historical stats.
     */
    detectInstability(): InstabilityReport {
        const stats = this.getStats();
        const reasons: string[] = [];
        let severity: 'healthy' | 'warning' | 'critical' = 'healthy';

        // Memory check
        if (stats.memoryMB > MEMORY_MB_THRESHOLD * 1.5) {
            reasons.push(`Critical memory: ${stats.memoryMB}MB (threshold: ${MEMORY_MB_THRESHOLD}MB)`);
            severity = 'critical';
        } else if (stats.memoryMB > MEMORY_MB_THRESHOLD) {
            reasons.push(`High memory: ${stats.memoryMB}MB (threshold: ${MEMORY_MB_THRESHOLD}MB)`);
            if (severity === 'healthy') severity = 'warning';
        }

        // Error rate check
        if (stats.errorRate > ERROR_RATE_THRESHOLD * 2) {
            reasons.push(`Critical error rate: ${(stats.errorRate * 100).toFixed(1)}%`);
            severity = 'critical';
        } else if (stats.errorRate > ERROR_RATE_THRESHOLD) {
            reasons.push(`High error rate: ${(stats.errorRate * 100).toFixed(1)}%`);
            if (severity === 'healthy') severity = 'warning';
        }

        // Timeout rate check
        if (stats.timeoutRate > TIMEOUT_RATE_THRESHOLD * 2) {
            reasons.push(`Critical timeout rate: ${(stats.timeoutRate * 100).toFixed(1)}%`);
            severity = 'critical';
        } else if (stats.timeoutRate > TIMEOUT_RATE_THRESHOLD) {
            reasons.push(`High timeout rate: ${(stats.timeoutRate * 100).toFixed(1)}%`);
            if (severity === 'healthy') severity = 'warning';
        }

        // Queue depth check
        if (stats.queueDepth > 100) {
            reasons.push(`Queue depth very high: ${stats.queueDepth}`);
            if (severity === 'healthy') severity = 'warning';
        }

        // Memory trend check (increasing over last 5 snapshots)
        if (this.snapshots.length >= 5) {
            const recent = this.snapshots.slice(-5);
            const memoryIncreasing = recent.every((s, i) =>
                i === 0 || s.memoryMB >= recent[i - 1].memoryMB,
            );
            if (memoryIncreasing && recent[recent.length - 1].memoryMB - recent[0].memoryMB > 50) {
                reasons.push('Memory trending upward (+50MB in last 5 snapshots)');
                if (severity === 'healthy') severity = 'warning';
            }
        }

        const isUnstable = severity !== 'healthy';

        // Recommendation
        let recommendation = 'System healthy — no action needed';
        if (severity === 'critical') {
            recommendation = 'Reduce MAX_CONCURRENT_SCANS, disable non-essential strategy flags, investigate memory leaks';
        } else if (severity === 'warning') {
            recommendation = 'Monitor closely, consider reducing concurrency or scan scope';
        }

        if (isUnstable) {
            log.warn('Instability detected', {
                severity,
                reasons,
                memoryMB: stats.memoryMB,
                errorRate: stats.errorRate.toFixed(3),
                timeoutRate: stats.timeoutRate.toFixed(3),
                queueDepth: stats.queueDepth,
            });
        }

        return { isUnstable, reasons, severity, recommendation };
    }

    // ─── External Counter API ───────────────────────────────────────────────

    /** Record a completed request. */
    recordRequest(): void {
        this.requestCount++;
    }

    /** Record an error. */
    recordError(): void {
        this.errorCount++;
        this.requestCount++;
    }

    /** Record a timeout. */
    recordTimeout(): void {
        this.timeoutCount++;
        this.requestCount++;
    }

    /** Update current queue depth (call from JobDispatcher). */
    setQueueDepth(depth: number): void {
        this.currentQueueDepth = Math.max(0, depth);
    }

    // ─── Private ────────────────────────────────────────────────────────────

    private takeSnapshot(): void {
        const mem = process.memoryUsage();
        const snapshot: Snapshot = {
            memoryMB: Math.round(mem.rss / 1024 / 1024),
            queueDepth: this.currentQueueDepth,
            errors: this.errorCount,
            timeouts: this.timeoutCount,
            totalRequests: this.requestCount,
            timestamp: Date.now(),
        };

        this.snapshots.push(snapshot);

        // Auto-trim history
        if (this.snapshots.length > MAX_HISTORY) {
            this.snapshots.splice(0, this.snapshots.length - MAX_HISTORY);
        }

        log.debug('Stability snapshot', {
            memoryMB: snapshot.memoryMB,
            queueDepth: snapshot.queueDepth,
            errorRate: snapshot.totalRequests > 0
                ? (snapshot.errors / snapshot.totalRequests).toFixed(3)
                : '0',
            timeoutRate: snapshot.totalRequests > 0
                ? (snapshot.timeouts / snapshot.totalRequests).toFixed(3)
                : '0',
        });
    }
}

// ─── Integration Example (does NOT modify any existing code) ────────────────
//
// import { StabilityMonitor } from './StabilityMonitor';
//
// const monitor = new StabilityMonitor();
//
// // Start at scan begin:
// monitor.startMonitoring();
//
// // During scan, record events:
// monitor.recordRequest();
// monitor.recordError();       // on failure
// monitor.recordTimeout();     // on timeout
// monitor.setQueueDepth(15);   // from JobDispatcher
//
// // Periodically or before big decisions:
// const report = monitor.detectInstability();
// if (report.severity === 'critical') {
//   // Reduce concurrency, pause non-essential probes
// }
//
// // At scan end:
// monitor.stopMonitoring();
