/**
 * LongScanMonitor — Track system health during extended scans.
 *
 * Monitors memory (process.memoryUsage), CPU (process.cpuUsage),
 * and error rates. Detects memory leaks, high error rates, and slowdowns.
 * Safe timers — auto-stop after scan completes.
 */
import { logger } from '../../utils/logger';

const log = logger.child({ module: 'LongScanMonitor' });

// ─── Constants ──────────────────────────────────────────────────────────────

const POLL_INTERVAL_MS = 15_000; // 15 seconds
const MAX_SNAPSHOTS = 500;
const MEMORY_LEAK_THRESHOLD_MB = 50; // Growth > 50MB over window = leak
const MEMORY_LEAK_WINDOW = 10;       // Compare last 10 snapshots
const HIGH_ERROR_RATE = 10;          // >10 errors/min = high
const SLOWDOWN_FACTOR = 2.0;        // Duration > 2x baseline = slowdown

// ─── Types ──────────────────────────────────────────────────────────────────

export interface SystemSnapshot {
    timestamp: number;
    memoryMB: number;
    heapUsedMB: number;
    heapTotalMB: number;
    externalMB: number;
    cpuUserMs: number;
    cpuSystemMs: number;
    errorCount: number;
    activeRequests: number;
}

export interface HealthStatus {
    healthy: boolean;
    memoryLeakDetected: boolean;
    highErrorRate: boolean;
    slowdownDetected: boolean;
    currentMemoryMB: number;
    peakMemoryMB: number;
    errorRate: number;
    uptimeSeconds: number;
    snapshotCount: number;
    warnings: string[];
}

// ─── Monitor ────────────────────────────────────────────────────────────────

export class LongScanMonitor {
    private snapshots: SystemSnapshot[] = [];
    private timer: ReturnType<typeof setInterval> | null = null;
    private startTime = 0;
    private errorCounter = 0;
    private lastErrorReset = 0;
    private errorsPerMinute = 0;
    private activeRequests = 0;
    private baselineDurationMs = 0;
    private lastCpuUsage: NodeJS.CpuUsage | null = null;

    /**
     * Start monitoring. Safe to call multiple times — restarts if already running.
     */
    start(): void {
        this.stop();
        this.startTime = Date.now();
        this.lastErrorReset = Date.now();
        this.errorCounter = 0;
        this.errorsPerMinute = 0;
        this.snapshots = [];
        this.lastCpuUsage = process.cpuUsage();

        this.takeSnapshot();

        this.timer = setInterval(() => {
            this.takeSnapshot();
        }, POLL_INTERVAL_MS);

        // Prevent timer from keeping Node alive
        if (this.timer && typeof this.timer === 'object' && 'unref' in this.timer) {
            this.timer.unref();
        }

        log.info('Long scan monitor started');
    }

    /**
     * Stop monitoring. Cleans up timer.
     */
    stop(): void {
        if (this.timer !== null) {
            clearInterval(this.timer);
            this.timer = null;
            log.info('Long scan monitor stopped', {
                duration: Math.round((Date.now() - this.startTime) / 1000),
                snapshots: this.snapshots.length,
            });
        }
    }

    /**
     * Record an error occurrence.
     */
    recordError(): void {
        this.errorCounter++;
    }

    /**
     * Set current active request count.
     */
    setActiveRequests(count: number): void {
        this.activeRequests = Math.max(0, count);
    }

    /**
     * Set baseline duration for slowdown detection.
     */
    setBaselineDuration(ms: number): void {
        this.baselineDurationMs = Math.max(0, ms);
    }

    /**
     * Get current health status with all diagnostics.
     */
    getHealth(): HealthStatus {
        const warnings: string[] = [];
        const now = Date.now();

        // Current memory
        const mem = process.memoryUsage();
        const currentMemoryMB = Math.round(mem.rss / 1024 / 1024);
        const peakMemoryMB = this.snapshots.length > 0
            ? Math.max(...this.snapshots.map(s => s.memoryMB))
            : currentMemoryMB;

        // Error rate (per minute)
        const minuteElapsed = (now - this.lastErrorReset) / 60_000;
        this.errorsPerMinute = minuteElapsed > 0 ? this.errorCounter / minuteElapsed : 0;

        // Memory leak detection
        const memoryLeakDetected = this.detectMemoryLeak();
        if (memoryLeakDetected) {
            warnings.push(`Memory leak suspected: RSS grew >  ${MEMORY_LEAK_THRESHOLD_MB}MB over last ${MEMORY_LEAK_WINDOW} snapshots`);
        }

        // High error rate
        const highErrorRate = this.errorsPerMinute > HIGH_ERROR_RATE;
        if (highErrorRate) {
            warnings.push(`High error rate: ${this.errorsPerMinute.toFixed(1)} errors/min (threshold: ${HIGH_ERROR_RATE})`);
        }

        // Slowdown detection
        const slowdownDetected = this.detectSlowdown();
        if (slowdownDetected) {
            warnings.push(`Slowdown detected: scan duration exceeds ${SLOWDOWN_FACTOR}x baseline`);
        }

        const healthy = !memoryLeakDetected && !highErrorRate && !slowdownDetected;

        return {
            healthy,
            memoryLeakDetected,
            highErrorRate,
            slowdownDetected,
            currentMemoryMB,
            peakMemoryMB,
            errorRate: Math.round(this.errorsPerMinute * 10) / 10,
            uptimeSeconds: Math.round((now - this.startTime) / 1000),
            snapshotCount: this.snapshots.length,
            warnings,
        };
    }

    /**
     * Get all snapshots (for charting/debugging).
     */
    getSnapshots(): SystemSnapshot[] {
        return [...this.snapshots];
    }

    // ─── Private ──────────────────────────────────────────────────────────

    private takeSnapshot(): void {
        const mem = process.memoryUsage();
        const cpuDelta = process.cpuUsage(this.lastCpuUsage ?? undefined);
        this.lastCpuUsage = process.cpuUsage();

        const snapshot: SystemSnapshot = {
            timestamp: Date.now(),
            memoryMB: Math.round(mem.rss / 1024 / 1024),
            heapUsedMB: Math.round(mem.heapUsed / 1024 / 1024),
            heapTotalMB: Math.round(mem.heapTotal / 1024 / 1024),
            externalMB: Math.round(mem.external / 1024 / 1024),
            cpuUserMs: Math.round(cpuDelta.user / 1000),
            cpuSystemMs: Math.round(cpuDelta.system / 1000),
            errorCount: this.errorCounter,
            activeRequests: this.activeRequests,
        };

        this.snapshots.push(snapshot);

        // Auto-trim
        if (this.snapshots.length > MAX_SNAPSHOTS) {
            this.snapshots.splice(0, this.snapshots.length - MAX_SNAPSHOTS);
        }
    }

    private detectMemoryLeak(): boolean {
        if (this.snapshots.length < MEMORY_LEAK_WINDOW) return false;

        const recent = this.snapshots.slice(-MEMORY_LEAK_WINDOW);
        const first = recent[0].memoryMB;
        const last = recent[recent.length - 1].memoryMB;
        const growth = last - first;

        // Check for monotonic increase
        let increasing = 0;
        for (let i = 1; i < recent.length; i++) {
            if (recent[i].memoryMB > recent[i - 1].memoryMB) increasing++;
        }

        return growth > MEMORY_LEAK_THRESHOLD_MB && increasing >= MEMORY_LEAK_WINDOW * 0.7;
    }

    private detectSlowdown(): boolean {
        if (this.baselineDurationMs <= 0) return false;
        const elapsed = Date.now() - this.startTime;
        return elapsed > this.baselineDurationMs * SLOWDOWN_FACTOR;
    }
}
