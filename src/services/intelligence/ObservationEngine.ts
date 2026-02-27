/**
 * ObservationEngine — Track endpoint behavior over time.
 *
 * Records entropy, status codes, response lengths, and error frequency
 * per endpoint. Detects anomaly trends using ShannonAnalyzer.
 *
 * Security: Memory-safe with auto-trim at MAX_HISTORY (500).
 * No full body storage. No DB dependency.
 */
import { z } from 'zod';
import { ShannonAnalyzer } from './ShannonAnalyzer';
import { logger } from '../../utils/logger';

const log = logger.child({ module: 'ObservationEngine' });

// ─── Constants ──────────────────────────────────────────────────────────────

const MAX_HISTORY = 500;
const ANOMALY_WINDOW = 10;
const ENTROPY_DEVIATION_THRESHOLD = 0.3;
const LENGTH_DEVIATION_THRESHOLD = 0.5;
const ERROR_RATE_THRESHOLD = 0.4;

// ─── Zod Schemas ────────────────────────────────────────────────────────────

const RecordInputSchema = z.object({
    endpointId: z.string().min(1).max(2048),
    statusCode: z.number().int().min(100).max(599),
    contentLength: z.number().int().min(0).max(100_000_000),
    bodySnippet: z.string().max(1000),
    isError: z.boolean(),
}).strict();

// ─── Types ──────────────────────────────────────────────────────────────────

export interface Observation {
    endpointId: string;
    entropyHistory: number[];
    statusHistory: number[];
    lengthHistory: number[];
    errorHistory: boolean[];
    timestamps: number[];
}

export interface RecordInput {
    endpointId: string;
    statusCode: number;
    contentLength: number;
    bodySnippet: string;
    isError: boolean;
}

export interface AnomalyTrend {
    hasAnomaly: boolean;
    entropyTrend: 'stable' | 'increasing' | 'decreasing' | 'volatile';
    lengthTrend: 'stable' | 'increasing' | 'decreasing' | 'volatile';
    errorRate: number;
    recentEntropyDeviation: number;
    recentLengthDeviation: number;
    confidence: number;
}

// ─── Engine ─────────────────────────────────────────────────────────────────

export class ObservationEngine {
    private observations: Map<string, Observation> = new Map();

    /**
     * Record an observation for an endpoint.
     * Auto-trims history arrays at MAX_HISTORY (500).
     * Calculates Shannon entropy on bodySnippet.
     */
    recordObservation(input: RecordInput): Observation {
        const validated = RecordInputSchema.parse(input);

        let obs = this.observations.get(validated.endpointId);
        if (!obs) {
            obs = {
                endpointId: validated.endpointId,
                entropyHistory: [],
                statusHistory: [],
                lengthHistory: [],
                errorHistory: [],
                timestamps: [],
            };
            this.observations.set(validated.endpointId, obs);
        }

        // Calculate entropy via ShannonAnalyzer
        const entropy = ShannonAnalyzer.calculateEntropy(validated.bodySnippet);

        obs.entropyHistory.push(entropy);
        obs.statusHistory.push(validated.statusCode);
        obs.lengthHistory.push(validated.contentLength);
        obs.errorHistory.push(validated.isError);
        obs.timestamps.push(Date.now());

        // Auto-trim to prevent memory leaks
        if (obs.entropyHistory.length > MAX_HISTORY) {
            const excess = obs.entropyHistory.length - MAX_HISTORY;
            obs.entropyHistory.splice(0, excess);
            obs.statusHistory.splice(0, excess);
            obs.lengthHistory.splice(0, excess);
            obs.errorHistory.splice(0, excess);
            obs.timestamps.splice(0, excess);
        }

        log.debug('Observation recorded', {
            endpointId: validated.endpointId,
            entropy: entropy.toFixed(3),
            statusCode: validated.statusCode,
            historySize: obs.entropyHistory.length,
        });

        return obs;
    }

    /**
     * Get observation history for an endpoint.
     * Returns null if no observations exist.
     */
    getObservation(endpointId: string): Observation | null {
        return this.observations.get(endpointId) ?? null;
    }

    /**
     * Detect anomaly trends in recent observations.
     * Analyzes the last ANOMALY_WINDOW (10) entries against the full baseline.
     */
    detectAnomalyTrend(endpointId: string): AnomalyTrend {
        const obs = this.observations.get(endpointId);

        if (!obs || obs.entropyHistory.length < 3) {
            return {
                hasAnomaly: false,
                entropyTrend: 'stable',
                lengthTrend: 'stable',
                errorRate: 0,
                recentEntropyDeviation: 0,
                recentLengthDeviation: 0,
                confidence: 0,
            };
        }

        const total = obs.entropyHistory.length;
        const windowSize = Math.min(ANOMALY_WINDOW, total);
        const recentStart = total - windowSize;

        // ── Entropy Analysis ──────────────────────────────────────────────────
        const allEntropy = obs.entropyHistory;
        const recentEntropy = allEntropy.slice(recentStart);
        const baselineEntropyAvg = this.average(allEntropy.slice(0, recentStart));
        const recentEntropyAvg = this.average(recentEntropy);
        const entropyStdDev = this.stdDev(allEntropy);

        const recentEntropyDeviation = entropyStdDev > 0
            ? Math.abs(recentEntropyAvg - baselineEntropyAvg) / entropyStdDev
            : 0;

        const entropyTrend = this.classifyTrend(recentEntropy, baselineEntropyAvg);

        // ── Length Analysis ────────────────────────────────────────────────────
        const allLengths = obs.lengthHistory;
        const recentLengths = allLengths.slice(recentStart);
        const baselineLengthAvg = this.average(allLengths.slice(0, recentStart));
        const recentLengthAvg = this.average(recentLengths);
        const lengthStdDev = this.stdDev(allLengths);

        const recentLengthDeviation = lengthStdDev > 0
            ? Math.abs(recentLengthAvg - baselineLengthAvg) / lengthStdDev
            : 0;

        const lengthTrend = this.classifyTrend(recentLengths, baselineLengthAvg);

        // ── Error Rate ────────────────────────────────────────────────────────
        const recentErrors = obs.errorHistory.slice(recentStart);
        const errorRate = recentErrors.filter(e => e).length / recentErrors.length;

        // ── Anomaly Detection ─────────────────────────────────────────────────
        const hasEntropyAnomaly = recentEntropyDeviation > ENTROPY_DEVIATION_THRESHOLD;
        const hasLengthAnomaly = recentLengthDeviation > LENGTH_DEVIATION_THRESHOLD;
        const hasErrorAnomaly = errorRate > ERROR_RATE_THRESHOLD;
        const hasAnomaly = hasEntropyAnomaly || hasLengthAnomaly || hasErrorAnomaly;

        // ── Confidence ────────────────────────────────────────────────────────
        let confidence = 0;
        if (hasEntropyAnomaly) confidence += 30;
        if (hasLengthAnomaly) confidence += 25;
        if (hasErrorAnomaly) confidence += 25;
        // More data points = higher confidence
        if (total >= 20) confidence += 10;
        else if (total >= 10) confidence += 5;
        // Consistent anomaly signals boost confidence
        if (hasEntropyAnomaly && hasLengthAnomaly) confidence += 10;
        confidence = Math.min(confidence, 100);

        const result: AnomalyTrend = {
            hasAnomaly,
            entropyTrend,
            lengthTrend,
            errorRate,
            recentEntropyDeviation,
            recentLengthDeviation,
            confidence,
        };

        if (hasAnomaly) {
            log.info('Anomaly trend detected', {
                endpointId,
                entropyTrend,
                lengthTrend,
                errorRate: errorRate.toFixed(2),
                confidence,
                dataPoints: total,
            });
        }

        return result;
    }

    /**
     * Get all tracked endpoint IDs.
     */
    getTrackedEndpoints(): string[] {
        return Array.from(this.observations.keys());
    }

    /**
     * Clear observation data for an endpoint (for testing / cleanup).
     */
    clear(endpointId: string): void {
        this.observations.delete(endpointId);
    }

    /**
     * Get total memory footprint (entry count across all endpoints).
     */
    getTotalEntries(): number {
        let total = 0;
        for (const obs of this.observations.values()) {
            total += obs.entropyHistory.length;
        }
        return total;
    }

    // ─── Private Helpers ────────────────────────────────────────────────────

    private average(arr: number[]): number {
        if (arr.length === 0) return 0;
        return arr.reduce((a, b) => a + b, 0) / arr.length;
    }

    private stdDev(arr: number[]): number {
        if (arr.length < 2) return 0;
        const avg = this.average(arr);
        const variance = arr.reduce((sum, v) => sum + (v - avg) ** 2, 0) / arr.length;
        return Math.sqrt(variance);
    }

    private classifyTrend(
        recent: number[],
        baselineAvg: number,
    ): 'stable' | 'increasing' | 'decreasing' | 'volatile' {
        if (recent.length < 2) return 'stable';

        const recentAvg = this.average(recent);
        const recentStdDev = this.stdDev(recent);
        const delta = recentAvg - baselineAvg;
        const relativeStdDev = baselineAvg > 0 ? recentStdDev / baselineAvg : recentStdDev;

        // High variance = volatile
        if (relativeStdDev > 0.5) return 'volatile';

        // Directional trend
        if (baselineAvg > 0) {
            const relDelta = delta / baselineAvg;
            if (relDelta > 0.2) return 'increasing';
            if (relDelta < -0.2) return 'decreasing';
        } else {
            if (delta > 1) return 'increasing';
            if (delta < -1) return 'decreasing';
        }

        return 'stable';
    }
}

// ─── Integration Example (does NOT modify any existing code) ────────────────
//
// import { ObservationEngine } from './ObservationEngine';
//
// const observer = new ObservationEngine();
//
// // After each probe response:
// observer.recordObservation({
//   endpointId: '/api/users',
//   statusCode: 200,
//   contentLength: 1452,
//   bodySnippet: responseBody.slice(0, 500),
//   isError: false,
// });
//
// // Check for anomalies:
// const trend = observer.detectAnomalyTrend('/api/users');
// if (trend.hasAnomaly) {
//   // Feed into strategy engine to escalate this endpoint
// }
