/**
 * ResearchEngine — Detect anomalies in endpoint responses.
 *
 * Detects unusual response lengths, structural changes, and timing outliers.
 * No heavy ML — uses statistical analysis (z-scores, Jaccard similarity).
 * Additive — does not modify existing modules.
 */
import { logger } from '../../utils/logger';

const log = logger.child({ module: 'ResearchEngine' });

// ─── Constants ──────────────────────────────────────────────────────────────

const LENGTH_ANOMALY_FACTOR = 5.0;     // >5x expected = anomaly
const TIMING_ANOMALY_FACTOR = 5.0;     // >5x median = outlier
const MIN_SAMPLES = 3;                  // Need ≥3 samples for analysis
const MAX_OBSERVATIONS = 1000;
const STRUCTURE_SIMILARITY_THRESHOLD = 0.5; // <50% key similarity = structural change

// ─── Types ──────────────────────────────────────────────────────────────────

export interface ResponseObservation {
    endpoint: string;
    statusCode: number;
    contentLength: number;
    responseTimeMs: number;
    jsonKeys: string[];
    timestamp: number;
}

export interface Anomaly {
    anomalyType: 'response_length' | 'structure_change' | 'timing_outlier';
    endpoint: string;
    confidence: number;
    description: string;
}

export interface AnomalyReport {
    anomalies: Anomaly[];
    totalEndpoints: number;
    totalObservations: number;
    durationMs: number;
}

// ─── Engine ─────────────────────────────────────────────────────────────────

export class ResearchEngine {
    private observations: Map<string, ResponseObservation[]> = new Map();

    /**
     * Record a response observation for an endpoint.
     */
    record(obs: ResponseObservation): void {
        const list = this.observations.get(obs.endpoint) || [];
        list.push(obs);

        // Auto-trim per endpoint
        if (list.length > MAX_OBSERVATIONS) {
            list.splice(0, list.length - MAX_OBSERVATIONS);
        }

        this.observations.set(obs.endpoint, list);
    }

    /**
     * Record multiple observations at once.
     */
    recordBatch(observations: ResponseObservation[]): void {
        for (const obs of observations) {
            this.record(obs);
        }
    }

    /**
     * Run full anomaly detection across all recorded endpoints.
     */
    detectAll(): AnomalyReport {
        const start = Date.now();
        const anomalies: Anomaly[] = [];

        anomalies.push(...this.detectUnusualResponses());
        anomalies.push(...this.detectStructureChanges());
        anomalies.push(...this.detectTimingOutliers());

        // Deduplicate by endpoint + type
        const seen = new Set<string>();
        const deduped = anomalies.filter(a => {
            const key = `${a.endpoint}::${a.anomalyType}`;
            if (seen.has(key)) return false;
            seen.add(key);
            return true;
        });

        log.info('Anomaly detection complete', {
            endpoints: this.observations.size,
            anomalies: deduped.length,
            durationMs: Date.now() - start,
        });

        return {
            anomalies: deduped.sort((a, b) => b.confidence - a.confidence),
            totalEndpoints: this.observations.size,
            totalObservations: Array.from(this.observations.values()).reduce((sum, obs) => sum + obs.length, 0),
            durationMs: Date.now() - start,
        };
    }

    /**
     * Detect unusual response lengths.
     * Flags responses significantly larger or smaller than the baseline.
     *
     * Example: Expected 2KB, Actual 20KB → anomaly
     */
    detectUnusualResponses(): Anomaly[] {
        const anomalies: Anomaly[] = [];

        for (const [endpoint, observations] of this.observations.entries()) {
            if (observations.length < MIN_SAMPLES) continue;

            const lengths = observations.map(o => o.contentLength);
            const median = this.median(lengths);
            const mad = this.medianAbsoluteDeviation(lengths);

            if (median === 0) continue;

            // Check recent observations against baseline
            const recent = observations.slice(-3);
            for (const obs of recent) {
                const ratio = obs.contentLength / median;

                if (ratio > LENGTH_ANOMALY_FACTOR || (mad > 0 && Math.abs(obs.contentLength - median) > mad * 3)) {
                    const confidence = Math.min(95, Math.round(50 + (ratio - 1) * 10));
                    anomalies.push({
                        anomalyType: 'response_length',
                        endpoint,
                        confidence,
                        description: `Response length anomaly: expected ~${this.formatBytes(median)}, got ${this.formatBytes(obs.contentLength)} (${ratio.toFixed(1)}x larger)`,
                    });
                    break; // One per endpoint
                }

                if (ratio < 1 / LENGTH_ANOMALY_FACTOR && median > 100) {
                    const confidence = Math.min(90, Math.round(40 + (1 / ratio) * 8));
                    anomalies.push({
                        anomalyType: 'response_length',
                        endpoint,
                        confidence,
                        description: `Response length anomaly: expected ~${this.formatBytes(median)}, got ${this.formatBytes(obs.contentLength)} (${(1 / ratio).toFixed(1)}x smaller)`,
                    });
                    break;
                }
            }
        }

        return anomalies;
    }

    /**
     * Detect structural changes in JSON responses.
     * Compares JSON key sets between baseline and recent responses.
     */
    detectStructureChanges(): Anomaly[] {
        const anomalies: Anomaly[] = [];

        for (const [endpoint, observations] of this.observations.entries()) {
            if (observations.length < MIN_SAMPLES) continue;

            // Get baseline key set (from first half of observations)
            const midpoint = Math.floor(observations.length / 2);
            const baselineObs = observations.slice(0, midpoint);
            const recentObs = observations.slice(midpoint);

            const baselineKeys = this.mergeKeySets(baselineObs.map(o => o.jsonKeys));
            const recentKeys = this.mergeKeySets(recentObs.map(o => o.jsonKeys));

            if (baselineKeys.size === 0 || recentKeys.size === 0) continue;

            const similarity = this.jaccardSimilarity(baselineKeys, recentKeys);

            if (similarity < STRUCTURE_SIMILARITY_THRESHOLD) {
                // Find added/removed keys
                const added = [...recentKeys].filter(k => !baselineKeys.has(k));
                const removed = [...baselineKeys].filter(k => !recentKeys.has(k));

                const confidence = Math.min(95, Math.round((1 - similarity) * 100));

                let description = `JSON structure changed: ${Math.round(similarity * 100)}% similarity`;
                if (added.length > 0) description += `. New keys: ${added.slice(0, 5).join(', ')}`;
                if (removed.length > 0) description += `. Removed keys: ${removed.slice(0, 5).join(', ')}`;

                anomalies.push({
                    anomalyType: 'structure_change',
                    endpoint,
                    confidence,
                    description,
                });
            }
        }

        return anomalies;
    }

    /**
     * Detect timing outliers.
     * Flags responses significantly slower than the baseline.
     *
     * Example: Median 200ms, Actual 1000ms (5x slower) → outlier
     */
    detectTimingOutliers(): Anomaly[] {
        const anomalies: Anomaly[] = [];

        for (const [endpoint, observations] of this.observations.entries()) {
            if (observations.length < MIN_SAMPLES) continue;

            const times = observations.map(o => o.responseTimeMs);
            const med = this.median(times);

            if (med <= 0) continue;

            // Check recent observations
            const recent = observations.slice(-3);
            for (const obs of recent) {
                const ratio = obs.responseTimeMs / med;

                if (ratio >= TIMING_ANOMALY_FACTOR) {
                    const confidence = Math.min(95, Math.round(40 + ratio * 5));
                    anomalies.push({
                        anomalyType: 'timing_outlier',
                        endpoint,
                        confidence,
                        description: `Timing anomaly: median ${Math.round(med)}ms, actual ${Math.round(obs.responseTimeMs)}ms (${ratio.toFixed(1)}x slower)`,
                    });
                    break;
                }
            }
        }

        return anomalies;
    }

    /**
     * Clear all observations (useful between scans).
     */
    clear(): void {
        this.observations.clear();
    }

    // ─── Statistics ───────────────────────────────────────────────────────

    private median(values: number[]): number {
        if (values.length === 0) return 0;
        const sorted = [...values].sort((a, b) => a - b);
        const mid = Math.floor(sorted.length / 2);
        return sorted.length % 2 !== 0
            ? sorted[mid]
            : (sorted[mid - 1] + sorted[mid]) / 2;
    }

    private medianAbsoluteDeviation(values: number[]): number {
        const med = this.median(values);
        const deviations = values.map(v => Math.abs(v - med));
        return this.median(deviations);
    }

    private jaccardSimilarity(a: Set<string>, b: Set<string>): number {
        let intersection = 0;
        for (const item of a) {
            if (b.has(item)) intersection++;
        }
        const union = a.size + b.size - intersection;
        return union === 0 ? 1 : intersection / union;
    }

    private mergeKeySets(keyArrays: string[][]): Set<string> {
        const merged = new Set<string>();
        for (const keys of keyArrays) {
            for (const key of keys) {
                merged.add(key);
            }
        }
        return merged;
    }

    private formatBytes(bytes: number): string {
        if (bytes < 1024) return `${bytes}B`;
        if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)}KB`;
        return `${(bytes / (1024 * 1024)).toFixed(1)}MB`;
    }
}
