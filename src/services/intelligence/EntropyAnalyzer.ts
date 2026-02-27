/**
 * Part 6 — EntropyAnalyzer
 * Compares response signatures without storing full bodies.
 * Uses: length, header count, status code, structural hash.
 */
import { ResponseSignature, EntropyResult } from '../../strategy.types';
import { strategyFlags } from '../../strategyConfig';
import { logger } from '../../utils/logger';

const log = logger.child({ module: 'EntropyAnalyzer' });

export class EntropyAnalyzer {
    /**
     * Create a lightweight signature from response metadata.
     * Never stores full body — only length, headerCount, statusCode, and structural hash.
     */
    static createSignature(
        statusCode: number,
        contentLength: number,
        headers: Record<string, string>,
        bodySnippet: string,
    ): ResponseSignature {
        return {
            statusCode,
            contentLength,
            headerCount: Object.keys(headers).length,
            structuralHash: EntropyAnalyzer.hashSnippet(bodySnippet),
        };
    }

    /**
     * Compare two response signatures to detect anomalies.
     * Returns entropy/anomaly/deviation scores (0-1).
     */
    static compare(
        baseline: ResponseSignature,
        test: ResponseSignature,
        endpointId: string,
        scanId: string,
    ): EntropyResult {
        if (!strategyFlags.ENABLE_ENTROPY_ANALYSIS) {
            return { entropyScore: 0, anomalyScore: 0, baselineDeviation: 0 };
        }

        const start = Date.now();

        // Length deviation (0-1): how much the length changed relative to baseline
        const lengthDelta = baseline.contentLength > 0
            ? Math.abs(test.contentLength - baseline.contentLength) / baseline.contentLength
            : (test.contentLength > 0 ? 1 : 0);

        // Status code change: binary signal
        const statusChange = baseline.statusCode !== test.statusCode ? 1 : 0;

        // Header count deviation
        const headerDelta = baseline.headerCount > 0
            ? Math.abs(test.headerCount - baseline.headerCount) / baseline.headerCount
            : 0;

        // Structural hash comparison (0 = identical, 1 = completely different)
        const hashDelta = baseline.structuralHash !== test.structuralHash ? 1 : 0;

        // Entropy score: weighted combination
        const entropyScore = Math.min(
            lengthDelta * 0.3 + statusChange * 0.3 + headerDelta * 0.1 + hashDelta * 0.3,
            1,
        );

        // Anomaly score: higher if multiple signals diverge
        const divergentSignals = [
            lengthDelta > 0.2 ? 1 : 0,
            statusChange,
            headerDelta > 0.3 ? 1 : 0,
            hashDelta,
        ].reduce((a, b) => a + b, 0);

        const anomalyScore = Math.min(divergentSignals / 4, 1);

        // Baseline deviation: raw distance metric
        const baselineDeviation = Math.min(
            (lengthDelta + statusChange + headerDelta + hashDelta) / 4,
            1,
        );

        const durationMs = Date.now() - start;
        log.debug('Entropy analysis complete', {
            scanId,
            endpointId,
            entropyScore: entropyScore.toFixed(3),
            anomalyScore: anomalyScore.toFixed(3),
            durationMs,
        });

        return { entropyScore, anomalyScore, baselineDeviation };
    }

    /**
     * Lightweight structural hash of a body snippet.
     * Hashes first 200 chars to detect structural changes without storing body.
     * DJB2 hash — fast, deterministic, no crypto dependency.
     */
    private static hashSnippet(snippet: string): number {
        const s = snippet.slice(0, 200);
        let hash = 5381;
        for (let i = 0; i < s.length; i++) {
            hash = ((hash << 5) + hash + s.charCodeAt(i)) | 0; // hash * 33 + c
        }
        return hash >>> 0; // Ensure unsigned
    }
}
