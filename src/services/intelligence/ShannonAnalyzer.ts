/**
 * ShannonAnalyzer — Shannon entropy calculator for response content.
 * Detects anomalous, random, or encrypted content.
 * Does NOT store full bodies — operates on snippets only.
 */
import { logger } from '../../utils/logger';

const log = logger.child({ module: 'ShannonAnalyzer' });

export interface ShannonResult {
    entropy: number;          // 0-8 bits (log2 256)
    deviation: number;        // Distance from baseline entropy (0-1 normalized)
    anomalyScore: number;     // 0-1, higher = more anomalous
}

export class ShannonAnalyzer {
    /**
     * Calculate Shannon entropy of a text snippet.
     * Returns entropy in bits (0 to ~8 for byte-level).
     * O(n) — single pass frequency count + log2 calculation.
     */
    static calculateEntropy(text: string): number {
        if (text.length === 0) return 0;

        // Byte frequency map
        const freq: Map<number, number> = new Map();
        for (let i = 0; i < text.length; i++) {
            const code = text.charCodeAt(i);
            freq.set(code, (freq.get(code) ?? 0) + 1);
        }

        // Shannon formula: H = -Σ p(x) * log2(p(x))
        let entropy = 0;
        const len = text.length;
        for (const count of freq.values()) {
            const p = count / len;
            if (p > 0) {
                entropy -= p * Math.log2(p);
            }
        }

        return entropy;
    }

    /**
     * Compare entropy of a test response against a baseline.
     * Returns deviation and anomaly score.
     */
    static compare(
        baselineSnippet: string,
        testSnippet: string,
        endpointId: string,
        scanId: string,
    ): ShannonResult {
        const start = Date.now();

        const baseEntropy = this.calculateEntropy(baselineSnippet);
        const testEntropy = this.calculateEntropy(testSnippet);

        // Deviation: normalized absolute difference
        const maxEntropy = Math.max(baseEntropy, testEntropy, 1); // avoid divide by zero
        const deviation = Math.abs(testEntropy - baseEntropy) / maxEntropy;

        // Anomaly score: considers both entropy level and deviation
        // High entropy (>6 bits) in HTML responses is unusual (suggests encrypted/random data)
        // Low entropy (<2 bits) in API responses is unusual (suggests empty/error)
        let anomalyScore = 0;

        // Deviation contributes 60%
        anomalyScore += deviation * 0.6;

        // Absolute entropy anomaly contributes 40%
        if (testEntropy > 6.5) {
            anomalyScore += 0.4; // Unusually high entropy (encrypted/compressed data)
        } else if (testEntropy < 1.5 && testSnippet.length > 10) {
            anomalyScore += 0.3; // Unusually low entropy (repetitive/error content)
        }

        anomalyScore = Math.min(anomalyScore, 1);

        const durationMs = Date.now() - start;
        log.debug('Shannon analysis complete', {
            event: 'entropyAnalysis',
            scanId,
            endpointId,
            baseEntropy: baseEntropy.toFixed(3),
            testEntropy: testEntropy.toFixed(3),
            deviation: deviation.toFixed(3),
            anomalyScore: anomalyScore.toFixed(3),
            durationMs,
        });

        return {
            entropy: testEntropy,
            deviation,
            anomalyScore,
        };
    }

    /**
     * Batch analyze multiple snippets against a baseline.
     * Returns the one with highest anomaly score.
     */
    static findMostAnomalous(
        baselineSnippet: string,
        testSnippets: string[],
        endpointId: string,
        scanId: string,
    ): { index: number; result: ShannonResult } | null {
        if (testSnippets.length === 0) return null;

        let bestIndex = 0;
        let bestResult = this.compare(baselineSnippet, testSnippets[0], endpointId, scanId);

        for (let i = 1; i < testSnippets.length; i++) {
            const result = this.compare(baselineSnippet, testSnippets[i], endpointId, scanId);
            if (result.anomalyScore > bestResult.anomalyScore) {
                bestResult = result;
                bestIndex = i;
            }
        }

        return { index: bestIndex, result: bestResult };
    }
}
