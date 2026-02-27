/**
 * Part 7 — ConfidenceScorerV2
 * Extends ConfidenceScorer via composition.
 * Adds exploitReliability and stabilityScore.
 * Original ConfidenceScorer remains untouched.
 */
import { ScanFinding } from '../../types';
import { EnhancedConfidenceResult } from '../../strategy.types';
import { ConfidenceScorer } from './ConfidenceScorer';
import { logger } from '../../utils/logger';

const log = logger.child({ module: 'ConfidenceScorerV2' });

/** Types where exploitation is highly reliable when confirmed */
const HIGH_RELIABILITY_TYPES: ReadonlySet<string> = new Set([
    'sqli', 'rce', 'ssrf', 'lfi', 'file_upload',
]);

/** Types that are stable (deterministic, not timing-dependent) */
const STABLE_DETECTION_TYPES: ReadonlySet<string> = new Set([
    'clickjacking', 'cors', 'csrf', 'config', 'info', 'graphql_deep',
]);

/** Types where detection is inherently noisy */
const NOISY_DETECTION_TYPES: ReadonlySet<string> = new Set([
    'race_condition', 'anomaly', 'cache_deception',
]);

export class ConfidenceScorerV2 {
    /**
     * Enhanced confidence scoring with reliability and stability.
     * Wraps original ConfidenceScorer.calculateConfidence().
     */
    static calculate(finding: ScanFinding, scanId: string): EnhancedConfidenceResult {
        const start = Date.now();

        // Base confidence from original scorer (unchanged)
        const baseConfidence = ConfidenceScorer.calculateConfidence(finding);

        // Exploit Reliability (0-100): How reliably can this be exploited?
        let exploitReliability = 50; // Default
        if (HIGH_RELIABILITY_TYPES.has(finding.type)) {
            exploitReliability = 85;
            // Boost further if evidence is strong
            const evidence = finding.evidence.toLowerCase();
            if (evidence.includes('oast') || evidence.includes('root:x:0:0')) {
                exploitReliability = 100;
            }
        } else if (finding.type === 'xss') {
            exploitReliability = 70; // Depends on context
        } else if (finding.type === 'bac' || finding.type === 'idor') {
            exploitReliability = 75;
        } else if (NOISY_DETECTION_TYPES.has(finding.type)) {
            exploitReliability = 30;
        }

        // Stability Score (0-100): How stable/repeatable is this detection?
        let stabilityScore = 60; // Default
        if (STABLE_DETECTION_TYPES.has(finding.type)) {
            stabilityScore = 95; // Header-based checks are deterministic
        } else if (NOISY_DETECTION_TYPES.has(finding.type)) {
            stabilityScore = 35; // Timing-dependent, may not reproduce
        } else if (finding.metrics?.timeDelta && finding.metrics.timeDelta > 2000) {
            stabilityScore = 40; // Timing-based detection
        } else if (finding.metrics?.diffScore && finding.metrics.diffScore > 0.8) {
            stabilityScore = 70; // Content diff is moderately stable
        }

        // Final confidence: weighted blend
        const finalConfidence = Math.round(
            baseConfidence * 0.5 +
            exploitReliability * 0.25 +
            stabilityScore * 0.25
        );

        const durationMs = Date.now() - start;
        log.debug('Enhanced confidence calculated', {
            scanId,
            findingType: finding.type,
            baseConfidence,
            exploitReliability,
            stabilityScore,
            finalConfidence,
            durationMs,
        });

        return {
            baseConfidence,
            exploitReliability,
            stabilityScore,
            finalConfidence: Math.min(Math.max(finalConfidence, 0), 100),
        };
    }
}
