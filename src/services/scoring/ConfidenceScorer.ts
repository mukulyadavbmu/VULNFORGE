import { ScanFinding } from '../../types';

export class ConfidenceScorer {
    static calculateConfidence(finding: ScanFinding): number {
        let score = 50; // Base confidence

        // 1. Evidence Quality
        const evidence = finding.evidence.toLowerCase();

        // High Confidence Signals
        if (evidence.includes('oast interaction') || evidence.includes('dns callback')) return 100;
        if (evidence.includes('root:x:0:0') || evidence.includes('win.ini')) return 100; // Proof of LFI
        if (evidence.includes('syntax error') && finding.type === 'sqli') score += 30; // Strong indicator
        if (evidence.includes('alert(1)') || evidence.includes('xss_test')) score += 20;

        // Medium Confidence Signals
        if (evidence.includes('time delta') || evidence.includes('delay')) {
            // Timing attacks are noisy
            score = 60;
        }
        if (evidence.includes('diff=')) {
            // Heuristic diff
            score = 65;
        }

        // 2. Type Baseline
        switch (finding.type) {
            case 'rce': score += 10; break; // Usually distinct errors
            case 'clickjacking': score = 90; // Header check is deterministic
            case 'cors': score = 90; // Header check is deterministic
            case 'csrf': score = 80; // Cookie check is reliable
            case 'anomaly': score = 30; // Very vague
        }

        return Math.min(Math.max(score, 0), 100);
    }
}
