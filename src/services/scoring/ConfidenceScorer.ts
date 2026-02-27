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
            case 'rce': score += 10; break;
            case 'clickjacking': score = 90; break;
            case 'cors': score = 90; break;
            case 'csrf': score = 80; break;
            case 'cache_deception': score = 75; break;
            case 'race_condition': score = 60; break;
            case 'proto_pollution': score = 70; break;
            case 'anomaly': score = 30; break;
        }

        return Math.min(Math.max(score, 0), 100);
    }
}
