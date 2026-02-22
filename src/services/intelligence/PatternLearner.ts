import { ScanFinding } from '../../types';
import { logger } from '../../utils/logger';

export class PatternLearner {
    /**
     * Analyzes findings to identify which attack types are successful against specific tech stacks or contexts.
     * This is a simplified version; in a real ML system this would training a model.
     * Here we just look for frequency correlations.
     */
    static analyzePatterns(findings: ScanFinding[]): string[] {
        const patterns: string[] = [];

        // 1. Frequency Analysis
        const typeCounts: Record<string, number> = {};
        findings.forEach(f => {
            typeCounts[f.type] = (typeCounts[f.type] || 0) + 1;
        });

        for (const [type, count] of Object.entries(typeCounts)) {
            if (count > 2) {
                patterns.push(`Recurring Weakness: ${type} found ${count} times.`);
            }
        }

        // 2. Parameter Correlation (e.g., "id" parameter often vulnerable)
        // We need finding metadata for this, assuming evidence contains param info or we infer it.
        // For now, heuristic based on evidence text.
        const idorCount = findings.filter(f => f.type === 'idor' || f.type === 'bac').length;
        if (idorCount > 1) {
            patterns.push('High susceptibility to Access Control (IDOR/BAC) issues.');
        }

        const injectionCount = findings.filter(f => ['sqli', 'xss', 'ssti', 'lfi'].includes(f.type)).length;
        if (injectionCount > 2) {
            patterns.push('Application appears highly vulnerable to Injection attacks.');
        }

        return patterns;
    }
}
