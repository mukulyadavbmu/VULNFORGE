/**
 * Part 5 — CorrelationEngine
 * Correlates findings to detect systemic weaknesses.
 * Uses finding summaries only — never raw DB scans.
 * O(n) single pass over findings.
 */
import { ScanFinding } from '../../types';
import { CorrelationResult } from '../../strategy.types';
import { strategyFlags } from '../../strategyConfig';
import { logger } from '../../utils/logger';

const log = logger.child({ module: 'CorrelationEngine' });

const INJECTION_TYPES: ReadonlySet<string> = new Set([
    'sqli', 'xss', 'ssti', 'csti', 'rce', 'lfi', 'proto_pollution',
]);

const AUTH_TYPES: ReadonlySet<string> = new Set([
    'bac', 'idor', 'csrf', 'cors', 'websocket', 'auth_weakness',
]);

export class CorrelationEngine {
    /**
     * Analyze findings for systemic patterns.
     * O(n) single pass. No DB calls.
     */
    static correlate(findings: ScanFinding[], scanId: string): CorrelationResult {
        if (!strategyFlags.ENABLE_CORRELATION_ENGINE) {
            return {
                systemicWeaknessScore: 0,
                recurringPatternList: [],
                injectionLikelihood: 0,
                authWeaknessLikelihood: 0,
            };
        }

        const start = Date.now();

        // Type frequency map — O(n) single pass
        const typeCount: Map<string, number> = new Map();
        const severityCount: Record<string, number> = { low: 0, medium: 0, high: 0, critical: 0 };
        let injectionFindings = 0;
        let authFindings = 0;

        for (const finding of findings) {
            // Count by type
            typeCount.set(finding.type, (typeCount.get(finding.type) ?? 0) + 1);
            // Count by severity
            severityCount[finding.severity]++;
            // Categorize
            if (INJECTION_TYPES.has(finding.type)) injectionFindings++;
            if (AUTH_TYPES.has(finding.type)) authFindings++;
        }

        // Recurring patterns: any type found 2+ times
        const recurringPatternList: string[] = [];
        for (const [type, count] of typeCount) {
            if (count >= 2) {
                recurringPatternList.push(`${type} (${count} occurrences)`);
            }
        }

        // Systemic weakness score: 0-100
        // Based on: variety of vuln types, severity distribution, recurrence
        const uniqueTypes = typeCount.size;
        const totalFindings = findings.length;
        const criticalRatio = totalFindings > 0 ? (severityCount.critical + severityCount.high) / totalFindings : 0;
        const recurrenceRatio = totalFindings > 0 ? recurringPatternList.length / uniqueTypes : 0;

        const systemicWeaknessScore = Math.min(
            Math.round(
                (uniqueTypes * 5) +          // More unique types = broader weakness
                (criticalRatio * 40) +       // High severity ratio
                (recurrenceRatio * 30) +     // Recurrence indicates systemic
                (totalFindings > 10 ? 20 : totalFindings * 2) // Volume factor
            ),
            100,
        );

        // Likelihood scores: 0-1
        const injectionLikelihood = totalFindings > 0
            ? Math.min(injectionFindings / totalFindings + (injectionFindings > 3 ? 0.2 : 0), 1)
            : 0;

        const authWeaknessLikelihood = totalFindings > 0
            ? Math.min(authFindings / totalFindings + (authFindings > 3 ? 0.2 : 0), 1)
            : 0;

        const durationMs = Date.now() - start;
        log.info('Correlation complete', {
            scanId,
            systemicWeaknessScore,
            patternCount: recurringPatternList.length,
            durationMs,
        });

        return {
            systemicWeaknessScore,
            recurringPatternList,
            injectionLikelihood,
            authWeaknessLikelihood,
        };
    }
}
