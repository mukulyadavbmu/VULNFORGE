/**
 * Part 4 — RiskAnalyzerV2
 * Extends RiskAnalyzer via composition (wrapping).
 * Adds ScoreBreakdown. Original RiskAnalyzer remains untouched.
 */
import { AttackNode, ScanFinding } from '../../types';
import { ScoreBreakdown, KnowledgeSummary } from '../../strategy.types';
import { RiskAnalyzer } from './RiskAnalyzer';
import { logger } from '../../utils/logger';

const log = logger.child({ module: 'RiskAnalyzerV2' });

const SENSITIVE_KEYWORDS = [
    'admin', 'login', 'passwd', 'password', 'config', 'user', 'account',
    'billing', 'payment', 'reset', 'auth', 'token', 'key', 'secret',
    'dashboard', 'private', 'upload', 'file', 'graphql',
];

const RISKY_PARAMS = ['id', 'uuid', 'file', 'path', 'url', 'redirect', 'cmd', 'exec', 'query', 'sql'];

export class RiskAnalyzerV2 {
    /**
     * Calculate detailed score breakdown for a node.
     * Backward compatible: baseRisk comes from original RiskAnalyzer.
     */
    static calculateBreakdown(
        node: AttackNode,
        findings: ScanFinding[],
        knowledge: KnowledgeSummary,
    ): ScoreBreakdown {
        const start = Date.now();

        // Base risk from original analyzer (unchanged)
        const baseRisk = RiskAnalyzer.calculateNodeRisk(node);

        // Auth weight
        let authWeight = 0;
        if (node.authContext === 'guest') authWeight = 1;
        else if (node.authContext === 'userA') authWeight = 3;
        else authWeight = 5; // userB -> multi-role

        // Parameter weight
        let paramWeight = 0;
        if (node.params && node.params.length > 0) {
            paramWeight = Math.min(node.params.length, 3); // Cap at 3
            for (const p of node.params) {
                if (RISKY_PARAMS.some(rp => p.toLowerCase().includes(rp))) {
                    paramWeight += 2;
                }
            }
            paramWeight = Math.min(paramWeight, 10);
        }

        // History weight
        let historyWeight = 0;
        const urlLower = node.url.toLowerCase();
        for (const success of knowledge.pastSuccesses) {
            if (urlLower.includes(success.context.toLowerCase())) {
                historyWeight += 3;
            }
        }
        historyWeight = Math.min(historyWeight, 10);

        // Keyword weight
        let keywordWeight = 0;
        for (const kw of SENSITIVE_KEYWORDS) {
            if (urlLower.includes(kw)) keywordWeight += 1;
        }
        keywordWeight = Math.min(keywordWeight, 10);

        const durationMs = Date.now() - start;
        log.debug('Score breakdown calculated', {
            endpointId: node.id,
            baseRisk,
            durationMs,
        });

        return {
            baseRisk,
            authWeight,
            paramWeight,
            historyWeight,
            keywordWeight,
        };
    }

    /**
     * Convenience: calculate combined score from breakdown.
     */
    static combinedScore(breakdown: ScoreBreakdown): number {
        return (
            breakdown.baseRisk * 0.3 +
            breakdown.authWeight * 0.15 +
            breakdown.paramWeight * 0.2 +
            breakdown.historyWeight * 0.2 +
            breakdown.keywordWeight * 0.15
        );
    }
}
