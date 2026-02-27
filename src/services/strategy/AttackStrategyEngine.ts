/**
 * Part 1 — AttackStrategyEngine
 * Deterministic weighted scoring to select next attack.
 * O(n) single-pass over endpoint list.
 * AI is never used for core logic.
 */
import { AttackNode, ScanFinding } from '../../types';
import {
    NextAttackDecision,
    StrategyInput,
    ScoringWeights,
    EndpointScore,
    KnowledgeSummary,
} from '../../strategy.types';
import { strategyFlags } from '../../strategyConfig';
import { RiskAnalyzer } from './RiskAnalyzer';
import { logger } from '../../utils/logger';

const log = logger.child({ module: 'AttackStrategyEngine' });

// Attack types matched to tech stacks for techMatchScore
const TECH_ATTACK_MAP: Record<string, string[]> = {
    'Node.js': ['proto_pollution_probe', 'nosqli_probe', 'ssti_probe'],
    'Express': ['proto_pollution_probe', 'nosqli_probe', 'config_probe'],
    'PHP': ['sqli_probe', 'path_traversal_probe', 'file_upload_probe', 'rce_probe'],
    'Django': ['ssti_probe', 'csrf_probe', 'sqli_probe'],
    'Laravel': ['sqli_probe', 'file_upload_probe', 'csrf_probe'],
    'Java': ['ssti_probe', 'rce_probe', 'sqli_probe'],
    'ASP.NET': ['sqli_probe', 'path_traversal_probe', 'rce_probe'],
    'Flask/Werkzeug': ['ssti_probe', 'config_probe', 'path_traversal_probe'],
    'React': ['xss_probe', 'clickjacking_probe'],
    'Next.js': ['ssrf_probe', 'xss_probe', 'cors_probe'],
};

// Escalation level determines probe depth
const ESCALATION_ATTACK_TYPES: Record<number, string[]> = {
    1: ['repeat_as_guest', 'cross_role_access', 'config_probe', 'clickjacking_probe', 'cors_probe'],
    2: ['sqli_probe', 'xss_probe', 'nosqli_probe', 'csrf_probe', 'id_tamper', 'graphql_probe'],
    3: ['ssrf_probe', 'ssti_probe', 'path_traversal_probe', 'file_upload_probe', 'rce_probe', 'websocket_probe'],
    4: ['race_condition_probe', 'cache_deception_probe', 'proto_pollution_probe', 'graphql_deep_probe'],
};

// Sensitive URL keywords for endpointSensitivity
const SENSITIVITY_KEYWORDS = [
    'admin', 'dashboard', 'billing', 'payment', 'user', 'account',
    'password', 'auth', 'token', 'secret', 'private', 'upload', 'config',
];

export class AttackStrategyEngine {
    private executedSet: Set<string> = new Set();

    /**
     * Select next optimal attack. O(n) over endpoints.
     * Returns null if no viable attacks remain.
     */
    selectNextAttack(input: StrategyInput): NextAttackDecision | null {
        if (!strategyFlags.ENABLE_STRATEGY_ENGINE) return null;

        const start = Date.now();
        const { scanId, endpointList, existingFindings, knowledgeSummary } = input;

        // Build executed key set from existing findings
        this.buildExecutedSet(existingFindings);

        let bestScore: EndpointScore | null = null;

        // O(n) single pass
        for (const endpoint of endpointList) {
            const scored = this.scoreEndpoint(endpoint, existingFindings, knowledgeSummary);
            if (scored && (!bestScore || scored.finalScore > bestScore.finalScore)) {
                bestScore = scored;
            }
        }

        const durationMs = Date.now() - start;

        if (!bestScore) {
            log.info('No viable attacks found', { scanId, durationMs });
            return null;
        }

        const decision: NextAttackDecision = {
            endpointId: bestScore.endpointId,
            attackType: bestScore.bestAttackType,
            escalationLevel: bestScore.escalationLevel,
            confidence: Math.round(bestScore.finalScore * 100) / 100,
            reason: this.buildReason(bestScore),
        };

        log.info('Attack decision made', {
            scanId,
            endpointId: decision.endpointId,
            decisionId: `${scanId}:${decision.endpointId}:${decision.attackType}`,
            durationMs,
        });

        return decision;
    }

    private buildExecutedSet(findings: ScanFinding[]): void {
        for (const f of findings) {
            // Key: url:type to avoid re-probing same endpoint with same attack class
            this.executedSet.add(`${f.url}:${f.type}`);
        }
    }

    private scoreEndpoint(
        node: AttackNode,
        findings: ScanFinding[],
        knowledge: KnowledgeSummary,
    ): EndpointScore | null {
        const baseRisk = (node.riskScore ?? RiskAnalyzer.calculateNodeRisk(node)) / 10; // 0-1

        const endpointSensitivity = this.calculateSensitivity(node);
        const parameterScore = this.calculateParameterScore(node);
        const authWeight = this.calculateAuthWeight(node);
        const historicalSuccess = this.calculateHistoricalSuccess(node, knowledge);
        const techMatchScore = this.calculateTechMatchScore(node, knowledge);

        const finalScore =
            baseRisk * 0.3 +
            endpointSensitivity * 0.2 +
            parameterScore * 0.1 +
            authWeight * 0.1 +
            historicalSuccess * 0.2 +
            techMatchScore * 0.1;

        // Determine best attack type and escalation level
        const attackSelection = this.selectAttackType(node, findings, knowledge);
        if (!attackSelection) return null; // All attacks exhausted for this endpoint

        return {
            endpointId: node.id,
            finalScore,
            weights: {
                riskScore: baseRisk,
                endpointSensitivity,
                parameterScore,
                authWeight,
                historicalSuccess,
                techMatchScore,
            },
            bestAttackType: attackSelection.type,
            escalationLevel: attackSelection.level,
        };
    }

    private calculateSensitivity(node: AttackNode): number {
        const lower = node.url.toLowerCase();
        let score = 0;
        for (const kw of SENSITIVITY_KEYWORDS) {
            if (lower.includes(kw)) score += 0.15;
        }
        return Math.min(score, 1);
    }

    private calculateParameterScore(node: AttackNode): number {
        if (!node.params || node.params.length === 0) return 0;
        const riskyParams = ['id', 'file', 'path', 'url', 'redirect', 'cmd', 'query', 'sql', 'token'];
        let score = Math.min(node.params.length * 0.1, 0.4); // Base from count
        for (const p of node.params) {
            if (riskyParams.some(rp => p.toLowerCase().includes(rp))) {
                score += 0.15;
            }
        }
        return Math.min(score, 1);
    }

    private calculateAuthWeight(node: AttackNode): number {
        // Authenticated endpoints are higher value targets
        if (node.authContext === 'guest') return 0.2;
        if (node.authContext === 'userA') return 0.6;
        return 0.8; // userB implies multi-role, higher value
    }

    private calculateHistoricalSuccess(node: AttackNode, knowledge: KnowledgeSummary): number {
        if (knowledge.pastSuccesses.length === 0) return 0;
        // Check if any past success matches this endpoint's characteristics
        let score = 0;
        for (const success of knowledge.pastSuccesses) {
            if (node.url.toLowerCase().includes(success.context.toLowerCase())) {
                score += 0.3;
            }
        }
        return Math.min(score, 1);
    }

    private calculateTechMatchScore(node: AttackNode, knowledge: KnowledgeSummary): number {
        if (knowledge.techStack.length === 0) return 0.5; // Unknown stack = neutral
        // No attack type to match yet at scoring time — this weights endpoints that
        // belong to tech stacks with known attack surfaces
        let matches = 0;
        for (const tech of knowledge.techStack) {
            if (TECH_ATTACK_MAP[tech]) matches++;
        }
        return Math.min(matches * 0.25, 1);
    }

    private selectAttackType(
        node: AttackNode,
        findings: ScanFinding[],
        knowledge: KnowledgeSummary,
    ): { type: string; level: 1 | 2 | 3 | 4 } | null {
        // Try escalation levels 1-4, picking the first non-redundant attack
        for (const level of [1, 2, 3, 4] as const) {
            const attacks = ESCALATION_ATTACK_TYPES[level];
            for (const attackType of attacks) {
                const key = `${node.url}:${attackType}`;
                if (!this.executedSet.has(key)) {
                    this.executedSet.add(key); // Mark as planned
                    return { type: attackType, level };
                }
            }
        }
        return null; // All exhausted
    }

    private buildReason(score: EndpointScore): string {
        const w = score.weights;
        const parts: string[] = [];
        if (w.riskScore > 0.5) parts.push('high-risk endpoint');
        if (w.endpointSensitivity > 0.3) parts.push('sensitive URL pattern');
        if (w.parameterScore > 0.3) parts.push('risky parameters detected');
        if (w.historicalSuccess > 0) parts.push('historical success on similar endpoints');
        if (w.techMatchScore > 0.5) parts.push('tech stack matches attack surface');
        return parts.join('; ') || 'standard probe selection';
    }
}
