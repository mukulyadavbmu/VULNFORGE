/**
 * Part 3 — DecisionExplainer
 * Pure function. Takes scoring data → human-readable explanation.
 * AI reasoning is optional.
 */
import {
    DecisionExplanation,
    NextAttackDecision,
    ScoringWeights,
    EndpointScore,
} from '../../strategy.types';
import { logger } from '../../utils/logger';

const log = logger.child({ module: 'DecisionExplainer' });

export class DecisionExplainer {
    /**
     * Build structured explanation from a decision and its scoring weights.
     * Pure function, no side effects, < 1ms.
     */
    static explain(
        decision: NextAttackDecision,
        weights: ScoringWeights,
        scanId: string,
        aiReasoning?: string,
    ): DecisionExplanation {
        const start = Date.now();
        const decisionId = `${scanId}:${decision.endpointId}:${decision.attackType}`;

        const signalsUsed: string[] = [];
        const riskFactors: string[] = [];
        const historicalInfluence: string[] = [];

        // Analyze which signals contributed
        if (weights.riskScore > 0.5) {
            signalsUsed.push('endpoint_risk_score');
            riskFactors.push(`High base risk (${(weights.riskScore * 10).toFixed(1)}/10)`);
        }

        if (weights.endpointSensitivity > 0.3) {
            signalsUsed.push('url_sensitivity');
            riskFactors.push('URL contains sensitive keywords (admin, payment, auth, etc.)');
        }

        if (weights.parameterScore > 0.3) {
            signalsUsed.push('parameter_analysis');
            riskFactors.push('Endpoint has risky parameters (id, file, redirect, etc.)');
        }

        if (weights.authWeight > 0.5) {
            signalsUsed.push('auth_context');
            riskFactors.push('Authenticated endpoint — higher value target');
        }

        if (weights.historicalSuccess > 0) {
            signalsUsed.push('historical_success');
            historicalInfluence.push(`Past success rate: ${(weights.historicalSuccess * 100).toFixed(0)}%`);
        }

        if (weights.techMatchScore > 0.3) {
            signalsUsed.push('tech_stack_match');
            riskFactors.push('Attack type matches detected tech stack');
        }

        const escalationReasons: Record<number, string> = {
            1: 'Reconnaissance — low-risk passive checks',
            2: 'Active probing — injection and access control tests',
            3: 'Deep exploitation — RCE, SSRF, file-based attacks',
            4: 'Advanced exploitation — race conditions, prototype pollution, deep GraphQL',
        };

        const explanation: DecisionExplanation = {
            decisionId,
            signalsUsed,
            escalationReason: escalationReasons[decision.escalationLevel] ?? 'Unknown escalation level',
            riskFactors,
            historicalInfluence,
            aiReasoning,
        };

        const durationMs = Date.now() - start;
        log.debug('Explanation generated', { scanId, decisionId, durationMs });

        return explanation;
    }
}
