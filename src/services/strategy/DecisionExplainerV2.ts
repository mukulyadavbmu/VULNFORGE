/**
 * Phase 8 Part 3+5 — DecisionExplainerV2
 * Extends DecisionExplainer with:
 * - Escalation context
 * - Workflow state
 * - Payload success influence
 * - Multi-step decision chains
 * Does NOT modify original DecisionExplainer.
 */
import {
    NextAttackDecision,
    ScoringWeights,
    EnhancedDecisionExplanation,
    WorkflowStateType,
} from '../../strategy.types';
import { strategyFlags } from '../../strategyConfig';
import { DecisionExplainer } from './DecisionExplainer';
import { logger } from '../../utils/logger';

const log = logger.child({ module: 'DecisionExplainerV2' });

export class DecisionExplainerV2 {
    /**
     * Build enhanced explanation with escalation, workflow, payload influence, and step chain.
     * Wraps original DecisionExplainer.explain().
     */
    static explain(
        decision: NextAttackDecision,
        weights: ScoringWeights,
        scanId: string,
        context: {
            escalationLevel: 1 | 2 | 3 | 4;
            escalationReason: string;
            workflowState: WorkflowStateType;
            transitionReason: string;
            payloadSuccessRate: number;
            chainTriggerFinding?: string;
        },
        aiReasoning?: string,
    ): EnhancedDecisionExplanation {
        const start = Date.now();

        // Get base explanation from original
        const base = DecisionExplainer.explain(decision, weights, scanId, aiReasoning);

        // Build multi-step decision chain
        const decisionSteps: string[] = [];

        // Step 1: Risk assessment
        if (weights.riskScore > 0.5) {
            decisionSteps.push(`Endpoint risk score high (${(weights.riskScore * 10).toFixed(1)}/10)`);
        } else {
            decisionSteps.push(`Endpoint risk score moderate (${(weights.riskScore * 10).toFixed(1)}/10)`);
        }

        // Step 2: Workflow state
        decisionSteps.push(`Workflow state: ${context.workflowState}`);

        // Step 3: Signal detection
        if (context.chainTriggerFinding) {
            decisionSteps.push(`Vulnerability signal detected: ${context.chainTriggerFinding}`);
        }

        // Step 4: Escalation decision
        if (context.escalationLevel > 1) {
            decisionSteps.push(`Escalation to level ${context.escalationLevel}: ${context.escalationReason}`);
        }

        // Step 5: Payload history
        if (context.payloadSuccessRate > 0) {
            decisionSteps.push(`Payload history boost: ${(context.payloadSuccessRate * 100).toFixed(0)}% prior success rate`);
        }

        // Step 6: Attack selection
        decisionSteps.push(`Selected attack: ${decision.attackType} (confidence: ${decision.confidence.toFixed(2)})`);

        // Build payload success influence text
        let payloadSuccessInfluence = 'No historical payload data';
        if (context.payloadSuccessRate > 0.7) {
            payloadSuccessInfluence = `Strong: ${(context.payloadSuccessRate * 100).toFixed(0)}% success rate — prioritized`;
        } else if (context.payloadSuccessRate > 0.3) {
            payloadSuccessInfluence = `Moderate: ${(context.payloadSuccessRate * 100).toFixed(0)}% success rate — factored in`;
        } else if (context.payloadSuccessRate > 0) {
            payloadSuccessInfluence = `Weak: ${(context.payloadSuccessRate * 100).toFixed(0)}% success rate — minimal weight`;
        }

        const enhanced: EnhancedDecisionExplanation = {
            ...base,
            escalationLevel: context.escalationLevel,
            escalationReason: context.escalationReason,
            workflowState: context.workflowState,
            transitionReason: context.transitionReason,
            payloadSuccessInfluence,
            decisionSteps,
        };

        const durationMs = Date.now() - start;
        log.info('Enhanced explanation generated', {
            event: 'decision.explain',
            scanId,
            decisionId: enhanced.decisionId,
            escalationLevel: context.escalationLevel,
            workflowState: context.workflowState,
            stepCount: decisionSteps.length,
            durationMs,
        });

        return enhanced;
    }
}
