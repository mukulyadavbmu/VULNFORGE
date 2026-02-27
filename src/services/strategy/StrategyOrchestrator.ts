/**
 * StrategyOrchestrator — Integration layer for all intelligent attacker modules.
 * Wires together: AttackStrategyEngine, ChainingEngine, EscalationTracker,
 * EscalationPlaybook, WorkflowState, RedundancyGuard, DecisionExplainerV2.
 *
 * This does NOT modify any existing orchestrator. It provides a standalone
 * entry point that can be called additively from the existing scan loop.
 */
import { AttackNode, ScanFinding, AuthContext } from '../../types';
import {
    NextAttackDecision,
    StrategyInput,
    KnowledgeSummary,
    FollowupAttack,
    EnhancedDecisionExplanation,
    WorkflowStateType,
} from '../../strategy.types';
import { strategyFlags } from '../../strategyConfig';
import { AttackStrategyEngine } from './AttackStrategyEngine';
import { ChainingEngine } from './ChainingEngine';
import { EscalationTracker } from './EscalationTracker';
import { EscalationPlaybook, EscalationAction } from './EscalationPlaybook';
import { WorkflowState } from './WorkflowState';
import { RedundancyGuard } from './RedundancyGuard';
import { DecisionExplainerV2 } from './DecisionExplainerV2';
import { logger } from '../../utils/logger';

const log = logger.child({ module: 'StrategyOrchestrator' });

export interface StrategyDecision {
    attack: NextAttackDecision | null;
    escalationAction: EscalationAction | null;
    followups: FollowupAttack[];
    explanation: EnhancedDecisionExplanation | null;
    workflowState: WorkflowStateType;
    skipped: boolean;
    skipReason?: string;
}

export class StrategyOrchestrator {
    private strategyEngine: AttackStrategyEngine;
    private chainingEngine: ChainingEngine;
    private escalationTracker: EscalationTracker;
    private workflowState: WorkflowState;
    private redundancyGuard: RedundancyGuard;

    constructor() {
        this.strategyEngine = new AttackStrategyEngine();
        this.chainingEngine = new ChainingEngine();
        this.escalationTracker = new EscalationTracker();
        this.workflowState = new WorkflowState();
        this.redundancyGuard = new RedundancyGuard();
    }

    /**
     * Full strategy decision pipeline:
     * 1. Strategy Engine selects next attack
     * 2. RedundancyGuard checks for duplicates
     * 3. EscalationTracker determines escalation level
     * 4. EscalationPlaybook resolves concrete action
     * 5. WorkflowState transitions
     * 6. ChainingEngine generates follow-ups
     * 7. DecisionExplainerV2 builds explanation
     *
     * Returns null-safe StrategyDecision — never throws.
     */
    decide(
        scanId: string,
        endpoints: AttackNode[],
        findings: ScanFinding[],
        knowledge: KnowledgeSummary,
        authContext: AuthContext,
    ): StrategyDecision {
        const start = Date.now();

        // Default result
        const defaultResult: StrategyDecision = {
            attack: null,
            escalationAction: null,
            followups: [],
            explanation: null,
            workflowState: 'RECON',
            skipped: true,
            skipReason: 'Strategy engine disabled',
        };

        if (!strategyFlags.ENABLE_STRATEGY_ENGINE) return defaultResult;

        // 1. Select next attack
        const input: StrategyInput = {
            scanId,
            endpointList: endpoints,
            existingFindings: findings,
            knowledgeSummary: knowledge,
        };

        const attack = this.strategyEngine.selectNextAttack(input);
        if (!attack) {
            return { ...defaultResult, skipReason: 'No viable attacks remaining' };
        }

        // 2. Redundancy check
        const payloadClass = this.getPayloadClass(attack.attackType);
        if (this.redundancyGuard.isDuplicate(attack.endpointId, attack.attackType, payloadClass, authContext)) {
            return { ...defaultResult, skipReason: 'Redundant — already tested' };
        }

        // 3. Escalation level
        let escalationLevel = attack.escalationLevel;
        if (this.escalationTracker.shouldEscalate(attack.endpointId, attack.attackType)) {
            escalationLevel = this.escalationTracker.incrementLevel(
                attack.endpointId,
                attack.attackType,
                'Probe threshold reached',
            );
        }

        // 4. Playbook action
        const escalationAction = EscalationPlaybook.getAction(
            attack.attackType,
            escalationLevel as 1 | 2 | 3 | 4,
        );

        // 5. Workflow transition
        const currentState = this.workflowState.getState(attack.endpointId);
        let workflowState = currentState;

        if (currentState === 'RECON') {
            this.workflowState.transition(attack.endpointId, 'Endpoint selected for probing');
            workflowState = 'PROBE';
        }

        // Check if findings exist for this endpoint → advance workflow
        const endpointFindings = findings.filter(f => f.url === attack.endpointId || f.id === attack.endpointId);
        if (endpointFindings.length > 0 && workflowState === 'PROBE') {
            this.workflowState.transition(attack.endpointId, 'Vulnerability signal detected');
            workflowState = 'EXPLOIT';
        }
        if (escalationLevel >= 3 && workflowState === 'EXPLOIT') {
            this.workflowState.transition(attack.endpointId, 'Exploitation confirmed, pivoting');
            workflowState = 'PIVOT';
        }

        // 6. Chaining follow-ups
        const followups = this.chainingEngine.generateFollowups(findings);

        // 7. Record in redundancy guard
        this.redundancyGuard.record(attack.endpointId, attack.attackType, payloadClass, authContext);
        this.escalationTracker.recordProbe(attack.endpointId, attack.attackType);

        // 8. Explanation
        const explanation = DecisionExplainerV2.explain(
            { ...attack, escalationLevel: escalationLevel as 1 | 2 | 3 | 4 },
            {
                riskScore: attack.confidence,
                endpointSensitivity: 0,
                parameterScore: 0,
                authWeight: 0,
                historicalSuccess: 0,
                techMatchScore: 0,
            },
            scanId,
            {
                escalationLevel: escalationLevel as 1 | 2 | 3 | 4,
                escalationReason: escalationAction.instructions[0],
                workflowState,
                transitionReason: this.workflowState.getLatestTransitionReason(attack.endpointId),
                payloadSuccessRate: 0,
                chainTriggerFinding: endpointFindings.length > 0 ? endpointFindings[0].type : undefined,
            },
        );

        const durationMs = Date.now() - start;
        log.info('Strategy decision complete', {
            event: 'strategyDecision',
            scanId,
            endpointId: attack.endpointId,
            attackType: attack.attackType,
            escalationLevel,
            workflowState,
            followupCount: followups.length,
            durationMs,
        });

        return {
            attack: { ...attack, escalationLevel: escalationLevel as 1 | 2 | 3 | 4 },
            escalationAction,
            followups,
            explanation,
            workflowState,
            skipped: false,
        };
    }

    /**
     * Process new findings — advance workflow states and generate chaining follow-ups.
     * Call this after each attack execution that produces findings.
     */
    onFindingsDiscovered(scanId: string, newFindings: ScanFinding[]): FollowupAttack[] {
        for (const finding of newFindings) {
            // Advance workflow for the endpoint
            const state = this.workflowState.getState(finding.url);
            if (state === 'PROBE') {
                this.workflowState.transition(finding.url, `${finding.type} detected (${finding.severity})`);
            }
            if (state === 'EXPLOIT' && (finding.severity === 'high' || finding.severity === 'critical')) {
                this.workflowState.transition(finding.url, `High-severity ${finding.type} confirmed — pivoting`);
            }
        }

        return this.chainingEngine.generateFollowups(newFindings);
    }

    /** Map attack types to payload classes for redundancy checking. */
    private getPayloadClass(attackType: string): string {
        const classMap: Record<string, string> = {
            sqli_probe: 'injection',
            nosqli_probe: 'injection',
            xss_probe: 'injection',
            ssti_probe: 'injection',
            csti_probe: 'injection',
            rce_probe: 'injection',
            ssrf_probe: 'network',
            oast_probe: 'network',
            cors_probe: 'header',
            clickjacking_probe: 'header',
            csrf_probe: 'header',
            path_traversal_probe: 'file',
            file_upload_probe: 'file',
            id_tamper: 'access',
            cross_role_access: 'access',
            repeat_as_guest: 'access',
            config_probe: 'recon',
            anomaly_probe: 'recon',
            graphql_probe: 'graphql',
            graphql_deep_probe: 'graphql',
            websocket_probe: 'protocol',
            race_condition_probe: 'timing',
            cache_deception_probe: 'cache',
            proto_pollution_probe: 'prototype',
        };
        return classMap[attackType] ?? 'unknown';
    }
}
