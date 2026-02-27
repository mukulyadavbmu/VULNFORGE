/**
 * VulnForge Phase 7 — Shared DTOs for Intelligent Attacker Behavior
 * All types used across Parts 1-9 are defined here.
 * No existing types are modified.
 */
import { ScanFinding, AttackNode, AuthContext } from './types';

// ─── Part 1: AttackStrategyEngine ───────────────────────────────────────────

export interface NextAttackDecision {
    endpointId: string;
    attackType: string;
    escalationLevel: 1 | 2 | 3 | 4;
    confidence: number;
    reason: string;
}

export interface StrategyInput {
    scanId: string;
    endpointList: AttackNode[];
    existingFindings: ScanFinding[];
    knowledgeSummary: KnowledgeSummary;
}

export interface KnowledgeSummary {
    techStack: string[];
    pastSuccesses: PastSuccess[];
}

export interface PastSuccess {
    vulnType: string;
    context: string;
}

export interface ScoringWeights {
    riskScore: number;
    endpointSensitivity: number;
    parameterScore: number;
    authWeight: number;
    historicalSuccess: number;
    techMatchScore: number;
}

export interface EndpointScore {
    endpointId: string;
    finalScore: number;
    weights: ScoringWeights;
    bestAttackType: string;
    escalationLevel: 1 | 2 | 3 | 4;
}

// ─── Part 2: ChainingEngine ────────────────────────────────────────────────

export interface FollowupAttack {
    endpointId: string;
    attackType: string;
    escalationLevel: number;
    triggerFindingId: string;
}

export type ChainingRule = {
    triggerType: ScanFinding['type'];
    followupAttackType: string;
    escalationLevel: number;
    description: string;
};

// ─── Part 3: DecisionExplainer ─────────────────────────────────────────────

export interface DecisionExplanation {
    decisionId: string;
    signalsUsed: string[];
    escalationReason: string;
    riskFactors: string[];
    historicalInfluence: string[];
    aiReasoning?: string;
}

// ─── Part 4: RiskAnalyzerV2 ────────────────────────────────────────────────

export interface ScoreBreakdown {
    baseRisk: number;
    authWeight: number;
    paramWeight: number;
    historyWeight: number;
    keywordWeight: number;
}

// ─── Part 5: CorrelationEngine ─────────────────────────────────────────────

export interface CorrelationResult {
    systemicWeaknessScore: number;
    recurringPatternList: string[];
    injectionLikelihood: number;
    authWeaknessLikelihood: number;
}

// ─── Part 6: EntropyAnalyzer ───────────────────────────────────────────────

export interface ResponseSignature {
    statusCode: number;
    contentLength: number;
    headerCount: number;
    structuralHash: number;
}

export interface EntropyResult {
    entropyScore: number;
    anomalyScore: number;
    baselineDeviation: number;
}

// ─── Part 7: ConfidenceScorerV2 ────────────────────────────────────────────

export interface EnhancedConfidenceResult {
    baseConfidence: number;
    exploitReliability: number;
    stabilityScore: number;
    finalConfidence: number;
}

// ─── Part 8: PrivilegeModeler ──────────────────────────────────────────────

export interface PrivilegeModelResult {
    escalationPaths: string[];
    privilegeRiskScore: number;
}

export interface AuthFinding {
    findingId: string;
    url: string;
    type: ScanFinding['type'];
    authContext: AuthContext;
    severity: ScanFinding['severity'];
}

// ─── Part 9: SaaS Foundations ──────────────────────────────────────────────

export interface APIKey {
    id: string;
    tenantId: string;
    keyHash: string;
    createdAt: number;
    revokedAt?: number;
    isActive: boolean;
}

export interface TenantInfo {
    tenantId: string;
    name: string;
    apiKeyId: string;
}

export interface ScheduledScan {
    id: string;
    tenantId: string;
    targetUrl: string;
    cronExpression: string;
    lastRunAt?: number;
    nextRunAt: number;
    enabled: boolean;
}

// ─── Phase 8: Attacker Behavior Realism ────────────────────────────────────

export type WorkflowStateType = 'RECON' | 'PROBE' | 'EXPLOIT' | 'PIVOT' | 'CONFIRM';

export interface EscalationRecord {
    endpointId: string;
    attackType: string;
    currentLevel: 1 | 2 | 3 | 4;
    lastEscalatedAt: number;
    reason: string;
}

export interface WorkflowTransition {
    endpointId: string;
    fromState: WorkflowStateType;
    toState: WorkflowStateType;
    reason: string;
    timestamp: number;
}

export interface EnhancedDecisionExplanation extends DecisionExplanation {
    escalationLevel: 1 | 2 | 3 | 4;
    workflowState: WorkflowStateType;
    transitionReason: string;
    payloadSuccessInfluence: string;
    decisionSteps: string[];
}

export interface ExtendedScoringWeights extends ScoringWeights {
    payloadSuccessWeight: number;
    workflowStateWeight: number;
}

export interface RedundancyCheck {
    endpointId: string;
    attackType: string;
    authContext: string;
    testedAt: number;
}
