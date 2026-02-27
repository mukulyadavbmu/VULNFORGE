/**
 * VulnForge Phase 7 — Feature Flags for Intelligent Attacker Behavior
 * Separate from config.ts to avoid modifying existing code.
 * All flags default to false.
 */

export interface StrategyFlags {
    ENABLE_STRATEGY_ENGINE: boolean;
    ENABLE_CHAINING_ENGINE: boolean;
    ENABLE_ENTROPY_ANALYSIS: boolean;
    ENABLE_CORRELATION_ENGINE: boolean;
    ENABLE_PRIVILEGE_MODELING: boolean;
    // Phase 8
    ENABLE_ESCALATION_TRACKER: boolean;
    ENABLE_WORKFLOW_STATE: boolean;
    ENABLE_PERSISTENT_REDUNDANCY: boolean;
    ENABLE_DECISION_CHAINS: boolean;
    REDUNDANCY_WINDOW_HOURS: number;
}

const parseBool = (val: string | undefined): boolean =>
    val === 'true' || val === '1';

export const strategyFlags: StrategyFlags = {
    ENABLE_STRATEGY_ENGINE: parseBool(process.env.ENABLE_STRATEGY_ENGINE),
    ENABLE_CHAINING_ENGINE: parseBool(process.env.ENABLE_CHAINING_ENGINE),
    ENABLE_ENTROPY_ANALYSIS: parseBool(process.env.ENABLE_ENTROPY_ANALYSIS),
    ENABLE_CORRELATION_ENGINE: parseBool(process.env.ENABLE_CORRELATION_ENGINE),
    ENABLE_PRIVILEGE_MODELING: parseBool(process.env.ENABLE_PRIVILEGE_MODELING),
    // Phase 8
    ENABLE_ESCALATION_TRACKER: parseBool(process.env.ENABLE_ESCALATION_TRACKER),
    ENABLE_WORKFLOW_STATE: parseBool(process.env.ENABLE_WORKFLOW_STATE),
    ENABLE_PERSISTENT_REDUNDANCY: parseBool(process.env.ENABLE_PERSISTENT_REDUNDANCY),
    ENABLE_DECISION_CHAINS: parseBool(process.env.ENABLE_DECISION_CHAINS),
    REDUNDANCY_WINDOW_HOURS: parseInt(process.env.REDUNDANCY_WINDOW_HOURS ?? '24', 10),
};
