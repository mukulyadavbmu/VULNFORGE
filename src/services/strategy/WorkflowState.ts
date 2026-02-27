/**
 * Phase 8 Part 2 — WorkflowState
 * Tracks attacker workflow state per endpoint.
 * RECON → PROBE → EXPLOIT → PIVOT → CONFIRM
 */
import { WorkflowStateType, WorkflowTransition } from '../../strategy.types';
import { strategyFlags } from '../../strategyConfig';
import { logger } from '../../utils/logger';

const log = logger.child({ module: 'WorkflowState' });

/** Valid state transitions */
const VALID_TRANSITIONS: Record<WorkflowStateType, WorkflowStateType[]> = {
    RECON: ['PROBE'],
    PROBE: ['EXPLOIT'],
    EXPLOIT: ['PIVOT'],
    PIVOT: ['CONFIRM'],
    CONFIRM: [], // Terminal state
};

/** Workflow state priority for scoring — higher = more advanced = higher priority */
const STATE_PRIORITY: Record<WorkflowStateType, number> = {
    RECON: 0.1,
    PROBE: 0.3,
    EXPLOIT: 0.6,
    PIVOT: 0.8,
    CONFIRM: 1.0,
};

export class WorkflowState {
    private states: Map<string, WorkflowStateType> = new Map();
    private history: WorkflowTransition[] = [];

    /** Get current workflow state for an endpoint. Defaults to RECON. */
    getState(endpointId: string): WorkflowStateType {
        if (!strategyFlags.ENABLE_WORKFLOW_STATE) return 'RECON';
        return this.states.get(endpointId) ?? 'RECON';
    }

    /** Force-set state (for initialization). */
    setState(endpointId: string, state: WorkflowStateType): void {
        this.states.set(endpointId, state);
    }

    /** Transition to next valid state. Returns true if transition succeeded. */
    transition(endpointId: string, reason: string): boolean {
        if (!strategyFlags.ENABLE_WORKFLOW_STATE) return false;

        const current = this.getState(endpointId);
        const validNextStates = VALID_TRANSITIONS[current];

        if (validNextStates.length === 0) {
            log.debug('Already at terminal state', { endpointId, currentState: current });
            return false;
        }

        const nextState = validNextStates[0]; // Always advance to the single next state

        const transition: WorkflowTransition = {
            endpointId,
            fromState: current,
            toState: nextState,
            reason,
            timestamp: Date.now(),
        };

        this.states.set(endpointId, nextState);
        this.history.push(transition);

        log.info('Workflow transition', {
            event: 'workflow.transition',
            endpointId,
            fromState: current,
            toState: nextState,
            reason,
        });

        return true;
    }

    /** Get priority score for an endpoint based on its workflow state. 0-1. */
    getPriority(endpointId: string): number {
        const state = this.getState(endpointId);
        return STATE_PRIORITY[state];
    }

    /** Get transition history for an endpoint. */
    getHistory(endpointId: string): WorkflowTransition[] {
        return this.history.filter(h => h.endpointId === endpointId);
    }

    /** Get latest transition reason for explainability. */
    getLatestTransitionReason(endpointId: string): string {
        const endpointHistory = this.getHistory(endpointId);
        if (endpointHistory.length === 0) return 'Initial state';
        return endpointHistory[endpointHistory.length - 1].reason;
    }

    /** Get all endpoints in a specific state. */
    getEndpointsInState(state: WorkflowStateType): string[] {
        const result: string[] = [];
        for (const [endpointId, s] of this.states) {
            if (s === state) result.push(endpointId);
        }
        return result;
    }
}
