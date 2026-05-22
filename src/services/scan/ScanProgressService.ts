/**
 * ScanProgressService — In-memory real-time scan progress tracking.
 *
 * Rolling event buffer (max 50). No DB storage.
 * Supports 6+ hour scans with capped memory.
 * Thread-safe singleton pattern.
 */
import { logger } from '../../utils/logger';

const log = logger.child({ module: 'ScanProgressService' });

const MAX_EVENTS = 50;

export type ScanEventType = 'info' | 'success' | 'warning' | 'attack' | 'recon';

export interface ScanEvent {
    timestamp: number;
    message: string;
    type: ScanEventType;
}

export interface ScanState {
    scanId: string;
    currentPhase: string;
    currentAction: string;
    events: ScanEvent[];
    lastUpdated: number;
}

export interface ScanProgress {
    currentPhase: string;
    currentAction: string;
    events: ScanEvent[];
}

class ScanProgressServiceImpl {
    private states: Map<string, ScanState> = new Map();

    setPhase(scanId: string, phase: string): void {
        const state = this.getOrCreate(scanId);
        state.currentPhase = phase;
        state.lastUpdated = Date.now();
        log.debug('Phase updated', { scanId, phase });
    }

    setAction(scanId: string, action: string): void {
        const state = this.getOrCreate(scanId);
        state.currentAction = action;
        state.lastUpdated = Date.now();
    }

    addEvent(scanId: string, message: string, type: ScanEventType): void {
        const state = this.getOrCreate(scanId);
        state.events.push({ timestamp: Date.now(), message, type });

        // Rolling buffer — remove oldest if exceeded
        if (state.events.length > MAX_EVENTS) {
            state.events.splice(0, state.events.length - MAX_EVENTS);
        }

        state.lastUpdated = Date.now();
    }

    getProgress(scanId: string): ScanProgress {
        const state = this.states.get(scanId);
        if (!state) {
            return { currentPhase: '', currentAction: '', events: [] };
        }
        return {
            currentPhase: state.currentPhase,
            currentAction: state.currentAction,
            events: state.events,
        };
    }

    clear(scanId: string): void {
        this.states.delete(scanId);
        log.debug('Progress cleared', { scanId });
    }

    private getOrCreate(scanId: string): ScanState {
        let state = this.states.get(scanId);
        if (!state) {
            state = {
                scanId,
                currentPhase: '',
                currentAction: '',
                events: [],
                lastUpdated: Date.now(),
            };
            this.states.set(scanId, state);
        }
        return state;
    }
}

/** Singleton instance */
export const ScanProgressService = new ScanProgressServiceImpl();
