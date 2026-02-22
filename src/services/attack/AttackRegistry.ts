import { AIAttackAction, ScanSession } from '../../types';

export type AttackHandler = (session: ScanSession, action: AIAttackAction) => Promise<void>;

const registry = new Map<string, AttackHandler>();

export function registerAttack(type: string, handler: AttackHandler) {
    registry.set(type, handler);
}

export function getHandler(type: string): AttackHandler | undefined {
    return registry.get(type);
}
