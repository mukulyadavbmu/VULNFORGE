import { randomUUID } from 'crypto';
import { logger } from '../../utils/logger';
import { config } from '../../config';

// In-memory store for callback interactions (MVP)
const interactions = new Map<string, { timestamp: number, sourceIp: string, data: any }>();

export class OASTService {
    static getCallbackUrl(token: string): string {
        return `http://localhost:${config.PORT}/callback/${token}`;
    }

    static generateToken(): string {
        return randomUUID();
    }

    static recordInteraction(token: string, sourceIp: string, data: any) {
        logger.info(`OAST Callback received for token ${token}`, { sourceIp });
        interactions.set(token, {
            timestamp: Date.now(),
            sourceIp,
            data
        });
    }

    static hasInteraction(token: string): boolean {
        return interactions.has(token);
    }

    static getInteraction(token: string) {
        return interactions.get(token);
    }
}
