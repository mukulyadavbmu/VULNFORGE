import { v4 as uuidv4 } from 'uuid';
import { logger } from '../../utils/logger';

// In-memory store for callback interactions (MVP)
const interactions = new Map<string, { timestamp: number, sourceIp: string, data: any }>();

export class OASTService {
    static getCallbackUrl(token: string): string {
        return `http://localhost:3000/callback/${token}`;
    }

    static generateToken(): string {
        return uuidv4();
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
