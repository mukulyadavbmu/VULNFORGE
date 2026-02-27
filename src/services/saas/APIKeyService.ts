/**
 * Part 9a — APIKeyService
 * Minimal in-memory API key management.
 * No schema changes. Production would use DB.
 */
import { APIKey } from '../../strategy.types';
import { logger } from '../../utils/logger';
import crypto from 'crypto';

const log = logger.child({ module: 'APIKeyService' });

export class APIKeyService {
    private static keys: Map<string, APIKey> = new Map();

    /** Create a new API key for a tenant. Returns the raw key (only shown once). */
    static create(tenantId: string): { rawKey: string; record: APIKey } {
        const rawKey = `vf_${crypto.randomBytes(24).toString('hex')}`;
        const keyHash = crypto.createHash('sha256').update(rawKey).digest('hex');
        const id = crypto.randomUUID();

        const record: APIKey = {
            id,
            tenantId,
            keyHash,
            createdAt: Date.now(),
            isActive: true,
        };

        this.keys.set(id, record);
        log.info('API key created', { tenantId, keyId: id });
        return { rawKey, record };
    }

    /** Validate raw key. Returns tenant ID or null. */
    static validate(rawKey: string): string | null {
        const keyHash = crypto.createHash('sha256').update(rawKey).digest('hex');
        for (const [, record] of this.keys) {
            if (record.keyHash === keyHash && record.isActive && !record.revokedAt) {
                return record.tenantId;
            }
        }
        return null;
    }

    /** Revoke an API key by ID. */
    static revoke(keyId: string): boolean {
        const record = this.keys.get(keyId);
        if (!record) return false;
        record.isActive = false;
        record.revokedAt = Date.now();
        log.info('API key revoked', { keyId, tenantId: record.tenantId });
        return true;
    }

    /** List keys for a tenant (hashes only, never raw keys). */
    static listForTenant(tenantId: string): APIKey[] {
        const result: APIKey[] = [];
        for (const [, record] of this.keys) {
            if (record.tenantId === tenantId) result.push(record);
        }
        return result;
    }
}
