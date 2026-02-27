/**
 * Part 9b — TenantContext
 * Request-scoped tenant resolution.
 * No schema changes. In-memory for MVP.
 */
import { TenantInfo } from '../../strategy.types';
import { logger } from '../../utils/logger';

const log = logger.child({ module: 'TenantContext' });

export class TenantContext {
    private static tenants: Map<string, TenantInfo> = new Map();

    /** Register a tenant. */
    static register(tenantId: string, name: string, apiKeyId: string): TenantInfo {
        const info: TenantInfo = { tenantId, name, apiKeyId };
        this.tenants.set(tenantId, info);
        log.info('Tenant registered', { tenantId, name });
        return info;
    }

    /** Resolve tenant from tenant ID. Returns null if not found. */
    static resolve(tenantId: string): TenantInfo | null {
        return this.tenants.get(tenantId) ?? null;
    }

    /**
     * Create a request-scoped context object.
     * Intended for use in middleware to attach to req object.
     */
    static createRequestScope(tenantId: string): RequestScope | null {
        const tenant = this.resolve(tenantId);
        if (!tenant) return null;

        return {
            tenantId: tenant.tenantId,
            tenantName: tenant.name,
            resolvedAt: Date.now(),
        };
    }
}

export interface RequestScope {
    tenantId: string;
    tenantName: string;
    resolvedAt: number;
}
