/**
 * APIPatternAnalyzer — Detect sequential ID patterns and resource clusters in endpoints.
 *
 * Identifies IDOR-susceptible patterns like /api/user/1, /api/user/2, /api/user/3.
 * Groups endpoints into resource clusters for risk analysis.
 * Additive — does not modify existing modules.
 */
import { z } from 'zod';
import { logger } from '../../utils/logger';

const log = logger.child({ module: 'APIPatternAnalyzer' });

// ─── Constants ──────────────────────────────────────────────────────────────

const MAX_ENDPOINTS = 5000;
const MAX_GROUPS = 200;

// ─── Types ──────────────────────────────────────────────────────────────────

export interface SequentialPattern {
    basePattern: string;
    ids: number[];
    count: number;
    isSequential: boolean;
    idorRisk: 'low' | 'medium' | 'high' | 'critical';
    description: string;
}

export interface ResourceGroup {
    resource: string;
    endpoints: string[];
    methods: string[];
    hasNumericIds: boolean;
    idorRisk: 'low' | 'medium' | 'high' | 'critical';
    description: string;
}

export interface PatternAnalysisResult {
    sequentialPatterns: SequentialPattern[];
    resourceGroups: ResourceGroup[];
    totalEndpoints: number;
    highRiskGroups: number;
    durationMs: number;
}

// ─── Zod ────────────────────────────────────────────────────────────────────

const EndpointInputSchema = z.object({
    url: z.string().min(1).max(2048),
    method: z.string().max(10).optional(),
}).strict();

// ─── Engine ─────────────────────────────────────────────────────────────────

export class APIPatternAnalyzer {
    /**
     * Analyze a list of endpoints for sequential ID patterns and resource groups.
     */
    analyze(
        endpoints: Array<{ url: string; method?: string }>,
    ): PatternAnalysisResult {
        const start = Date.now();
        const limited = endpoints.slice(0, MAX_ENDPOINTS);

        // Validate
        const validated = limited.map(ep => {
            try {
                return EndpointInputSchema.parse(ep);
            } catch {
                return null;
            }
        }).filter((ep): ep is z.infer<typeof EndpointInputSchema> => ep !== null);

        const sequentialPatterns = this.detectSequentialPatterns(validated);
        const resourceGroups = this.detectResourceGroups(validated);
        const highRiskGroups = resourceGroups.filter(g => g.idorRisk === 'high' || g.idorRisk === 'critical').length;
        const durationMs = Date.now() - start;

        log.info('API pattern analysis complete', {
            endpoints: validated.length,
            sequential: sequentialPatterns.length,
            groups: resourceGroups.length,
            highRisk: highRiskGroups,
            durationMs,
        });

        return {
            sequentialPatterns,
            resourceGroups,
            totalEndpoints: validated.length,
            highRiskGroups,
            durationMs,
        };
    }

    /**
     * Detect sequential numeric ID patterns.
     * Example: /api/user/1, /api/user/2, /api/user/3 → sequential IDs
     */
    private detectSequentialPatterns(
        endpoints: Array<{ url: string; method?: string }>,
    ): SequentialPattern[] {
        const patterns = new Map<string, number[]>();

        for (const ep of endpoints) {
            // Extract URL path only
            let path: string;
            try {
                const urlObj = new URL(ep.url, 'http://placeholder');
                path = urlObj.pathname;
            } catch {
                path = ep.url;
            }

            // Match paths ending with numeric ID
            const match = path.match(/^(.+\/)(\d+)$/);
            if (!match) continue;

            const base = match[1];
            const id = parseInt(match[2], 10);
            if (isNaN(id) || id > 1_000_000) continue;

            const ids = patterns.get(base) || [];
            ids.push(id);
            patterns.set(base, ids);
        }

        const results: SequentialPattern[] = [];

        for (const [base, ids] of patterns.entries()) {
            if (ids.length < 2) continue;

            const sorted = [...new Set(ids)].sort((a, b) => a - b);
            const isSequential = this.checkSequential(sorted);

            let idorRisk: 'low' | 'medium' | 'high' | 'critical' = 'low';
            if (isSequential && sorted.length >= 5) idorRisk = 'critical';
            else if (isSequential && sorted.length >= 3) idorRisk = 'high';
            else if (sorted.length >= 3) idorRisk = 'medium';

            const description = isSequential
                ? `Sequential IDs found: ${base}{${sorted.slice(0, 5).join(',')}${sorted.length > 5 ? '...' : ''}} — high IDOR risk`
                : `Numeric IDs found: ${base}{${sorted.slice(0, 5).join(',')}${sorted.length > 5 ? '...' : ''}}`;

            results.push({
                basePattern: base + '{id}',
                ids: sorted.slice(0, 50),
                count: sorted.length,
                isSequential,
                idorRisk,
                description,
            });

            if (results.length >= MAX_GROUPS) break;
        }

        return results.sort((a, b) => {
            const riskOrder = { critical: 0, high: 1, medium: 2, low: 3 };
            return riskOrder[a.idorRisk] - riskOrder[b.idorRisk];
        });
    }

    /**
     * Group endpoints by resource name.
     * Example: /api/users, /api/orders, /api/payments → separate groups.
     */
    private detectResourceGroups(
        endpoints: Array<{ url: string; method?: string }>,
    ): ResourceGroup[] {
        const groups = new Map<string, { urls: Set<string>; methods: Set<string>; hasNumeric: boolean }>();

        for (const ep of endpoints) {
            let path: string;
            try {
                const urlObj = new URL(ep.url, 'http://placeholder');
                path = urlObj.pathname;
            } catch {
                path = ep.url;
            }

            // Extract resource name (first 2 segments: /api/users → "api/users")
            const segments = path.split('/').filter(Boolean);
            if (segments.length < 1) continue;

            const resource = segments.length >= 2
                ? `/${segments[0]}/${segments[1]}`
                : `/${segments[0]}`;

            const group = groups.get(resource) || { urls: new Set(), methods: new Set(), hasNumeric: false };
            group.urls.add(ep.url);
            if (ep.method) group.methods.add(ep.method.toUpperCase());

            // Check for numeric segment
            if (segments.some(s => /^\d+$/.test(s))) {
                group.hasNumeric = true;
            }

            groups.set(resource, group);
        }

        const results: ResourceGroup[] = [];

        for (const [resource, group] of groups.entries()) {
            if (group.urls.size < 2) continue;

            let idorRisk: 'low' | 'medium' | 'high' | 'critical' = 'low';
            if (group.hasNumeric && group.urls.size >= 5) idorRisk = 'critical';
            else if (group.hasNumeric && group.urls.size >= 3) idorRisk = 'high';
            else if (group.hasNumeric) idorRisk = 'medium';

            const description = group.hasNumeric
                ? `${resource} cluster: ${group.urls.size} endpoints with numeric IDs — IDOR risk`
                : `${resource} cluster: ${group.urls.size} endpoints`;

            results.push({
                resource,
                endpoints: Array.from(group.urls).slice(0, 50),
                methods: Array.from(group.methods),
                hasNumericIds: group.hasNumeric,
                idorRisk,
                description,
            });

            if (results.length >= MAX_GROUPS) break;
        }

        return results.sort((a, b) => {
            const riskOrder = { critical: 0, high: 1, medium: 2, low: 3 };
            return riskOrder[a.idorRisk] - riskOrder[b.idorRisk];
        });
    }

    /**
     * Check if sorted numbers form a sequential pattern (gaps ≤ 3).
     */
    private checkSequential(sorted: number[]): boolean {
        if (sorted.length < 2) return false;
        let sequential = 0;
        for (let i = 1; i < sorted.length; i++) {
            if (sorted[i] - sorted[i - 1] <= 3) sequential++;
        }
        return sequential >= (sorted.length - 1) * 0.6;
    }
}
