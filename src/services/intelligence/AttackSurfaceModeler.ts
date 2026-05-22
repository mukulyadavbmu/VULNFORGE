/**
 * AttackSurfaceModeler — Build a structured attack surface map from endpoints.
 *
 * Groups endpoints by resource path, maps parameters per endpoint,
 * maps auth roles, and auto-detects sensitive endpoints.
 *
 * Pure data transformation — no network calls, no AI dependency.
 * Input: AttackNode[] from session.
 * Output: SurfaceMap for hypothesis engine and attack prioritization.
 */
import { AttackNode, AuthContext } from '../../types';
import { logger } from '../../utils/logger';

const log = logger.child({ module: 'AttackSurfaceModeler' });

// ─── Types ──────────────────────────────────────────────────────────────────

export interface EndpointGroup {
    /** Normalized path prefix (e.g., /api/users) */
    basePath: string;
    /** All endpoints sharing this prefix */
    endpoints: AttackNode[];
    /** All HTTP methods seen */
    methods: Set<string>;
    /** All unique parameter names */
    parameters: Set<string>;
    /** Auth contexts that can access endpoints in this group */
    accessibleBy: Set<AuthContext>;
    /** Risk assessment for this group */
    riskLevel: 'low' | 'medium' | 'high' | 'critical';
    /** Tags aggregated from all endpoints */
    aggregatedTags: Set<string>;
}

export interface AuthRoleMapping {
    /** Auth context (guest, userA, userB) */
    role: AuthContext;
    /** Endpoints accessible by this role */
    accessibleEndpoints: string[];
    /** Endpoints exclusively accessible by this role (not shared) */
    exclusiveEndpoints: string[];
    /** Count of sensitive endpoints accessible */
    sensitiveAccessCount: number;
}

export interface SensitiveEndpoint {
    /** Endpoint node ID */
    nodeId: string;
    /** URL */
    url: string;
    /** Reason it's considered sensitive */
    reasons: string[];
    /** Sensitivity level */
    level: 'medium' | 'high' | 'critical';
}

export interface SurfaceMap {
    /** Endpoints grouped by resource path */
    groups: EndpointGroup[];
    /** Auth role to endpoint mapping */
    authMapping: AuthRoleMapping[];
    /** Detected sensitive endpoints */
    sensitiveEndpoints: SensitiveEndpoint[];
    /** Total unique endpoints */
    totalEndpoints: number;
    /** Total unique parameters */
    totalParameters: number;
    /** Total resource groups */
    totalGroups: number;
    /** Analysis duration in milliseconds */
    durationMs: number;
}

// ─── Sensitive Detection Patterns ───────────────────────────────────────────

const SENSITIVE_PATH_PATTERNS: Array<{ regex: RegExp; reason: string; level: 'medium' | 'high' | 'critical' }> = [
    { regex: /\/admin/i, reason: 'Admin panel access', level: 'critical' },
    { regex: /\/dashboard/i, reason: 'Dashboard endpoint', level: 'high' },
    { regex: /\/billing|\/payment|\/checkout/i, reason: 'Financial operation', level: 'critical' },
    { regex: /\/password|\/reset|\/recover/i, reason: 'Password management', level: 'critical' },
    { regex: /\/token|\/oauth|\/auth/i, reason: 'Authentication endpoint', level: 'high' },
    { regex: /\/upload|\/import/i, reason: 'File upload/import', level: 'high' },
    { regex: /\/export|\/download/i, reason: 'Data export/download', level: 'high' },
    { regex: /\/delete|\/remove|\/destroy/i, reason: 'Destructive operation', level: 'high' },
    { regex: /\/config|\/settings|\/preferences/i, reason: 'Configuration endpoint', level: 'medium' },
    { regex: /\/internal|\/debug|\/test/i, reason: 'Internal/debug endpoint', level: 'critical' },
    { regex: /\/api\/v\d+\/users?/i, reason: 'User management API', level: 'high' },
    { regex: /\/graphql/i, reason: 'GraphQL endpoint', level: 'high' },
    { regex: /\/webhook|\/callback/i, reason: 'Webhook/callback endpoint', level: 'medium' },
    { regex: /\/secret|\/private|\/key/i, reason: 'Secret/key management', level: 'critical' },
    { regex: /\/transfer|\/wire|\/send/i, reason: 'Money transfer operation', level: 'critical' },
];

const SENSITIVE_PARAM_PATTERNS: Array<{ regex: RegExp; reason: string; level: 'medium' | 'high' | 'critical' }> = [
    { regex: /^(id|user_?id|account_?id|order_?id)$/i, reason: 'Direct object reference parameter', level: 'high' },
    { regex: /^(token|api_?key|secret|password|auth)$/i, reason: 'Authentication parameter', level: 'critical' },
    { regex: /^(role|admin|privilege|permission)$/i, reason: 'Authorization parameter', level: 'critical' },
    { regex: /^(redirect|url|next|return|callback)$/i, reason: 'Redirect parameter (open redirect risk)', level: 'medium' },
    { regex: /^(file|path|filename|upload)$/i, reason: 'File path parameter (traversal risk)', level: 'high' },
    { regex: /^(query|search|q|filter|sort)$/i, reason: 'Query parameter (injection risk)', level: 'medium' },
    { regex: /^(email|phone|ssn|credit_card)$/i, reason: 'PII parameter', level: 'high' },
];

// ─── Engine ─────────────────────────────────────────────────────────────────

export class AttackSurfaceModeler {

    /**
     * Build a complete attack surface map from discovered endpoints.
     */
    model(nodes: AttackNode[]): SurfaceMap {
        const start = Date.now();

        log.info('Building attack surface map', { endpointCount: nodes.length });

        // 1. Group endpoints by resource path
        const groups = this.groupByResource(nodes);

        // 2. Build auth role mapping
        const authMapping = this.buildAuthMapping(nodes);

        // 3. Detect sensitive endpoints
        const sensitiveEndpoints = this.detectSensitiveEndpoints(nodes);

        // 4. Tag sensitive endpoints in the node objects (side effect)
        for (const se of sensitiveEndpoints) {
            const node = nodes.find(n => n.id === se.nodeId);
            if (node) {
                if (!node.tags.includes('sensitive_auto')) {
                    node.tags.push('sensitive_auto');
                }
                if (se.level === 'critical' && !node.tags.includes('sensitive_critical')) {
                    node.tags.push('sensitive_critical');
                }
            }
        }

        // Collect statistics
        const allParams = new Set<string>();
        for (const node of nodes) {
            for (const p of node.params) {
                allParams.add(p);
            }
        }

        const durationMs = Date.now() - start;

        log.info('Attack surface map built', {
            groups: groups.length,
            sensitiveEndpoints: sensitiveEndpoints.length,
            totalParams: allParams.size,
            durationMs,
        });

        return {
            groups,
            authMapping,
            sensitiveEndpoints,
            totalEndpoints: nodes.length,
            totalParameters: allParams.size,
            totalGroups: groups.length,
            durationMs,
        };
    }

    /**
     * Group endpoints by normalized resource path prefix.
     * E.g., /api/users/1 and /api/users/2 both go under /api/users.
     */
    private groupByResource(nodes: AttackNode[]): EndpointGroup[] {
        const groupMap = new Map<string, EndpointGroup>();

        for (const node of nodes) {
            const basePath = this.normalizeBasePath(node.url);

            let group = groupMap.get(basePath);
            if (!group) {
                group = {
                    basePath,
                    endpoints: [],
                    methods: new Set<string>(),
                    parameters: new Set<string>(),
                    accessibleBy: new Set<AuthContext>(),
                    riskLevel: 'low',
                    aggregatedTags: new Set<string>(),
                };
                groupMap.set(basePath, group);
            }

            group.endpoints.push(node);
            if (node.method) group.methods.add(node.method);
            group.accessibleBy.add(node.authContext);
            for (const p of node.params) group.parameters.add(p);
            for (const t of node.tags) group.aggregatedTags.add(t);
        }

        // Calculate risk level for each group
        for (const group of groupMap.values()) {
            group.riskLevel = this.calculateGroupRisk(group);
        }

        // Sort by risk (critical first)
        const riskOrder = { critical: 0, high: 1, medium: 2, low: 3 };
        return Array.from(groupMap.values()).sort(
            (a, b) => riskOrder[a.riskLevel] - riskOrder[b.riskLevel],
        );
    }

    /**
     * Build auth role mapping — which roles can access which endpoints.
     */
    private buildAuthMapping(nodes: AttackNode[]): AuthRoleMapping[] {
        const roleToEndpoints = new Map<AuthContext, Set<string>>();

        for (const node of nodes) {
            let set = roleToEndpoints.get(node.authContext);
            if (!set) {
                set = new Set<string>();
                roleToEndpoints.set(node.authContext, set);
            }
            set.add(node.id);
        }

        // Find all endpoint IDs accessed by any role
        const allEndpointsByRole = Array.from(roleToEndpoints.entries());

        const mappings: AuthRoleMapping[] = [];
        for (const [role, endpointIds] of allEndpointsByRole) {
            const allEndpoints = Array.from(endpointIds);

            // Find exclusive endpoints (not accessible by other roles)
            const exclusiveEndpoints = allEndpoints.filter(epId => {
                for (const [otherRole, otherIds] of allEndpointsByRole) {
                    if (otherRole !== role && otherIds.has(epId)) return false;
                }
                return true;
            });

            // Count sensitive endpoints accessible
            const sensitiveAccessCount = allEndpoints.filter(epId => {
                const node = nodes.find(n => n.id === epId);
                return node && (
                    node.tags.includes('sensitive_path') ||
                    node.tags.includes('sensitive_api') ||
                    node.tags.includes('sensitive_auto')
                );
            }).length;

            mappings.push({
                role,
                accessibleEndpoints: allEndpoints,
                exclusiveEndpoints,
                sensitiveAccessCount,
            });
        }

        return mappings;
    }

    /**
     * Detect sensitive endpoints based on URL patterns and parameters.
     */
    private detectSensitiveEndpoints(nodes: AttackNode[]): SensitiveEndpoint[] {
        const results: SensitiveEndpoint[] = [];
        const seenIds = new Set<string>();

        for (const node of nodes) {
            if (seenIds.has(node.id)) continue;

            const reasons: string[] = [];
            let highestLevel: 'medium' | 'high' | 'critical' = 'medium';

            // Check URL path patterns
            for (const pattern of SENSITIVE_PATH_PATTERNS) {
                if (pattern.regex.test(node.url)) {
                    reasons.push(pattern.reason);
                    if (this.levelOrder(pattern.level) < this.levelOrder(highestLevel)) {
                        highestLevel = pattern.level;
                    }
                }
            }

            // Check parameter patterns
            for (const param of node.params) {
                for (const pattern of SENSITIVE_PARAM_PATTERNS) {
                    if (pattern.regex.test(param)) {
                        reasons.push(`${pattern.reason} (param: ${param})`);
                        if (this.levelOrder(pattern.level) < this.levelOrder(highestLevel)) {
                            highestLevel = pattern.level;
                        }
                    }
                }
            }

            // Check existing tags
            if (node.tags.includes('sensitive_path') || node.tags.includes('sensitive_api')) {
                reasons.push('Pre-tagged as sensitive');
            }

            if (reasons.length > 0) {
                seenIds.add(node.id);
                results.push({
                    nodeId: node.id,
                    url: node.url,
                    reasons,
                    level: highestLevel,
                });
            }
        }

        return results;
    }

    /**
     * Normalize a URL to its base resource path.
     * /api/users/123 → /api/users
     * /api/orders/456/items → /api/orders/_/items
     */
    private normalizeBasePath(url: string): string {
        try {
            const u = new URL(url);
            const segments = u.pathname.split('/').filter(Boolean);

            // Replace numeric segments with wildcard
            const normalized = segments.map(seg =>
                /^\d+$/.test(seg) ? '*' : seg,
            );

            return '/' + normalized.join('/');
        } catch {
            return url;
        }
    }

    /**
     * Calculate risk level for an endpoint group.
     */
    private calculateGroupRisk(group: EndpointGroup): 'low' | 'medium' | 'high' | 'critical' {
        let riskScore = 0;

        // Sensitive tags boost risk
        if (group.aggregatedTags.has('sensitive_path') || group.aggregatedTags.has('sensitive_api')) {
            riskScore += 30;
        }
        if (group.aggregatedTags.has('idor_susceptible')) {
            riskScore += 25;
        }
        if (group.aggregatedTags.has('hidden_api')) {
            riskScore += 20;
        }

        // Multiple auth contexts on same resource = potential BAC
        if (group.accessibleBy.size > 1) {
            riskScore += 15;
        }

        // Many parameters = larger attack surface
        if (group.parameters.size >= 5) riskScore += 15;
        else if (group.parameters.size >= 3) riskScore += 10;
        else if (group.parameters.size >= 1) riskScore += 5;

        // Multiple HTTP methods = richer attack surface
        if (group.methods.size >= 3) riskScore += 10;

        // Multiple endpoints in group = likely CRUD → IDOR potential
        if (group.endpoints.length >= 3) riskScore += 10;

        // URL keyword sensitivity
        for (const pattern of SENSITIVE_PATH_PATTERNS) {
            if (pattern.regex.test(group.basePath)) {
                riskScore += pattern.level === 'critical' ? 20 : pattern.level === 'high' ? 15 : 10;
                break; // Count once
            }
        }

        if (riskScore >= 60) return 'critical';
        if (riskScore >= 40) return 'high';
        if (riskScore >= 20) return 'medium';
        return 'low';
    }

    private levelOrder(level: 'medium' | 'high' | 'critical'): number {
        return level === 'critical' ? 0 : level === 'high' ? 1 : 2;
    }
}
