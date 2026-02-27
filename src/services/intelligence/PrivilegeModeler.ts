/**
 * Part 8 — PrivilegeModeler
 * Models privilege escalation paths from multi-auth findings.
 * Deterministic analysis, no AI dependency.
 */
import { ScanFinding, AuthContext } from '../../types';
import { PrivilegeModelResult, AuthFinding } from '../../strategy.types';
import { strategyFlags } from '../../strategyConfig';
import { logger } from '../../utils/logger';

const log = logger.child({ module: 'PrivilegeModeler' });

/** Auth context privilege levels (lower = less privilege) */
const PRIVILEGE_LEVELS: Record<AuthContext, number> = {
    guest: 0,
    userA: 1,
    userB: 2,
};

/** Types that indicate access control issues */
const ACCESS_CONTROL_TYPES: ReadonlySet<string> = new Set([
    'bac', 'idor', 'websocket', 'csrf', 'auth_weakness',
]);

export class PrivilegeModeler {
    /**
     * Analyze findings across auth contexts to identify privilege escalation paths.
     * O(n) over findings.
     */
    static analyze(
        findings: ScanFinding[],
        authContextMap: Map<string, AuthContext>,
        scanId: string,
    ): PrivilegeModelResult {
        if (!strategyFlags.ENABLE_PRIVILEGE_MODELING) {
            return { escalationPaths: [], privilegeRiskScore: 0 };
        }

        const start = Date.now();

        const escalationPaths: string[] = [];
        let privilegeRiskScore = 0;

        // Build auth findings
        const authFindings: AuthFinding[] = [];
        for (const finding of findings) {
            if (ACCESS_CONTROL_TYPES.has(finding.type)) {
                const ctx = authContextMap.get(finding.url) ?? 'guest';
                authFindings.push({
                    findingId: finding.id,
                    url: finding.url,
                    type: finding.type,
                    authContext: ctx,
                    severity: finding.severity,
                });
            }
        }

        // Detect escalation patterns
        // Group by URL
        const urlGroups: Map<string, AuthFinding[]> = new Map();
        for (const af of authFindings) {
            const list = urlGroups.get(af.url) ?? [];
            list.push(af);
            urlGroups.set(af.url, list);
        }

        for (const [url, group] of urlGroups) {
            // Check if same endpoint is vulnerable across multiple auth contexts
            const contexts = new Set(group.map(g => g.authContext));

            if (contexts.has('guest')) {
                escalationPaths.push(`GUEST → AUTHENTICATED: ${url} (no auth required)`);
                privilegeRiskScore += 30;
            }

            if (contexts.size >= 2) {
                escalationPaths.push(`CROSS-ROLE: ${url} (accessible by ${[...contexts].join(', ')})`);
                privilegeRiskScore += 20;
            }

            // High severity access control finding
            const criticalFindings = group.filter(g => g.severity === 'critical' || g.severity === 'high');
            if (criticalFindings.length > 0) {
                escalationPaths.push(`HIGH-RISK: ${url} — ${criticalFindings.map(f => f.type).join(', ')}`);
                privilegeRiskScore += 25;
            }
        }

        // Vertical escalation: if IDOR findings exist alongside BAC
        const hasIDOR = authFindings.some(f => f.type === 'idor');
        const hasBAC = authFindings.some(f => f.type === 'bac');
        if (hasIDOR && hasBAC) {
            escalationPaths.push('VERTICAL: IDOR + BAC combination suggests full privilege escalation');
            privilegeRiskScore += 25;
        }

        privilegeRiskScore = Math.min(privilegeRiskScore, 100);

        const durationMs = Date.now() - start;
        log.info('Privilege model complete', {
            scanId,
            pathCount: escalationPaths.length,
            privilegeRiskScore,
            durationMs,
        });

        return { escalationPaths, privilegeRiskScore };
    }
}
