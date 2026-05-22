import { ScanSession, AuthContext, ScanFinding } from '../../types';
import { httpRequest, calculateDiff } from '../../utils/scanUtils';
import { logger } from '../../utils/logger';

const log = logger.child({ module: 'DifferentialRoleValidator' });

// Fields that expose sensitive data \u2014 their presence in lower-privilege responses is a violation
const SENSITIVE_FIELDS = new Set([
    'password', 'passwd', 'secret', 'token', 'api_key', 'apikey', 'access_key',
    'private_key', 'credit_card', 'ssn', 'bank_account', 'cvv', 'pin',
    'admin', 'role', 'permissions', 'is_admin', 'is_superuser',
    'salary', 'balance', 'account_number',
]);

/**
 * Collect all keys from a JSON object recursively (max depth 5 to prevent DoS).
 */
function extractAllKeys(obj: any, depth = 0): Set<string> {
    const keys = new Set<string>();
    if (!obj || typeof obj !== 'object' || depth > 5) return keys;
    for (const key of Object.keys(obj)) {
        keys.add(key.toLowerCase());
        if (typeof obj[key] === 'object' && obj[key] !== null) {
            for (const nested of extractAllKeys(obj[key], depth + 1)) {
                keys.add(nested);
            }
        }
    }
    return keys;
}

/**
 * Structural diff: returns 0 for identical structure, 1.0 for completely different.
 * Ignores dynamic fields (timestamps, IDs, tokens).
 */
const DYNAMIC_FIELDS = new Set(['timestamp', 'created_at', 'updated_at', 'id', 'uuid', 'token', 'nonce', 'expires_at']);

function structuralDiff(obj1: any, obj2: any): number {
    if (!obj1 || !obj2) return 1.0;

    const getKeys = (obj: any, prefix = ''): string[] => {
        if (typeof obj !== 'object' || obj === null) return [];
        let keys: string[] = [];
        for (const key of Object.keys(obj)) {
            if (DYNAMIC_FIELDS.has(key.toLowerCase())) continue;
            keys.push(prefix + key);
            if (typeof obj[key] === 'object') {
                keys = keys.concat(getKeys(obj[key], prefix + key + '.'));
            }
        }
        return keys;
    };

    const keys1 = new Set(getKeys(obj1));
    const keys2 = new Set(getKeys(obj2));
    const intersection = new Set([...keys1].filter(x => keys2.has(x)));
    const union = new Set([...keys1, ...keys2]);
    if (union.size === 0) return 0;
    return 1.0 - (intersection.size / union.size);
}

export class DifferentialRoleValidator {
    /**
     * Executes requests across all specified roles and performs differential analysis.
     * Generates findings for:
     *   - Horizontal Privilege Escalation (BOLA): userA vs userB
     *   - Vertical Privilege Escalation (BAC): admin vs userA
     *   - Missing Authentication: guest vs userA
     *   - Sensitive Field Exposure: lower-privilege role sees sensitive fields
     *   - Status-Code-Based Bypass: expected 401/403 but got 200
     */
    static async validateCrossRoleAccess(
        session: ScanSession,
        url: string,
        explanation: string,
        roles: AuthContext[] = ['admin', 'userA', 'userB', 'guest']
    ): Promise<ScanFinding[]> {
        const responses: Record<string, {
            status: number;
            length: number;
            json?: unknown;
            keys?: Set<string>;
        }> = {};
        const findings: ScanFinding[] = [];

        // 1. Gather Responses across all active roles
        for (const role of roles) {
            if (role !== 'guest' && !Object.keys(session.authHeaders[role] ?? {}).length) {
                log.debug(`Role '${role}' has no auth headers, skipping for ${url}`);
                continue;
            }
            try {
                const res = await httpRequest(session, url, role);
                let jsonParsed: unknown;
                try { jsonParsed = JSON.parse(res.bodySnippet); } catch { /* not JSON */ }

                responses[role] = {
                    status: res.status,
                    length: res.length,
                    json: jsonParsed,
                    keys: jsonParsed ? extractAllKeys(jsonParsed) : undefined,
                };

                log.debug(`Role '${role}' → ${res.status} (${res.length}B) for ${url}`);
            } catch (err) {
                log.warn(`Request failed for role '${role}' on ${url}`, { error: err });
            }
        }

        // 2. BOLA: Horizontal escalation — userA vs userB
        const userA = responses['userA'];
        const userB = responses['userB'];
        if (userA && userB && userA.status === 200 && userB.status === 200) {
            const delta = userA.json && userB.json
                ? structuralDiff(userA.json, userB.json)
                : Math.abs(userA.length - userB.length) / (userA.length || 1);

            if (delta < 0.15) {
                findings.push({
                    id: `bola_${Date.now()}_${Math.random().toString(36).slice(2)}`,
                    type: 'bac',
                    classification: 'vulnerability',
                    url,
                    severity: 'critical',
                    evidence: `BOLA (Horizontal Privilege Escalation): 'userA' and 'userB' receive structurally identical responses (structural delta: ${delta.toFixed(3)}). Object-level isolation is absent.`,
                    aiExplanation: explanation,
                });
            }
        }

        // 3. BAC: Vertical escalation — admin vs userA (on admin-scoped paths)
        const admin = responses['admin'];
        if (admin && userA && admin.status === 200 && userA.status === 200) {
            const delta = admin.json && userA.json
                ? structuralDiff(admin.json, userA.json)
                : Math.abs(admin.length - userA.length) / (admin.length || 1);

            const isAdminPath = /admin|manage|panel|dashboard|internal/i.test(url);
            if (delta < 0.2 && isAdminPath) {
                findings.push({
                    id: `bac_vert_${Date.now()}_${Math.random().toString(36).slice(2)}`,
                    type: 'bac',
                    classification: 'vulnerability',
                    url,
                    severity: 'critical',
                    evidence: `BAC (Vertical Privilege Escalation): 'userA' accessed an admin-scoped endpoint with equivalent data structure as 'admin' (structural delta: ${delta.toFixed(3)}).`,
                    aiExplanation: explanation,
                });
            }
        }

        // 4. Missing Authentication: guest vs userA
        const guest = responses['guest'];
        if (guest && userA && guest.status === 200 && userA.status === 200) {
            const delta = guest.json && userA.json
                ? structuralDiff(guest.json, userA.json)
                : Math.abs(guest.length - userA.length) / (userA.length || 1);

            if (delta < 0.2) {
                findings.push({
                    id: `bac_guest_${Date.now()}_${Math.random().toString(36).slice(2)}`,
                    type: 'bac',
                    classification: 'vulnerability',
                    url,
                    severity: 'high',
                    evidence: `Missing Authentication: Unauthenticated 'guest' can access endpoint with near-identical response as authenticated 'userA' (structural delta: ${delta.toFixed(3)}).`,
                    aiExplanation: explanation,
                });
            }
        }

        // 5. Status-code bypass: expected 401/403 for lower-priv but got 200
        // If admin gets 200 but guest should be denied (401/403) — and guest also gets 200
        if (admin && admin.status === 200 && guest && guest.status === 200) {
            const adminPath = /admin|manage|panel|dashboard|internal/i.test(url);
            if (adminPath) {
                findings.push({
                    id: `auth_bypass_status_${Date.now()}`,
                    type: 'auth_bypass',
                    classification: 'vulnerability',
                    url,
                    severity: 'critical',
                    evidence: `Auth Bypass (Status Code): Admin-scoped endpoint returned HTTP 200 to unauthenticated 'guest' — expected 401 or 403.`,
                    aiExplanation: explanation,
                });
            }
        }

        // 6. Sensitive Field Exposure: detect sensitive field keys in lower-privilege responses
        const sensitiveExposureRoles: AuthContext[] = ['userA', 'userB', 'guest'];
        for (const role of sensitiveExposureRoles) {
            const r = responses[role];
            if (!r || r.status !== 200 || !r.keys) continue;

            const exposedFields = [...r.keys].filter(k => SENSITIVE_FIELDS.has(k));
            if (exposedFields.length > 0) {
                findings.push({
                    id: `sensitive_field_${role}_${Date.now()}`,
                    type: 'bac',
                    classification: 'vulnerability',
                    url,
                    severity: 'high',
                    evidence: `Sensitive Field Disclosure: Role '${role}' received response containing sensitive fields: [${exposedFields.join(', ')}].`,
                    aiExplanation: explanation,
                });
            }
        }

        log.info(`DifferentialRoleValidator: ${findings.length} finding(s) for ${url}`, {
            rolesChecked: Object.keys(responses),
        });

        return findings;
    }
}
