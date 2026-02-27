/**
 * Part 2 — ChainingEngine
 * Deterministic rule-based follow-up attack generator.
 * No AI. Configurable rule table.
 */
import { ScanFinding } from '../../types';
import { FollowupAttack, ChainingRule } from '../../strategy.types';
import { strategyFlags } from '../../strategyConfig';
import { logger } from '../../utils/logger';

const log = logger.child({ module: 'ChainingEngine' });

/** Default deterministic chaining rules */
const DEFAULT_RULES: ChainingRule[] = [
    { triggerType: 'ssrf', followupAttackType: 'ssrf_probe', escalationLevel: 3, description: 'Internal SSRF pivot' },
    { triggerType: 'idor', followupAttackType: 'id_tamper', escalationLevel: 2, description: 'ID range expansion' },
    { triggerType: 'file_upload', followupAttackType: 'rce_probe', escalationLevel: 3, description: 'Uploaded file execution' },
    { triggerType: 'graphql_deep', followupAttackType: 'graphql_deep_probe', escalationLevel: 4, description: 'Deep nesting DoS' },
    { triggerType: 'sqli', followupAttackType: 'sqli_probe', escalationLevel: 3, description: 'Privilege escalation via SQLi' },
    { triggerType: 'xss', followupAttackType: 'xss_probe', escalationLevel: 2, description: 'Session hijack chain' },
    { triggerType: 'lfi', followupAttackType: 'path_traversal_probe', escalationLevel: 3, description: 'Deeper path traversal' },
    { triggerType: 'cors', followupAttackType: 'cors_probe', escalationLevel: 2, description: 'Credentialed CORS request' },
    { triggerType: 'bac', followupAttackType: 'cross_role_access', escalationLevel: 2, description: 'Role escalation' },
    { triggerType: 'config', followupAttackType: 'ssrf_probe', escalationLevel: 3, description: 'Config leak → internal pivot' },
    { triggerType: 'ssti', followupAttackType: 'rce_probe', escalationLevel: 3, description: 'SSTI → RCE escalation' },
    { triggerType: 'csrf', followupAttackType: 'clickjacking_probe', escalationLevel: 1, description: 'CSRF → Clickjacking chain' },
    { triggerType: 'websocket', followupAttackType: 'websocket_probe', escalationLevel: 3, description: 'WebSocket deep probe' },
    { triggerType: 'proto_pollution', followupAttackType: 'rce_probe', escalationLevel: 4, description: 'Proto pollution → RCE' },
    { triggerType: 'race_condition', followupAttackType: 'race_condition_probe', escalationLevel: 4, description: 'Race condition re-verify' },
];

export class ChainingEngine {
    private rules: ChainingRule[];
    private processedFindings: Set<string> = new Set();

    constructor(customRules?: ChainingRule[]) {
        this.rules = customRules ?? DEFAULT_RULES;
    }

    /**
     * Generate follow-up attacks from confirmed findings.
     * O(findings * rules) — both are bounded constants, effectively O(n).
     */
    generateFollowups(findings: ScanFinding[]): FollowupAttack[] {
        if (!strategyFlags.ENABLE_CHAINING_ENGINE) return [];

        const start = Date.now();
        const followups: FollowupAttack[] = [];

        for (const finding of findings) {
            // Skip already-chained findings
            if (this.processedFindings.has(finding.id)) continue;

            const matchingRules = this.rules.filter(r => r.triggerType === finding.type);

            for (const rule of matchingRules) {
                // Avoid chaining same attack type back to same endpoint
                const dedupeKey = `${finding.url}:${rule.followupAttackType}:${rule.escalationLevel}`;
                if (this.processedFindings.has(dedupeKey)) continue;

                followups.push({
                    endpointId: finding.url, // Using URL as endpoint reference
                    attackType: rule.followupAttackType,
                    escalationLevel: rule.escalationLevel,
                    triggerFindingId: finding.id,
                });

                this.processedFindings.add(dedupeKey);
            }

            this.processedFindings.add(finding.id);
        }

        const durationMs = Date.now() - start;
        log.info('Chaining complete', {
            findingCount: findings.length,
            followupCount: followups.length,
            durationMs,
        });

        return followups;
    }

    /** Get current rule table (for inspection/debugging) */
    getRules(): ReadonlyArray<ChainingRule> {
        return this.rules;
    }
}
