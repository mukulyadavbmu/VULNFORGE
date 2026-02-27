/**
 * EscalationPlaybook — Defines concrete attack behaviors for each escalation level.
 * Level 1: Basic probe, single payload
 * Level 2: Adaptive mutation via PayloadFactory
 * Level 3: Attack-specific escalation logic
 * Level 4: Persistence simulation, multi-role, token reuse
 */
import { ScanFinding } from '../../types';
import { logger } from '../../utils/logger';

const log = logger.child({ module: 'EscalationPlaybook' });

export interface EscalationAction {
    attackType: string;
    level: 1 | 2 | 3 | 4;
    payloadStrategy: 'single' | 'mutated' | 'escalated' | 'persistence';
    instructions: string[];
    paramOverrides: Record<string, string>;
}

/** Level 3 escalation rules — attack-specific deep exploitation */
const LEVEL3_RULES: Record<string, EscalationAction> = {
    ssrf_probe: {
        attackType: 'ssrf_probe',
        level: 3,
        payloadStrategy: 'escalated',
        instructions: [
            'Replace external callback with internal IP range (127.0.0.1, 169.254.169.254, 10.0.0.0/8)',
            'Test cloud metadata endpoints (AWS IMDSv1, GCP metadata)',
            'Attempt protocol switching (gopher://, file://, dict://)',
        ],
        paramOverrides: { target: '169.254.169.254/latest/meta-data/' },
    },
    id_tamper: {
        attackType: 'id_tamper',
        level: 3,
        payloadStrategy: 'escalated',
        instructions: [
            'Expand single ID to range (id-1, id+1, id+100)',
            'Try UUID prediction / sequential UUIDs',
            'Test negative IDs and boundary values (0, -1, MAX_INT)',
        ],
        paramOverrides: { range: '1-100' },
    },
    file_upload_probe: {
        attackType: 'file_upload_probe',
        level: 3,
        payloadStrategy: 'escalated',
        instructions: [
            'Upload polyglot file (valid image with embedded PHP/JSP)',
            'Test double extension bypass (.php.jpg, .jsp.png)',
            'Attempt path traversal in filename (../../shell.php)',
            'Try null byte injection (shell.php%00.jpg)',
        ],
        paramOverrides: { filename: 'shell.php.jpg' },
    },
    graphql_probe: {
        attackType: 'graphql_deep_probe',
        level: 3,
        payloadStrategy: 'escalated',
        instructions: [
            'Attempt deep nesting (10+ levels)',
            'Batch alias overloading (20+ aliases)',
            'Query mutation introspection for write operations',
            'Test field suggestion exploitation',
        ],
        paramOverrides: { depth: '10' },
    },
    sqli_probe: {
        attackType: 'sqli_probe',
        level: 3,
        payloadStrategy: 'escalated',
        instructions: [
            'Switch from boolean-based to time-based blind SQLi',
            'Attempt UNION-based extraction',
            'Try stacked queries for privilege escalation',
            'Test information_schema access',
        ],
        paramOverrides: { technique: 'union' },
    },
    xss_probe: {
        attackType: 'xss_probe',
        level: 3,
        payloadStrategy: 'escalated',
        instructions: [
            'Test DOM-based XSS vectors',
            'Attempt CSP bypass via allowed sources',
            'Try polyglot XSS payloads',
            'Test mutation XSS (mXSS) via innerHTML',
        ],
        paramOverrides: { context: 'dom' },
    },
    path_traversal_probe: {
        attackType: 'path_traversal_probe',
        level: 3,
        payloadStrategy: 'escalated',
        instructions: [
            'Attempt double encoding (..%252f..%252f)',
            'Try UTF-8 overlong encoding',
            'Test null byte injection (%00)',
            'Target sensitive files (/etc/shadow, web.config)',
        ],
        paramOverrides: { encoding: 'double' },
    },
    cors_probe: {
        attackType: 'cors_probe',
        level: 3,
        payloadStrategy: 'escalated',
        instructions: [
            'Test subdomain wildcard reflection',
            'Attempt null origin bypass',
            'Test with credentials: include',
            'Verify pre-flight bypass via simple requests',
        ],
        paramOverrides: { origin: 'null' },
    },
};

/** Level 4 persistence actions — cross-cutting, not attack-specific */
const LEVEL4_ACTIONS: EscalationAction = {
    attackType: 'persistence_simulation',
    level: 4,
    payloadStrategy: 'persistence',
    instructions: [
        'Replay attack as different auth roles (guest, userA, userB)',
        'Test token reuse after logout/invalidation',
        'Attempt session fixation',
        'Test concurrent requests with same credential',
        'Verify finding stability across 3 consecutive attempts',
    ],
    paramOverrides: { roles: 'guest,userA,userB' },
};

export class EscalationPlaybook {
    /**
     * Get the concrete escalation action for a given attack type and level.
     * Returns specific instructions, payload strategy, and parameter overrides.
     */
    static getAction(attackType: string, level: 1 | 2 | 3 | 4): EscalationAction {
        const start = Date.now();

        let action: EscalationAction;

        switch (level) {
            case 1:
                action = {
                    attackType,
                    level: 1,
                    payloadStrategy: 'single',
                    instructions: ['Execute single baseline payload', 'Record response signature'],
                    paramOverrides: {},
                };
                break;

            case 2:
                action = {
                    attackType,
                    level: 2,
                    payloadStrategy: 'mutated',
                    instructions: [
                        'Generate mutations via PayloadFactory',
                        'Apply encoding variations (URL, HTML, Base64)',
                        'Test case-sensitivity bypass',
                        'Try JSON wrapping for injection payloads',
                    ],
                    paramOverrides: { mutations: 'encoding,case,json' },
                };
                break;

            case 3:
                action = LEVEL3_RULES[attackType] ?? {
                    attackType,
                    level: 3,
                    payloadStrategy: 'escalated',
                    instructions: ['Apply advanced payload variants', 'Test bypass techniques'],
                    paramOverrides: {},
                };
                break;

            case 4:
                action = { ...LEVEL4_ACTIONS, attackType };
                break;
        }

        const durationMs = Date.now() - start;
        log.debug('Playbook action resolved', {
            attackType,
            level,
            payloadStrategy: action.payloadStrategy,
            instructionCount: action.instructions.length,
            durationMs,
        });

        return action;
    }

    /** Get all defined Level 3 attack types. */
    static getSupportedEscalations(): string[] {
        return Object.keys(LEVEL3_RULES);
    }

    /** Check if a specific attack type has Level 3 escalation defined. */
    static hasEscalation(attackType: string): boolean {
        return attackType in LEVEL3_RULES;
    }
}
