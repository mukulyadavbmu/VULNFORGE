/**
 * RequestMutationEngine — Generate mutated HTTP requests to bypass security controls.
 *
 * Mutation strategies:
 * 1. Header injection (X-Forwarded-For, X-Original-URL, X-Rewrite-URL)
 * 2. Content-type switching (JSON ↔ form ↔ multipart)
 * 3. Method switching (GET → POST, POST → PUT, etc.)
 * 4. Duplicate parameters (HTTP parameter pollution)
 * 5. Encoding mutations (URL encode, double encode, unicode)
 *
 * No eval(). Bounded output. Type-safe.
 */
import { ScanSession } from '../../types';
import { httpRequest } from '../../utils/scanUtils';
import { logger } from '../../utils/logger';

const log = logger.child({ module: 'RequestMutationEngine' });

// ─── Types ──────────────────────────────────────────────────────────────────

export interface BaseRequest {
    url: string;
    method: string;
    headers: Record<string, string>;
    body?: string;
    contentType?: string;
}

export interface MutatedRequest extends BaseRequest {
    mutationType: string;
    mutationDescription: string;
}

export interface MutationResult {
    mutation: MutatedRequest;
    response: {
        status: number;
        bodySnippet: string;
        length: number;
        timeMs: number;
    };
    isAnomaly: boolean;
    anomalyReason?: string;
}

// ─── Header Injection Payloads ──────────────────────────────────────────────

const INJECTION_HEADERS: Array<{ header: string; value: string; description: string }> = [
    { header: 'X-Forwarded-For', value: '127.0.0.1', description: 'IP spoof via X-Forwarded-For' },
    { header: 'X-Original-URL', value: '/admin', description: 'URL override via X-Original-URL' },
    { header: 'X-Rewrite-URL', value: '/admin', description: 'URL rewrite bypass' },
    { header: 'X-Forwarded-Host', value: 'evil.com', description: 'Host header injection' },
    { header: 'X-Custom-IP-Authorization', value: '127.0.0.1', description: 'IP-based auth bypass' },
    { header: 'X-Forwarded-Port', value: '443', description: 'Port-based routing manipulation' },
    { header: 'X-HTTP-Method-Override', value: 'PUT', description: 'Method override via header' },
    { header: 'X-Method-Override', value: 'DELETE', description: 'Method override variant' },
];

// ─── Method Switches ────────────────────────────────────────────────────────

const METHOD_SWITCHES: Array<{ from: string; to: string }> = [
    { from: 'GET', to: 'POST' },
    { from: 'POST', to: 'PUT' },
    { from: 'GET', to: 'DELETE' },
    { from: 'POST', to: 'PATCH' },
    { from: 'GET', to: 'HEAD' },
    { from: 'PUT', to: 'PATCH' },
];

// ─── Content Type Switches ──────────────────────────────────────────────────

const CONTENT_TYPES = [
    'application/json',
    'application/x-www-form-urlencoded',
    'text/plain',
    'application/xml',
];

// ─── Engine ─────────────────────────────────────────────────────────────────

export class RequestMutationEngine {

    /**
     * Generate all mutations for a base request.
     * Returns an array of mutated requests to test.
     */
    generateMutations(base: BaseRequest): MutatedRequest[] {
        const mutations: MutatedRequest[] = [];

        mutations.push(...this.generateHeaderInjections(base));
        mutations.push(...this.generateMethodSwitches(base));
        mutations.push(...this.generateContentTypeSwitches(base));
        mutations.push(...this.generateParameterDuplications(base));
        mutations.push(...this.generateEncodingMutations(base));

        return mutations;
    }

    /**
     * Execute a mutation and compare with baseline to detect anomalies.
     */
    async applyMutation(
        session: ScanSession,
        mutation: MutatedRequest,
        baseline: { status: number; bodySnippet: string; length: number },
    ): Promise<MutationResult> {
        const res = await httpRequest(session, mutation.url, 'userA', {
            method: mutation.method,
            data: mutation.body,
            headers: mutation.headers,
        });

        let isAnomaly = false;
        let anomalyReason: string | undefined;

        // Detect anomalies by comparing with baseline
        if (res.status !== baseline.status) {
            isAnomaly = true;
            anomalyReason = `Status changed: ${baseline.status} → ${res.status}`;
        }

        if (!isAnomaly && Math.abs(res.length - baseline.length) / (baseline.length || 1) > 0.5) {
            isAnomaly = true;
            anomalyReason = `Response length changed significantly: ${baseline.length} → ${res.length}`;
        }

        // If a 403/401 became 200, that's a bypass
        if ((baseline.status === 403 || baseline.status === 401) && res.status === 200) {
            isAnomaly = true;
            anomalyReason = `Access control bypass: ${baseline.status} → ${res.status} via ${mutation.mutationType}`;
        }

        return {
            mutation,
            response: {
                status: res.status,
                bodySnippet: res.bodySnippet,
                length: res.length,
                timeMs: res.timeMs,
            },
            isAnomaly,
            anomalyReason,
        };
    }

    /**
     * Run all mutations for a request and return anomalous results.
     */
    async testAllMutations(
        session: ScanSession,
        base: BaseRequest,
    ): Promise<MutationResult[]> {
        // Get baseline
        const baseline = await httpRequest(session, base.url, 'userA', {
            method: base.method,
            headers: base.headers,
        });

        const mutations = this.generateMutations(base);
        const anomalies: MutationResult[] = [];

        for (const mutation of mutations) {
            try {
                const result = await this.applyMutation(session, mutation, baseline);
                if (result.isAnomaly) {
                    anomalies.push(result);
                    log.info('Mutation anomaly detected', {
                        scanId: session.id,
                        mutation: mutation.mutationType,
                        reason: result.anomalyReason,
                    });
                }
            } catch {
                // Skip failed mutations
            }
        }

        return anomalies;
    }

    // ─── Mutation Generators ────────────────────────────────────────────

    private generateHeaderInjections(base: BaseRequest): MutatedRequest[] {
        return INJECTION_HEADERS.map(inj => ({
            ...base,
            headers: { ...base.headers, [inj.header]: inj.value },
            mutationType: 'header_injection',
            mutationDescription: inj.description,
        }));
    }

    private generateMethodSwitches(base: BaseRequest): MutatedRequest[] {
        const mutations: MutatedRequest[] = [];
        const upperMethod = base.method.toUpperCase();

        for (const sw of METHOD_SWITCHES) {
            if (sw.from === upperMethod) {
                mutations.push({
                    ...base,
                    method: sw.to,
                    mutationType: 'method_switch',
                    mutationDescription: `Method switch: ${sw.from} → ${sw.to}`,
                });
            }
        }

        return mutations;
    }

    private generateContentTypeSwitches(base: BaseRequest): MutatedRequest[] {
        if (!base.body) return []; // No body to re-encode

        const mutations: MutatedRequest[] = [];
        const currentType = base.contentType ?? base.headers['Content-Type'] ?? '';

        for (const targetType of CONTENT_TYPES) {
            if (currentType.includes(targetType)) continue;

            const convertedBody = this.convertBody(base.body, currentType, targetType);
            if (convertedBody) {
                mutations.push({
                    ...base,
                    body: convertedBody,
                    contentType: targetType,
                    headers: { ...base.headers, 'Content-Type': targetType },
                    mutationType: 'content_type_switch',
                    mutationDescription: `Content-Type switch to ${targetType}`,
                });
            }
        }

        return mutations;
    }

    private generateParameterDuplications(base: BaseRequest): MutatedRequest[] {
        const mutations: MutatedRequest[] = [];

        try {
            const url = new URL(base.url);
            const params = Array.from(url.searchParams.entries());
            if (params.length === 0) return [];

            // Duplicate each parameter with a different value
            for (const [key, value] of params) {
                const mutatedUrl = new URL(base.url);
                mutatedUrl.searchParams.append(key, `${value}999`);

                mutations.push({
                    ...base,
                    url: mutatedUrl.toString(),
                    mutationType: 'param_duplication',
                    mutationDescription: `Duplicate param "${key}" (HTTP Parameter Pollution)`,
                });
            }
        } catch {
            // Invalid URL
        }

        return mutations;
    }

    private generateEncodingMutations(base: BaseRequest): MutatedRequest[] {
        const mutations: MutatedRequest[] = [];

        try {
            const url = new URL(base.url);
            const path = url.pathname;

            // Double URL encoding
            const doubleEncoded = path.replace(/[/]/g, (c) => encodeURIComponent(encodeURIComponent(c)));
            if (doubleEncoded !== path) {
                const doubleUrl = `${url.origin}${doubleEncoded}${url.search}`;
                mutations.push({
                    ...base,
                    url: doubleUrl,
                    mutationType: 'encoding_mutation',
                    mutationDescription: 'Double URL encoding on path',
                });
            }

            // Unicode normalization (e.g., /admin → /ádmin)
            const unicodePath = path.replace(/a/g, 'á').replace(/e/g, 'é');
            if (unicodePath !== path) {
                const unicodeUrl = `${url.origin}${unicodePath}${url.search}`;
                mutations.push({
                    ...base,
                    url: unicodeUrl,
                    mutationType: 'encoding_mutation',
                    mutationDescription: 'Unicode normalization bypass',
                });
            }

            // Path traversal encoding
            if (path.length > 1) {
                const traversalUrl = `${url.origin}${path}%00${url.search}`;
                mutations.push({
                    ...base,
                    url: traversalUrl,
                    mutationType: 'encoding_mutation',
                    mutationDescription: 'Null byte injection in path',
                });
            }
        } catch {
            // Invalid URL
        }

        return mutations;
    }

    // ─── Body Conversion ────────────────────────────────────────────────

    private convertBody(body: string, fromType: string, toType: string): string | null {
        try {
            if (fromType.includes('json') && toType.includes('form')) {
                // JSON → form-urlencoded
                const obj = JSON.parse(body) as Record<string, unknown>;
                return Object.entries(obj)
                    .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(String(v))}`)
                    .join('&');
            }

            if (fromType.includes('form') && toType.includes('json')) {
                // form-urlencoded → JSON
                const pairs = body.split('&');
                const obj: Record<string, string> = {};
                for (const pair of pairs) {
                    const [key, value] = pair.split('=');
                    if (key) obj[decodeURIComponent(key)] = decodeURIComponent(value ?? '');
                }
                return JSON.stringify(obj);
            }

            if (toType.includes('xml')) {
                // Convert to simple XML
                try {
                    const obj = JSON.parse(body) as Record<string, unknown>;
                    const xmlParts = Object.entries(obj)
                        .map(([k, v]) => `<${k}>${String(v)}</${k}>`);
                    return `<?xml version="1.0"?><root>${xmlParts.join('')}</root>`;
                } catch {
                    return `<?xml version="1.0"?><root><data>${body}</data></root>`;
                }
            }

            // text/plain: just pass through
            if (toType.includes('text/plain')) {
                return body;
            }

            return null;
        } catch {
            return null;
        }
    }
}
