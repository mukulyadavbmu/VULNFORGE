/**
 * JSAnalyzer — Extract API endpoints, tokens, secrets, and routes from JavaScript.
 *
 * Static analysis via regex patterns. No eval(). No AST parsing dependency.
 * Max JS size: 5MB. Safe string processing only.
 * Security: No code execution, bounded processing, timeout-safe.
 */
import { z } from 'zod';
import { logger } from '../../utils/logger';

const log = logger.child({ module: 'JSAnalyzer' });

// ─── Constants ──────────────────────────────────────────────────────────────

const MAX_JS_SIZE = 5 * 1024 * 1024; // 5MB
const MAX_RESULTS_PER_CATEGORY = 200;

// ─── Zod Schemas ────────────────────────────────────────────────────────────

const AnalyzeInputSchema = z.object({
    content: z.string().max(MAX_JS_SIZE),
    sourceUrl: z.string().max(2048).optional(),
}).strict();

// ─── Types ──────────────────────────────────────────────────────────────────

export interface JSAnalysisResult {
    sourceUrl: string | null;
    endpoints: ExtractedEndpoint[];
    secrets: ExtractedSecret[];
    routes: string[];
    totalFindings: number;
    durationMs: number;
}

export interface ExtractedEndpoint {
    path: string;
    method: string;
    context: string;
}

export interface ExtractedSecret {
    type: string;
    value: string;     // Masked — first 4 + last 2 chars only
    line: number;
    severity: 'low' | 'medium' | 'high' | 'critical';
}

// ─── Patterns ───────────────────────────────────────────────────────────────

/** API endpoint extraction patterns */
const ENDPOINT_PATTERNS: Array<{ regex: RegExp; method: string }> = [
    // fetch/axios calls
    { regex: /fetch\s*\(\s*['"`]([^'"`\s]{3,200})['"`]/g, method: 'GET' },
    { regex: /\.get\s*\(\s*['"`]([^'"`\s]{3,200})['"`]/g, method: 'GET' },
    { regex: /\.post\s*\(\s*['"`]([^'"`\s]{3,200})['"`]/g, method: 'POST' },
    { regex: /\.put\s*\(\s*['"`]([^'"`\s]{3,200})['"`]/g, method: 'PUT' },
    { regex: /\.patch\s*\(\s*['"`]([^'"`\s]{3,200})['"`]/g, method: 'PATCH' },
    { regex: /\.delete\s*\(\s*['"`]([^'"`\s]{3,200})['"`]/g, method: 'DELETE' },
    // XMLHttpRequest
    { regex: /\.open\s*\(\s*['"`](GET|POST|PUT|DELETE|PATCH)['"`]\s*,\s*['"`]([^'"`\s]{3,200})['"`]/g, method: 'DYNAMIC' },
    // URL strings that look like API paths
    { regex: /['"`](\/api\/[a-zA-Z0-9/_-]{2,150})['"`]/g, method: 'UNKNOWN' },
    { regex: /['"`](\/v[0-9]+\/[a-zA-Z0-9/_-]{2,150})['"`]/g, method: 'UNKNOWN' },
    // GraphQL endpoints
    { regex: /['"`](\/graphql[a-zA-Z0-9/_-]*)['"`]/g, method: 'POST' },
];

/** Secret/token detection patterns */
const SECRET_PATTERNS: Array<{
    name: string;
    regex: RegExp;
    severity: 'low' | 'medium' | 'high' | 'critical';
}> = [
        // API Keys
        { name: 'AWS Access Key', regex: /(?:AKIA)[A-Z0-9]{16}/g, severity: 'critical' },
        { name: 'Generic API Key', regex: /['"`]([a-zA-Z0-9_-]{32,64})['"`]\s*(?:,|\))/g, severity: 'medium' },
        { name: 'Bearer Token', regex: /Bearer\s+([a-zA-Z0-9._-]{20,500})/g, severity: 'high' },
        { name: 'JWT', regex: /eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}/g, severity: 'high' },
        // Private keys / passwords
        { name: 'Password Assignment', regex: /(?:password|passwd|pwd)\s*[:=]\s*['"`]([^'"`\s]{4,100})['"`]/gi, severity: 'critical' },
        { name: 'Secret Assignment', regex: /(?:secret|token|apikey|api_key)\s*[:=]\s*['"`]([^'"`\s]{8,200})['"`]/gi, severity: 'high' },
        // Cloud keys
        { name: 'Google API Key', regex: /AIza[a-zA-Z0-9_-]{35}/g, severity: 'high' },
        { name: 'Stripe Key', regex: /(?:sk|pk)_(?:live|test)_[a-zA-Z0-9]{20,}/g, severity: 'critical' },
        { name: 'GitHub Token', regex: /gh[pousr]_[a-zA-Z0-9]{36,}/g, severity: 'critical' },
        // Generic hex secrets (32+ chars)
        { name: 'Hex Secret', regex: /(?:secret|key|token)\s*[:=]\s*['"`]([a-f0-9]{32,64})['"`]/gi, severity: 'medium' },
    ];

/** Route patterns (SPA frameworks) */
const ROUTE_PATTERNS: RegExp[] = [
    // React Router
    /path\s*[:=]\s*['"`](\/[a-zA-Z0-9/:_-]{1,100})['"`]/g,
    // Vue Router
    /path\s*:\s*['"`](\/[a-zA-Z0-9/:_-]{1,100})['"`]/g,
    // Express-style
    /(?:app|router)\s*\.(?:get|post|put|delete|patch|all)\s*\(\s*['"`](\/[a-zA-Z0-9/:_-]{1,100})['"`]/g,
    // String path references
    /['"`](\/[a-z][a-zA-Z0-9/_-]{2,80})['"`]/g,
];

// ─── Engine ─────────────────────────────────────────────────────────────────

export class JSAnalyzer {
    /**
     * Analyze JavaScript content for endpoints, secrets, and routes.
     * No eval(). Static regex analysis only.
     */
    analyze(content: string, sourceUrl?: string): JSAnalysisResult {
        const validated = AnalyzeInputSchema.parse({ content, sourceUrl });
        const start = Date.now();

        log.info('JS analysis started', {
            sourceUrl: validated.sourceUrl ?? 'inline',
            contentLength: validated.content.length,
        });

        const endpoints = this.extractEndpoints(validated.content);
        const secrets = this.extractSecrets(validated.content);
        const routes = this.extractRoutes(validated.content);

        const totalFindings = endpoints.length + secrets.length + routes.length;
        const durationMs = Date.now() - start;

        log.info('JS analysis complete', {
            sourceUrl: validated.sourceUrl ?? 'inline',
            endpoints: endpoints.length,
            secrets: secrets.length,
            routes: routes.length,
            durationMs,
        });

        return {
            sourceUrl: validated.sourceUrl ?? null,
            endpoints,
            secrets,
            routes,
            totalFindings,
            durationMs,
        };
    }

    /**
     * Extract API endpoints from JS content.
     */
    private extractEndpoints(content: string): ExtractedEndpoint[] {
        const endpoints: ExtractedEndpoint[] = [];
        const seen = new Set<string>();

        for (const pattern of ENDPOINT_PATTERNS) {
            // Reset lastIndex for each pattern
            pattern.regex.lastIndex = 0;
            let match: RegExpExecArray | null;

            while ((match = pattern.regex.exec(content)) !== null) {
                // For XMLHttpRequest pattern, method is in group 1, URL in group 2
                let path: string;
                let method: string;

                if (pattern.method === 'DYNAMIC' && match[2]) {
                    method = match[1];
                    path = match[2];
                } else {
                    method = pattern.method;
                    path = match[1];
                }

                // Normalize
                path = path.trim();
                if (!path.startsWith('/') && !path.startsWith('http')) continue;
                if (path.length < 3) continue;

                const key = `${method}:${path}`;
                if (seen.has(key)) continue;
                seen.add(key);

                // Get surrounding context (30 chars before match)
                const contextStart = Math.max(0, match.index - 30);
                const context = content.slice(contextStart, match.index + match[0].length).trim();

                endpoints.push({ path, method, context: context.slice(0, 100) });

                if (endpoints.length >= MAX_RESULTS_PER_CATEGORY) break;
            }

            if (endpoints.length >= MAX_RESULTS_PER_CATEGORY) break;
        }

        return endpoints;
    }

    /**
     * Extract secrets and tokens from JS content.
     * Values are MASKED for safety — only first 4 + last 2 chars shown.
     */
    private extractSecrets(content: string): ExtractedSecret[] {
        const secrets: ExtractedSecret[] = [];
        const seen = new Set<string>();
        const lines = content.split('\n');

        for (const pattern of SECRET_PATTERNS) {
            pattern.regex.lastIndex = 0;
            let match: RegExpExecArray | null;

            while ((match = pattern.regex.exec(content)) !== null) {
                const rawValue = match[1] ?? match[0];

                // Skip short matches or common false positives
                if (rawValue.length < 8) continue;
                if (this.isFalsePositive(rawValue)) continue;

                const masked = this.maskValue(rawValue);

                if (seen.has(masked)) continue;
                seen.add(masked);

                // Find line number
                const lineNumber = this.getLineNumber(content, match.index, lines);

                secrets.push({
                    type: pattern.name,
                    value: masked,
                    line: lineNumber,
                    severity: pattern.severity,
                });

                if (secrets.length >= MAX_RESULTS_PER_CATEGORY) break;
            }

            if (secrets.length >= MAX_RESULTS_PER_CATEGORY) break;
        }

        return secrets;
    }

    /**
     * Extract front-end routes from JS content.
     */
    private extractRoutes(content: string): string[] {
        const routes = new Set<string>();

        for (const pattern of ROUTE_PATTERNS) {
            pattern.lastIndex = 0;
            let match: RegExpExecArray | null;

            while ((match = pattern.exec(content)) !== null) {
                const route = match[1].trim();
                if (route.length < 2 || route.length > 100) continue;
                if (!route.startsWith('/')) continue;

                routes.add(route);

                if (routes.size >= MAX_RESULTS_PER_CATEGORY) break;
            }

            if (routes.size >= MAX_RESULTS_PER_CATEGORY) break;
        }

        return Array.from(routes).sort();
    }

    /**
     * Mask a secret value for safe logging.
     * Shows first 4 and last 2 chars: "sk_live_abc...xy"
     */
    private maskValue(value: string): string {
        if (value.length <= 8) return '****';
        return `${value.slice(0, 4)}...${value.slice(-2)}`;
    }

    /**
     * Check for common false positives.
     */
    private isFalsePositive(value: string): boolean {
        // Common placeholder values
        const placeholders = [
            'undefined', 'null', 'true', 'false', 'function',
            'object', 'string', 'number', 'boolean', 'prototype',
            'constructor', 'toString', 'hasOwnProperty',
            'YOUR_API_KEY', 'INSERT_KEY_HERE', 'PLACEHOLDER',
            'xxxxxxxx', '00000000', 'aaaaaaaa',
        ];

        const lower = value.toLowerCase();
        if (placeholders.some(p => lower === p.toLowerCase())) return true;

        // All same character
        if (new Set(value).size <= 2) return true;

        return false;
    }

    /**
     * Get line number for a character offset.
     */
    private getLineNumber(content: string, offset: number, _lines: string[]): number {
        let line = 1;
        for (let i = 0; i < Math.min(offset, content.length); i++) {
            if (content[i] === '\n') line++;
        }
        return line;
    }
}
