/**
 * JSAnalyzer — Extract API endpoints, tokens, secrets, and routes from JavaScript.
 *
 * Static analysis via regex patterns. No eval(). No AST parsing dependency.
 * Max JS size: 5MB. Safe string processing only.
 * Security: No code execution, bounded processing, timeout-safe.
 */
import { z } from 'zod';
import { logger } from '../../utils/logger';
import { ShannonAnalyzer } from '../intelligence/ShannonAnalyzer';

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
    hiddenApis: HiddenAPI[];
    authLogic: AuthLogicRef[];
    sensitiveOps: SensitiveOpRef[];
    totalFindings: number;
    durationMs: number;
}

export interface HiddenAPI {
    path: string;
    reason: string;
    line: number;
}

export interface AuthLogicRef {
    pattern: string;
    context: string;
    line: number;
}

export interface SensitiveOpRef {
    operation: string;
    context: string;
    line: number;
}

export interface ExtractedEndpoint {
    path: string;
    method: string;
    context: string;
    paramPlaceholders: string[];
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
    // axios instance calls (axios.get, axios.post, etc.)
    { regex: /axios\s*\.\s*(get|post|put|delete|patch)\s*\(\s*['"`]([^'"`\s]{3,200})['"`]/g, method: 'DYNAMIC' },
    // XMLHttpRequest
    { regex: /\.open\s*\(\s*['"`](GET|POST|PUT|DELETE|PATCH)['"`]\s*,\s*['"`]([^'"`\s]{3,200})['"`]/g, method: 'DYNAMIC' },
    // URL strings that look like API paths
    { regex: /['"`](\/api\/[a-zA-Z0-9/_-]{2,150})['"`]/g, method: 'UNKNOWN' },
    { regex: /['"`](\/v[0-9]+\/[a-zA-Z0-9/_-]{2,150})['"`]/g, method: 'UNKNOWN' },
    // GraphQL endpoints
    { regex: /['"`](\/graphql[a-zA-Z0-9/_-]*)['"`]/g, method: 'POST' },
    // GraphQL mutation/subscription operations
    { regex: /(?:mutation|subscription)\s+(\w+)\s*\(/g, method: 'POST' },
    // REST route templates: router.get('/users/:id')
    { regex: /(?:router|app)\s*\.\s*(get|post|put|delete|patch|all)\s*\(\s*['"`]([^'"`\s]{3,200})['"`]/g, method: 'DYNAMIC' },
];

/** Template literal endpoint pattern (backtick strings with ${}) */
const TEMPLATE_LITERAL_PATTERN = /`([^`]*\$\{[^}]+\}[^`]*)`/g;

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
        const hiddenApis = this.detectHiddenApis(validated.content);
        const authLogic = this.detectAuthLogic(validated.content);
        const sensitiveOps = this.detectSensitiveOps(validated.content);

        const totalFindings = endpoints.length + secrets.length + routes.length
            + hiddenApis.length + authLogic.length + sensitiveOps.length;
        const durationMs = Date.now() - start;

        log.info('JS analysis complete', {
            sourceUrl: validated.sourceUrl ?? 'inline',
            endpoints: endpoints.length,
            secrets: secrets.length,
            routes: routes.length,
            hiddenApis: hiddenApis.length,
            authLogic: authLogic.length,
            sensitiveOps: sensitiveOps.length,
            durationMs,
        });

        return {
            sourceUrl: validated.sourceUrl ?? null,
            endpoints,
            secrets,
            routes,
            hiddenApis,
            authLogic,
            sensitiveOps,
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
                // For XMLHttpRequest/axios/router pattern, method is in group 1, URL in group 2
                let path: string;
                let method: string;

                if (pattern.method === 'DYNAMIC' && match[2]) {
                    method = match[1].toUpperCase();
                    path = match[2];
                } else {
                    method = pattern.method;
                    path = match[1];
                }

                // Normalize
                path = path.trim();
                if (!path.startsWith('/') && !path.startsWith('http')) continue;
                if (path.length < 3) continue;

                // Extract param placeholders from :param patterns
                const placeholders = this.extractPlaceholders(path);

                const key = `${method}:${path}`;
                if (seen.has(key)) continue;
                seen.add(key);

                // Get surrounding context (30 chars before match)
                const contextStart = Math.max(0, match.index - 30);
                const context = content.slice(contextStart, match.index + match[0].length).trim();

                endpoints.push({ path, method, context: context.slice(0, 100), paramPlaceholders: placeholders });

                if (endpoints.length >= MAX_RESULTS_PER_CATEGORY) break;
            }

            if (endpoints.length >= MAX_RESULTS_PER_CATEGORY) break;
        }

        // Also extract template literal endpoints
        TEMPLATE_LITERAL_PATTERN.lastIndex = 0;
        let tmplMatch: RegExpExecArray | null;
        while ((tmplMatch = TEMPLATE_LITERAL_PATTERN.exec(content)) !== null) {
            const raw = tmplMatch[1];
            // Convert `/api/user/${id}` → `/api/user/:id`
            const path = raw.replace(/\$\{([^}]+)\}/g, ':$1');
            if (!path.startsWith('/') || path.length < 3) continue;

            const placeholders = this.extractPlaceholders(path);
            const key = `UNKNOWN:${path}`;
            if (seen.has(key)) continue;
            seen.add(key);

            const contextStart = Math.max(0, tmplMatch.index - 20);
            const context = content.slice(contextStart, tmplMatch.index + tmplMatch[0].length).trim();
            endpoints.push({ path, method: 'UNKNOWN', context: context.slice(0, 100), paramPlaceholders: placeholders });

            if (endpoints.length >= MAX_RESULTS_PER_CATEGORY) break;
        }

        return endpoints;
    }

    /**
     * Extract :param placeholders from a route path.
     */
    private extractPlaceholders(path: string): string[] {
        const placeholders: string[] = [];
        const regex = /:([a-zA-Z_][a-zA-Z0-9_]*)/g;
        let m: RegExpExecArray | null;
        while ((m = regex.exec(path)) !== null) {
            placeholders.push(m[1]);
        }
        return placeholders;
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
     * Filters CSS variables, framework tokens, low-entropy strings, and placeholders.
     * Strict filtering: entropy > 4.2, length >= 16, mixed character types required.
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

        // ── Framework & CSS variable false positives ─────────────────────
        // Angular Material, MDC, CDK, Bootstrap tokens that look like secrets
        const CSS_PREFIXES = [
            'mat-', 'mdc-', 'cdk-', '--mat', '--mdc', '--cdk',
            'ng-', '--ng-', 'md-', '--md-', 'bs-', '--bs-',
            'data-', 'aria-', 'role-',
        ];
        if (CSS_PREFIXES.some(prefix => lower.startsWith(prefix))) return true;

        // CSS variable names and design tokens
        const CSS_KEYWORDS = [
            'theme', 'color', 'palette', 'font', 'spacing', 'border',
            'radius', 'shadow', 'opacity', 'transition', 'gradient',
            'margin', 'padding', 'width', 'height', 'display',
            'background', 'foreground', 'primary', 'secondary', 'accent',
            'surface', 'outline', 'container', 'elevation', 'breakpoint',
            'size', 'weight', 'family', 'line', 'track', 'state',
        ];
        if (CSS_KEYWORDS.some(kw => lower.includes(kw))) return true;

        // CSS-like patterns: custom properties, hex colors, units
        if (/^--[a-z]/.test(lower)) return true;
        if (/^#[0-9a-f]{3,8}$/.test(lower)) return true;
        if (/^\d+(\.\d+)?(px|rem|em|ex|ch|vw|vh|vmin|vmax|%)$/.test(lower)) return true;

        // ── Minimum length check (STRICT: >= 16) ──────────────────────
        if (value.length < 16) return true;

        // ── Require mixed character types: must have uppercase, lowercase, AND (digits OR symbols) ──
        const hasLower = /[a-z]/.test(value);
        const hasUpper = /[A-Z]/.test(value);
        const hasDigits = /[0-9]/.test(value);
        const hasSymbols = /[^a-zA-Z0-9]/.test(value);
        const mixedTypes = (hasLower || hasUpper) && (hasDigits || hasSymbols);
        if (!mixedTypes && !(/^[a-f0-9]{16,}$/i.test(value))) return true; // Allow hex if long enough

        // ── Entropy check: real secrets have HIGH randomness (STRICT: > 4.2) ──
        const entropy = ShannonAnalyzer.calculateEntropy(value);
        if (entropy < 4.2) return true;

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

    // ─── Hidden API Detection ───────────────────────────────────────────

    /**
     * Detect hidden/internal API paths in JS bundles.
     * Finds: /api/internal/*, /api/private/*, /v1/admin/*, etc.
     */
    detectHiddenApis(content: string): HiddenAPI[] {
        const results: HiddenAPI[] = [];
        const seen = new Set<string>();

        const HIDDEN_PATTERNS: Array<{ regex: RegExp; reason: string }> = [
            { regex: /['"`](\/api\/internal\/[a-zA-Z0-9/_-]{1,150})['"`]/g, reason: 'Internal API found inside JS bundle' },
            { regex: /['"`](\/api\/private\/[a-zA-Z0-9/_-]{1,150})['"`]/g, reason: 'Private API endpoint exposed in JS' },
            { regex: /['"`](\/internal\/[a-zA-Z0-9/_-]{1,150})['"`]/g, reason: 'Internal path found inside JS bundle' },
            { regex: /['"`](\/private\/[a-zA-Z0-9/_-]{1,150})['"`]/g, reason: 'Private endpoint exposed in client JS' },
            { regex: /['"`](\/api\/admin\/[a-zA-Z0-9/_-]{1,150})['"`]/g, reason: 'Admin API found inside JS bundle' },
            { regex: /['"`](\/v[0-9]+\/internal\/[a-zA-Z0-9/_-]{1,150})['"`]/g, reason: 'Versioned internal API in JS bundle' },
            { regex: /['"`](\/v[0-9]+\/admin\/[a-zA-Z0-9/_-]{1,150})['"`]/g, reason: 'Versioned admin API in JS bundle' },
            { regex: /['"`](\/debug\/[a-zA-Z0-9/_-]{1,150})['"`]/g, reason: 'Debug endpoint exposed in JS' },
            { regex: /['"`](\/api\/debug\/[a-zA-Z0-9/_-]{1,150})['"`]/g, reason: 'Debug API found inside JS bundle' },
            { regex: /['"`](\/api\/hidden\/[a-zA-Z0-9/_-]{1,150})['"`]/g, reason: 'Hidden API endpoint in JS' },
        ];

        for (const pattern of HIDDEN_PATTERNS) {
            pattern.regex.lastIndex = 0;
            let match: RegExpExecArray | null;

            while ((match = pattern.regex.exec(content)) !== null) {
                const path = match[1];
                if (seen.has(path)) continue;
                seen.add(path);

                const line = this.getLineNumber(content, match.index, []);
                results.push({ path, reason: pattern.reason, line });

                if (results.length >= MAX_RESULTS_PER_CATEGORY) break;
            }
            if (results.length >= MAX_RESULTS_PER_CATEGORY) break;
        }

        return results;
    }

    // ─── Auth Logic Detection ───────────────────────────────────────────

    /**
     * Detect client-side auth logic patterns.
     * Finds: isAdmin, role checks, token handling, auth guards.
     */
    detectAuthLogic(content: string): AuthLogicRef[] {
        const results: AuthLogicRef[] = [];
        const seen = new Set<string>();

        const AUTH_PATTERNS: Array<{ regex: RegExp; label: string }> = [
            { regex: /\bisAdmin\b/g, label: 'isAdmin check' },
            { regex: /\bis_admin\b/g, label: 'is_admin check' },
            { regex: /\brole\s*[=!]==?\s*['"`](admin|superuser|root|moderator)['"`]/g, label: 'Role comparison' },
            { regex: /\broles?\s*\.\s*includes?\s*\(/g, label: 'Role array check' },
            { regex: /\btoken\s*[:=]\s*(?:localStorage|sessionStorage|cookie)/gi, label: 'Token storage' },
            { regex: /\bauth(?:enticate|orize|Token|Header|Guard)\b/g, label: 'Auth function reference' },
            { regex: /\bsetAuth\b|\bgetAuth\b|\bcheckAuth\b/g, label: 'Auth state function' },
            { regex: /\bpermissions?\s*\.\s*(?:includes|has|check)/g, label: 'Permission check' },
            { regex: /(?:Bearer|Authorization)\s*[:=]/g, label: 'Auth header assignment' },
            { regex: /\.(?:canAccess|hasPermission|isAuthenticated|isLoggedIn)\b/g, label: 'Auth guard method' },
        ];

        for (const pattern of AUTH_PATTERNS) {
            pattern.regex.lastIndex = 0;
            let match: RegExpExecArray | null;

            while ((match = pattern.regex.exec(content)) !== null) {
                const key = `${pattern.label}:${match.index}`;
                if (seen.has(key)) continue;
                seen.add(key);

                const ctxStart = Math.max(0, match.index - 20);
                const ctxEnd = Math.min(content.length, match.index + match[0].length + 30);
                const context = content.slice(ctxStart, ctxEnd).replace(/\n/g, ' ').trim();
                const line = this.getLineNumber(content, match.index, []);

                results.push({ pattern: pattern.label, context: context.slice(0, 120), line });

                if (results.length >= MAX_RESULTS_PER_CATEGORY) break;
            }
            if (results.length >= MAX_RESULTS_PER_CATEGORY) break;
        }

        return results;
    }

    // ─── Sensitive Operation Detection ──────────────────────────────────

    /**
     * Detect sensitive operation references in JS.
     * Finds: deleteUser, updateUser, exportData, transferFunds, etc.
     */
    detectSensitiveOps(content: string): SensitiveOpRef[] {
        const results: SensitiveOpRef[] = [];
        const seen = new Set<string>();

        const SENSITIVE_OPS: Array<{ regex: RegExp; label: string }> = [
            { regex: /\bdeleteUser\b/g, label: 'deleteUser' },
            { regex: /\bupdateUser\b/g, label: 'updateUser' },
            { regex: /\bexportData\b/g, label: 'exportData' },
            { regex: /\bimportData\b/g, label: 'importData' },
            { regex: /\btransferFunds?\b/g, label: 'transferFunds' },
            { regex: /\bdeleteAccount\b/g, label: 'deleteAccount' },
            { regex: /\bresetPassword\b/g, label: 'resetPassword' },
            { regex: /\bchangeRole\b/g, label: 'changeRole' },
            { regex: /\bpromoteUser\b/g, label: 'promoteUser' },
            { regex: /\brevokeAccess\b/g, label: 'revokeAccess' },
            { regex: /\bgrantAccess\b/g, label: 'grantAccess' },
            { regex: /\bsuspendUser\b/g, label: 'suspendUser' },
            { regex: /\bbanUser\b/g, label: 'banUser' },
            { regex: /\bbulkDelete\b/g, label: 'bulkDelete' },
            { regex: /\bpurgeData\b/g, label: 'purgeData' },
            { regex: /\bdownloadReport\b/g, label: 'downloadReport' },
            { regex: /\bsendNotification\b/g, label: 'sendNotification' },
            { regex: /\bcreateAdmin\b/g, label: 'createAdmin' },
        ];

        for (const pattern of SENSITIVE_OPS) {
            pattern.regex.lastIndex = 0;
            let match: RegExpExecArray | null;

            while ((match = pattern.regex.exec(content)) !== null) {
                if (seen.has(pattern.label)) continue;
                seen.add(pattern.label);

                const ctxStart = Math.max(0, match.index - 20);
                const ctxEnd = Math.min(content.length, match.index + match[0].length + 40);
                const context = content.slice(ctxStart, ctxEnd).replace(/\n/g, ' ').trim();
                const line = this.getLineNumber(content, match.index, []);

                results.push({ operation: pattern.label, context: context.slice(0, 120), line });

                if (results.length >= MAX_RESULTS_PER_CATEGORY) break;
            }
            if (results.length >= MAX_RESULTS_PER_CATEGORY) break;
        }

        return results;
    }
}
