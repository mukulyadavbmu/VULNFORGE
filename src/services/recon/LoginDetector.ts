/**
 * LoginDetector — Detect login forms, identify login endpoints,
 * test default credentials, extract session data.
 *
 * Runs during recon phase to auto-populate auth contexts.
 * No eval(). Bounded attempts. Timeout-safe.
 */
import { ScanSession, AttackNode, AuthContext } from '../../types';
import { httpRequest } from '../../utils/scanUtils';
import { logger } from '../../utils/logger';

const log = logger.child({ module: 'LoginDetector' });

// ─── Constants ──────────────────────────────────────────────────────────────

const MAX_LOGIN_ATTEMPTS = 8;
const LOGIN_TIMEOUT_MS = 5000;

// ─── Types ──────────────────────────────────────────────────────────────────

export interface LoginForm {
    url: string;
    action: string;
    method: string;
    usernameField: string;
    passwordField: string;
}

export interface LoginEndpoint {
    url: string;
    method: string;
    source: 'form' | 'url_pattern';
}

export interface LoginResult {
    endpoint: string;
    username: string;
    success: boolean;
    cookies: Record<string, string>;
    tokens: string[];
    authContext: AuthContext | null;
}

export interface LoginDetectionResult {
    formsDetected: LoginForm[];
    endpointsIdentified: LoginEndpoint[];
    loginAttempts: number;
    successfulLogins: LoginResult[];
    authContextsPopulated: number;
}

// ─── Default Credentials ────────────────────────────────────────────────────

const DEFAULT_CREDENTIALS: Array<{ username: string; password: string }> = [
    // Common admin credentials
    { username: 'admin', password: 'admin' },
    { username: 'admin', password: 'password' },
    { username: 'admin', password: '123456' },
    { username: 'admin', password: 'admin123' },
    { username: 'admin', password: '12345678' },
    
    // Common test credentials
    { username: 'test', password: 'test' },
    { username: 'test', password: 'test123' },
    { username: 'test', password: 'password' },
    
    // Demo/guest accounts
    { username: 'demo', password: 'demo' },
    { username: 'demo', password: 'demo123' },
    { username: 'guest', password: 'guest' },
    { username: 'user', password: 'password' },
    { username: 'user', password: 'user123' },
    
    // Default system accounts
    { username: 'root', password: 'root' },
    { username: 'root', password: 'password' },
    { username: 'root', password: 'toor' },
    
    // Generic patterns
    { username: 'administrator', password: 'password' },
    { username: 'superuser', password: 'password' },
    { username: 'root@localhost', password: 'root' },
];

// ─── URL Patterns for Login Endpoints ───────────────────────────────────────

const LOGIN_URL_PATTERNS: RegExp[] = [
    /\/login\/?$/i,
    /\/signin\/?$/i,
    /\/sign-in\/?$/i,
    /\/auth\/login\/?$/i,
    /\/api\/auth\/login\/?$/i,
    /\/api\/login\/?$/i,
    /\/api\/signin\/?$/i,
    /\/api\/v\d+\/auth\/login\/?$/i,
    /\/api\/v\d+\/login\/?$/i,
    /\/session\/?$/i,
    /\/api\/session\/?$/i,
    /\/authenticate\/?$/i,
    /\/api\/authenticate\/?$/i,
];

// ─── Form Field Patterns ────────────────────────────────────────────────────

const USERNAME_FIELD_PATTERNS = [
    'username', 'user', 'email', 'login', 'user_name',
    'user_email', 'userid', 'user_id', 'uname',
];

const PASSWORD_FIELD_PATTERNS = [
    'password', 'pass', 'pwd', 'passwd', 'user_password',
    'user_pass', 'login_password',
];

// ─── Engine ─────────────────────────────────────────────────────────────────

export class LoginDetector {

    /**
     * Full login detection pipeline: detect forms → identify endpoints →
     * attempt default logins → extract sessions → store auth contexts.
     */
    async detect(session: ScanSession, nodes: AttackNode[]): Promise<LoginDetectionResult> {
        const forms = await this.detectLoginForms(session, nodes);
        const urlEndpoints = this.identifyLoginEndpoints(nodes);

        // Merge form-based and URL-based endpoints
        const allEndpoints: LoginEndpoint[] = [
            ...forms.map(f => ({
                url: this.resolveFormAction(session.targetUrl, f.action),
                method: f.method.toUpperCase(),
                source: 'form' as const,
            })),
            ...urlEndpoints,
        ];

        // Deduplicate by URL
        const seen = new Set<string>();
        const uniqueEndpoints = allEndpoints.filter(ep => {
            if (seen.has(ep.url)) return false;
            seen.add(ep.url);
            return true;
        });

        log.info('Login endpoints identified', {
            scanId: session.id,
            forms: forms.length,
            urlPatterns: urlEndpoints.length,
            unique: uniqueEndpoints.length,
        });

        // Attempt default logins
        const successfulLogins: LoginResult[] = [];
        let loginAttempts = 0;

        for (const endpoint of uniqueEndpoints.slice(0, 3)) {
            for (const cred of DEFAULT_CREDENTIALS) {
                if (loginAttempts >= MAX_LOGIN_ATTEMPTS) break;
                loginAttempts++;

                const result = await this.attemptLogin(session, endpoint, cred, forms);
                if (result.success) {
                    successfulLogins.push(result);
                    log.info('Default login succeeded', {
                        scanId: session.id,
                        endpoint: endpoint.url,
                        username: cred.username,
                    });
                    break; // One success per endpoint is enough
                }
            }
        }

        // Store auth contexts
        let authContextsPopulated = 0;
        // Prioritize admin logins first
        successfulLogins.sort((a, b) => {
            const aAdmin = a.username.toLowerCase().includes('admin') || a.username.toLowerCase().includes('root');
            const bAdmin = b.username.toLowerCase().includes('admin') || b.username.toLowerCase().includes('root');
            if (aAdmin && !bAdmin) return -1;
            if (!aAdmin && bAdmin) return 1;
            return 0;
        });

        for (let i = 0; i < successfulLogins.length && i < 3; i++) {
            const login = successfulLogins[i];
            
            // Assign roles
            let context: AuthContext;
            if (i === 0 && (login.username.toLowerCase().includes('admin') || login.username.toLowerCase().includes('root'))) {
                context = 'admin';
            } else if (i === 0) {
                context = 'userA';
            } else if (i === 1 && session.authHeaders['admin']) {
                context = 'userA';
            } else if (i === 1) {
                context = 'userB';
            } else {
                context = 'userB';
            }

            const headers: Record<string, string> = {};

            // Set cookies
            if (Object.keys(login.cookies).length > 0) {
                headers['Cookie'] = Object.entries(login.cookies)
                    .map(([k, v]) => `${k}=${v}`)
                    .join('; ');
            }

            // Set bearer token
            if (login.tokens.length > 0) {
                headers['Authorization'] = `Bearer ${login.tokens[0]}`;
            }

            if (Object.keys(headers).length > 0) {
                session.authHeaders[context] = {
                    ...session.authHeaders[context],
                    ...headers,
                };
                login.authContext = context;
                authContextsPopulated++;
                log.info('Auth context auto-populated', {
                    scanId: session.id,
                    context,
                    username: login.username,
                });
            }
        }

        return {
            formsDetected: forms,
            endpointsIdentified: uniqueEndpoints,
            loginAttempts,
            successfulLogins,
            authContextsPopulated,
        };
    }

    /**
     * Detect login forms by fetching pages and scanning HTML for
     * forms with username/email + password fields.
     */
    async detectLoginForms(session: ScanSession, nodes: AttackNode[]): Promise<LoginForm[]> {
        const forms: LoginForm[] = [];
        const pageNodes = nodes.filter(n => n.type === 'page').slice(0, 20);

        for (const node of pageNodes) {
            try {
                const res = await httpRequest(session, node.url, 'guest');
                const detectedForms = this.parseFormsFromHTML(res.bodySnippet, node.url);
                forms.push(...detectedForms);
            } catch {
                // Skip failed requests
            }
        }

        return forms;
    }

    /**
     * Identify login endpoints by URL pattern matching.
     */
    identifyLoginEndpoints(nodes: AttackNode[]): LoginEndpoint[] {
        const endpoints: LoginEndpoint[] = [];

        for (const node of nodes) {
            for (const pattern of LOGIN_URL_PATTERNS) {
                try {
                    const urlPath = new URL(node.url).pathname;
                    if (pattern.test(urlPath)) {
                        endpoints.push({
                            url: node.url,
                            method: node.method?.toUpperCase() ?? 'POST',
                            source: 'url_pattern',
                        });
                        break; // One match per node is enough
                    }
                } catch {
                    // Invalid URL
                }
            }
        }

        return endpoints;
    }

    // ─── Private Helpers ────────────────────────────────────────────────

    private parseFormsFromHTML(html: string, pageUrl: string): LoginForm[] {
        const forms: LoginForm[] = [];
        const formRegex = /<form[^>]*>([\s\S]*?)<\/form>/gi;
        let formMatch: RegExpExecArray | null;

        while ((formMatch = formRegex.exec(html)) !== null) {
            const formTag = formMatch[0];
            const formContent = formMatch[1];

            // Extract action
            const actionMatch = /action\s*=\s*["']([^"']+)["']/i.exec(formTag);
            const action = actionMatch ? actionMatch[1] : pageUrl;

            // Extract method
            const methodMatch = /method\s*=\s*["']([^"']+)["']/i.exec(formTag);
            const method = methodMatch ? methodMatch[1].toUpperCase() : 'POST';

            // Find input fields
            const inputs = this.extractInputFields(formContent);
            const usernameField = this.findField(inputs, USERNAME_FIELD_PATTERNS);
            const passwordField = this.findField(inputs, PASSWORD_FIELD_PATTERNS);

            // Must have both username and password fields
            if (usernameField && passwordField) {
                forms.push({
                    url: pageUrl,
                    action,
                    method,
                    usernameField,
                    passwordField,
                });
            }
        }

        return forms;
    }

    private extractInputFields(formContent: string): Array<{ name: string; type: string }> {
        const fields: Array<{ name: string; type: string }> = [];
        const inputRegex = /<input[^>]*>/gi;
        let inputMatch: RegExpExecArray | null;

        while ((inputMatch = inputRegex.exec(formContent)) !== null) {
            const tag = inputMatch[0];
            const nameMatch = /name\s*=\s*["']([^"']+)["']/i.exec(tag);
            const typeMatch = /type\s*=\s*["']([^"']+)["']/i.exec(tag);
            if (nameMatch) {
                fields.push({
                    name: nameMatch[1],
                    type: typeMatch ? typeMatch[1].toLowerCase() : 'text',
                });
            }
        }

        return fields;
    }

    private findField(
        inputs: Array<{ name: string; type: string }>,
        patterns: string[],
    ): string | null {
        // First try by type
        const passwordByType = inputs.find(i => i.type === 'password');
        if (patterns === PASSWORD_FIELD_PATTERNS && passwordByType) {
            return passwordByType.name;
        }

        // Then by name
        for (const input of inputs) {
            const lower = input.name.toLowerCase();
            if (patterns.some(p => lower.includes(p))) {
                return input.name;
            }
        }

        return null;
    }

    private async attemptLogin(
        session: ScanSession,
        endpoint: LoginEndpoint,
        cred: { username: string; password: string },
        forms: LoginForm[],
    ): Promise<LoginResult> {
        const result: LoginResult = {
            endpoint: endpoint.url,
            username: cred.username,
            success: false,
            cookies: {},
            tokens: [],
            authContext: null,
        };

        try {
            // Find matching form for field names
            const form = forms.find(f => {
                const resolvedAction = this.resolveFormAction(session.targetUrl, f.action);
                return resolvedAction === endpoint.url;
            });

            const usernameField = form?.usernameField ?? 'username';
            const passwordField = form?.passwordField ?? 'password';

            // Try JSON body first for API endpoints
            const isApi = endpoint.url.includes('/api/') || endpoint.source === 'url_pattern';

            const body = isApi
                ? JSON.stringify({ [usernameField]: cred.username, [passwordField]: cred.password })
                : `${encodeURIComponent(usernameField)}=${encodeURIComponent(cred.username)}&${encodeURIComponent(passwordField)}=${encodeURIComponent(cred.password)}`;

            const contentType = isApi ? 'application/json' : 'application/x-www-form-urlencoded';

            const res = await httpRequest(session, endpoint.url, 'guest', {
                method: endpoint.method,
                data: body,
                headers: { 'Content-Type': contentType },
            });

            // Determine success: 2xx status + no obvious error messages
            const isSuccess = res.status >= 200 && res.status < 400
                && !res.bodySnippet.toLowerCase().includes('invalid')
                && !res.bodySnippet.toLowerCase().includes('incorrect')
                && !res.bodySnippet.toLowerCase().includes('failed')
                && !res.bodySnippet.toLowerCase().includes('unauthorized');

            if (isSuccess) {
                result.success = true;

                // Extract cookies from Set-Cookie headers
                if (res.headers) {
                    const setCookieHeaders = Array.isArray(res.headers['set-cookie'])
                        ? res.headers['set-cookie']
                        : res.headers['set-cookie']
                          ? [res.headers['set-cookie']]
                          : [];

                    for (const cookie of setCookieHeaders) {
                        const match = /^([^=]+)=([^;]+)/.exec(cookie);
                        if (match) {
                            result.cookies[match[1].trim()] = match[2].trim();
                        }
                    }
                }

                // Extract tokens from response body
                const tokenPatterns = [
                    /["']?(?:token|access_token|jwt|id_token)["']?\s*[:=]\s*["']?([a-zA-Z0-9._-]{20,500})["']?/i,
                    /eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/,
                    /bearer\s+([a-zA-Z0-9._-]{20,500})/i,
                    /Authorization["']?\s*:\s*["']?([a-zA-Z0-9._-]{20,500})["']?/i,
                ];

                for (const pattern of tokenPatterns) {
                    const match = pattern.exec(res.bodySnippet);
                    if (match) {
                        const token = match[1] ?? match[0];
                        if (token && !result.tokens.includes(token)) {
                            result.tokens.push(token);
                        }
                    }
                }
            }
        } catch (error) {
            const msg = error instanceof Error ? error.message : 'Unknown';
            log.debug('Login attempt failed', { endpoint: endpoint.url, error: msg });
        }

        return result;
    }

    private resolveFormAction(baseUrl: string, action: string): string {
        if (action.startsWith('http://') || action.startsWith('https://')) return action;
        try {
            const origin = new URL(baseUrl).origin;
            return `${origin}${action.startsWith('/') ? '' : '/'}${action}`;
        } catch {
            return action;
        }
    }
}
