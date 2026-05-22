/**
 * StatefulAttackEngine — Per-scan session state for multi-step attack sequences.
 *
 * Maintains cookies, tokens, visited endpoints, and previous responses.
 * Enables multi-step workflows: login → extract token → reuse → escalate.
 *
 * No external dependencies. Bounded state size. Thread-safe per scanId.
 */
import { ScanSession, AttackNode } from '../../types';
import { httpRequest } from '../../utils/scanUtils';
import { logger } from '../../utils/logger';

const log = logger.child({ module: 'StatefulAttackEngine' });

// ─── Constants ──────────────────────────────────────────────────────────────

const MAX_STORED_RESPONSES = 100;
const MAX_EXTRACTED_TOKENS = 20;
const MAX_WORKFLOW_STEPS = 10;

// ─── Types ──────────────────────────────────────────────────────────────────

export interface WorkflowState {
    scanId: string;
    authTokens: Map<string, string>;
    cookies: Map<string, string>;
    visitedEndpoints: Set<string>;
    previousResponses: Map<string, StoredResponse>;
    extractedCredentials: ExtractedCredential[];
    extractedObjectIds: Array<{ type: string; value: string; sourceRole: string; createdAt: number }>;
    currentStep: number;
    createdAt: number;
}

export interface StoredResponse {
    status: number;
    bodySnippet: string;
    headers: Record<string, string>;
    timeMs: number;
    capturedAt: number;
}

export interface ExtractedCredential {
    source: string;
    type: 'cookie' | 'bearer' | 'jwt' | 'api_key' | 'session_id';
    key: string;
    value: string;
    extractedAt: number;
}

export interface WorkflowStep {
    label: string;
    action: 'request' | 'extract_token' | 'set_auth' | 'escalate';
    url?: string;
    method?: string;
    body?: string;
    headers?: Record<string, string>;
    extractPattern?: RegExp;
    extractTarget?: 'body' | 'header';
    authContext?: 'guest' | 'userA' | 'userB';
}

export interface WorkflowSequenceResult {
    stepsExecuted: number;
    stepsSucceeded: number;
    tokensExtracted: number;
    errors: string[];
}

export interface WorkflowContext {
    authTokens: ReadonlyMap<string, string>;
    cookies: ReadonlyMap<string, string>;
    visitedEndpoints: ReadonlySet<string>;
    getResponse(url: string): StoredResponse | undefined;
    getLatestToken(): ExtractedCredential | undefined;
    getAvailableObjectIds(type?: string): Array<{ type: string; value: string; sourceRole: string }>;
}

// ─── Token Extraction Patterns ──────────────────────────────────────────────

const TOKEN_PATTERNS: Array<{
    name: string;
    type: ExtractedCredential['type'];
    regex: RegExp;
}> = [
        { name: 'JWT in body', type: 'jwt', regex: /["']?(?:token|access_token|jwt|id_token)["']?\s*[:=]\s*["']?(eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)["']?/i },
        { name: 'Bearer token', type: 'bearer', regex: /["']?(?:token|access_token|bearer)["']?\s*[:=]\s*["']?([a-zA-Z0-9._-]{20,500})["']?/i },
        { name: 'Session ID', type: 'session_id', regex: /["']?(?:session_id|sessionid|sid|PHPSESSID|JSESSIONID)["']?\s*[:=]\s*["']?([a-zA-Z0-9._-]{16,200})["']?/i },
        { name: 'API Key', type: 'api_key', regex: /["']?(?:api_key|apikey|x-api-key)["']?\s*[:=]\s*["']?([a-zA-Z0-9._-]{20,200})["']?/i },
    ];

const COOKIE_PATTERN = /^([^=]+)=(.+)$/;

// ─── Engine ─────────────────────────────────────────────────────────────────

export class StatefulAttackEngine {
    private workflows: Map<string, WorkflowState> = new Map();

    /**
     * Initialize an empty workflow state for a scan.
     */
    initWorkflow(scanId: string): void {
        if (this.workflows.has(scanId)) return;

        this.workflows.set(scanId, {
            scanId,
            authTokens: new Map(),
            cookies: new Map(),
            visitedEndpoints: new Set(),
            previousResponses: new Map(),
            extractedCredentials: [],
            extractedObjectIds: [],
            currentStep: 0,
            createdAt: Date.now(),
        });

        log.info('Workflow initialized', { scanId });
    }

    /**
     * Record an HTTP response and auto-extract cookies + tokens.
     */
    recordResponse(
        scanId: string,
        url: string,
        response: { status: number; bodySnippet: string; headers?: Record<string, string>; timeMs: number },
    ): void {
        const state = this.workflows.get(scanId);
        if (!state) return;

        state.visitedEndpoints.add(url);

        // Store response (bounded)
        if (state.previousResponses.size < MAX_STORED_RESPONSES) {
            state.previousResponses.set(url, {
                status: response.status,
                bodySnippet: response.bodySnippet,
                headers: response.headers ?? {},
                timeMs: response.timeMs,
                capturedAt: Date.now(),
            });
        }

        // Auto-extract cookies from Set-Cookie headers
        if (response.headers) {
            const setCookie = response.headers['set-cookie'] || response.headers['Set-Cookie'];
            if (setCookie) {
                this.extractCookies(state, setCookie, url);
            }
        }

        // Auto-extract tokens from response body
        this.extractTokensFromBody(state, response.bodySnippet, url);
    }

    /**
     * Get read-only workflow context for attack probes.
     */
    getContext(scanId: string): WorkflowContext | null {
        const state = this.workflows.get(scanId);
        if (!state) return null;

        return {
            authTokens: state.authTokens,
            cookies: state.cookies,
            visitedEndpoints: state.visitedEndpoints,
            getResponse: (url: string) => state.previousResponses.get(url),
            getLatestToken: () =>
                state.extractedCredentials.length > 0
                    ? state.extractedCredentials[state.extractedCredentials.length - 1]
                    : undefined,
            getAvailableObjectIds: (type?: string) => 
                type ? state.extractedObjectIds.filter(id => id.type === type) : state.extractedObjectIds,
        };
    }

    /**
     * Register a newly discovered Object ID.
     */
    registerObjectId(scanId: string, type: string, value: string, sourceRole: string): void {
        const state = this.workflows.get(scanId);
        if (!state) return;
        
        // Avoid duplicates
        if (!state.extractedObjectIds.some(id => id.type === type && id.value === value)) {
            state.extractedObjectIds.push({
                type,
                value,
                sourceRole,
                createdAt: Date.now()
            });
            log.info('Object ID extracted', { scanId, type, value, sourceRole });
        }
    }

    /**
     * Execute a multi-step workflow sequence.
     * Steps are executed in order; each step can use tokens from previous steps.
     */
    async runWorkflowSequence(
        session: ScanSession,
        scanId: string,
        steps: WorkflowStep[],
    ): Promise<WorkflowSequenceResult> {
        const state = this.workflows.get(scanId);
        if (!state) {
            return { stepsExecuted: 0, stepsSucceeded: 0, tokensExtracted: 0, errors: ['Workflow not initialized'] };
        }

        const boundedSteps = steps.slice(0, MAX_WORKFLOW_STEPS);
        let stepsExecuted = 0;
        let stepsSucceeded = 0;
        let tokensExtracted = 0;
        const errors: string[] = [];

        for (const step of boundedSteps) {
            stepsExecuted++;
            state.currentStep = stepsExecuted;

            try {
                switch (step.action) {
                    case 'request': {
                        if (!step.url) { errors.push(`Step ${stepsExecuted}: missing URL`); continue; }

                        // Build headers with accumulated auth
                        const headers: Record<string, string> = { ...(step.headers ?? {}) };
                        const latestToken = state.extractedCredentials[state.extractedCredentials.length - 1];
                        if (latestToken && !headers['Authorization']) {
                            if (latestToken.type === 'jwt' || latestToken.type === 'bearer') {
                                headers['Authorization'] = `Bearer ${latestToken.value}`;
                            }
                        }

                        // Add accumulated cookies
                        if (state.cookies.size > 0 && !headers['Cookie']) {
                            const cookieStr = Array.from(state.cookies.entries())
                                .map(([k, v]) => `${k}=${v}`)
                                .join('; ');
                            headers['Cookie'] = cookieStr;
                        }

                        const authContext = step.authContext ?? 'userA';
                        const res = await httpRequest(session, step.url, authContext, {
                            method: step.method ?? 'GET',
                            data: step.body,
                            headers,
                        });

                        this.recordResponse(scanId, step.url, {
                            status: res.status,
                            bodySnippet: res.bodySnippet,
                            timeMs: res.timeMs,
                        });

                        if (res.status < 400) stepsSucceeded++;
                        else errors.push(`Step ${stepsExecuted} (${step.label}): HTTP ${res.status}`);
                        break;
                    }

                    case 'extract_token': {
                        if (!step.url) { errors.push(`Step ${stepsExecuted}: missing URL`); continue; }
                        const storedRes = state.previousResponses.get(step.url);
                        if (!storedRes) { errors.push(`Step ${stepsExecuted}: no stored response for ${step.url}`); continue; }

                        const content = step.extractTarget === 'header'
                            ? JSON.stringify(storedRes.headers)
                            : storedRes.bodySnippet;

                        if (step.extractPattern) {
                            const match = step.extractPattern.exec(content);
                            if (match?.[1]) {
                                state.authTokens.set(step.url, match[1]);
                                state.extractedCredentials.push({
                                    source: step.url,
                                    type: 'bearer',
                                    key: 'extracted',
                                    value: match[1],
                                    extractedAt: Date.now(),
                                });
                                tokensExtracted++;
                                stepsSucceeded++;
                            } else {
                                errors.push(`Step ${stepsExecuted}: pattern did not match`);
                            }
                        } else {
                            // Use auto-extraction (already done in recordResponse)
                            const newTokens = this.extractTokensFromBody(state, content, step.url);
                            tokensExtracted += newTokens;
                            if (newTokens > 0) stepsSucceeded++;
                            else errors.push(`Step ${stepsExecuted}: no tokens found`);
                        }
                        break;
                    }

                    case 'set_auth': {
                        const latestCred = state.extractedCredentials[state.extractedCredentials.length - 1];
                        if (latestCred) {
                            const context = step.authContext ?? 'userA';
                            if (latestCred.type === 'jwt' || latestCred.type === 'bearer') {
                                session.authHeaders[context] = {
                                    ...session.authHeaders[context],
                                    'Authorization': `Bearer ${latestCred.value}`,
                                };
                            } else if (latestCred.type === 'cookie' || latestCred.type === 'session_id') {
                                session.authHeaders[context] = {
                                    ...session.authHeaders[context],
                                    'Cookie': `${latestCred.key}=${latestCred.value}`,
                                };
                            }
                            stepsSucceeded++;
                            log.info('Auth context updated from workflow', {
                                scanId,
                                context,
                                tokenType: latestCred.type,
                            });
                        } else {
                            errors.push(`Step ${stepsExecuted}: no credentials to set`);
                        }
                        break;
                    }

                    case 'escalate': {
                        // Attempt privilege escalation by replaying with elevated token
                        if (!step.url) { errors.push(`Step ${stepsExecuted}: missing URL`); continue; }
                        const escalateHeaders: Record<string, string> = {};
                        const token = state.extractedCredentials[state.extractedCredentials.length - 1];
                        if (token) {
                            escalateHeaders['Authorization'] = `Bearer ${token.value}`;
                        }

                        const escalateRes = await httpRequest(session, step.url, 'guest', {
                            method: step.method ?? 'GET',
                            headers: escalateHeaders,
                        });

                        this.recordResponse(scanId, `escalate:${step.url}`, {
                            status: escalateRes.status,
                            bodySnippet: escalateRes.bodySnippet,
                            timeMs: escalateRes.timeMs,
                        });

                        if (escalateRes.status < 400) stepsSucceeded++;
                        break;
                    }
                }
            } catch (error) {
                const msg = error instanceof Error ? error.message : 'Unknown';
                errors.push(`Step ${stepsExecuted} (${step.label}): ${msg.slice(0, 100)}`);
                log.warn('Workflow step failed', { scanId, step: step.label, error: msg });
            }
        }

        log.info('Workflow sequence complete', {
            scanId,
            stepsExecuted,
            stepsSucceeded,
            tokensExtracted,
            errorCount: errors.length,
        });

        return { stepsExecuted, stepsSucceeded, tokensExtracted, errors };
    }

    /**
     * Get summary of workflow state for logging/reporting.
     */
    getSummary(scanId: string): {
        visitedCount: number;
        storedResponses: number;
        extractedTokens: number;
        cookieCount: number;
    } | null {
        const state = this.workflows.get(scanId);
        if (!state) return null;
        return {
            visitedCount: state.visitedEndpoints.size,
            storedResponses: state.previousResponses.size,
            extractedTokens: state.extractedCredentials.length,
            cookieCount: state.cookies.size,
        };
    }

    /**
     * Clean up state for a completed scan.
     */
    cleanup(scanId: string): void {
        this.workflows.delete(scanId);
        log.info('Workflow state cleaned up', { scanId });
    }

    // ─── Private Helpers ────────────────────────────────────────────────

    private extractCookies(state: WorkflowState, setCookieHeader: string, sourceUrl: string): void {
        // Handle multiple Set-Cookie values (semicolon-separated in single header)
        const cookies = setCookieHeader.split(',').map(c => c.trim());
        for (const cookie of cookies) {
            const parts = cookie.split(';')[0]; // Take cookie before attributes
            const match = COOKIE_PATTERN.exec(parts.trim());
            if (match) {
                const [, key, value] = match;
                state.cookies.set(key.trim(), value.trim());
                if (state.extractedCredentials.length < MAX_EXTRACTED_TOKENS) {
                    state.extractedCredentials.push({
                        source: sourceUrl,
                        type: 'cookie',
                        key: key.trim(),
                        value: value.trim(),
                        extractedAt: Date.now(),
                    });
                }
            }
        }
    }

    private extractTokensFromBody(state: WorkflowState, body: string, sourceUrl: string): number {
        let count = 0;
        if (state.extractedCredentials.length >= MAX_EXTRACTED_TOKENS) return 0;

        for (const pattern of TOKEN_PATTERNS) {
            pattern.regex.lastIndex = 0;
            const match = pattern.regex.exec(body);
            if (match?.[1]) {
                const value = match[1];
                // Avoid duplicates
                const exists = state.extractedCredentials.some(
                    c => c.value === value && c.type === pattern.type,
                );
                if (!exists) {
                    state.authTokens.set(sourceUrl, value);
                    state.extractedCredentials.push({
                        source: sourceUrl,
                        type: pattern.type,
                        key: pattern.name,
                        value,
                        extractedAt: Date.now(),
                    });
                    count++;
                    log.info('Token extracted from response', {
                        scanId: state.scanId,
                        type: pattern.type,
                        source: sourceUrl,
                    });
                }
            }
        }

        return count;
    }
}

export const statefulEngine = new StatefulAttackEngine();
