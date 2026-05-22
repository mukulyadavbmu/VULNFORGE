/**
 * TokenAnalyzer — Analyze JWT and session tokens for weaknesses.
 *
 * JWT: Decodes header/payload/signature, detects alg:none, weak expiry, sensitive claims.
 * Session: Measures entropy, length consistency, pattern repetition.
 * Security: No eval(), base64 decode only, bounded processing.
 */
import { z } from 'zod';
import { logger } from '../../utils/logger';

const log = logger.child({ module: 'TokenAnalyzer' });

// ─── Constants ──────────────────────────────────────────────────────────────

const MAX_TOKEN_LENGTH = 10_000;
const MAX_TOKENS_PER_BATCH = 100;
const MIN_SESSION_ENTROPY = 3.5; // Below this = predictable
const MIN_SECURE_EXPIRY_HOURS = 1;
const MAX_SAFE_EXPIRY_HOURS = 24;

// ─── Zod Schemas ────────────────────────────────────────────────────────────

const TokenInputSchema = z.object({
    token: z.string().min(1).max(MAX_TOKEN_LENGTH),
    source: z.string().max(512).optional(),
}).strict();

// ─── Types ──────────────────────────────────────────────────────────────────

export interface JWTAnalysis {
    isJWT: boolean;
    header: Record<string, unknown> | null;
    payload: Record<string, unknown> | null;
    signaturePresent: boolean;
    weaknesses: TokenWeakness[];
}

export interface TokenWeakness {
    type: string;
    severity: 'low' | 'medium' | 'high' | 'critical';
    description: string;
}

export interface SessionTokenAnalysis {
    entropy: number;
    length: number;
    isWeak: boolean;
    weaknesses: TokenWeakness[];
}

export interface BatchAnalysis {
    tokens: number;
    jwtCount: number;
    sessionCount: number;
    weakTokens: number;
    predictable: boolean;
    lengthConsistent: boolean;
    findings: TokenWeakness[];
}

// ─── Sensitive Claims ───────────────────────────────────────────────────────

const SENSITIVE_CLAIMS = new Set([
    'password', 'passwd', 'pwd', 'secret', 'ssn',
    'credit_card', 'creditcard', 'cc_number', 'cvv',
    'private_key', 'privatekey', 'api_key', 'apikey',
    'bank_account', 'routing_number',
]);

const ADMIN_CLAIMS = new Set([
    'role', 'is_admin', 'isAdmin', 'admin', 'permissions',
    'scope', 'groups', 'roles', 'privilege',
]);

// ─── Engine ─────────────────────────────────────────────────────────────────

export class TokenAnalyzer {
    /**
     * Analyze a single token — auto-detects JWT vs session token.
     */
    analyzeToken(token: string, source?: string): JWTAnalysis | SessionTokenAnalysis {
        const validated = TokenInputSchema.parse({ token, source });
        const t = validated.token.trim();

        if (this.isJWT(t)) {
            return this.analyzeJWT(t);
        }
        return this.analyzeSessionToken(t);
    }

    /**
     * Detect weak tokens from a batch.
     * Returns batch analysis with aggregate findings.
     */
    detectWeakTokens(tokens: string[]): BatchAnalysis {
        const limited = tokens.slice(0, MAX_TOKENS_PER_BATCH);
        const findings: TokenWeakness[] = [];
        let jwtCount = 0;
        let sessionCount = 0;
        let weakCount = 0;

        for (const token of limited) {
            if (token.length > MAX_TOKEN_LENGTH) continue;

            if (this.isJWT(token)) {
                jwtCount++;
                const analysis = this.analyzeJWT(token);
                if (analysis.weaknesses.length > 0) {
                    weakCount++;
                    findings.push(...analysis.weaknesses);
                }
            } else {
                sessionCount++;
                const analysis = this.analyzeSessionToken(token);
                if (analysis.isWeak) {
                    weakCount++;
                    findings.push(...analysis.weaknesses);
                }
            }
        }

        // Check predictability across session tokens
        const sessionTokens = limited.filter(t => !this.isJWT(t));
        const predictable = this.detectPredictability(sessionTokens);

        // Length consistency
        const lengths = sessionTokens.map(t => t.length);
        const lengthConsistent = lengths.length >= 2 &&
            lengths.every(l => l === lengths[0]);

        if (predictable && sessionTokens.length >= 2) {
            findings.push({
                type: 'PREDICTABLE_TOKENS',
                severity: 'critical',
                description: 'Session tokens show predictable patterns — may be sequentially generated',
            });
        }

        log.info('Batch token analysis complete', {
            tokens: limited.length, jwtCount, sessionCount, weakCount,
        });

        return {
            tokens: limited.length,
            jwtCount,
            sessionCount,
            weakTokens: weakCount,
            predictable,
            lengthConsistent,
            findings,
        };
    }

    /**
     * Detect predictability across multiple tokens.
     * Checks for sequential patterns, low entropy, and shared prefixes.
     */
    detectPredictability(tokens: string[]): boolean {
        if (tokens.length < 2) return false;

        // Check for shared long prefix (>50% of token length)
        const first = tokens[0];
        const minLen = Math.min(...tokens.map(t => t.length));
        let commonPrefix = 0;
        for (let i = 0; i < minLen; i++) {
            if (tokens.every(t => t[i] === first[i])) {
                commonPrefix++;
            } else {
                break;
            }
        }
        if (commonPrefix > minLen * 0.5 && commonPrefix > 5) return true;

        // Check for low average entropy
        const entropies = tokens.map(t => this.shannonEntropy(t));
        const avgEntropy = entropies.reduce((a, b) => a + b, 0) / entropies.length;
        if (avgEntropy < MIN_SESSION_ENTROPY) return true;

        // Check for sequential numeric endings
        const numericEndings = tokens.map(t => {
            const match = t.match(/(\d+)$/);
            return match ? parseInt(match[1], 10) : null;
        }).filter((n): n is number => n !== null);

        if (numericEndings.length >= 2) {
            const sorted = [...numericEndings].sort((a, b) => a - b);
            let sequential = true;
            for (let i = 1; i < sorted.length; i++) {
                if (sorted[i] - sorted[i - 1] > 3) {
                    sequential = false;
                    break;
                }
            }
            if (sequential) return true;
        }

        return false;
    }

    // ─── JWT Analysis ─────────────────────────────────────────────────────

    private analyzeJWT(token: string): JWTAnalysis {
        const parts = token.split('.');
        const weaknesses: TokenWeakness[] = [];

        // Decode header
        let header: Record<string, unknown> | null = null;
        try {
            header = JSON.parse(this.base64UrlDecode(parts[0]));
        } catch {
            header = null;
        }

        // Decode payload
        let payload: Record<string, unknown> | null = null;
        try {
            payload = JSON.parse(this.base64UrlDecode(parts[1]));
        } catch {
            payload = null;
        }

        const signaturePresent = parts.length >= 3 && parts[2].length > 0;

        // ── Weakness Detection ──

        // 1. alg:none
        if (header) {
            const alg = String(header.alg ?? '').toLowerCase();
            if (alg === 'none' || alg === '' || alg === 'null') {
                weaknesses.push({
                    type: 'ALG_NONE',
                    severity: 'critical',
                    description: 'JWT uses alg:none — signature verification bypassed',
                });
            }

            // Weak algorithm
            if (alg === 'hs256' && !signaturePresent) {
                weaknesses.push({
                    type: 'WEAK_ALGORITHM',
                    severity: 'high',
                    description: 'JWT uses HS256 without signature — tampering possible',
                });
            }
        }

        // 2. Weak expiry
        if (payload) {
            const exp = payload.exp;
            const iat = payload.iat;

            if (typeof exp === 'number' && typeof iat === 'number') {
                const lifetimeHrs = (exp - iat) / 3600;
                if (lifetimeHrs > MAX_SAFE_EXPIRY_HOURS * 7) {
                    weaknesses.push({
                        type: 'WEAK_EXPIRY',
                        severity: 'high',
                        description: `JWT lifetime is ${Math.round(lifetimeHrs)} hours (>168h) — excessive token lifetime`,
                    });
                }
            }

            if (typeof exp === 'number') {
                const now = Date.now() / 1000;
                if (exp < now) {
                    weaknesses.push({
                        type: 'EXPIRED_TOKEN',
                        severity: 'medium',
                        description: 'JWT is expired — may indicate token reuse vulnerability',
                    });
                }
            }

            if (exp === undefined) {
                weaknesses.push({
                    type: 'NO_EXPIRY',
                    severity: 'high',
                    description: 'JWT has no expiry (exp) claim — token never expires',
                });
            }

            // 3. Sensitive claims
            for (const key of Object.keys(payload)) {
                if (SENSITIVE_CLAIMS.has(key.toLowerCase())) {
                    weaknesses.push({
                        type: 'SENSITIVE_CLAIM',
                        severity: 'critical',
                        description: `JWT contains sensitive claim: "${key}" — should not be in token payload`,
                    });
                }
            }

            // 4. Admin/role claims (informational)
            for (const key of Object.keys(payload)) {
                if (ADMIN_CLAIMS.has(key)) {
                    const val = payload[key];
                    if (val === true || val === 'admin' || val === 'root' || val === 'superuser') {
                        weaknesses.push({
                            type: 'ADMIN_CLAIM',
                            severity: 'medium',
                            description: `JWT contains admin claim: ${key}=${String(val)} — test for privilege escalation`,
                        });
                    }
                }
            }
        }

        // 5. Missing signature
        if (!signaturePresent) {
            weaknesses.push({
                type: 'NO_SIGNATURE',
                severity: 'critical',
                description: 'JWT has no signature — integrity not verified',
            });
        }

        log.debug('JWT analyzed', {
            alg: header?.alg ?? 'unknown',
            weaknesses: weaknesses.length,
            hasSig: signaturePresent,
        });

        return { isJWT: true, header, payload, signaturePresent, weaknesses };
    }

    // ─── Session Token Analysis ───────────────────────────────────────────

    private analyzeSessionToken(token: string): SessionTokenAnalysis {
        const weaknesses: TokenWeakness[] = [];
        const entropy = this.shannonEntropy(token);
        const length = token.length;

        // Low entropy
        if (entropy < MIN_SESSION_ENTROPY) {
            weaknesses.push({
                type: 'LOW_ENTROPY',
                severity: 'high',
                description: `Token entropy is ${entropy.toFixed(2)} (min: ${MIN_SESSION_ENTROPY}) — may be predictable`,
            });
        }

        // Short token
        if (length < 16) {
            weaknesses.push({
                type: 'SHORT_TOKEN',
                severity: 'high',
                description: `Token is only ${length} chars — insufficient for session security (min: 16)`,
            });
        }

        // Repeated patterns
        const repeatRatio = this.measureRepetition(token);
        if (repeatRatio > 0.5) {
            weaknesses.push({
                type: 'REPETITIVE_PATTERN',
                severity: 'medium',
                description: `Token has ${Math.round(repeatRatio * 100)}% pattern repetition — weak randomness`,
            });
        }

        // All numeric
        if (/^\d+$/.test(token)) {
            weaknesses.push({
                type: 'NUMERIC_ONLY',
                severity: 'high',
                description: 'Token is purely numeric — low keyspace, brute-forceable',
            });
        }

        // Looks like timestamp
        if (/^1[67]\d{8,11}$/.test(token)) {
            weaknesses.push({
                type: 'TIMESTAMP_TOKEN',
                severity: 'critical',
                description: 'Token appears to be a Unix timestamp — fully predictable',
            });
        }

        const isWeak = weaknesses.length > 0;

        return { entropy, length, isWeak, weaknesses };
    }

    // ─── Helpers ──────────────────────────────────────────────────────────

    private isJWT(token: string): boolean {
        const parts = token.split('.');
        if (parts.length < 2 || parts.length > 3) return false;
        // JWT header always starts with eyJ (base64 of '{"')
        return parts[0].startsWith('eyJ');
    }

    private base64UrlDecode(str: string): string {
        // Replace URL-safe chars
        let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
        // Pad
        while (base64.length % 4 !== 0) base64 += '=';
        return Buffer.from(base64, 'base64').toString('utf-8');
    }

    private shannonEntropy(str: string): number {
        if (str.length === 0) return 0;
        const freq = new Map<string, number>();
        for (const ch of str) {
            freq.set(ch, (freq.get(ch) ?? 0) + 1);
        }
        let entropy = 0;
        for (const count of freq.values()) {
            const p = count / str.length;
            if (p > 0) entropy -= p * Math.log2(p);
        }
        return entropy;
    }

    private measureRepetition(str: string): number {
        if (str.length < 4) return 0;
        let repeats = 0;
        // Check for 2-4 char repeating substrings
        for (let subLen = 2; subLen <= 4; subLen++) {
            for (let i = 0; i <= str.length - subLen * 2; i++) {
                const sub = str.slice(i, i + subLen);
                const rest = str.slice(i + subLen);
                if (rest.includes(sub)) repeats++;
            }
        }
        const maxPossible = str.length * 3; // Approximate normalization
        return Math.min(repeats / maxPossible, 1);
    }
}
