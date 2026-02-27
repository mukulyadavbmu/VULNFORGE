/**
 * HypothesisEngine — Persistent attacker hypothesis formation.
 *
 * Allows VulnForge to form, update, merge, and detect hypotheses like:
 * - "Possible IDOR cluster on /api/users/*"
 * - "Injection surface across 5 search endpoints"
 * - "Auth weakness: admin endpoints accessible by guest"
 *
 * Security: Zod validation, length limits, timeout safety, no memory leaks.
 * AI: Optional generateAIHypotheses() with rule-based fallback.
 */
import { z } from 'zod';
import { AttackNode, ScanFinding } from '../../types';
import { logger } from '../../utils/logger';

const log = logger.child({ module: 'HypothesisEngine' });

// ─── Constants ──────────────────────────────────────────────────────────────

const MAX_ENDPOINTS_PER_HYPOTHESIS = 200;
const MAX_EVIDENCE_ENTRIES = 50;
const MAX_HYPOTHESES_PER_SCAN = 100;
const MERGE_SIMILARITY_THRESHOLD = 0.6;

// ─── Zod Schemas ────────────────────────────────────────────────────────────

const HypothesisTypeSchema = z.enum([
    'IDOR', 'Injection', 'Auth', 'SSRF', 'SensitiveAPI',
]);

const HypothesisSchema = z.object({
    id: z.string().uuid(),
    scanId: z.string().uuid(),
    type: HypothesisTypeSchema,
    confidence: z.number().min(0).max(100),
    evidence: z.array(z.string().max(500)).max(MAX_EVIDENCE_ENTRIES),
    relatedEndpoints: z.array(z.string().max(2048)).max(MAX_ENDPOINTS_PER_HYPOTHESIS),
    createdAt: z.number().int().positive(),
    updatedAt: z.number().int().positive(),
}).strict();

const CreateHypothesisInputSchema = z.object({
    scanId: z.string().uuid(),
    type: HypothesisTypeSchema,
    confidence: z.number().min(0).max(100),
    evidence: z.array(z.string().max(500)).max(MAX_EVIDENCE_ENTRIES),
    relatedEndpoints: z.array(z.string().max(2048)).max(MAX_ENDPOINTS_PER_HYPOTHESIS),
}).strict();

const UpdateHypothesisInputSchema = z.object({
    confidence: z.number().min(0).max(100).optional(),
    evidence: z.array(z.string().max(500)).max(MAX_EVIDENCE_ENTRIES).optional(),
    relatedEndpoints: z.array(z.string().max(2048)).max(MAX_ENDPOINTS_PER_HYPOTHESIS).optional(),
}).strict();

// ─── Types ──────────────────────────────────────────────────────────────────

export type HypothesisType = z.infer<typeof HypothesisTypeSchema>;

export interface Hypothesis {
    id: string;
    scanId: string;
    type: HypothesisType;
    confidence: number;
    evidence: string[];
    relatedEndpoints: string[];
    createdAt: number;
    updatedAt: number;
}

type CreateInput = z.infer<typeof CreateHypothesisInputSchema>;
type UpdateInput = z.infer<typeof UpdateHypothesisInputSchema>;

// ─── Detection Config ───────────────────────────────────────────────────────

const NUMERIC_PARAM_NAMES = new Set([
    'id', 'uid', 'user_id', 'userId', 'account_id', 'accountId',
    'order_id', 'orderId', 'item_id', 'itemId', 'pid', 'page',
    'offset', 'limit', 'num', 'number', 'idx',
]);

const ADMIN_KEYWORDS = [
    'admin', 'dashboard', 'manage', 'control', 'panel', 'internal',
    'backoffice', 'staff', 'moderate', 'superuser', 'root',
];

const INJECTION_FINDING_TYPES = new Set([
    'sqli', 'xss', 'ssti', 'csti', 'rce', 'lfi', 'proto_pollution',
]);

const AUTH_FINDING_TYPES = new Set([
    'bac', 'idor', 'auth_weakness', 'csrf', 'cors',
]);

// ─── Engine ─────────────────────────────────────────────────────────────────

export class HypothesisEngine {
    private store: Map<string, Hypothesis> = new Map();
    private scanIndex: Map<string, Set<string>> = new Map();
    private idCounter = 0;

    /**
     * Create a new hypothesis with full Zod validation.
     * Enforces max hypotheses per scan.
     */
    createHypothesis(input: CreateInput): Hypothesis {
        const validated = CreateHypothesisInputSchema.parse(input);

        // Enforce per-scan limit
        const scanSet = this.scanIndex.get(validated.scanId);
        if (scanSet && scanSet.size >= MAX_HYPOTHESES_PER_SCAN) {
            throw new Error(`Max hypotheses per scan reached (${MAX_HYPOTHESES_PER_SCAN})`);
        }

        const now = Date.now();
        const id = this.generateId();

        const hypothesis: Hypothesis = {
            id,
            scanId: validated.scanId,
            type: validated.type,
            confidence: validated.confidence,
            evidence: validated.evidence.slice(0, MAX_EVIDENCE_ENTRIES),
            relatedEndpoints: validated.relatedEndpoints.slice(0, MAX_ENDPOINTS_PER_HYPOTHESIS),
            createdAt: now,
            updatedAt: now,
        };

        this.store.set(id, hypothesis);

        if (!this.scanIndex.has(validated.scanId)) {
            this.scanIndex.set(validated.scanId, new Set());
        }
        this.scanIndex.get(validated.scanId)!.add(id);

        log.info('Hypothesis created', {
            hypothesisId: id,
            scanId: validated.scanId,
            type: validated.type,
            confidence: validated.confidence,
            endpointCount: validated.relatedEndpoints.length,
        });

        return hypothesis;
    }

    /**
     * Update an existing hypothesis. Merges evidence and endpoints.
     */
    updateHypothesis(hypothesisId: string, input: UpdateInput): Hypothesis {
        const validated = UpdateHypothesisInputSchema.parse(input);
        const existing = this.store.get(hypothesisId);

        if (!existing) {
            throw new Error(`Hypothesis not found: ${hypothesisId}`);
        }

        if (validated.confidence !== undefined) {
            existing.confidence = validated.confidence;
        }

        if (validated.evidence) {
            const merged = new Set([...existing.evidence, ...validated.evidence]);
            existing.evidence = Array.from(merged).slice(0, MAX_EVIDENCE_ENTRIES);
        }

        if (validated.relatedEndpoints) {
            const merged = new Set([...existing.relatedEndpoints, ...validated.relatedEndpoints]);
            existing.relatedEndpoints = Array.from(merged).slice(0, MAX_ENDPOINTS_PER_HYPOTHESIS);
        }

        existing.updatedAt = Date.now();

        log.debug('Hypothesis updated', {
            hypothesisId,
            confidence: existing.confidence,
            evidenceCount: existing.evidence.length,
            endpointCount: existing.relatedEndpoints.length,
        });

        return existing;
    }

    /**
     * Get all hypotheses for a scan.
     */
    getHypothesesForScan(scanId: string): Hypothesis[] {
        const ids = this.scanIndex.get(scanId);
        if (!ids) return [];

        const results: Hypothesis[] = [];
        for (const id of ids) {
            const h = this.store.get(id);
            if (h) results.push(h);
        }
        return results;
    }

    /**
     * Merge two hypotheses of the same type. Combines evidence and endpoints.
     * Removes the second hypothesis after merging into the first.
     */
    mergeHypotheses(primaryId: string, secondaryId: string): Hypothesis {
        const primary = this.store.get(primaryId);
        const secondary = this.store.get(secondaryId);

        if (!primary) throw new Error(`Primary hypothesis not found: ${primaryId}`);
        if (!secondary) throw new Error(`Secondary hypothesis not found: ${secondaryId}`);
        if (primary.type !== secondary.type) {
            throw new Error(`Cannot merge different types: ${primary.type} vs ${secondary.type}`);
        }
        if (primary.scanId !== secondary.scanId) {
            throw new Error('Cannot merge hypotheses from different scans');
        }

        // Merge evidence (deduplicated)
        const mergedEvidence = new Set([...primary.evidence, ...secondary.evidence]);
        primary.evidence = Array.from(mergedEvidence).slice(0, MAX_EVIDENCE_ENTRIES);

        // Merge endpoints (deduplicated)
        const mergedEndpoints = new Set([...primary.relatedEndpoints, ...secondary.relatedEndpoints]);
        primary.relatedEndpoints = Array.from(mergedEndpoints).slice(0, MAX_ENDPOINTS_PER_HYPOTHESIS);

        // Confidence = max of both
        primary.confidence = Math.max(primary.confidence, secondary.confidence);
        primary.updatedAt = Date.now();

        // Remove secondary
        this.store.delete(secondaryId);
        this.scanIndex.get(secondary.scanId)?.delete(secondaryId);

        log.info('Hypotheses merged', {
            primaryId,
            secondaryId,
            resultConfidence: primary.confidence,
            resultEndpoints: primary.relatedEndpoints.length,
        });

        return primary;
    }

    /**
     * Detect hypotheses from endpoints and findings.
     * Pure rule-based detection — O(n) over endpoints + O(m) over findings.
     * No AI dependency. No DB calls.
     */
    detectHypotheses(
        scanId: string,
        endpoints: AttackNode[],
        findings: ScanFinding[],
    ): Hypothesis[] {
        const start = Date.now();
        const detected: Hypothesis[] = [];

        // ── IDOR Detection ──────────────────────────────────────────────────────
        const idorEndpoints: string[] = [];
        for (const ep of endpoints) {
            if (!ep.params) continue;
            const numericParams = ep.params.filter(p => NUMERIC_PARAM_NAMES.has(p.toLowerCase()));
            if (numericParams.length > 0) {
                idorEndpoints.push(ep.url);
            }
        }

        if (idorEndpoints.length >= 2) {
            detected.push(this.createHypothesis({
                scanId,
                type: 'IDOR',
                confidence: Math.min(30 + idorEndpoints.length * 10, 90),
                evidence: [
                    `${idorEndpoints.length} endpoints with numeric ID parameters detected`,
                    'Multiple numeric parameters suggest IDOR attack surface',
                ],
                relatedEndpoints: idorEndpoints.slice(0, MAX_ENDPOINTS_PER_HYPOTHESIS),
            }));
        }

        // ── Injection Detection ─────────────────────────────────────────────────
        const injectionFindings = findings.filter(f => INJECTION_FINDING_TYPES.has(f.type));
        const injectionEndpoints = [...new Set(injectionFindings.map(f => f.url))];

        if (injectionFindings.length >= 2) {
            detected.push(this.createHypothesis({
                scanId,
                type: 'Injection',
                confidence: Math.min(40 + injectionFindings.length * 15, 95),
                evidence: injectionFindings.slice(0, 10).map(
                    f => `${f.type} on ${f.url} (${f.severity})`,
                ),
                relatedEndpoints: injectionEndpoints.slice(0, MAX_ENDPOINTS_PER_HYPOTHESIS),
            }));
        }

        // Also detect from anomaly findings (error-based)
        const anomalyFindings = findings.filter(f => f.type === 'anomaly');
        if (anomalyFindings.length >= 3) {
            const anomalyEndpoints = [...new Set(anomalyFindings.map(f => f.url))];
            detected.push(this.createHypothesis({
                scanId,
                type: 'Injection',
                confidence: Math.min(20 + anomalyFindings.length * 8, 70),
                evidence: [
                    `${anomalyFindings.length} anomaly/error responses suggest injection surface`,
                    ...anomalyFindings.slice(0, 5).map(f => `Error on ${f.url}`),
                ],
                relatedEndpoints: anomalyEndpoints.slice(0, MAX_ENDPOINTS_PER_HYPOTHESIS),
            }));
        }

        // ── Auth Weakness Detection ─────────────────────────────────────────────
        const authFindings = findings.filter(f => AUTH_FINDING_TYPES.has(f.type));
        const authEndpoints = [...new Set(authFindings.map(f => f.url))];

        if (authFindings.length >= 1) {
            detected.push(this.createHypothesis({
                scanId,
                type: 'Auth',
                confidence: Math.min(50 + authFindings.length * 15, 95),
                evidence: authFindings.slice(0, 10).map(
                    f => `${f.type} on ${f.url} (${f.severity})`,
                ),
                relatedEndpoints: authEndpoints.slice(0, MAX_ENDPOINTS_PER_HYPOTHESIS),
            }));
        }

        // ── SSRF Detection ──────────────────────────────────────────────────────
        const ssrfFindings = findings.filter(f => f.type === 'ssrf' || f.type === 'oast');
        if (ssrfFindings.length >= 1) {
            const ssrfEndpoints = [...new Set(ssrfFindings.map(f => f.url))];
            detected.push(this.createHypothesis({
                scanId,
                type: 'SSRF',
                confidence: Math.min(60 + ssrfFindings.length * 20, 95),
                evidence: ssrfFindings.slice(0, 10).map(
                    f => `${f.type} on ${f.url} — ${f.evidence.slice(0, 100)}`,
                ),
                relatedEndpoints: ssrfEndpoints.slice(0, MAX_ENDPOINTS_PER_HYPOTHESIS),
            }));
        }

        // Also detect from URL/redirect parameters (SSRF surface)
        const ssrfSurfaceEndpoints: string[] = [];
        for (const ep of endpoints) {
            if (!ep.params) continue;
            const urlParams = ep.params.filter(p =>
                ['url', 'redirect', 'callback', 'next', 'dest', 'target', 'uri', 'href', 'link']
                    .includes(p.toLowerCase()),
            );
            if (urlParams.length > 0) ssrfSurfaceEndpoints.push(ep.url);
        }

        if (ssrfSurfaceEndpoints.length >= 2) {
            detected.push(this.createHypothesis({
                scanId,
                type: 'SSRF',
                confidence: Math.min(25 + ssrfSurfaceEndpoints.length * 10, 70),
                evidence: [
                    `${ssrfSurfaceEndpoints.length} endpoints with URL/redirect parameters`,
                    'Potential SSRF/open redirect attack surface',
                ],
                relatedEndpoints: ssrfSurfaceEndpoints.slice(0, MAX_ENDPOINTS_PER_HYPOTHESIS),
            }));
        }

        // ── Sensitive API Detection ─────────────────────────────────────────────
        const sensitiveEndpoints: string[] = [];
        for (const ep of endpoints) {
            const lower = ep.url.toLowerCase();
            if (ADMIN_KEYWORDS.some(kw => lower.includes(kw))) {
                sensitiveEndpoints.push(ep.url);
            }
        }

        if (sensitiveEndpoints.length >= 1) {
            detected.push(this.createHypothesis({
                scanId,
                type: 'SensitiveAPI',
                confidence: Math.min(40 + sensitiveEndpoints.length * 10, 85),
                evidence: [
                    `${sensitiveEndpoints.length} endpoints match admin/sensitive keywords`,
                    ...sensitiveEndpoints.slice(0, 5).map(url => `Sensitive: ${url}`),
                ],
                relatedEndpoints: sensitiveEndpoints.slice(0, MAX_ENDPOINTS_PER_HYPOTHESIS),
            }));
        }

        // ── Auto-merge same-type hypotheses ──────────────────────────────────────
        this.autoMerge(scanId);

        const durationMs = Date.now() - start;
        log.info('Hypothesis detection complete', {
            scanId,
            endpointCount: endpoints.length,
            findingCount: findings.length,
            hypothesesDetected: detected.length,
            durationMs,
        });

        return detected;
    }

    /**
     * AI-powered hypothesis generation.
     * Uses AIProvider if available. Falls back to rule-based detectHypotheses().
     * Timeout-protected: aborts after 5 seconds and returns rule-based results.
     */
    async generateAIHypotheses(
        scanId: string,
        endpoints: AttackNode[],
        findings: ScanFinding[],
    ): Promise<Hypothesis[]> {
        // Always run rule-based first as baseline
        const ruleBasedResults = this.detectHypotheses(scanId, endpoints, findings);

        // Build concise summary for AI (no full bodies, limited data)
        const summary = {
            endpointCount: endpoints.length,
            findingTypes: [...new Set(findings.map(f => f.type))],
            severityCounts: {
                critical: findings.filter(f => f.severity === 'critical').length,
                high: findings.filter(f => f.severity === 'high').length,
                medium: findings.filter(f => f.severity === 'medium').length,
                low: findings.filter(f => f.severity === 'low').length,
            },
            parameterPatterns: [...new Set(endpoints.flatMap(e => e.params || []))].slice(0, 20),
            urlPatterns: endpoints.slice(0, 15).map(e => e.url),
            existingHypotheses: ruleBasedResults.map(h => ({
                type: h.type,
                confidence: h.confidence,
                endpointCount: h.relatedEndpoints.length,
            })),
        };

        const prompt = `Analyze this scan summary and suggest additional security hypotheses.
Return ONLY a JSON array of objects with: type (IDOR|Injection|Auth|SSRF|SensitiveAPI), reason (string), confidence (0-100).
Summary: ${JSON.stringify(summary)}
Return JSON only, no markdown.`;

        try {
            // Dynamic import to avoid hard dependency
            const apiKey = process.env.GEMINI_API_KEY;
            if (!apiKey) {
                log.debug('No GEMINI_API_KEY, using rule-based only', { scanId });
                return ruleBasedResults;
            }

            const { GoogleGenerativeAI } = require('@google/generative-ai') as {
                GoogleGenerativeAI: new (key: string) => {
                    getGenerativeModel: (config: { model: string }) => {
                        generateContent: (prompt: string) => Promise<{
                            response: { text: () => string };
                        }>;
                    };
                };
            };

            const genAI = new GoogleGenerativeAI(apiKey);
            const genModel = genAI.getGenerativeModel({ model: 'gemini-pro' });

            // Timeout-protected AI call (5 seconds)
            const result = await Promise.race([
                genModel.generateContent(prompt),
                new Promise<never>((_, reject) =>
                    setTimeout(() => reject(new Error('AI hypothesis timeout (5s)')), 5000),
                ),
            ]);

            let content = result.response.text();
            content = content.replace(/```json\n?/g, '').replace(/```\n?/g, '').trim();

            const parsed = JSON.parse(content);

            const AIHypothesisSchema = z.array(z.object({
                type: HypothesisTypeSchema,
                reason: z.string().max(500),
                confidence: z.number().min(0).max(100),
            }).strict()).max(10);

            const validated = AIHypothesisSchema.parse(parsed);

            for (const aiH of validated) {
                const existingOfType = ruleBasedResults.find(r => r.type === aiH.type);
                if (!existingOfType) {
                    this.createHypothesis({
                        scanId,
                        type: aiH.type,
                        confidence: Math.min(aiH.confidence, 70),
                        evidence: [`[AI] ${aiH.reason}`],
                        relatedEndpoints: [],
                    });
                } else if (aiH.confidence > existingOfType.confidence) {
                    this.updateHypothesis(existingOfType.id, {
                        confidence: Math.min(existingOfType.confidence + 10, 95),
                        evidence: [`[AI] ${aiH.reason}`],
                    });
                }
            }

            log.info('AI hypotheses generated', {
                scanId,
                aiSuggestions: validated.length,
            });
        } catch (error) {
            log.warn('AI hypothesis generation failed, using rule-based only', {
                scanId,
                error: error instanceof Error ? error.message : 'Unknown error',
            });
        }

        return this.getHypothesesForScan(scanId);
    }

    /**
     * Auto-merge hypotheses of the same type within a scan.
     * Reduces noise by combining overlapping hypotheses.
     */
    private autoMerge(scanId: string): void {
        const hypotheses = this.getHypothesesForScan(scanId);
        const byType: Map<HypothesisType, Hypothesis[]> = new Map();

        for (const h of hypotheses) {
            const list = byType.get(h.type) ?? [];
            list.push(h);
            byType.set(h.type, list);
        }

        for (const [, group] of byType) {
            if (group.length <= 1) continue;

            // Merge all into the first (highest confidence)
            group.sort((a, b) => b.confidence - a.confidence);
            const primary = group[0];

            for (let i = 1; i < group.length; i++) {
                const overlap = this.calculateOverlap(
                    primary.relatedEndpoints,
                    group[i].relatedEndpoints,
                );
                if (overlap >= MERGE_SIMILARITY_THRESHOLD) {
                    this.mergeHypotheses(primary.id, group[i].id);
                }
            }
        }
    }

    /**
     * Calculate Jaccard similarity between two endpoint sets.
     */
    private calculateOverlap(a: string[], b: string[]): number {
        if (a.length === 0 && b.length === 0) return 1;
        const setA = new Set(a);
        const setB = new Set(b);
        let intersection = 0;
        for (const item of setB) {
            if (setA.has(item)) intersection++;
        }
        const union = setA.size + setB.size - intersection;
        return union === 0 ? 0 : intersection / union;
    }

    private generateId(): string {
        this.idCounter++;
        const ts = Date.now().toString(36);
        const cnt = this.idCounter.toString(36).padStart(4, '0');
        const rand = Math.random().toString(36).slice(2, 6);
        // Format as UUID-like for Zod validation
        const raw = `${ts}${cnt}${rand}`.padEnd(32, '0');
        return [
            raw.slice(0, 8),
            raw.slice(8, 12),
            '4' + raw.slice(12, 15),
            '8' + raw.slice(15, 18),
            raw.slice(18, 30),
        ].join('-');
    }
}
