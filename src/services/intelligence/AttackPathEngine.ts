/**
 * AttackPathEngine — Multi-step attack chain tracker.
 *
 * Models real penetration paths like:
 *   Guest → Login → Profile API → IDOR → Admin
 *   Upload → Stored File → RCE → Internal Pivot
 *
 * Security: Zod validation, length limits, timeout-safe AI, no memory leaks.
 * AI: Optional scoreAttackPath() with deterministic fallback.
 */
import { z } from 'zod';
import { ScanFinding } from '../../types';
import { logger } from '../../utils/logger';

const log = logger.child({ module: 'AttackPathEngine' });

// ─── Constants ──────────────────────────────────────────────────────────────

const MAX_NODES_PER_PATH = 20;
const MAX_VULNS_PER_PATH = 20;
const MAX_TRANSITIONS_PER_PATH = 10;
const MAX_PATHS_PER_SCAN = 50;

// ─── Zod Schemas ────────────────────────────────────────────────────────────

const AttackPathSchema = z.object({
    id: z.string().min(1).max(64),
    scanId: z.string().min(1).max(64),
    nodes: z.array(z.string().min(1).max(2048)).min(1).max(MAX_NODES_PER_PATH),
    vulnerabilities: z.array(z.string().min(1).max(256)).max(MAX_VULNS_PER_PATH),
    privilegeTransitions: z.array(z.string().min(1).max(256)).max(MAX_TRANSITIONS_PER_PATH),
    confidence: z.number().min(0).max(100),
    createdAt: z.number().int().positive(),
}).strict();

const CreatePathInputSchema = z.object({
    scanId: z.string().min(1).max(64),
    nodes: z.array(z.string().min(1).max(2048)).min(1).max(MAX_NODES_PER_PATH),
    vulnerabilities: z.array(z.string().min(1).max(256)).max(MAX_VULNS_PER_PATH),
    privilegeTransitions: z.array(z.string().min(1).max(256)).max(MAX_TRANSITIONS_PER_PATH),
    confidence: z.number().min(0).max(100),
}).strict();

const UpdatePathInputSchema = z.object({
    nodes: z.array(z.string().min(1).max(2048)).max(MAX_NODES_PER_PATH).optional(),
    vulnerabilities: z.array(z.string().min(1).max(256)).max(MAX_VULNS_PER_PATH).optional(),
    privilegeTransitions: z.array(z.string().min(1).max(256)).max(MAX_TRANSITIONS_PER_PATH).optional(),
    confidence: z.number().min(0).max(100).optional(),
}).strict();

// ─── Types ──────────────────────────────────────────────────────────────────

export interface AttackPath {
    id: string;
    scanId: string;
    nodes: string[];
    vulnerabilities: string[];
    privilegeTransitions: string[];
    confidence: number;
    createdAt: number;
}

type CreateInput = z.infer<typeof CreatePathInputSchema>;
type UpdateInput = z.infer<typeof UpdatePathInputSchema>;

interface PathScore {
    confidence: number;
    impactLevel: 'low' | 'medium' | 'high' | 'critical';
    reason: string;
}

// ─── Detection Rules ────────────────────────────────────────────────────────

interface PathRule {
    name: string;
    requiredTypes: Set<string>;
    minFindings: number;
    baseConfidence: number;
    privilegeTransition: string;
    buildPath: (findings: ScanFinding[]) => string[];
}

const PATH_RULES: PathRule[] = [
    {
        name: 'Privilege Escalation via IDOR',
        requiredTypes: new Set(['idor', 'bac']),
        minFindings: 2,
        baseConfidence: 70,
        privilegeTransition: 'User → Admin (IDOR + BAC)',
        buildPath: (findings) => {
            const urls = [...new Set(findings.filter(f => f.type === 'idor' || f.type === 'bac').map(f => f.url))];
            return ['Guest Access', ...urls.slice(0, 5), 'Privilege Escalation'];
        },
    },
    {
        name: 'IDOR with Auth Weakness',
        requiredTypes: new Set(['idor', 'auth_weakness']),
        minFindings: 2,
        baseConfidence: 75,
        privilegeTransition: 'Guest → Authenticated (Auth Weakness + IDOR)',
        buildPath: (findings) => {
            const authUrl = findings.find(f => f.type === 'auth_weakness')?.url ?? 'Auth Endpoint';
            const idorUrl = findings.find(f => f.type === 'idor')?.url ?? 'Target Endpoint';
            return ['Guest', authUrl, 'Auth Bypass', idorUrl, 'Data Access'];
        },
    },
    {
        name: 'SSRF Internal Pivot',
        requiredTypes: new Set(['ssrf']),
        minFindings: 1,
        baseConfidence: 65,
        privilegeTransition: 'External → Internal Network (SSRF)',
        buildPath: (findings) => {
            const ssrfUrl = findings.find(f => f.type === 'ssrf')?.url ?? 'SSRF Endpoint';
            return ['External Request', ssrfUrl, 'Internal Pivot', 'Internal Services'];
        },
    },
    {
        name: 'SSRF + OAST Confirmation',
        requiredTypes: new Set(['ssrf', 'oast']),
        minFindings: 2,
        baseConfidence: 85,
        privilegeTransition: 'External → Internal (SSRF confirmed via OAST)',
        buildPath: (findings) => {
            const ssrfUrl = findings.find(f => f.type === 'ssrf')?.url ?? 'SSRF Endpoint';
            return ['External', ssrfUrl, 'Out-of-Band Callback', 'Internal Network Access'];
        },
    },
    {
        name: 'Upload to RCE',
        requiredTypes: new Set(['file_upload', 'rce']),
        minFindings: 2,
        baseConfidence: 90,
        privilegeTransition: 'User → System (Upload + RCE)',
        buildPath: (findings) => {
            const uploadUrl = findings.find(f => f.type === 'file_upload')?.url ?? 'Upload Endpoint';
            const rceUrl = findings.find(f => f.type === 'rce')?.url ?? 'Execution Endpoint';
            return ['Authenticated User', uploadUrl, 'Malicious File Stored', rceUrl, 'System Access'];
        },
    },
    {
        name: 'Upload to Execution (Potential)',
        requiredTypes: new Set(['file_upload']),
        minFindings: 1,
        baseConfidence: 45,
        privilegeTransition: 'User → Potential System (Unvalidated Upload)',
        buildPath: (findings) => {
            const uploadUrl = findings.find(f => f.type === 'file_upload')?.url ?? 'Upload Endpoint';
            return ['Authenticated User', uploadUrl, 'File Stored', 'Potential Execution'];
        },
    },
    {
        name: 'Injection Chain (SQLi → Data)',
        requiredTypes: new Set(['sqli']),
        minFindings: 1,
        baseConfidence: 60,
        privilegeTransition: 'User → Database (SQLi)',
        buildPath: (findings) => {
            const sqliUrls = [...new Set(findings.filter(f => f.type === 'sqli').map(f => f.url))];
            return ['Input', ...sqliUrls.slice(0, 3), 'Database Access', 'Data Exfiltration'];
        },
    },
    {
        name: 'XSS Session Hijack',
        requiredTypes: new Set(['xss', 'csrf']),
        minFindings: 2,
        baseConfidence: 55,
        privilegeTransition: 'Victim → Attacker Session (XSS + CSRF)',
        buildPath: (findings) => {
            const xssUrl = findings.find(f => f.type === 'xss')?.url ?? 'XSS Endpoint';
            return ['Victim Browsing', xssUrl, 'Script Injected', 'Session Stolen', 'Account Takeover'];
        },
    },
    {
        name: 'SSTI to RCE',
        requiredTypes: new Set(['ssti']),
        minFindings: 1,
        baseConfidence: 70,
        privilegeTransition: 'User → System (SSTI → RCE)',
        buildPath: (findings) => {
            const sstiUrl = findings.find(f => f.type === 'ssti')?.url ?? 'Template Endpoint';
            return ['User Input', sstiUrl, 'Template Engine', 'Code Execution', 'System Access'];
        },
    },
    {
        name: 'CORS + Auth Bypass',
        requiredTypes: new Set(['cors', 'bac']),
        minFindings: 2,
        baseConfidence: 60,
        privilegeTransition: 'External Origin → Authenticated Actions (CORS)',
        buildPath: (findings) => {
            const corsUrl = findings.find(f => f.type === 'cors')?.url ?? 'CORS Endpoint';
            return ['Attacker Origin', corsUrl, 'Cross-Origin Request', 'Authenticated Action'];
        },
    },
];

// ─── Engine ─────────────────────────────────────────────────────────────────

export class AttackPathEngine {
    private store: Map<string, AttackPath> = new Map();
    private scanIndex: Map<string, Set<string>> = new Map();
    private idCounter = 0;

    /**
     * Create a new attack path with Zod validation.
     */
    createPath(input: CreateInput): AttackPath {
        const validated = CreatePathInputSchema.parse(input);

        const scanSet = this.scanIndex.get(validated.scanId);
        if (scanSet && scanSet.size >= MAX_PATHS_PER_SCAN) {
            throw new Error(`Max paths per scan reached (${MAX_PATHS_PER_SCAN})`);
        }

        const id = this.generateId();
        const path: AttackPath = {
            id,
            scanId: validated.scanId,
            nodes: validated.nodes,
            vulnerabilities: validated.vulnerabilities,
            privilegeTransitions: validated.privilegeTransitions,
            confidence: validated.confidence,
            createdAt: Date.now(),
        };

        this.store.set(id, path);
        if (!this.scanIndex.has(validated.scanId)) {
            this.scanIndex.set(validated.scanId, new Set());
        }
        this.scanIndex.get(validated.scanId)!.add(id);

        log.info('Attack path created', {
            pathId: id,
            scanId: validated.scanId,
            nodeCount: validated.nodes.length,
            vulnCount: validated.vulnerabilities.length,
            confidence: validated.confidence,
        });

        return path;
    }

    /**
     * Update an existing path. Appends nodes/vulns/transitions (deduplicated).
     */
    updatePath(pathId: string, input: UpdateInput): AttackPath {
        const validated = UpdatePathInputSchema.parse(input);
        const existing = this.store.get(pathId);
        if (!existing) throw new Error(`Attack path not found: ${pathId}`);

        if (validated.nodes) {
            const merged = [...new Set([...existing.nodes, ...validated.nodes])];
            existing.nodes = merged.slice(0, MAX_NODES_PER_PATH);
        }

        if (validated.vulnerabilities) {
            const merged = [...new Set([...existing.vulnerabilities, ...validated.vulnerabilities])];
            existing.vulnerabilities = merged.slice(0, MAX_VULNS_PER_PATH);
        }

        if (validated.privilegeTransitions) {
            const merged = [...new Set([...existing.privilegeTransitions, ...validated.privilegeTransitions])];
            existing.privilegeTransitions = merged.slice(0, MAX_TRANSITIONS_PER_PATH);
        }

        if (validated.confidence !== undefined) {
            existing.confidence = validated.confidence;
        }

        log.debug('Attack path updated', {
            pathId,
            nodeCount: existing.nodes.length,
            confidence: existing.confidence,
        });

        return existing;
    }

    /**
     * Get all paths for a scan.
     */
    getPaths(scanId: string): AttackPath[] {
        const ids = this.scanIndex.get(scanId);
        if (!ids) return [];
        const results: AttackPath[] = [];
        for (const id of ids) {
            const p = this.store.get(id);
            if (p) results.push(p);
        }
        return results;
    }

    /**
     * Detect attack paths from findings.
     * Rule-based: matches finding type combinations against PATH_RULES.
     * O(rules * findings) — both bounded constants.
     */
    detectPaths(scanId: string, findings: ScanFinding[]): AttackPath[] {
        const start = Date.now();
        const detected: AttackPath[] = [];
        const findingTypeSet: Set<string> = new Set(findings.map(f => f.type));

        for (const rule of PATH_RULES) {
            // Check if findings contain ALL required types
            const hasAllTypes = [...rule.requiredTypes].every(t => findingTypeSet.has(t));
            if (!hasAllTypes) continue;

            // Check minimum finding count
            const relevant = findings.filter(f => rule.requiredTypes.has(f.type));
            if (relevant.length < rule.minFindings) continue;

            // Build path
            const nodes = rule.buildPath(findings);
            const vulns = relevant.map(f => `${f.type}:${f.url.slice(0, 100)}`);

            // Severity boost
            const hasCritical = relevant.some(f => f.severity === 'critical');
            const hasHigh = relevant.some(f => f.severity === 'high');
            const severityBoost = hasCritical ? 15 : hasHigh ? 8 : 0;

            // Multi-finding boost
            const countBoost = Math.min((relevant.length - rule.minFindings) * 5, 20);

            const confidence = Math.min(rule.baseConfidence + severityBoost + countBoost, 98);

            try {
                const path = this.createPath({
                    scanId,
                    nodes,
                    vulnerabilities: vulns.slice(0, MAX_VULNS_PER_PATH),
                    privilegeTransitions: [rule.privilegeTransition],
                    confidence,
                });
                detected.push(path);
            } catch (error) {
                // Max paths reached — stop
                if (error instanceof Error && error.message.includes('Max paths')) break;
                throw error;
            }
        }

        const durationMs = Date.now() - start;
        log.info('Path detection complete', {
            scanId,
            findingCount: findings.length,
            pathsDetected: detected.length,
            durationMs,
        });

        return detected;
    }

    /**
     * Score an attack path. AI-powered with deterministic fallback.
     * Timeout: 5 seconds.
     */
    async scoreAttackPath(path: AttackPath): Promise<PathScore> {
        // Deterministic scoring first
        const deterministicScore = this.deterministicScore(path);

        // Attempt AI scoring
        const apiKey = process.env.GEMINI_API_KEY;
        if (!apiKey) return deterministicScore;

        try {
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
            const model = genAI.getGenerativeModel({ model: 'gemini-pro' });

            const prompt = `Score this attack path severity (0-100) and impact level (low/medium/high/critical).
Path: ${path.nodes.join(' → ')}
Vulnerabilities: ${path.vulnerabilities.join(', ')}
Privilege transitions: ${path.privilegeTransitions.join(', ')}
Return JSON only: {"confidence":number,"impactLevel":"low"|"medium"|"high"|"critical","reason":"string"}`;

            const result = await Promise.race([
                model.generateContent(prompt),
                new Promise<never>((_, reject) =>
                    setTimeout(() => reject(new Error('AI score timeout (5s)')), 5000),
                ),
            ]);

            let content = result.response.text();
            content = content.replace(/```json\n?/g, '').replace(/```\n?/g, '').trim();

            const AIScoreSchema = z.object({
                confidence: z.number().min(0).max(100),
                impactLevel: z.enum(['low', 'medium', 'high', 'critical']),
                reason: z.string().max(500),
            }).strict();

            const aiScore = AIScoreSchema.parse(JSON.parse(content));

            // Blend AI and deterministic (60% deterministic, 40% AI)
            const blended: PathScore = {
                confidence: Math.round(deterministicScore.confidence * 0.6 + aiScore.confidence * 0.4),
                impactLevel: this.higherImpact(deterministicScore.impactLevel, aiScore.impactLevel),
                reason: `${deterministicScore.reason} | [AI] ${aiScore.reason}`,
            };

            log.info('AI path scoring complete', {
                pathId: path.id,
                deterministicConfidence: deterministicScore.confidence,
                aiConfidence: aiScore.confidence,
                blendedConfidence: blended.confidence,
            });

            return blended;
        } catch (error) {
            log.warn('AI path scoring failed, using deterministic', {
                pathId: path.id,
                error: error instanceof Error ? error.message : 'Unknown',
            });
            return deterministicScore;
        }
    }

    /**
     * Deterministic scoring based on path characteristics.
     */
    private deterministicScore(path: AttackPath): PathScore {
        let score = 30; // Base
        let impactLevel: 'low' | 'medium' | 'high' | 'critical' = 'low';
        const reasons: string[] = [];

        // Node count — longer chains are more impactful
        if (path.nodes.length >= 5) {
            score += 15;
            reasons.push('long chain');
        } else if (path.nodes.length >= 3) {
            score += 8;
        }

        // Vulnerability count
        score += Math.min(path.vulnerabilities.length * 8, 25);
        if (path.vulnerabilities.length >= 3) reasons.push('multi-vuln chain');

        // Privilege transitions
        if (path.privilegeTransitions.length > 0) {
            score += 20;
            reasons.push('privilege escalation');
            impactLevel = 'high';
        }

        // RCE in chain
        if (path.vulnerabilities.some(v => v.startsWith('rce:'))) {
            score += 15;
            impactLevel = 'critical';
            reasons.push('RCE in chain');
        }

        // SSRF internal pivot
        if (path.vulnerabilities.some(v => v.startsWith('ssrf:'))) {
            score += 10;
            if (impactLevel !== 'critical') impactLevel = 'high';
            reasons.push('SSRF pivot');
        }

        // SQLi data access
        if (path.vulnerabilities.some(v => v.startsWith('sqli:'))) {
            score += 10;
            if (impactLevel === 'low') impactLevel = 'medium';
            reasons.push('SQLi data access');
        }

        score = Math.min(score, 98);

        return {
            confidence: score,
            impactLevel,
            reason: reasons.join('; ') || 'standard path',
        };
    }

    private higherImpact(
        a: 'low' | 'medium' | 'high' | 'critical',
        b: 'low' | 'medium' | 'high' | 'critical',
    ): 'low' | 'medium' | 'high' | 'critical' {
        const order = { low: 0, medium: 1, high: 2, critical: 3 };
        return order[a] >= order[b] ? a : b;
    }

    private generateId(): string {
        this.idCounter++;
        const ts = Date.now().toString(36);
        const cnt = this.idCounter.toString(36).padStart(4, '0');
        return `ap-${ts}-${cnt}`;
    }
}
