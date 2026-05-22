/**
 * AttackPathSimulator — Simulate multi-step attack chains from scan data.
 *
 * Builds realistic penetration paths like:
 *   Guest → /profile → IDOR → Admin API
 *
 * Data sources: Findings, Endpoints, AuthContexts, Hypotheses.
 * Does NOT modify AttackPathEngine — uses it as read-only data source.
 */
import { z } from 'zod';
import { PrismaClient } from '@prisma/client';
import { logger } from '../../utils/logger';

const log = logger.child({ module: 'AttackPathSimulator' });
const prisma = new PrismaClient();

// ─── Constants ──────────────────────────────────────────────────────────────

const MAX_PATH_DEPTH = 10;
const MAX_SIMULATED_PATHS = 30;

// ─── Types ──────────────────────────────────────────────────────────────────

export interface SimulatedPath {
    id: string;
    scanId: string;
    steps: PathStep[];
    risk: 'low' | 'medium' | 'high' | 'critical';
    probability: number;
    description: string;
    entryPoint: string;
    objective: string;
}

export interface PathStep {
    order: number;
    endpoint: string;
    action: string;
    vulnerability: string | null;
    authContext: string;
    outcome: string;
}

export interface PathScore {
    pathId: string;
    risk: 'low' | 'medium' | 'high' | 'critical';
    probability: number;
    impactFactors: string[];
}

// ─── Transition Rules ───────────────────────────────────────────────────────

interface TransitionRule {
    fromVuln: string;
    toAction: string;
    escalation: string;
    riskBoost: number;
}

const TRANSITION_RULES: TransitionRule[] = [
    { fromVuln: 'idor', toAction: 'Access other user data', escalation: 'User → Admin', riskBoost: 0.2 },
    { fromVuln: 'bac', toAction: 'Bypass authorization', escalation: 'Guest → Authenticated', riskBoost: 0.25 },
    { fromVuln: 'auth_weakness', toAction: 'Exploit weak auth', escalation: 'Guest → User', riskBoost: 0.15 },
    { fromVuln: 'ssrf', toAction: 'Pivot to internal service', escalation: 'External → Internal', riskBoost: 0.3 },
    { fromVuln: 'sqli', toAction: 'Extract database data', escalation: 'User → Database', riskBoost: 0.25 },
    { fromVuln: 'xss', toAction: 'Steal session token', escalation: 'None → Session Hijack', riskBoost: 0.1 },
    { fromVuln: 'rce', toAction: 'Execute system commands', escalation: 'User → System', riskBoost: 0.4 },
    { fromVuln: 'ssti', toAction: 'Template code execution', escalation: 'User → System', riskBoost: 0.35 },
    { fromVuln: 'file_upload', toAction: 'Upload malicious file', escalation: 'User → Stored Payload', riskBoost: 0.2 },
    { fromVuln: 'cors', toAction: 'Cross-origin data theft', escalation: 'Victim → Attacker', riskBoost: 0.1 },
    { fromVuln: 'csrf', toAction: 'Force victim action', escalation: 'Victim → State Change', riskBoost: 0.1 },
];

const SENSITIVE_KEYWORDS = ['admin', 'dashboard', 'manage', 'internal', 'debug', 'config', 'billing', 'export'];

// ─── Engine ─────────────────────────────────────────────────────────────────

export class AttackPathSimulator {
    private idCounter = 0;

    /**
     * Simulate attack paths from scan data.
     * Pulls findings, endpoints, auth contexts, and hypotheses from the DB.
     */
    async simulatePaths(scanId: string): Promise<SimulatedPath[]> {
        const start = Date.now();

        // Load data from Prisma
        const [endpoints, findings, authContexts, hypotheses] = await Promise.all([
            prisma.endpoint.findMany({ where: { scanId } }),
            prisma.finding.findMany({ where: { scanId } }),
            prisma.authContext.findMany({ where: { scanId } }),
            prisma.hypothesis.findMany({ where: { scanId, status: 'active' } }),
        ]);

        const paths: SimulatedPath[] = [];

        // 1. Build paths from finding chains
        const findingsByUrl = new Map<string, typeof findings>();
        for (const f of findings) {
            const list = findingsByUrl.get(f.url) || [];
            list.push(f);
            findingsByUrl.set(f.url, list);
        }

        // 2. Identify entry points (guest-accessible or auth-bypass endpoints)
        const entryEndpoints = endpoints.filter(ep => {
            const lower = ep.url.toLowerCase();
            return ep.type === 'page' || lower.includes('login') || lower.includes('register') || lower.includes('public');
        });

        // 3. Identify high-value targets
        const sensitiveEndpoints = endpoints.filter(ep =>
            SENSITIVE_KEYWORDS.some(kw => ep.url.toLowerCase().includes(kw)),
        );

        // 4. Build paths: entry → vulnerability → escalation → target
        for (const entry of entryEndpoints.slice(0, 10)) {
            for (const finding of findings) {
                const rule = TRANSITION_RULES.find(r => r.fromVuln === finding.type);
                if (!rule) continue;

                // Find reachable sensitive targets
                for (const target of sensitiveEndpoints.slice(0, 5)) {
                    if (target.url === entry.url) continue;

                    const steps = this.buildSteps(entry, finding, rule, target, authContexts);
                    const probability = this.calculateProbability(finding, rule, hypotheses);
                    const risk = this.classifyRisk(probability, finding.severity);

                    paths.push({
                        id: this.generateId(),
                        scanId,
                        steps,
                        risk,
                        probability,
                        description: `${rule.escalation}: ${entry.url} → ${finding.type} → ${target.url}`,
                        entryPoint: entry.url,
                        objective: target.url,
                    });

                    if (paths.length >= MAX_SIMULATED_PATHS) break;
                }
                if (paths.length >= MAX_SIMULATED_PATHS) break;
            }
            if (paths.length >= MAX_SIMULATED_PATHS) break;
        }

        // 5. Build paths from hypothesis clusters
        for (const hyp of hypotheses.slice(0, 5)) {
            if (paths.length >= MAX_SIMULATED_PATHS) break;

            const relatedFindings = findings.filter(f =>
                f.type === hyp.type.toLowerCase() ||
                (hyp.type === 'Auth' && (f.type === 'bac' || f.type === 'auth_weakness')),
            );

            if (relatedFindings.length === 0) continue;

            const steps: PathStep[] = [
                { order: 1, endpoint: 'Entry Point', action: 'Reconnaissance', vulnerability: null, authContext: 'guest', outcome: 'Identified target surface' },
                ...relatedFindings.slice(0, 3).map((f, i) => ({
                    order: i + 2,
                    endpoint: f.url,
                    action: `Exploit ${f.type}`,
                    vulnerability: f.type,
                    authContext: 'guest',
                    outcome: f.evidence.slice(0, 100),
                })),
                { order: relatedFindings.length + 2, endpoint: 'Objective', action: hyp.description.slice(0, 100), vulnerability: null, authContext: 'escalated', outcome: `${hyp.type} cluster confirmed` },
            ];

            paths.push({
                id: this.generateId(),
                scanId,
                steps,
                risk: hyp.confidence > 70 ? 'critical' : hyp.confidence > 40 ? 'high' : 'medium',
                probability: hyp.confidence / 100,
                description: `Hypothesis-driven: ${hyp.description.slice(0, 120)}`,
                entryPoint: relatedFindings[0]?.url ?? 'Unknown',
                objective: hyp.type + ' exploitation',
            });
        }

        // Sort by probability descending
        paths.sort((a, b) => b.probability - a.probability);

        log.info('Path simulation complete', {
            scanId,
            endpointCount: endpoints.length,
            findingCount: findings.length,
            hypothesisCount: hypotheses.length,
            simulatedPaths: paths.length,
            durationMs: Date.now() - start,
        });

        return paths;
    }

    /**
     * Score all simulated paths.
     */
    scorePaths(paths: SimulatedPath[]): PathScore[] {
        return paths.map(path => {
            const impactFactors: string[] = [];

            if (path.steps.length >= 4) impactFactors.push('Multi-step chain');
            if (path.steps.some(s => s.vulnerability === 'rce' || s.vulnerability === 'ssti')) impactFactors.push('Code execution risk');
            if (path.steps.some(s => s.vulnerability === 'sqli')) impactFactors.push('Database compromise');
            if (path.steps.some(s => s.vulnerability === 'ssrf')) impactFactors.push('Internal pivot');
            if (path.steps.some(s => s.authContext !== 'guest' && s.authContext !== path.steps[0]?.authContext)) impactFactors.push('Privilege escalation');
            if (path.objective.toLowerCase().includes('admin')) impactFactors.push('Admin access');

            return {
                pathId: path.id,
                risk: path.risk,
                probability: path.probability,
                impactFactors,
            };
        });
    }

    /**
     * Get only critical-risk paths.
     */
    getCriticalPaths(paths: SimulatedPath[]): SimulatedPath[] {
        return paths.filter(p => p.risk === 'critical' || p.probability >= 0.8);
    }

    // ─── Private Helpers ────────────────────────────────────────────────────

    private buildSteps(
        entry: { url: string },
        finding: { url: string; type: string; evidence: string },
        rule: TransitionRule,
        target: { url: string },
        authContexts: Array<{ role: string }>,
    ): PathStep[] {
        const authRoles = authContexts.map(a => a.role);
        const initialAuth = authRoles.includes('guest') ? 'guest' : authRoles[0] ?? 'guest';

        const steps: PathStep[] = [
            {
                order: 1,
                endpoint: entry.url,
                action: 'Initial access',
                vulnerability: null,
                authContext: initialAuth,
                outcome: 'Application entry point reached',
            },
            {
                order: 2,
                endpoint: finding.url,
                action: `Exploit ${finding.type}`,
                vulnerability: finding.type,
                authContext: initialAuth,
                outcome: finding.evidence.slice(0, 100),
            },
            {
                order: 3,
                endpoint: finding.url,
                action: rule.toAction,
                vulnerability: finding.type,
                authContext: 'escalated',
                outcome: rule.escalation,
            },
            {
                order: 4,
                endpoint: target.url,
                action: 'Access privileged resource',
                vulnerability: null,
                authContext: 'escalated',
                outcome: `Reached ${target.url}`,
            },
        ];

        return steps.slice(0, MAX_PATH_DEPTH);
    }

    private calculateProbability(
        finding: { severity: string },
        rule: TransitionRule,
        hypotheses: Array<{ type: string; confidence: number }>,
    ): number {
        let prob = 0.3; // Base

        // Severity boost
        if (finding.severity === 'critical') prob += 0.3;
        else if (finding.severity === 'high') prob += 0.2;
        else if (finding.severity === 'medium') prob += 0.1;

        // Rule boost
        prob += rule.riskBoost;

        // Hypothesis boost
        const relatedHyp = hypotheses.find(h =>
            h.type.toLowerCase() === finding.severity || h.confidence > 60,
        );
        if (relatedHyp) prob += 0.1;

        return Math.min(prob, 0.98);
    }

    private classifyRisk(probability: number, severity: string): 'low' | 'medium' | 'high' | 'critical' {
        if (probability >= 0.8 || severity === 'critical') return 'critical';
        if (probability >= 0.6 || severity === 'high') return 'high';
        if (probability >= 0.4) return 'medium';
        return 'low';
    }

    private generateId(): string {
        this.idCounter++;
        return `sim-${Date.now().toString(36)}-${this.idCounter.toString(36).padStart(4, '0')}`;
    }
}
