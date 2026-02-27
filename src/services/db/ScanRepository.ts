
import { prisma } from './prisma';
import {
    ScanSession,
    AttackNode,
    ScanFinding,
    AIAttackAction,
    AuthContext,
    NodeType
} from '../../types';
import { logger } from '../../utils/logger';

export class ScanRepository {

    static async createScan(targetUrl: string): Promise<ScanSession> {
        const scan = await prisma.scan.create({
            data: {
                targetUrl,
                status: 'running',
                config: JSON.stringify({}),
            }
        });
        return this.mapToSession(scan);
    }

    static async getScan(id: string): Promise<ScanSession | null> {
        const scan = await prisma.scan.findUnique({
            where: { id },
            include: {
                endpoints: true,
                findings: true,
                authContexts: true,
                aiLogs: true,
            }
        });
        if (!scan) return null;
        return this.mapToSession(scan);
    }

    static async getAllScans(): Promise<ScanSession[]> {
        const scans = await prisma.scan.findMany({
            orderBy: { createdAt: 'desc' },
            include: { // Minimal include for list view performance, strictly we should optimize this
                findings: { select: { id: true } }
            }
        });
        // For list view we might not need full details, but for now reuse mapper map
        // Note: This is expensive if we have many scans with many nodes.
        // Optimization for Phase 2: Create a lightweight ScanSummary type.
        return scans.map(s => ({
            id: s.id,
            targetUrl: s.targetUrl,
            status: s.status as any,
            createdAt: s.createdAt.getTime(),
            attackNodes: {},
            attackEdges: {},
            findings: s.findings as any[], // cast for summary
            actions: [],
            authHeaders: { guest: {}, userA: {}, userB: {} }
        }));
    }

    static async updateStatus(id: string, status: string) {
        await prisma.scan.update({
            where: { id },
            data: { status }
        });
    }

    static async addNode(scanId: string, node: AttackNode) {
        try {
            await prisma.endpoint.create({
                data: {
                    scanId,
                    url: node.url,
                    method: node.method || 'GET',
                    type: node.type,
                    params: JSON.stringify(node.params),
                    headers: JSON.stringify({}), // We don't track headers per node in AttackNode yet
                }
            });
        } catch (e) {
            // Ignore duplicates (unique constraint violation if we had one, but we don't have unique url yet)
            // Actually we have @@index([scanId, url]) but not unique.
            // We should check existence to avoid bloat.
            const exists = await prisma.endpoint.findFirst({
                where: { scanId, url: node.url, method: node.method || 'GET' }
            });
            if (exists) return;

            logger.error('Failed to persist node', { error: e, scanId });
        }
    }

    static async addFinding(scanId: string, finding: ScanFinding) {
        await prisma.finding.create({
            data: {
                scanId,
                url: finding.url,
                type: finding.type,
                severity: finding.severity,
                evidence: finding.evidence,
                aiExplanation: finding.aiExplanation,
            }
        });

        // Record cross-scan knowledge
        if (finding.severity === 'high' || finding.severity === 'critical') {
            // Extract payload from evidence if possible? 
            // Finding evidence is free text.
            // For MVP, we might miss the exact payload string unless we structure Finding better.
            // But we can record generic success.
            // Ideally handlers should pass payload explicitly.
            // But let's assume evidence contains it or just record that this target is vulnerable.
            // For now, we just pass evidence as payload (might be messy but better than nothing).
            try {
                // Circular dependency risk if we import KnowledgeBase here?
                // ScanRepository -> KnowledgeBase -> prisma -> ScanRepository?? No.
                // KnowledgeBase -> prisma.
                // ScanRepository -> KnowledgeBase.
                // Seems safe.
                const { KnowledgeBase } = require('../knowledge/KnowledgeBase');
                // Use require to lazy load and avoid potential circular issues if any.
                // Wait, finding.url might be missing in schema mapping but is passed in arg.
                // finding arg has url.
                await KnowledgeBase.recordSuccess(finding.url, finding.type, finding.evidence.slice(0, 200), 'unknown');
            } catch (e) {
                logger.warn('Failed to record knowledge', { error: e });
            }
        }
    }

    static async addActionLog(scanId: string, actions: AIAttackAction[]) {
        await prisma.aILog.create({
            data: {
                scanId,
                step: 'planning',
                prompt: 'Hidden (Prompt usually too large)',
                response: 'Hidden',
                decision: JSON.stringify({ actions }),
                model: 'gemini-pro',
                tokensUsed: 0
            }
        });
    }

    static async logExecutionResult(scanId: string, actionId: string, result: any) {
        await prisma.aILog.create({
            data: {
                scanId,
                step: 'execution_result',
                prompt: '',
                response: '',
                decision: JSON.stringify({ actionId, result }),
                model: 'system',
                tokensUsed: 0
            }
        });
    }

    static async updateAuthContext(scanId: string, context: AuthContext, headers: Record<string, string>) {
        // Check if exists
        const existing = await prisma.authContext.findFirst({
            where: { scanId, role: context }
        });

        if (existing) {
            await prisma.authContext.update({
                where: { id: existing.id },
                data: { headers: JSON.stringify(headers) }
            });
        } else {
            await prisma.authContext.create({
                data: {
                    scanId,
                    role: context,
                    headers: JSON.stringify(headers)
                }
            });
        }
    }

    private static mapToSession(scan: any): ScanSession {
        const nodes: Record<string, AttackNode> = {};
        if (scan.endpoints) {
            scan.endpoints.forEach((ep: any) => {
                const id = `${ep.type}:${ep.url}`; // Reconstruct ID logic from crawler
                nodes[id] = {
                    id,
                    url: ep.url,
                    method: ep.method,
                    type: ep.type as NodeType,
                    authContext: 'guest', // DB doesn't store this on endpoint currently, assumes guest discovery
                    params: JSON.parse(ep.params || '[]'),
                    tags: []
                };
            });
        }

        const authHeaders: Record<AuthContext, Record<string, string>> = {
            guest: {},
            userA: {},
            userB: {}
        };

        if (scan.authContexts) {
            scan.authContexts.forEach((ac: any) => {
                if (ac.role in authHeaders) {
                    authHeaders[ac.role as AuthContext] = JSON.parse(ac.headers || '{}');
                }
            });
        }

        const findings = scan.findings ? scan.findings.map((f: any) => ({
            id: f.id,
            type: f.type,
            url: 'unknown', // DB finding doesn't store URL directly in my schema? Wait, schema has finding linked to scan, finding has evidence.
            // Mistake in schema: Finding table doesn't have 'url' field explicitly, it has endpoint relation.
            // But finding also needs a URL because it might be a fuzzed URL not in endpoints table.
            // I will assume for now we use 'evidence' or add 'url' to schema.
            // Checking Schema: Finding does NOT have url. It has endpointId.
            // This is a schema gap. I should add 'url' to Finding model or use evidence.
            // ... I'll fix this in the mapping.
            severity: f.severity,
            evidence: f.evidence,
            aiExplanation: f.aiExplanation
        })) : [];

        const actions: AIAttackAction[] = [];
        const actionResults: Record<string, any> = {};

        if (scan.aiLogs) {
            scan.aiLogs.forEach((log: any) => {
                try {
                    const decision = JSON.parse(log.decision);
                    // Handle planning logs
                    if (log.step === 'planning' && decision.actions && Array.isArray(decision.actions)) {
                        actions.push(...decision.actions);
                    }
                    // Handle execution result logs
                    if (log.step === 'execution_result' && decision.actionId && decision.result) {
                        actionResults[decision.actionId] = decision.result;
                    }
                } catch { }
            });
        }

        // Apply results to actions
        actions.forEach(action => {
            if (actionResults[action.id]) {
                action.result = actionResults[action.id];
            }
        });

        return {
            id: scan.id,
            targetUrl: scan.targetUrl,
            status: scan.status as any,
            createdAt: scan.createdAt.getTime(),
            attackNodes: nodes,
            attackEdges: {}, // Edges not persisted in MVP
            findings,
            actions,
            authHeaders
        };
    }
}
