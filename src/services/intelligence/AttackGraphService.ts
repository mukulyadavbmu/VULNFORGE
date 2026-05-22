/**
 * AttackGraphService — Generate structured attack graph data for visualization.
 *
 * Produces { nodes, edges } from Endpoints, Findings, Hypotheses,
 * AuthContexts, and AttackPaths (via Prisma).
 * Additive — no schema changes, no existing module modifications.
 */
import { PrismaClient } from '@prisma/client';
import { logger } from '../../utils/logger';

const log = logger.child({ module: 'AttackGraphService' });
const prisma = new PrismaClient();

// ─── Constants ──────────────────────────────────────────────────────────────

const MAX_NODES = 500;
const MAX_EDGES = 1000;

// ─── Types ──────────────────────────────────────────────────────────────────

export type NodeType = 'endpoint' | 'vulnerability' | 'authRole' | 'hypothesis';
export type EdgeType = 'leads_to' | 'exploits' | 'requires_auth' | 'hypothesis_link';

export interface GraphNode {
    id: string;
    type: NodeType;
    label: string;
    riskScore: number;
}

export interface GraphEdge {
    from: string;
    to: string;
    type: EdgeType;
}

export interface AttackGraph {
    nodes: GraphNode[];
    edges: GraphEdge[];
    scanId: string;
    generatedAt: number;
}

// ─── Severity to Risk ───────────────────────────────────────────────────────

function severityToScore(severity: string): number {
    switch (severity.toLowerCase()) {
        case 'critical': return 95;
        case 'high': return 75;
        case 'medium': return 50;
        case 'low': return 25;
        default: return 10;
    }
}

// ─── Service ────────────────────────────────────────────────────────────────

export class AttackGraphService {
    /**
     * Generate the full attack graph for a scan.
     *
     * Data sources: Endpoints, Findings, Hypotheses, AuthContexts.
     * Returns { nodes, edges } suitable for frontend visualization.
     */
    async generateGraph(scanId: string): Promise<AttackGraph> {
        const start = Date.now();

        const [endpoints, findings, hypotheses, authContexts] = await Promise.all([
            prisma.endpoint.findMany({ where: { scanId }, take: MAX_NODES }),
            prisma.finding.findMany({ where: { scanId }, take: MAX_NODES }),
            prisma.hypothesis.findMany({ where: { scanId, status: 'active' }, take: 100 }),
            prisma.authContext.findMany({ where: { scanId } }),
        ]);

        const nodes: GraphNode[] = [];
        const edges: GraphEdge[] = [];
        const nodeIds = new Set<string>();

        // ── Auth Role Nodes ─────────────────────────────────────────────────
        for (const auth of authContexts) {
            const nodeId = `auth-${auth.role}`;
            if (nodeIds.has(nodeId)) continue;
            nodeIds.add(nodeId);
            nodes.push({
                id: nodeId,
                type: 'authRole',
                label: auth.role.charAt(0).toUpperCase() + auth.role.slice(1),
                riskScore: auth.role === 'guest' ? 10 : 30,
            });
        }

        // Add implicit Guest node if missing
        if (!nodeIds.has('auth-guest')) {
            nodeIds.add('auth-guest');
            nodes.push({
                id: 'auth-guest',
                type: 'authRole',
                label: 'Guest',
                riskScore: 10,
            });
        }

        // ── Endpoint Nodes ──────────────────────────────────────────────────
        for (const ep of endpoints) {
            if (nodes.length >= MAX_NODES) break;
            const nodeId = `ep-${ep.id}`;
            if (nodeIds.has(nodeId)) continue;
            nodeIds.add(nodeId);

            // Extract short label from URL
            let label: string;
            try {
                const urlObj = new URL(ep.url, 'http://placeholder');
                label = urlObj.pathname;
            } catch {
                label = ep.url;
            }
            if (label.length > 60) label = label.slice(0, 57) + '...';

            nodes.push({
                id: nodeId,
                type: 'endpoint',
                label: `${ep.method} ${label}`,
                riskScore: this.endpointRiskScore(ep.url),
            });

            // Edge: Guest → Endpoint (all endpoints are reachable from guest initially)
            if (edges.length < MAX_EDGES) {
                edges.push({
                    from: 'auth-guest',
                    to: nodeId,
                    type: 'leads_to',
                });
            }
        }

        // ── Vulnerability Nodes (from Findings) ─────────────────────────────
        for (const finding of findings) {
            if (nodes.length >= MAX_NODES) break;
            const vulnId = `vuln-${finding.id}`;
            if (nodeIds.has(vulnId)) continue;
            nodeIds.add(vulnId);

            nodes.push({
                id: vulnId,
                type: 'vulnerability',
                label: `${finding.type.toUpperCase()} on ${this.shortenUrl(finding.url)}`,
                riskScore: severityToScore(finding.severity),
            });

            // Edge: Endpoint → Vulnerability (exploits)
            if (finding.endpointId && edges.length < MAX_EDGES) {
                const epNodeId = `ep-${finding.endpointId}`;
                if (nodeIds.has(epNodeId)) {
                    edges.push({
                        from: epNodeId,
                        to: vulnId,
                        type: 'exploits',
                    });
                }
            }

            // Edge: Vulnerability → higher auth (for privesc vulns)
            if (['idor', 'bac', 'auth_weakness'].includes(finding.type.toLowerCase())) {
                const adminNode = nodeIds.has('auth-admin') ? 'auth-admin' : null;
                if (adminNode && edges.length < MAX_EDGES) {
                    edges.push({
                        from: vulnId,
                        to: adminNode,
                        type: 'leads_to',
                    });
                }
            }
        }

        // ── Hypothesis Nodes ────────────────────────────────────────────────
        for (const hyp of hypotheses) {
            if (nodes.length >= MAX_NODES) break;
            const hypId = `hyp-${hyp.id}`;
            if (nodeIds.has(hypId)) continue;
            nodeIds.add(hypId);

            nodes.push({
                id: hypId,
                type: 'hypothesis',
                label: `${hyp.type}: ${hyp.description.slice(0, 50)}`,
                riskScore: Math.round(hyp.confidence),
            });

            // Link hypotheses to related findings of same type
            for (const finding of findings) {
                if (edges.length >= MAX_EDGES) break;
                if (finding.type.toLowerCase() === hyp.type.toLowerCase() ||
                    (hyp.type === 'Auth' && ['bac', 'auth_weakness'].includes(finding.type.toLowerCase()))) {
                    edges.push({
                        from: `vuln-${finding.id}`,
                        to: hypId,
                        type: 'hypothesis_link',
                    });
                }
            }
        }

        // ── Auth-required edges ─────────────────────────────────────────────
        // Endpoints with auth-related findings require authentication
        for (const finding of findings) {
            if (edges.length >= MAX_EDGES) break;
            if (['bac', 'idor'].includes(finding.type.toLowerCase()) && finding.endpointId) {
                const epNodeId = `ep-${finding.endpointId}`;
                for (const auth of authContexts) {
                    if (auth.role !== 'guest' && edges.length < MAX_EDGES) {
                        edges.push({
                            from: epNodeId,
                            to: `auth-${auth.role}`,
                            type: 'requires_auth',
                        });
                        break; // One auth edge per endpoint
                    }
                }
            }
        }

        log.info('Attack graph generated', {
            scanId,
            nodes: nodes.length,
            edges: edges.length,
            endpoints: endpoints.length,
            findings: findings.length,
            hypotheses: hypotheses.length,
            durationMs: Date.now() - start,
        });

        return {
            nodes,
            edges,
            scanId,
            generatedAt: Date.now(),
        };
    }

    // ─── Helpers ──────────────────────────────────────────────────────────

    private endpointRiskScore(url: string): number {
        const lower = url.toLowerCase();
        const sensitiveKeywords = ['admin', 'debug', 'internal', 'config', 'billing', 'export', 'delete', 'manage'];
        if (sensitiveKeywords.some(kw => lower.includes(kw))) return 70;
        if (lower.includes('/api/')) return 40;
        return 20;
    }

    private shortenUrl(url: string): string {
        try {
            const urlObj = new URL(url, 'http://placeholder');
            const path = urlObj.pathname;
            return path.length > 40 ? path.slice(0, 37) + '...' : path;
        } catch {
            return url.slice(0, 40);
        }
    }
}
