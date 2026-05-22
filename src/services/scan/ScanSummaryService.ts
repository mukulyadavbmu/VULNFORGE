/**
 * ScanSummaryService — Generate scan intelligence summaries from DB + in-memory session.
 * Uses Prisma to query Endpoint and Finding tables.
 * No schema changes. Read-only operations.
 */
import { PrismaClient } from '@prisma/client';
import { logger } from '../../utils/logger';
import { getScanSession } from '../../scanOrchestrator';
import { ReliabilityTier } from '../../types';

const log = logger.child({ module: 'ScanSummaryService' });
const prisma = new PrismaClient();

const SENSITIVE_KEYWORDS = [
    'admin', 'debug', 'billing', 'export', 'internal', 'config',
    'dashboard', 'manage', 'panel', 'secret', 'token', 'private',
];

export interface ScanSummaryData {
    // DB-backed counts
    endpoints: number;
    sensitivePaths: number;
    vulnerabilities: number;
    criticalFindings: number;
    highFindings: number;
    confirmedExploits: number;
    // Phase 2C: Reliability breakdown
    reliabilityBreakdown: Record<ReliabilityTier | string, number>;
    replayStatusBreakdown: Record<string, number>;
    // Coverage & diagnostics from session
    coverageMetrics?: {
        endpointsDiscovered: number;
        endpointsAttacked: number;
        authenticatedEndpointsTested: number;
        roleTestedEndpoints: number;
        parametersFuzzed: number;
        attackSuccessCount: number;
        attackFailureCount: number;
        replayAttempts: number;
        replaySuccesses: number;
        skippedAttacks: Record<string, number>;
        failedVerifications: Record<string, number>;
    };
    budgetUsage?: Record<string, {
        mutationsUsed: number;
        replaysUsed: number;
        roleTransitionsUsed: number;
        verificationRetriesUsed: number;
    }>;
    diagnosticsLogs?: any[];
    // Finding details with reliability info
    findingSummaries?: Array<{
        id: string;
        type: string;
        url: string;
        severity: string;
        reliabilityTier?: string;
        replayStatus?: string;
        verificationAttempts: number;
    }>;
}

export async function generateSummary(scanId: string): Promise<ScanSummaryData> {
    try {
        // Count endpoints
        const endpoints = await prisma.endpoint.count({ where: { scanId } });

        // Get all endpoint URLs for sensitive path analysis
        const allEndpoints = await prisma.endpoint.findMany({
            where: { scanId },
            select: { url: true },
        });

        const sensitivePaths = allEndpoints.filter(ep => {
            const lower = ep.url.toLowerCase();
            return SENSITIVE_KEYWORDS.some(kw => lower.includes(kw));
        }).length;

        // Count findings by severity from DB
        const dbFindings = await prisma.finding.findMany({
            where: { scanId },
            select: { id: true, severity: true, evidence: true, type: true, url: true },
        });

        const vulnerabilities = dbFindings.length;
        const criticalFindings = dbFindings.filter(f => f.severity === 'critical').length;
        const highFindings = dbFindings.filter(f => f.severity === 'high').length;
        const confirmedExploits = dbFindings.filter(
            f => f.evidence.length > 50 && (f.severity === 'critical' || f.severity === 'high'),
        ).length;

        log.debug('DB summary generated', { scanId, endpoints, vulnerabilities, criticalFindings });

        // Pull in-memory session for reliability metrics
        const session = await getScanSession(scanId);

        // Build reliability + replay status breakdowns from in-memory findings
        const reliabilityBreakdown: Record<string, number> = {};
        const replayStatusBreakdown: Record<string, number> = {};
        const findingSummaries: ScanSummaryData['findingSummaries'] = [];

        if (session) {
            for (const f of session.findings) {
                const tier = f.reliabilityTier ?? 'signal';
                reliabilityBreakdown[tier] = (reliabilityBreakdown[tier] ?? 0) + 1;

                const rStatus = f.replayStatus ?? 'pending';
                replayStatusBreakdown[rStatus] = (replayStatusBreakdown[rStatus] ?? 0) + 1;

                findingSummaries.push({
                    id: f.id,
                    type: f.type,
                    url: f.url,
                    severity: f.severity,
                    reliabilityTier: f.reliabilityTier,
                    replayStatus: f.replayStatus,
                    verificationAttempts: f.verificationHistory?.length ?? 0,
                });
            }
        }

        return {
            endpoints,
            sensitivePaths,
            vulnerabilities,
            criticalFindings,
            highFindings,
            confirmedExploits,
            reliabilityBreakdown,
            replayStatusBreakdown,
            coverageMetrics: session?.coverageMetrics,
            budgetUsage: session?.budgetUsage,
            diagnosticsLogs: session?.diagnosticsLogs,
            findingSummaries,
        };
    } catch (error) {
        log.error('Summary generation failed', {
            scanId,
            error: error instanceof Error ? error.message : 'Unknown',
        });
        return {
            endpoints: 0,
            sensitivePaths: 0,
            vulnerabilities: 0,
            criticalFindings: 0,
            highFindings: 0,
            confirmedExploits: 0,
            reliabilityBreakdown: {},
            replayStatusBreakdown: {},
        };
    }
}
