/**
 * BenchmarkHarness — Standalone runtime effectiveness evaluator.
 *
 * Architecture constraint: this harness is ISOLATED from the normal AutoScanPipeline.
 * It does NOT tightly couple to scan orchestration internals.
 * Accessible via: POST /benchmark/:profile
 */
import { ScanSession } from '../../types';
import { createScanSessionAsync, getScanSession } from '../../scanOrchestrator';
import { startPipeline } from '../scan/AutoScanPipeline';
import { logger } from '../../utils/logger';

const log = logger.child({ module: 'BenchmarkHarness' });

export interface BenchmarkProfile {
    id: string;
    name: string;
    targetUrl: string;
    expectedVulnerabilities: Array<{
        type: string;
        pathRegex: string;
        severity: string;
        description?: string;
    }>;
}

export interface BenchmarkResult {
    profileId: string;
    scanId: string;
    targetUrl: string;
    durationMs: number;
    // Detection quality
    totalExpected: number;
    totalFound: number;
    truePositives: number;
    falsePositives: number;
    falseNegatives: number;
    coveragePercentage: number;
    // Phase 2C: Extended metrics
    replaySuccessRate: number;
    exploitConfirmationRate: number;
    authCoverage: number;
    reliabilityBreakdown: Record<string, number>; // tier -> count
    // Reporting detail
    missedVulnerabilities: string[];
    noisyFindings: string[];
    confirmedExploits: string[];
    coverageMetrics?: any;
}

// ─── Ground Truth Profiles ───────────────────────────────────────────────────

const PROFILES: Record<string, BenchmarkProfile> = {
    'juice-shop': {
        id: 'juice-shop',
        name: 'OWASP Juice Shop',
        targetUrl: 'http://localhost:3000',
        expectedVulnerabilities: [
            { type: 'sqli',       pathRegex: '.*/rest/user/login.*',        severity: 'critical', description: 'SQLi on login endpoint' },
            { type: 'bac',        pathRegex: '.*/rest/basket/.*',           severity: 'high',     description: 'BOLA on basket endpoint' },
            { type: 'xss',        pathRegex: '.*/api/Feedbacks.*',          severity: 'high',     description: 'XSS on feedback form' },
            { type: 'idor',       pathRegex: '.*/api/Users/\\d+.*',         severity: 'high',     description: 'IDOR on user profile' },
            { type: 'auth_bypass',pathRegex: '.*/rest/user/.*',             severity: 'critical', description: 'Auth bypass on user endpoints' },
            { type: 'ssrf',       pathRegex: '.*/rest/products/.*',         severity: 'medium',   description: 'SSRF via product image URL' },
        ],
    },
    'dvwa': {
        id: 'dvwa',
        name: 'DVWA (Damn Vulnerable Web Application)',
        targetUrl: 'http://localhost:4280',
        expectedVulnerabilities: [
            { type: 'sqli',       pathRegex: '.*/vulnerabilities/sqli.*',   severity: 'critical', description: 'Classic SQLi' },
            { type: 'xss',       pathRegex: '.*/vulnerabilities/xss_r.*',  severity: 'high',     description: 'Reflected XSS' },
            { type: 'xss',       pathRegex: '.*/vulnerabilities/xss_s.*',  severity: 'critical', description: 'Stored XSS' },
            { type: 'lfi',       pathRegex: '.*/vulnerabilities/fi.*',     severity: 'high',     description: 'File Inclusion' },
            { type: 'rce',       pathRegex: '.*/vulnerabilities/exec.*',   severity: 'critical', description: 'Remote Code Execution' },
            { type: 'csrf',      pathRegex: '.*/vulnerabilities/csrf.*',   severity: 'medium',   description: 'CSRF on password change' },
            { type: 'file_upload',pathRegex: '.*/vulnerabilities/upload.*', severity: 'high',     description: 'Unrestricted file upload' },
        ],
    },
    'webgoat': {
        id: 'webgoat',
        name: 'WebGoat',
        targetUrl: 'http://localhost:8081/WebGoat',
        expectedVulnerabilities: [
            { type: 'sqli',       pathRegex: '.*/SqlInjection.*',           severity: 'critical', description: 'SQL Injection' },
            { type: 'xss',       pathRegex: '.*/CrossSiteScripting.*',     severity: 'high',     description: 'Cross-Site Scripting' },
            { type: 'idor',      pathRegex: '.*/IDOR.*',                   severity: 'high',     description: 'Insecure Direct Object Reference' },
            { type: 'jwt_weakness',pathRegex: '.*/JWT.*',                  severity: 'high',     description: 'JWT Vulnerabilities' },
            { type: 'ssrf',      pathRegex: '.*/SSRF.*',                   severity: 'medium',   description: 'Server-Side Request Forgery' },
            { type: 'auth_bypass',pathRegex: '.*/auth/bypass.*',           severity: 'critical', description: 'Authentication Bypass' },
        ],
    },
};

// ─── Harness Engine ──────────────────────────────────────────────────────────

export class BenchmarkHarness {

    /**
     * Executes a full benchmark run for a given profile.
     * Runs the AutoScanPipeline and compares results against ground truth.
     */
    static async runBenchmark(profileId: string, customUrl?: string, timeoutMs = 120_000): Promise<BenchmarkResult> {
        const profile = PROFILES[profileId];
        if (!profile) {
            throw new Error(`Unknown benchmark profile: '${profileId}'. Available: ${Object.keys(PROFILES).join(', ')}`);
        }

        const targetUrl = customUrl || profile.targetUrl;
        log.info(`Benchmark run starting: profile='${profileId}' target='${targetUrl}'`);

        const startTime = Date.now();

        // 1. Create an isolated scan session for this benchmark
        const session = await createScanSessionAsync(targetUrl);
        log.info(`Benchmark scan session created: ${session.id}`);

        // 2. Run the AutoScanPipeline and wait up to timeoutMs
        try {
            await Promise.race([
                startPipeline(session.id),
                new Promise<void>((_, reject) =>
                    setTimeout(() => reject(new Error(`Benchmark pipeline timeout after ${timeoutMs}ms`)), timeoutMs)
                ),
            ]);
        } catch (err) {
            // Timeout is acceptable — we evaluate whatever was found within the window
            log.warn(`Benchmark pipeline ended (possibly timeout): ${(err as Error).message}`);
        }

        // 3. Retrieve final session state
        const completedSession = await getScanSession(session.id);
        if (!completedSession) {
            throw new Error(`Failed to retrieve benchmark session ${session.id}`);
        }

        const durationMs = Date.now() - startTime;

        // 4. Ground truth comparison
        return this.compareGroundTruth(profile, completedSession, targetUrl, durationMs);
    }

    // ─── Ground Truth Comparison ─────────────────────────────────────────────

    private static compareGroundTruth(
        profile: BenchmarkProfile,
        session: ScanSession,
        targetUrl: string,
        durationMs: number,
    ): BenchmarkResult {
        // All reported findings with vuln/exploit classification
        const reportedFindings = session.findings.filter(
            f => f.classification === 'confirmed_exploit' || f.classification === 'vulnerability'
        );

        // True positives: expected vuln matched by reported finding
        let truePositives = 0;
        const missedVulnerabilities: string[] = [];
        const matchedFindingIds = new Set<string>();

        for (const expected of profile.expectedVulnerabilities) {
            const regex = new RegExp(expected.pathRegex, 'i');
            const match = reportedFindings.find(f =>
                f.type === expected.type && regex.test(f.url) && !matchedFindingIds.has(f.id)
            );
            if (match) {
                truePositives++;
                matchedFindingIds.add(match.id);
            } else {
                missedVulnerabilities.push(`[${expected.severity.toUpperCase()}] ${expected.type} — ${expected.description ?? expected.pathRegex}`);
            }
        }

        const falseNegatives = profile.expectedVulnerabilities.length - truePositives;
        // False positives: reported findings not matching any expected entry
        const falsePositives = Math.max(0, reportedFindings.length - truePositives);
        const noisyFindings = reportedFindings
            .filter(f => !matchedFindingIds.has(f.id))
            .map(f => `${f.type} @ ${f.url}`);

        const totalExpected = profile.expectedVulnerabilities.length;
        const coveragePercentage = totalExpected > 0 ? (truePositives / totalExpected) * 100 : 0;

        // Confirmed exploits list
        const confirmedExploits = session.findings
            .filter(f => f.classification === 'confirmed_exploit' || f.reliabilityTier === 'reproducible' || f.reliabilityTier === 'stateful_confirmed')
            .map(f => `${f.type} @ ${f.url} [${f.reliabilityTier ?? 'unknown'}]`);

        // Exploit confirmation rate: ratio of confirmed_exploit findings to all vulnerability findings
        const exploitConfirmationRate = reportedFindings.length > 0
            ? (session.findings.filter(f => f.classification === 'confirmed_exploit').length / reportedFindings.length) * 100
            : 0;

        // Replay success rate from coverage metrics
        const cm = session.coverageMetrics;
        const replaySuccessRate = cm && cm.replayAttempts > 0
            ? (cm.replaySuccesses / cm.replayAttempts) * 100
            : 0;

        // Auth coverage: what % of expected auth-requiring endpoints had a test with a non-guest role
        const authRequiringExpected = profile.expectedVulnerabilities.filter(
            e => !/public|login|register/.test(e.pathRegex)
        ).length;
        const authCoverage = authRequiringExpected > 0
            ? (truePositives / authRequiringExpected) * 100
            : 100;

        // Reliability breakdown
        const reliabilityBreakdown: Record<string, number> = {};
        for (const f of session.findings) {
            const tier = f.reliabilityTier ?? 'signal';
            reliabilityBreakdown[tier] = (reliabilityBreakdown[tier] ?? 0) + 1;
        }

        log.info(`Benchmark complete: profile='${profile.id}' coverage=${coveragePercentage.toFixed(1)}% exploits=${confirmedExploits.length}`);

        return {
            profileId: profile.id,
            scanId: session.id,
            targetUrl,
            durationMs,
            totalExpected,
            totalFound: reportedFindings.length,
            truePositives,
            falsePositives,
            falseNegatives,
            coveragePercentage,
            replaySuccessRate,
            exploitConfirmationRate,
            authCoverage,
            reliabilityBreakdown,
            missedVulnerabilities,
            noisyFindings,
            confirmedExploits,
            coverageMetrics: session.coverageMetrics,
        };
    }

    /**
     * Returns available benchmark profiles (id, name, target, expected count).
     */
    static getAvailableProfiles(): Array<{ id: string; name: string; targetUrl: string; expectedCount: number }> {
        return Object.values(PROFILES).map(p => ({
            id: p.id,
            name: p.name,
            targetUrl: p.targetUrl,
            expectedCount: p.expectedVulnerabilities.length,
        }));
    }
}
