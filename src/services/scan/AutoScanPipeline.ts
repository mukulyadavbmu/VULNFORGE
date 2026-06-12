/**
 * AutoScanPipeline — Fully autonomous scan execution.
 *
 * 8-Phase Attacker Workflow:
 *   1. Recon (crawl + JS analysis + fingerprint + subdomain + API patterns)
 *   2. Surface Mapping (endpoint grouping + auth mapping + sensitive detection)
 *   3. Hypothesis Generation (rule-based + AI hypothesis formation)
 *   4. Targeted Attack Execution (hypothesis-driven + baseline fallback)
 *   5. Exploit Verification (reproducibility check for high/critical findings)
 *   6. Attack Chain Modeling (multi-step path detection from findings)
 *   7. Risk Scoring (confidence + exploit reliability)
 *   8. Report (summary generation)
 *
 * Reports progress via ScanProgressService.
 * Persists status via ScanRepository.
 */
import { crawlTarget } from '../../crawler';
import { executeAction } from '../../detectionEngine';
import { getScanSession } from '../../scanOrchestrator';
import { ScanProgressService } from './ScanProgressService';
import { ScanRepository } from '../db/ScanRepository';
import { config } from '../../config';
import { logger } from '../../utils/logger';
import { AIAttackAction, AttackNode, ScanSession } from '../../types';
import { CheckpointService } from './CheckpointService';

// Recon Intelligence modules
import { JSAnalyzer, JSAnalysisResult } from '../recon/JSAnalyzer';
import { ServiceFingerprint, FingerprintResult } from '../recon/ServiceFingerprint';
import { SubdomainDiscovery, SubdomainResult } from '../recon/SubdomainDiscovery';
import { APIPatternAnalyzer, PatternAnalysisResult } from '../intelligence/APIPatternAnalyzer';
import { addAttackNode } from '../../scanOrchestrator';
import { maybeAddFinding } from '../../utils/scanUtils';

// Phase 2: Surface Modeling
import { AttackSurfaceModeler, SurfaceMap } from '../intelligence/AttackSurfaceModeler';

// Phase 3: Hypothesis Engine
import { HypothesisEngine } from '../intelligence/HypothesisEngine';

// Phase 5: Exploit Verification
import { ExploitVerifier } from '../intelligence/ExploitVerifier';
import { defaultExploitExecutor } from '../intelligence/DefaultExploitExecutor';
import { queues, isDistributedMode } from '../queue/QueueManager';

// Phase 6: Attack Path Engine
import { AttackPathEngine } from '../intelligence/AttackPathEngine';

// Phase 4b: Parameter Fuzzing
import { ParameterFuzzer } from '../fuzzing/ParameterFuzzer';

// Task 1: Stateful Attack Workflows
import { statefulEngine } from '../workflow/StatefulAttackEngine';

// Task 2: Login Flow Detection
import { LoginDetector } from '../recon/LoginDetector';

// Task 4: API Schema Inference
import { APISchemaInferer } from '../recon/APISchemaInferer';

// Task 6: Request Mutation Engine
import { RequestMutationEngine } from '../mutation/RequestMutationEngine';

const log = logger.child({ module: 'AutoScanPipeline' });

/** Baseline probes to run on every eligible endpoint — no AI needed */
const BASELINE_PROBES: AIAttackAction['actionType'][] = [
    'sqli_probe',
    'xss_probe',
    'id_tamper',
    'cors_probe',
    'csrf_probe',
];

/** Mandatory vulnerability category coverage across the scan. */
const CATEGORY_COVERAGE_PROBES: AIAttackAction['actionType'][] = [
    'sqli_probe',
    'xss_probe',
    'id_tamper',
    'csrf_probe',
    'jwt_analysis_probe',
    'file_upload_probe',
    'ssrf_probe',
    'rce_probe',
    'ssti_probe',
    'path_traversal_probe',
];

/** Hypothesis type to attack probe mapping */
const HYPOTHESIS_ATTACK_MAP: Record<string, AIAttackAction['actionType'][]> = {
    'IDOR': ['id_tamper', 'cross_role_access', 'repeat_as_guest'],
    'Injection': ['sqli_probe', 'xss_probe', 'ssti_probe', 'nosqli_probe'],
    'Auth': ['cross_role_access', 'repeat_as_guest', 'csrf_probe', 'cors_probe'],
    'SSRF': ['ssrf_probe', 'oast_probe'],
    'SensitiveAPI': ['config_probe', 'path_traversal_probe', 'cors_probe'],
    'FileUpload': ['file_upload_probe', 'path_traversal_probe'],
    'JWTWeakness': ['jwt_analysis_probe', 'token_replay_probe', 'auth_bypass_probe'],
    'CORSAbuse': ['cors_probe', 'csrf_probe'],
};

// ─── Recon Intelligence Result ──────────────────────────────────────────────

interface ReconIntelligence {
    jsAnalysis: JSAnalysisResult[];
    fingerprint: FingerprintResult | null;
    subdomains: SubdomainResult | null;
    apiPatterns: PatternAnalysisResult | null;
    techStack: string[];
}

/**
 * Start the autonomous scan pipeline.
 * Must be called asynchronously (never awaited from HTTP handler).
 */
export async function startPipeline(scanId: string): Promise<void> {
    log.info('Autonomous pipeline starting', { scanId });

    // Shared engine instances
    const hypothesisEngine = new HypothesisEngine();
    const attackPathEngine = new AttackPathEngine();
    const exploitVerifier = new ExploitVerifier(defaultExploitExecutor);
    const surfaceModeler = new AttackSurfaceModeler();
    const parameterFuzzer = new ParameterFuzzer();
    const loginDetector = new LoginDetector();
    const schemaInferer = new APISchemaInferer();
    const mutationEngine = new RequestMutationEngine();

    try {
        // ═══════════════════════════════════════════════════════════════════
        // PHASE 1: RECONNAISSANCE
        // ═══════════════════════════════════════════════════════════════════
        await ScanRepository.updateStatus(scanId, 'running');
        ScanProgressService.setPhase(scanId, 'Reconnaissance');
        ScanProgressService.setAction(scanId, 'Recon + endpoint discovery');
        ScanProgressService.addEvent(scanId, 'Scan started — beginning reconnaissance', 'recon');

        let session = await getScanSession(scanId);
        if (!session) {
            log.error('Session not found at pipeline start', { scanId });
            return;
        }

        ScanProgressService.addEvent(scanId, `Crawling target: ${session.targetUrl}`, 'recon');
        log.info('Phase 1: Crawl started', { scanId, target: session.targetUrl });

        if (isDistributedMode() && queues.crawlJobs) {
            const job = await queues.crawlJobs.add('crawl', { scanId });
            while (true) {
                const state = await job.getState();
                if (state === 'completed' || state === 'failed') break;
                await new Promise(r => setTimeout(r, 2000));
            }
        } else {
            await crawlTarget(session, 'guest', { maxPages: config.MAX_PAGES_PER_SCAN });
        }

        session = await getScanSession(scanId) as ScanSession;
        if (!session) { log.error('Session lost after crawl', { scanId }); return; }

        const initialNodes = Object.values(session.attackNodes);
        ScanProgressService.addEvent(scanId, `Crawl complete — ${initialNodes.length} endpoints discovered`, 'success');

        if (initialNodes.length === 0) {
            await ScanRepository.updateStatus(scanId, 'completed');
            ScanProgressService.setPhase(scanId, 'Completed');
            ScanProgressService.addEvent(scanId, 'No endpoints found — scan completed', 'warning');
            return;
        }

        // Phase 1b: Deep Recon Intelligence
        ScanProgressService.setAction(scanId, 'Running deep recon intelligence');
        ScanProgressService.addEvent(scanId, 'Starting deep recon: JS analysis, fingerprinting, API patterns', 'recon');

        const reconIntel = await runReconIntelligence(session, initialNodes);
        await processReconResults(session, scanId, reconIntel, initialNodes);

        // Phase 1b-ii: API Schema Inference
        try {
            ScanProgressService.setAction(scanId, 'Inferring API response schemas');
            const schemaResult = await schemaInferer.inferSchemas(session, initialNodes);
            if (schemaResult.endpointsWithSchema > 0) {
                ScanProgressService.addEvent(
                    scanId,
                    `Schema inference: ${schemaResult.endpointsWithSchema} schemas inferred from ${schemaResult.endpointsProbed} endpoints`,
                    'success',
                );
            }
        } catch (schemaError) {
            const msg = schemaError instanceof Error ? schemaError.message : 'Unknown';
            log.warn('Schema inference error', { scanId, error: msg });
        }

        // Reload session with newly added nodes
        session = await getScanSession(scanId) as ScanSession;
        if (!session) { log.error('Session lost after recon', { scanId }); return; }

        const allNodes = Object.values(session.attackNodes);
        ScanProgressService.addEvent(
            scanId,
            `Recon complete — ${allNodes.length} total endpoints`,
            'success',
        );

        // Save Checkpoint after Recon
        await CheckpointService.saveCheckpoint(scanId, 'recon', 1, [], session);

        // ── Phase 1c: Login Flow Detection ───────────────────────────────
        ScanProgressService.setAction(scanId, 'Authentication discovery');
        ScanProgressService.addEvent(scanId, 'Scanning for login forms and endpoints', 'recon');

        try {
            const loginResult = await loginDetector.detect(session, allNodes);
            if (loginResult.successfulLogins.length > 0) {
                ScanProgressService.addEvent(
                    scanId,
                    `Login detection: ${loginResult.formsDetected.length} forms, ${loginResult.successfulLogins.length} successful logins, ${loginResult.authContextsPopulated} auth contexts populated`,
                    'success',
                );
            } else if (loginResult.endpointsIdentified.length > 0) {
                ScanProgressService.addEvent(
                    scanId,
                    `Login detection: ${loginResult.endpointsIdentified.length} endpoints found, no default credentials worked`,
                    'info',
                );
            } else {
                ScanProgressService.addEvent(scanId, 'No login forms or endpoints detected', 'info');
            }
        } catch (loginError) {
            const msg = loginError instanceof Error ? loginError.message : 'Unknown';
            log.warn('Login detection error', { scanId, error: msg });
            ScanProgressService.addEvent(scanId, `Login detection error: ${msg.slice(0, 80)}`, 'warning');
        }

        // Reload session after login detection may have updated auth contexts
        session = await getScanSession(scanId) as ScanSession;
        if (!session) { log.error('Session lost after login detection', { scanId }); return; }

        // ── Initialize Stateful Workflow ─────────────────────────────────
        statefulEngine.initWorkflow(scanId);
        ScanProgressService.addEvent(scanId, 'Stateful workflow engine initialized', 'info');

        // ═══════════════════════════════════════════════════════════════════
        // PHASE 2: ATTACK SURFACE MAPPING
        // ═══════════════════════════════════════════════════════════════════
        ScanProgressService.setPhase(scanId, 'Surface Mapping');
        ScanProgressService.setAction(scanId, 'Building attack surface map');
        ScanProgressService.addEvent(scanId, 'Mapping endpoints, parameters, and auth roles', 'recon');

        const surfaceMap = surfaceModeler.model(allNodes);

        ScanProgressService.addEvent(
            scanId,
            `Surface map: ${surfaceMap.totalGroups} resource groups, ${surfaceMap.sensitiveEndpoints.length} sensitive endpoints, ${surfaceMap.totalParameters} parameters`,
            'success',
        );
        log.info('Phase 2: Surface mapping complete', {
            scanId,
            groups: surfaceMap.totalGroups,
            sensitiveEndpoints: surfaceMap.sensitiveEndpoints.length,
        });

        // ═══════════════════════════════════════════════════════════════════
        // PHASE 3: HYPOTHESIS GENERATION
        // ═══════════════════════════════════════════════════════════════════
        ScanProgressService.setPhase(scanId, 'Hypothesis');
        ScanProgressService.setAction(scanId, 'Generating attack hypotheses');
        ScanProgressService.addEvent(scanId, 'Forming hypotheses from attack surface analysis', 'recon');

        const hypotheses = hypothesisEngine.detectHypotheses(scanId, allNodes, session.findings);

        ScanProgressService.addEvent(
            scanId,
            `${hypotheses.length} attack hypotheses generated`,
            'success',
        );

        // Report hypothesis types
        const hypothesisSummary = new Map<string, number>();
        for (const h of hypotheses) {
            hypothesisSummary.set(h.type, (hypothesisSummary.get(h.type) || 0) + 1);
        }
        for (const [type, count] of hypothesisSummary) {
            ScanProgressService.addEvent(scanId, `Hypothesis: ${count}× ${type} (avg confidence: ${Math.round(hypotheses.filter(h => h.type === type).reduce((s, h) => s + h.confidence, 0) / count)
                }%)`, 'info');
        }

        // Persist hypotheses
        try {
            await hypothesisEngine.saveAllHypotheses(scanId);
        } catch (e) {
            log.warn('Failed to persist hypotheses', { error: e });
        }

        log.info('Phase 3: Hypothesis generation complete', {
            scanId,
            hypothesisCount: hypotheses.length,
        });

        // ═══════════════════════════════════════════════════════════════════
        // PHASE 4: TARGETED ATTACK EXECUTION
        // ═══════════════════════════════════════════════════════════════════
        ScanProgressService.setPhase(scanId, 'Attacking');
        ScanProgressService.setAction(scanId, 'Generating targeted attack actions');
        ScanProgressService.addEvent(scanId, 'Starting hypothesis-driven attack execution', 'attack');

        // Build hypothesis-driven + fallback baseline actions
        const actions = buildTargetedActions(allNodes, hypotheses, surfaceMap);
        const totalActions = actions.length;

        ScanProgressService.addEvent(scanId, `${totalActions} targeted attack actions generated`, 'info');
        log.info('Phase 4: Executing targeted attacks', { scanId, totalActions });

        session.actions.push(...actions);
        await ScanRepository.addActionLog(scanId, actions);

        let executedCount = 0;
        let findingCount = 0;
        let fuzzAttempts = 0;
        let fuzzedParameters = 0;
        let mutationAttempts = 0;
        const attackedNodeIds = new Set<string>();

        for (let i = 0; i < actions.length; i++) {
            const action = actions[i];
            const targetNode = session.attackNodes[action.targetNodeId];
            if (!targetNode) continue;

            const label = action.actionType;
            const shortUrl = shortenUrl(targetNode.url);
            ScanProgressService.setAction(scanId, `${label} on ${shortUrl} (${i + 1}/${totalActions})`);

            try {
                attackedNodeIds.add(action.targetNodeId);
                const findingsBefore = session.findings.length;
                
                if (isDistributedMode() && queues.attackJobs) {
                    const job = await queues.attackJobs.add('attack', { scanId, action });
                    while (true) {
                        const state = await job.getState();
                        if (state === 'completed' || state === 'failed') break;
                        await new Promise(r => setTimeout(r, 1000));
                    }
                    // reload session to get findings added by worker
                    session = await getScanSession(scanId) as ScanSession;
                } else {
                    await executeAction(session, action);
                }
                
                executedCount++;

                const findingsAfter = session.findings.length;
                if (findingsAfter > findingsBefore) {
                    const newCount = findingsAfter - findingsBefore;
                    findingCount += newCount;
                    ScanProgressService.addEvent(scanId, `Vulnerability found: ${label} on ${shortUrl}`, 'success');
                }

                // Checkpoint every 20 actions
                if (i > 0 && i % 20 === 0) {
                    await CheckpointService.saveCheckpoint(scanId, 'attack', i, Array.from(attackedNodeIds), session);
                }
            } catch (error) {
                const msg = error instanceof Error ? error.message : 'Unknown error';
                log.warn('Attack execution error', { scanId, action: label, error: msg });
                ScanProgressService.addEvent(scanId, `Error during ${label}: ${msg.slice(0, 80)}`, 'warning');
            }
        }

        ScanProgressService.addEvent(
            scanId,
            `Attack phase complete: ${executedCount}/${totalActions} executed, ${findingCount} findings`,
            'info',
        );

        // ── Phase 4b: Parameter Fuzzing ──────────────────────────────────────
        ScanProgressService.setAction(scanId, 'Running parameter fuzzing');
        ScanProgressService.addEvent(scanId, 'Starting automated parameter fuzzing', 'attack');

        try {
            const fuzzResult = await parameterFuzzer.fuzz(session, allNodes);
            fuzzAttempts = fuzzResult.totalAttempts;
            fuzzedParameters = fuzzResult.parametersFuzzed;
            if (fuzzResult.findingsGenerated > 0) {
                ScanProgressService.addEvent(
                    scanId,
                    `Fuzzing: ${fuzzResult.findingsGenerated} findings from ${fuzzResult.totalAttempts} attempts on ${fuzzResult.endpointsProcessed} endpoints (${fuzzResult.parametersFuzzed} parameters fuzzed)`,
                    'success',
                );
            } else {
                ScanProgressService.addEvent(
                    scanId,
                    `Fuzzing: ${fuzzResult.totalAttempts} attempts on ${fuzzResult.endpointsProcessed} endpoints (${fuzzResult.parametersFuzzed} parameters fuzzed) — no issues found`,
                    'info',
                );
            }
        } catch (fuzzError) {
            const msg = fuzzError instanceof Error ? fuzzError.message : 'Unknown';
            log.warn('Parameter fuzzing error', { scanId, error: msg });
            ScanProgressService.addEvent(scanId, `Fuzzing error: ${msg.slice(0, 80)}`, 'warning');
        }

        // ── Phase 4c: Request Mutations ──────────────────────────────────
        ScanProgressService.setAction(scanId, 'Testing request mutations');
        ScanProgressService.addEvent(scanId, 'Starting request mutation testing (header injection, method switching, encoding)', 'attack');

        try {
            let mutationAnomalies = 0;
            const mutationTargets = allNodes
                .filter(n => n.type === 'api')
                .slice(0, 10);

            for (const target of mutationTargets) {
                mutationAttempts++;
                const anomalies = await mutationEngine.testAllMutations(session, {
                    url: target.url,
                    method: target.method ?? 'GET',
                    headers: {},
                });

                for (const anomaly of anomalies) {
                    mutationAnomalies++;
                    await maybeAddFinding(session, {
                        type: 'anomaly',
                        url: anomaly.mutation.url,
                        severity: anomaly.response.status === 200 ? 'high' : 'medium',
                        evidence: `Request mutation anomaly: ${anomaly.anomalyReason ?? anomaly.mutation.mutationDescription}`,
                    });
                }
            }

            if (mutationAnomalies > 0) {
                ScanProgressService.addEvent(
                    scanId,
                    `Mutations: ${mutationAnomalies} anomalies from ${mutationTargets.length} endpoints`,
                    'success',
                );
            } else {
                ScanProgressService.addEvent(
                    scanId,
                    `Mutations: ${mutationTargets.length} endpoints tested — no anomalies`,
                    'info',
                );
            }
        } catch (mutationError) {
            const msg = mutationError instanceof Error ? mutationError.message : 'Unknown';
            log.warn('Mutation testing error', { scanId, error: msg });
            ScanProgressService.addEvent(scanId, `Mutation error: ${msg.slice(0, 80)}`, 'warning');
        }

        // Reload session with new findings
        session = await getScanSession(scanId) as ScanSession;
        if (!session) { log.error('Session lost after attacks', { scanId }); return; }

        // ═══════════════════════════════════════════════════════════════════
        // PHASE 5: EXPLOIT VERIFICATION
        // ═══════════════════════════════════════════════════════════════════
        ScanProgressService.setPhase(scanId, 'Verification');
        ScanProgressService.setAction(scanId, 'Verifying exploit reproducibility');

        const highCritFindings = session.findings.filter(
            f => f.severity === 'high' || f.severity === 'critical',
        );

        if (highCritFindings.length > 0) {
            ScanProgressService.addEvent(
                scanId,
                `Verifying ${highCritFindings.length} high/critical findings (3x replay each)`,
                'info',
            );

            let confirmedCount = 0;
            let unconfirmedCount = 0;

            for (const finding of highCritFindings) {
                try {
                    let result;
                    if (isDistributedMode() && queues.verifyJobs) {
                        const job = await queues.verifyJobs.add('verify', {
                            scanId, findingId: finding.id,
                            traceSnapshot: {
                                endpointId: finding.url,
                                attackType: finding.type,
                                payload: finding.evidence.slice(0, 500),
                                attempts: 3,
                            },
                            frozenAuth: {} // In reality, we'd freeze current session auth
                        });
                        while (true) {
                            const state = await job.getState();
                            if (state === 'completed' || state === 'failed') break;
                            await new Promise(r => setTimeout(r, 1000));
                        }
                        session = await getScanSession(scanId) as ScanSession;
                        const updatedFinding = session.findings.find(f => f.id === finding.id);
                        const isSuccess = updatedFinding?.replayStatus === 'success';
                        result = { 
                            reproducible: isSuccess,
                            stable: isSuccess,
                            successRate: isSuccess ? 100 : 0,
                            successCount: isSuccess ? 3 : 0,
                            totalAttempts: 3,
                            payload: finding.evidence.slice(0, 500),
                            confidence: 0,
                            reliabilityTier: updatedFinding?.reliabilityTier || 'probable'
                        };
                    } else {
                        result = await exploitVerifier.verify({
                            endpointId: finding.url,
                            attackType: finding.type,
                            payload: finding.evidence.slice(0, 500),
                            attempts: 3,
                        });
                        
                        // Update locally
                        finding.reliabilityTier = result.reliabilityTier;
                        finding.replayStatus = result.reproducible ? 'success' : 'failed';
                        finding.verificationHistory = finding.verificationHistory || [];
                        finding.verificationHistory.push({
                            timestamp: Date.now(),
                            result: result.reproducible ? 'success' : 'failure',
                            diffScore: result.confidence
                        });
                    }

                    if (result.reproducible && result.successCount >= 2) {
                        confirmedCount++;
                        // Upgrade classification to confirmed_exploit
                        finding.classification = 'confirmed_exploit';
                        // Boost confidence for reproducible findings
                        if (!finding.metrics) finding.metrics = {};
                        finding.metrics.confidence = Math.min(
                            (finding.metrics.confidence || 50) + result.confidence * 0.3,
                            100,
                        );
                        // Store reliability data in metrics
                        (finding.metrics as Record<string, unknown>).reliabilityScore = result.successRate;
                        (finding.metrics as Record<string, unknown>).reproducibilityPayload = result.payload.slice(0, 200);
                        (finding.metrics as Record<string, unknown>).successCount = result.successCount;
                        (finding.metrics as Record<string, unknown>).totalAttempts = result.totalAttempts;

                        // Persist classification update
                        try {
                            await ScanRepository.updateFindingClassification(finding.id, 'confirmed_exploit');
                        } catch {
                            // Best-effort DB update
                        }
                    } else {
                        unconfirmedCount++;
                        // Reduce confidence for non-reproducible findings
                        if (finding.metrics) {
                            finding.metrics.confidence = (finding.metrics.confidence || 50) * 0.6;
                        }
                    }
                } catch (error) {
                    log.debug('Exploit verification failed for finding', {
                        findingId: finding.id,
                        error: error instanceof Error ? error.message : 'Unknown',
                    });
                }
            }

            ScanProgressService.addEvent(
                scanId,
                `Verification: ${confirmedCount} confirmed, ${unconfirmedCount} unconfirmed`,
                confirmedCount > 0 ? 'success' : 'info',
            );
        } else {
            ScanProgressService.addEvent(scanId, 'No high/critical findings to verify', 'info');
        }

        // ═══════════════════════════════════════════════════════════════════
        // PHASE 6: ATTACK CHAIN MODELING
        // ═══════════════════════════════════════════════════════════════════
        ScanProgressService.setPhase(scanId, 'Chain Analysis');
        ScanProgressService.setAction(scanId, 'Detecting attack chains');

        if (session.findings.length >= 1) {
            ScanProgressService.addEvent(scanId, 'Analyzing findings for multi-step attack paths', 'info');

            const attackPaths = attackPathEngine.detectPaths(scanId, session.findings);

            if (attackPaths.length > 0) {
                ScanProgressService.addEvent(
                    scanId,
                    `${attackPaths.length} attack chains detected`,
                    'success',
                );
                for (const path of attackPaths.slice(0, 3)) {
                    const transitions = path.privilegeTransitions.join(' → ');
                    ScanProgressService.addEvent(
                        scanId,
                        `Chain: ${transitions} (confidence: ${path.confidence}%)`,
                        'info',
                    );
                }

                // Persist chains to DB
                try {
                    await attackPathEngine.saveAllPaths(scanId);
                } catch (e) {
                    log.warn('Failed to persist attack chains', { error: e });
                }
            } else {
                ScanProgressService.addEvent(scanId, 'No multi-step chains detected', 'info');
            }
        } else {
            ScanProgressService.addEvent(scanId, 'No findings for chain analysis', 'info');
        }

        // ═══════════════════════════════════════════════════════════════════
        // PHASE 7: RISK SCORING (already done inline via ConfidenceScorer)
        // ═══════════════════════════════════════════════════════════════════
        ScanProgressService.setPhase(scanId, 'Risk Scoring');
        ScanProgressService.setAction(scanId, 'Calculating final risk scores');
        ScanProgressService.addEvent(scanId, 'Final risk scoring complete', 'info');

        // ═══════════════════════════════════════════════════════════════════
        // PHASE 8: COMPLETE
        // ═══════════════════════════════════════════════════════════════════
        const endpointsDiscovered = allNodes.length;
        const endpointsAttacked = attackedNodeIds.size;
        const confirmedVulnerabilities = session.findings.filter(f => f.classification === 'confirmed_exploit').length;
        const potentialVulnerabilities = Math.max(session.findings.length - confirmedVulnerabilities, 0);
        const attackAttempts = executedCount + fuzzAttempts + mutationAttempts;
        const coverageScore = endpointsDiscovered > 0
            ? Math.round((endpointsAttacked / endpointsDiscovered) * 100)
            : 0;

        ScanProgressService.addEvent(scanId, 'SCAN COVERAGE', 'info');
        ScanProgressService.addEvent(scanId, `Endpoints discovered: ${endpointsDiscovered}`, 'info');
        ScanProgressService.addEvent(scanId, `Endpoints attacked: ${endpointsAttacked}`, 'info');
        ScanProgressService.addEvent(scanId, `Parameters fuzzed: ${fuzzedParameters}`, 'info');
        ScanProgressService.addEvent(scanId, `Attack attempts: ${attackAttempts}`, 'info');
        ScanProgressService.addEvent(scanId, `Confirmed vulnerabilities: ${confirmedVulnerabilities}`, 'info');
        ScanProgressService.addEvent(scanId, `Potential vulnerabilities: ${potentialVulnerabilities}`, 'info');
        ScanProgressService.addEvent(scanId, `Coverage score: ${coverageScore}%`, coverageScore >= 70 ? 'success' : 'warning');

        await ScanRepository.updateStatus(scanId, 'completed');
        ScanProgressService.setPhase(scanId, 'Completed');
        ScanProgressService.setAction(scanId, 'Scan finished');
        ScanProgressService.addEvent(
            scanId,
            `Scan complete — ${executedCount} attacks, ${session.findings.length} findings, ${hypotheses.length} hypotheses`,
            'success',
        );

        log.info('Autonomous pipeline finished', {
            scanId,
            executed: executedCount,
            findings: session.findings.length,
            hypotheses: hypotheses.length,
            coverageScore,
            endpointsDiscovered,
            endpointsAttacked,
            fuzzedParameters,
        });

    } catch (error) {
        const msg = error instanceof Error ? error.message : 'Unknown error';
        log.error('Pipeline fatal error', {
            scanId,
            error: msg,
            stack: error instanceof Error ? error.stack : undefined,
            code: (error as any)?.code,
        });

        ScanProgressService.addEvent(scanId, `Pipeline error: ${msg.slice(0, 100)}`, 'warning');
        ScanProgressService.setPhase(scanId, 'Failed'); // HIGH-4: was incorrectly 'Completed'

        try {
            await ScanRepository.updateStatus(scanId, 'failed');
        } catch {
            // Best-effort
        }
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// RECON INTELLIGENCE
// ═════════════════════════════════════════════════════════════════════════════

async function runReconIntelligence(
    session: ScanSession,
    nodes: AttackNode[],
): Promise<ReconIntelligence> {
    const result: ReconIntelligence = {
        jsAnalysis: [],
        fingerprint: null,
        subdomains: null,
        apiPatterns: null,
        techStack: [],
    };

    const [jsResults, fpResult, subResult, patternResult] = await Promise.allSettled([
        runJSAnalysis(session, nodes),
        runServiceFingerprint(session),
        runSubdomainDiscovery(session),
        runAPIPatternAnalysis(nodes),
    ]);

    if (jsResults.status === 'fulfilled') result.jsAnalysis = jsResults.value;
    else log.warn('JS analysis failed', { error: jsResults.reason });

    if (fpResult.status === 'fulfilled') {
        result.fingerprint = fpResult.value;
        if (fpResult.value.detectedServer) result.techStack.push(fpResult.value.detectedServer);
    } else log.warn('Fingerprinting failed', { error: fpResult.reason });

    if (subResult.status === 'fulfilled') result.subdomains = subResult.value;
    else log.warn('Subdomain discovery failed', { error: subResult.reason });

    if (patternResult.status === 'fulfilled') result.apiPatterns = patternResult.value;
    else log.warn('API pattern analysis failed', { error: patternResult.reason });

    return result;
}

async function processReconResults(
    session: ScanSession,
    scanId: string,
    reconIntel: ReconIntelligence,
    initialNodes: AttackNode[],
): Promise<void> {
    let jsEndpointsAdded = 0;

    // Register JS-discovered endpoints and hidden APIs
    for (const jsResult of reconIntel.jsAnalysis) {
        for (const ep of jsResult.endpoints) {
            try {
                const fullUrl = resolveEndpointUrl(session.targetUrl, ep.path);
                const nodeId = `guest:api:${fullUrl}`;
                if (!session.attackNodes[nodeId]) {
                    await addAttackNode(session, {
                        id: nodeId, url: fullUrl, method: ep.method,
                        type: 'api', authContext: 'guest',
                        params: [], tags: ['js_discovered', 'api'],
                    });
                    jsEndpointsAdded++;
                }
            } catch { /* skip invalid URLs */ }
        }

        for (const hidden of jsResult.hiddenApis) {
            try {
                const fullUrl = resolveEndpointUrl(session.targetUrl, hidden.path);
                const nodeId = `guest:api:${fullUrl}`;
                if (!session.attackNodes[nodeId]) {
                    await addAttackNode(session, {
                        id: nodeId, url: fullUrl, type: 'api', authContext: 'guest',
                        params: [], tags: ['hidden_api', 'js_discovered', 'sensitive_api'],
                    });
                    jsEndpointsAdded++;
                }
            } catch { /* skip */ }
        }

        // Create findings for secrets
        for (const secret of jsResult.secrets) {
            await maybeAddFinding(session, {
                type: 'info', url: jsResult.sourceUrl || session.targetUrl,
                severity: secret.severity,
                evidence: `Secret detected in JavaScript: ${secret.type} — ${secret.value}`,
                aiExplanation: `A ${secret.type} was found exposed in client-side JavaScript.`,
            });
        }
    }

    if (jsEndpointsAdded > 0) {
        ScanProgressService.addEvent(scanId, `JS analysis discovered ${jsEndpointsAdded} additional endpoints`, 'success');
    }

    const totalSecrets = reconIntel.jsAnalysis.reduce((sum, r) => sum + r.secrets.length, 0);
    if (totalSecrets > 0) {
        ScanProgressService.addEvent(scanId, `${totalSecrets} secrets/tokens detected in JavaScript`, 'success');
    }

    if (reconIntel.fingerprint) {
        const fp = reconIntel.fingerprint;
        const info = [
            fp.detectedServer ? `Server: ${fp.detectedServer}` : null,
            fp.detectedTLS ? `TLS: ${fp.detectedTLS}` : null,
            fp.openPorts.length > 0 ? `Ports: ${fp.openPorts.join(', ')}` : null,
        ].filter(Boolean).join(', ');
        if (info) ScanProgressService.addEvent(scanId, `Fingerprint: ${info}`, 'recon');
    }

    if (reconIntel.techStack.length > 0) {
        ScanProgressService.addEvent(scanId, `Tech stack: ${reconIntel.techStack.join(', ')}`, 'recon');
    }

    if (reconIntel.subdomains && reconIntel.subdomains.totalFound > 0) {
        ScanProgressService.addEvent(scanId,
            `Subdomains: ${reconIntel.subdomains.totalFound} found, ${reconIntel.subdomains.totalResolved} resolved`, 'recon');
    }

    if (reconIntel.apiPatterns && reconIntel.apiPatterns.highRiskGroups > 0) {
        ScanProgressService.addEvent(scanId,
            `API patterns: ${reconIntel.apiPatterns.highRiskGroups} high-risk groups, ${reconIntel.apiPatterns.sequentialPatterns.length} IDOR patterns`, 'success');

        for (const sp of reconIntel.apiPatterns.sequentialPatterns) {
            if (sp.idorRisk === 'high' || sp.idorRisk === 'critical') {
                for (const node of initialNodes) {
                    if (node.url.includes(sp.basePattern) && !node.tags.includes('idor_susceptible')) {
                        node.tags.push('idor_susceptible');
                    }
                }
            }
        }
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// INDIVIDUAL RECON TASKS
// ═════════════════════════════════════════════════════════════════════════════

async function runJSAnalysis(session: ScanSession, nodes: AttackNode[]): Promise<JSAnalysisResult[]> {
    const jsAnalyzer = new JSAnalyzer();
    const results: JSAnalysisResult[] = [];
    const targetOrigin = new URL(session.targetUrl).origin;
    const analyzedUrls = new Set<string>();

    // Fetch and analyze main page to find script sources
    try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 5000);
        const response = await fetch(session.targetUrl, { signal: controller.signal });
        clearTimeout(timeout);

        if (response.ok) {
            const html = await response.text();

            // Extract and analyze linked scripts
            const srcRegex = /<script[^>]+src=["']([^"']+\.js[^"']*?)["']/gi;
            let match: RegExpExecArray | null;
            while ((match = srcRegex.exec(html)) !== null) {
                try {
                    const scriptUrl = new URL(match[1], targetOrigin).toString();
                    if (scriptUrl.startsWith(targetOrigin) && !analyzedUrls.has(scriptUrl) && analyzedUrls.size < 8) {
                        analyzedUrls.add(scriptUrl);
                        const analysis = await fetchAndAnalyzeJS(jsAnalyzer, scriptUrl);
                        if (analysis) results.push(analysis);
                    }
                } catch { /* skip */ }
            }

            // Analyze inline scripts
            const scriptRegex = /<script[^>]*>([\s\S]*?)<\/script>/gi;
            let inlineContent = '';
            while ((match = scriptRegex.exec(html)) !== null) {
                if (match[1] && match[1].trim().length > 20) inlineContent += match[1] + '\n';
            }
            if (inlineContent.length > 50) {
                const analysis = jsAnalyzer.analyze(inlineContent, session.targetUrl);
                if (analysis.totalFindings > 0) results.push(analysis);
            }
        }
    } catch (e) {
        log.debug('JS extraction failed', { error: e instanceof Error ? e.message : 'Unknown' });
    }

    return results;
}

async function fetchAndAnalyzeJS(analyzer: JSAnalyzer, url: string): Promise<JSAnalysisResult | null> {
    try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 5000);
        const response = await fetch(url, {
            signal: controller.signal,
            headers: { 'Accept': 'application/javascript' },
        });
        clearTimeout(timeout);

        if (!response.ok) return null;
        const text = await response.text();
        if (text.length < 50 || text.length > 5 * 1024 * 1024) return null;

        const analysis = analyzer.analyze(text, url);
        return analysis.totalFindings > 0 ? analysis : null;
    } catch {
        return null;
    }
}

async function runServiceFingerprint(session: ScanSession): Promise<FingerprintResult> {
    const fp = new ServiceFingerprint();
    return fp.fingerprint(new URL(session.targetUrl).hostname);
}

async function runSubdomainDiscovery(session: ScanSession): Promise<SubdomainResult> {
    const discovery = new SubdomainDiscovery();
    const host = new URL(session.targetUrl).hostname;
    const parts = host.split('.');
    const domain = parts.length > 2 ? parts.slice(-2).join('.') : host;
    return discovery.discover(domain);
}

async function runAPIPatternAnalysis(nodes: AttackNode[]): Promise<PatternAnalysisResult> {
    const analyzer = new APIPatternAnalyzer();
    return analyzer.analyze(nodes.map(n => ({ url: n.url, method: n.method })));
}

// ═════════════════════════════════════════════════════════════════════════════
// TARGETED ACTION BUILDER (Phase 4)
// ═════════════════════════════════════════════════════════════════════════════

interface HypothesisLike {
    type: string;
    confidence: number;
    relatedEndpoints: string[];
}

function buildTargetedActions(
    nodes: AttackNode[],
    hypotheses: HypothesisLike[],
    surfaceMap: SurfaceMap,
): AIAttackAction[] {
    const actions: AIAttackAction[] = [];
    let counter = 0;
    const coveredNodeIds = new Set<string>();

    // 1. Hypothesis-driven actions (highest priority)
    for (const hypothesis of hypotheses.sort((a, b) => b.confidence - a.confidence)) {
        const attackTypes = HYPOTHESIS_ATTACK_MAP[hypothesis.type];
        if (!attackTypes) continue;

        for (const endpointId of hypothesis.relatedEndpoints) {
            const node = nodes.find(n => n.id === endpointId);
            if (!node) continue;

            for (const probe of attackTypes) {
                // Skip id_tamper if no numeric ID in URL
                if (probe === 'id_tamper' && !/\/\d+\/?$/.test(node.url)) continue;

                counter++;
                actions.push({
                    id: `hyp-${counter}-${Date.now().toString(36)}`,
                    targetNodeId: node.id,
                    actionType: probe,
                    riskScore: Math.round(hypothesis.confidence),
                    explanation: `Hypothesis-driven ${probe}: ${hypothesis.type} hypothesis (confidence: ${hypothesis.confidence}%)`,
                });
                coveredNodeIds.add(node.id);
            }
        }
    }

    // 2. Sensitive endpoint actions (high priority)
    for (const se of surfaceMap.sensitiveEndpoints) {
        if (coveredNodeIds.has(se.nodeId)) continue;
        const node = nodes.find(n => n.id === se.nodeId);
        if (!node) continue;

        for (const probe of BASELINE_PROBES) {
            if (probe === 'id_tamper' && !/\/\d+\/?$/.test(node.url)) continue;
            counter++;
            actions.push({
                id: `sens-${counter}-${Date.now().toString(36)}`,
                targetNodeId: node.id,
                actionType: probe,
                riskScore: se.level === 'critical' ? 80 : se.level === 'high' ? 65 : 50,
                explanation: `Sensitive endpoint ${probe}: ${se.reasons[0]}`,
            });
        }
        coveredNodeIds.add(se.nodeId);
    }

    // 3. Baseline fallback for uncovered endpoints (ensure at least one attack per endpoint)
    const prioritized = prioritizeNodes(nodes.filter(n => !coveredNodeIds.has(n.id)));
    const fallbackTargets = prioritized;

    for (const target of fallbackTargets) {
        const probe = chooseProbeForNode(target);
        if (probe === 'id_tamper' && !/\/\d+\/?$/.test(target.url)) {
            counter++;
            actions.push({
                id: `baseline-${counter}-${Date.now().toString(36)}`,
                targetNodeId: target.id,
                actionType: 'sqli_probe',
                riskScore: 40,
                explanation: `Baseline sqli_probe on ${shortenUrl(target.url)}`,
            });
        } else {
            counter++;
            actions.push({
                id: `baseline-${counter}-${Date.now().toString(36)}`,
                targetNodeId: target.id,
                actionType: probe,
                riskScore: 40,
                explanation: `Baseline ${probe} on ${shortenUrl(target.url)}`,
            });
        }
    }

    // 4. Force broad category coverage across at least one endpoint each.
    const seenCoverageType = new Set(actions.map(a => a.actionType));
    const rankedNodes = prioritizeNodes(nodes);
    for (const probe of CATEGORY_COVERAGE_PROBES) {
        if (seenCoverageType.has(probe)) continue;
        const candidate = rankedNodes.find(n => isProbeApplicable(probe, n));
        if (!candidate) continue;
        counter++;
        actions.push({
            id: `coverage-${counter}-${Date.now().toString(36)}`,
            targetNodeId: candidate.id,
            actionType: probe,
            riskScore: 45,
            explanation: `Category coverage ${probe} on ${shortenUrl(candidate.url)}`,
        });
    }

    // Cap total actions to prevent excessive runtime
    return actions.slice(0, 260);
}

function prioritizeNodes(nodes: AttackNode[]): AttackNode[] {
    const seenIds = new Set<string>();
    const result: AttackNode[] = [];

    const groups = [
        nodes.filter(n => n.tags.includes('idor_susceptible')),
        nodes.filter(n => n.tags.includes('hidden_api')),
        nodes.filter(n => n.tags.includes('sensitive_path') || n.tags.includes('sensitive_api')),
        nodes.filter(n => n.params.length > 0),
        nodes.filter(n => n.type === 'api'),
        nodes,
    ];

    for (const group of groups) {
        for (const node of group) {
            if (!seenIds.has(node.id)) {
                seenIds.add(node.id);
                result.push(node);
            }
        }
    }

    return result;
}

// ═════════════════════════════════════════════════════════════════════════════
// HELPERS
// ═════════════════════════════════════════════════════════════════════════════

function shortenUrl(url: string): string {
    try {
        const u = new URL(url);
        const path = u.pathname + u.search;
        return path.length > 50 ? path.slice(0, 47) + '...' : path;
    } catch {
        return url.slice(0, 50);
    }
}

function resolveEndpointUrl(baseUrl: string, path: string): string {
    if (path.startsWith('http://') || path.startsWith('https://')) return path;
    const origin = new URL(baseUrl).origin;
    return `${origin}${path.startsWith('/') ? '' : '/'}${path}`;
}

function chooseProbeForNode(node: AttackNode): AIAttackAction['actionType'] {
    const url = node.url.toLowerCase();
    const tags = new Set(node.tags.map(t => t.toLowerCase()));

    if (/graphql/.test(url) || tags.has('graphql')) return 'graphql_probe';
    if (/upload|file|media|document/.test(url) || tags.has('upload_surface')) return 'file_upload_probe';
    if (/admin|internal|config|manage/.test(url) || tags.has('sensitive_api')) return 'auth_bypass_probe';
    if (/callback|redirect|proxy|url=/.test(url)) return 'ssrf_probe';
    if (/template|render|view/.test(url)) return 'ssti_probe';
    if (/path|download|open|file=/.test(url)) return 'path_traversal_probe';
    if (/\/(\d+)(\/|$)/.test(url)) return 'id_tamper';
    if (node.params.length > 0) return 'sqli_probe';
    return 'xss_probe';
}

function isProbeApplicable(probe: AIAttackAction['actionType'], node: AttackNode): boolean {
    if (probe === 'id_tamper') return /\/(\d+)(\/|$)/.test(node.url);
    if (probe === 'file_upload_probe') return /upload|file|media|document/i.test(node.url) || node.tags.includes('upload_surface');
    if (probe === 'jwt_analysis_probe') return /auth|token|session|oauth/i.test(node.url) || node.tags.includes('auth_related');
    if (probe === 'ssrf_probe') return /callback|redirect|proxy|url=|webhook/i.test(node.url);
    if (probe === 'path_traversal_probe') return /file|path|download|open/i.test(node.url);
    return true;
}
