import dotenv from 'dotenv';
dotenv.config();

import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import {
  createScanSessionAsync,
  getScanSession,
  listScanSessions,
  runPlanningStep,
  updateAuthContext
} from './scanOrchestrator';
import { crawlTarget } from './crawler';
import { executeAction } from './detectionEngine';
import { startPipeline } from './services/scan/AutoScanPipeline';
import { config } from './config';
import { logger } from './utils/logger';
import { isValidTarget } from './utils/security';
import { OASTService } from './services/oast/OASTService';
import { ScanProgressService } from './services/scan/ScanProgressService';
import { generateSummary } from './services/scan/ScanSummaryService';
import { AttackGraphService } from './services/intelligence/AttackGraphService';
import { getExploitableIssues } from './services/scan/ExploitableIssuesService';
import { statefulEngine } from './services/workflow/StatefulAttackEngine';
import { WorkerRegistry } from './workers/WorkerRegistry';
import { ScanLifecycleService } from './services/scan/ScanLifecycleService';
import { getQueueHealth, isDistributedMode } from './services/queue/QueueManager';
import { CheckpointService } from './services/scan/CheckpointService';
import { AuthService } from './services/saas/AuthService';
import { OrgService } from './services/saas/OrgService';
import { requireAuth, requireScanAccess, requireOrgRole, AuthenticatedRequest } from './middleware/auth';
const app = express();
app.use(express.json());

app.use(
  cors({
    origin: config.FRONTEND_ORIGIN,
  })
);

// Request logging middleware
app.use((req: Request, res: Response, next: NextFunction) => {
  logger.debug(`${req.method} ${req.url}`);
  next();
});

// Disable caching for scan endpoints
app.use((req: Request, res: Response, next: NextFunction) => {
  if (req.url.includes('/scan/') || req.url.includes('/oast/')) {
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0');
    res.set('Pragma', 'no-cache');
    res.set('Expires', '0');
  }
  next();
});

// ── Health Endpoints (Production Monitoring) ──
app.get('/health', async (_req, res) => {
  try {
    // Attempt to verify DB connectivity
    const { PrismaClient } = await import('@prisma/client');
    const prisma = new PrismaClient();
    await prisma.$queryRaw`SELECT 1`;
    await prisma.$disconnect();
    
    res.status(200).json({ status: 'ok', database: 'connected', version: '1.0.0' });
  } catch (err: any) {
    logger.error('Health check failed', { error: err.message });
    res.status(503).json({ status: 'error', database: 'disconnected', error: err.message });
  }
});

app.get('/healthz', (_req, res) => res.status(200).send('OK'));

// OAST Callback Routes (must be before auth middleware - no auth required)
app.post('/callback/:token', (req, res) => {
  const { token } = req.params;
  OASTService.recordInteraction(token, req.ip || 'unknown', req.body);
  res.status(200).send('OK');
});

app.get('/callback/:token', (req, res) => {
  const { token } = req.params;
  OASTService.recordInteraction(token, req.ip || 'unknown', req.query);
  res.status(200).send('OK');
});

// ── SaaS Auth & Org Routes (Public) ──
app.post('/auth/register', async (req, res) => {
  try {
    const { email, password, name } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
    const user = await AuthService.registerUser(email, password, name);
    res.status(201).json({ message: 'User registered', userId: user.id });
  } catch (err: any) {
    res.status(400).json({ error: err.message });
  }
});

app.post('/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const result = await AuthService.login(email, password);
    res.json(result);
  } catch (err: any) {
    res.status(401).json({ error: err.message });
  }
});

// Legacy / Fallback Hybrid Auth Middleware (applied to routes below)
app.use((req: Request, res: Response, next: NextFunction) => {
  // If API Key provided, allow it for backward compatibility / bot automation
  const provided = req.header('x-vulnforge-api-key');
  if (provided && provided === config.VULNFORGE_API_KEY) {
    return next();
  }
  // Otherwise enforce SaaS JWT Auth
  return requireAuth(req as AuthenticatedRequest, res, next);
});

app.post('/scan', async (req: Request, res: Response) => {
  const { targetUrl } = req.body as { targetUrl?: string };
  if (!targetUrl) {
    return res.status(400).json({ error: 'targetUrl is required' });
  }

  const validation = isValidTarget(targetUrl);
  if (!validation.valid) {
    return res.status(400).json({ error: validation.error });
  }

  // Extract orgId from user token (default to first org if not explicitly requested)
  const authReq = req as AuthenticatedRequest;
  const orgId = authReq.user?.memberships?.[0]?.orgId;
  const userId = authReq.user?.id;

  logger.info(`Starting new scan for target: ${targetUrl}`);
  try {
    const session = await createScanSessionAsync(targetUrl, orgId, userId);

    // Phase 3: Enqueue for distributed execution
    await ScanLifecycleService.enqueueScan(session.id);

    res.status(201).json({ scanId: session.id });
  } catch (err) {
    logger.error('Failed to create scan', { error: err });
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.get('/scan', async (_req, res) => {
  try {
    const sessions = await listScanSessions();
    const summary = sessions.map((s) => ({
      id: s.id,
      targetUrl: s.targetUrl,
      status: s.status,
      createdAt: s.createdAt,
      findingCount: s.findings.length,
    }));
    res.json(summary);
  } catch (err) {
    logger.error('Failed to list scans', { error: err });
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.get('/scan/:id', async (req, res) => {
  try {
    const session = await getScanSession(req.params.id);
    if (!session) {
      return res.status(404).json({ error: 'Scan not found' });
    }
    res.json(session);
  } catch (err) {
    logger.error('Failed to get scan', { error: err, scanId: req.params.id });
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.post('/scan/:id/plan', async (req, res) => {
  try {
    const session = await getScanSession(req.params.id);
    if (!session) {
      return res.status(404).json({ error: 'Scan not found' });
    }
    logger.info(`Running AI planning for scan ${session.id}`);
    const actions = await runPlanningStep(session);
    res.json({ actions });
  } catch (err) {
    logger.error('AI planning failed', { error: err, scanId: req.params.id });
    res.status(500).json({ error: 'AI planning failed' });
  }
});

// Phase 3 Lifecycle Endpoints
app.post('/scan/:id/pause', async (req, res) => {
  const success = await ScanLifecycleService.pauseScan(req.params.id);
  res.status(success ? 200 : 400).json({ success });
});

app.post('/scan/:id/resume', async (req, res) => {
  const success = await ScanLifecycleService.resumeScan(req.params.id);
  res.status(success ? 200 : 400).json({ success });
});

app.post('/scan/:id/cancel', async (req, res) => {
  const success = await ScanLifecycleService.cancelScan(req.params.id);
  res.status(success ? 200 : 400).json({ success });
});

app.get('/scan/:id/runtime', async (req, res) => {
  const checkpoint = await CheckpointService.getLatestCheckpoint(req.params.id);
  res.json({
    scanId: req.params.id,
    latestCheckpoint: checkpoint,
    mode: isDistributedMode() ? 'distributed' : 'fallback'
  });
});

app.get('/system/queues', async (_req, res) => {
  const health = await getQueueHealth();
  res.json(health);
});

app.get('/system/workers', (_req, res) => {
  res.json(WorkerRegistry.getStatus());
});

app.get('/system/runtime', (_req, res) => {
  res.json({
    distributedMode: isDistributedMode(),
    redisConfigured: !!config.REDIS_URL,
    workersStarted: isDistributedMode() ? true : false,
    version: '1.0.0',
    workerCounts: isDistributedMode() ? { scan: 3, crawl: 2, attack: 5, verify: 2 } : null
  });
});

app.post('/scan/:id/auth', async (req, res) => {
  try {
    const session = await getScanSession(req.params.id);
    if (!session) {
      return res.status(404).json({ error: 'Scan not found' });
    }
    const { context, headers } = req.body as {
      context?: 'guest' | 'userA' | 'userB';
      headers?: Record<string, string>;
    };
    if (!context || !headers) {
      return res
        .status(400)
        .json({ error: 'context and headers are required' });
    }

    await updateAuthContext(session, context, headers);

    return res.json({ ok: true });
  } catch (err) {
    logger.error('Auth update failed', { error: err, scanId: req.params.id });
    res.status(500).json({ error: 'Auth update failed' });
  }
});

app.post('/scan/:id/execute', async (req, res) => {
  try {
    const session = await getScanSession(req.params.id);
    if (!session) {
      return res.status(404).json({ error: 'Scan not found' });
    }
    const { actionId } = req.body as { actionId?: string };
    if (!actionId) {
      return res.status(400).json({ error: 'actionId is required' });
    }
    const action = session.actions.find((a) => a.id === actionId);
    if (!action) {
      return res.status(404).json({ error: 'Action not found in session' });
    }

    logger.info(`Executing action ${actionId} (${action.actionType})`, { scanId: session.id });
    await executeAction(session, action);
    res.json({ ok: true });
  } catch (err) {
    logger.error('Execution failed', { error: err, scanId: req.params.id });
    res.status(500).json({ error: 'Execution failed' });
  }
});

// ── Real-Time Progress API (polled every 3s by frontend) ──
app.get('/scan/:id/progress', (_req, res) => {
  try {
    const progress = ScanProgressService.getProgress(_req.params.id);
    res.json(progress);
  } catch {
    res.json({ currentPhase: '', currentAction: '', events: [] });
  }
});

app.get('/scan/:id/summary', async (req, res) => {
  try {
    const summary = await generateSummary(req.params.id);
    res.json(summary);
  } catch {
    res.json({
      endpoints: 0, sensitivePaths: 0, vulnerabilities: 0,
      criticalFindings: 0, highFindings: 0, confirmedExploits: 0,
    });
  }
});

app.get('/scan/:id/attack-graph', async (req, res) => {
  try {
    const graphService = new AttackGraphService();
    const graph = await graphService.generateGraph(req.params.id);
    res.json(graph);
  } catch {
    res.json({ nodes: [], edges: [], scanId: req.params.id, generatedAt: Date.now() });
  }
});

app.get('/scan/:id/exploitable-issues', async (req, res) => {
  try {
    const issues = await getExploitableIssues(req.params.id);
    res.json(issues);
  } catch {
    res.json([]);
  }
});

app.get('/scan/:id/hypotheses', async (req, res) => {
  try {
    const { HypothesisRepository } = await import('./services/intelligence/HypothesisRepository');
    const repo = new HypothesisRepository();
    const hypotheses = await repo.getAllHypotheses(req.params.id);
    res.json(hypotheses);
  } catch {
    res.json([]);
  }
});

app.post('/benchmark/:profile', async (req, res) => {
  try {
    const { BenchmarkHarness } = await import('./services/intelligence/BenchmarkHarness');
    const { targetUrl, timeoutMs } = req.body;
    const result = await BenchmarkHarness.runBenchmark(req.params.profile, targetUrl, timeoutMs);
    res.json(result);
  } catch (err: any) {
    res.status(400).json({ error: err.message || 'Benchmark failed' });
  }
});

app.get('/benchmark/profiles', async (_req, res) => {
  try {
    const { BenchmarkHarness } = await import('./services/intelligence/BenchmarkHarness');
    res.json(BenchmarkHarness.getAvailableProfiles());
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Failed to list profiles' });
  }
});

app.get('/scan/:id/state', async (req, res) => {
  try {
    const session = await getScanSession(req.params.id);
    if (!session) {
      return res.status(404).json({ error: 'Scan not found' });
    }
    const state = statefulEngine.getContext(req.params.id);
    const recentDiagnostics = (session.diagnosticsLogs ?? []).slice(-20);
    if (!state) {
      return res.json({
        authHeaders: session.authHeaders,
        objectIds: [],
        visitedEndpoints: [],
        latestToken: null,
        budgetUsage: session.budgetUsage ?? {},
        coverageMetrics: session.coverageMetrics ?? null,
        recentDiagnostics,
      });
    }
    res.json({
      authHeaders: session.authHeaders,
      objectIds: state.getAvailableObjectIds(),
      visitedEndpoints: Array.from(state.visitedEndpoints),
      latestToken: state.getLatestToken(),
      budgetUsage: session.budgetUsage ?? {},
      coverageMetrics: session.coverageMetrics ?? null,
      recentDiagnostics,
    });
  } catch (err) {
    logger.error('Failed to get scan state', { error: err });
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.get('/scan/:id/attack-paths', async (req, res) => {
  try {
    const { PrismaClient } = await import('@prisma/client');
    const prisma = new PrismaClient();
    const chains = await prisma.attackChain.findMany({
      where: { scanId: req.params.id },
      orderBy: { confidence: 'desc' },
    });
    await prisma.$disconnect();
    res.json(chains.map((c: any) => ({
      id: c.id,
      scanId: c.scanId,
      name: c.name,
      nodes: JSON.parse(c.nodes),
      vulnerabilities: JSON.parse(c.vulnerabilities),
      privilegeTransitions: JSON.parse(c.privilegeTransitions),
      confidence: c.confidence,
      createdAt: c.createdAt,
    })));
  } catch {
    res.json([]);
  }
});

// ── PHASE 4: Browser Observability APIs ──
app.get('/scan/:id/browser', async (req, res) => {
  try {
    const { PrismaClient } = await import('@prisma/client');
    const prisma = new PrismaClient();
    const artifacts = await prisma.browserArtifact.findMany({
      where: { scanId: req.params.id }
    });
    await prisma.$disconnect();
    
    res.json({
      scanId: req.params.id,
      totalArtifacts: artifacts.length,
      counts: {
        routes: artifacts.filter(a => a.artifactType === 'routes').length,
        apis: artifacts.filter(a => a.artifactType === 'apis').length,
        websockets: artifacts.filter(a => a.artifactType === 'websockets').length,
        storage: artifacts.filter(a => a.artifactType === 'storage').length,
        dom_sinks: artifacts.filter(a => a.artifactType === 'dom_sinks').length,
      }
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch browser stats' });
  }
});

app.get('/scan/:id/surface', async (req, res) => {
  try {
    const { PrismaClient } = await import('@prisma/client');
    const prisma = new PrismaClient();
    const artifacts = await prisma.browserArtifact.findMany({
      where: { scanId: req.params.id, artifactType: 'routes' }
    });
    await prisma.$disconnect();
    res.json(artifacts.map(a => JSON.parse(a.payload)).flat());
  } catch {
    res.json([]);
  }
});

app.get('/scan/:id/surface/summary', async (req, res) => {
  try {
    const { PrismaClient } = await import('@prisma/client');
    const prisma = new PrismaClient();
    const artifacts = await prisma.browserArtifact.findMany({
      where: { scanId: req.params.id }
    });
    await prisma.$disconnect();
    
    const routes = artifacts.filter(a => a.artifactType === 'routes').map(a => JSON.parse(a.payload)).flat();
    const apis = routes.filter((r: any) => r.type === 'api');
    const websockets = artifacts.filter(a => a.artifactType === 'websockets').map(a => JSON.parse(a.payload)).flat();
    const securityFiles = artifacts.filter(a => a.artifactType === 'security_files').map(a => JSON.parse(a.payload)).flat();
    
    res.json({
      totalRoutes: routes.length,
      publicRoutes: routes.filter((r: any) => !r.authRequired).length,
      authGatedRoutes: routes.filter((r: any) => r.authRequired).length,
      sensitiveRoutes: routes.filter((r: any) => r.sensitivity === 'admin' || r.sensitivity === 'sensitive').length,
      adminRoutes: routes.filter((r: any) => r.sensitivity === 'admin').length,
      apiEndpoints: apis.length,
      websockets: websockets.length,
      spaRoutes: routes.filter((r: any) => r.type === 'spa_route').length,
      securityFiles: securityFiles.length,
      crawlDepth: 3,
      coverageScore: Math.min(100, Math.floor((routes.length / 50) * 100))
    });
  } catch {
    res.json({ totalRoutes: 0, publicRoutes: 0, authGatedRoutes: 0, sensitiveRoutes: 0, adminRoutes: 0, apiEndpoints: 0, websockets: 0, spaRoutes: 0, securityFiles: 0, crawlDepth: 0, coverageScore: 0 });
  }
});

app.get('/scan/:id/security-files', async (req, res) => {
  try {
    const { PrismaClient } = await import('@prisma/client');
    const prisma = new PrismaClient();
    const artifacts = await prisma.browserArtifact.findMany({
      where: { scanId: req.params.id, artifactType: 'security_files' }
    });
    await prisma.$disconnect();
    res.json(artifacts.map(a => JSON.parse(a.payload)).flat());
  } catch {
    res.json([]);
  }
});

app.get('/scan/:id/websockets', async (req, res) => {
  try {
    const { PrismaClient } = await import('@prisma/client');
    const prisma = new PrismaClient();
    const artifacts = await prisma.browserArtifact.findMany({
      where: { scanId: req.params.id, artifactType: 'websockets' }
    });
    await prisma.$disconnect();
    res.json(artifacts.map(a => JSON.parse(a.payload)).flat());
  } catch {
    res.json([]);
  }
});

app.get('/scan/:id/storage', async (req, res) => {
  try {
    const { PrismaClient } = await import('@prisma/client');
    const prisma = new PrismaClient();
    const artifacts = await prisma.browserArtifact.findMany({
      where: { scanId: req.params.id, artifactType: 'storage' }
    });
    await prisma.$disconnect();
    res.json(artifacts.map(a => JSON.parse(a.payload)).flat());
  } catch {
    res.json([]);
  }
});

app.get('/scan/:id/correlation', async (req, res) => {
  try {
    const { FrontendCorrelationEngine } = await import('./services/intelligence/CorrelationEngine');
    const correlation = await FrontendCorrelationEngine.correlate(req.params.id);
    res.json(correlation);
  } catch {
    res.json([]);
  }
});

app.get('/system/queues', async (_req, res) => {
  const health = await getQueueHealth();
  res.json(health);
});

app.get('/system/workers', (_req, res) => {
  res.json(WorkerRegistry.getStatus());
});

app.get('/system/runtime', (_req, res) => {
  res.json({
    distributedMode: isDistributedMode(),
    redisConfigured: !!config.REDIS_URL,
    workersStarted: isDistributedMode() ? true : false,
    version: '1.0.0',
    workerCounts: isDistributedMode() ? { scan: 3, crawl: 2, attack: 5, verify: 2 } : null
  });
});

app.post('/scan/:id/auth', async (req, res) => {
  try {
    const session = await getScanSession(req.params.id);
    if (!session) {
      return res.status(404).json({ error: 'Scan not found' });
    }
    const { context, headers } = req.body as {
      context?: 'guest' | 'userA' | 'userB';
      headers?: Record<string, string>;
    };
    if (!context || !headers) {
      return res
        .status(400)
        .json({ error: 'context and headers are required' });
    }

    await updateAuthContext(session, context, headers);

    return res.json({ ok: true });
  } catch (err) {
    logger.error('Auth update failed', { error: err, scanId: req.params.id });
    res.status(500).json({ error: 'Auth update failed' });
  }
});

app.post('/scan/:id/execute', async (req, res) => {
  try {
    const session = await getScanSession(req.params.id);
    if (!session) {
      return res.status(404).json({ error: 'Scan not found' });
    }
    const { actionId } = req.body as { actionId?: string };
    if (!actionId) {
      return res.status(400).json({ error: 'actionId is required' });
    }
    const action = session.actions.find((a) => a.id === actionId);
    if (!action) {
      return res.status(404).json({ error: 'Action not found in session' });
    }

    logger.info(`Executing action ${actionId} (${action.actionType})`, { scanId: session.id });
    await executeAction(session, action);
    res.json({ ok: true });
  } catch (err) {
    logger.error('Execution failed', { error: err, scanId: req.params.id });
    res.status(500).json({ error: 'Execution failed' });
  }
});

// ── Real-Time Progress API (polled every 3s by frontend) ──
app.get('/scan/:id/progress', (_req, res) => {
  try {
    const progress = ScanProgressService.getProgress(_req.params.id);
    res.json(progress);
  } catch {
    res.json({ currentPhase: '', currentAction: '', events: [] });
  }
});

app.get('/scan/:id/summary', async (req, res) => {
  try {
    const summary = await generateSummary(req.params.id);
    res.json(summary);
  } catch {
    res.json({
      endpoints: 0, sensitivePaths: 0, vulnerabilities: 0,
      criticalFindings: 0, highFindings: 0, confirmedExploits: 0,
    });
  }
});

app.get('/scan/:id/attack-graph', async (req, res) => {
  try {
    const graphService = new AttackGraphService();
    const graph = await graphService.generateGraph(req.params.id);
    res.json(graph);
  } catch {
    res.json({ nodes: [], edges: [], scanId: req.params.id, generatedAt: Date.now() });
  }
});

app.get('/scan/:id/exploitable-issues', async (req, res) => {
  try {
    const issues = await getExploitableIssues(req.params.id);
    res.json(issues);
  } catch {
    res.json([]);
  }
});

app.get('/scan/:id/hypotheses', async (req, res) => {
  try {
    const { HypothesisRepository } = await import('./services/intelligence/HypothesisRepository');
    const repo = new HypothesisRepository();
    const hypotheses = await repo.getAllHypotheses(req.params.id);
    res.json(hypotheses);
  } catch {
    res.json([]);
  }
});

app.post('/benchmark/:profile', async (req, res) => {
  try {
    const { BenchmarkHarness } = await import('./services/intelligence/BenchmarkHarness');
    const { targetUrl, timeoutMs } = req.body;
    const result = await BenchmarkHarness.runBenchmark(req.params.profile, targetUrl, timeoutMs);
    res.json(result);
  } catch (err: any) {
    res.status(400).json({ error: err.message || 'Benchmark failed' });
  }
});

app.get('/benchmark/profiles', async (_req, res) => {
  try {
    const { BenchmarkHarness } = await import('./services/intelligence/BenchmarkHarness');
    res.json(BenchmarkHarness.getAvailableProfiles());
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Failed to list profiles' });
  }
});

app.get('/scan/:id/state', async (req, res) => {
  try {
    const session = await getScanSession(req.params.id);
    if (!session) {
      return res.status(404).json({ error: 'Scan not found' });
    }
    const state = statefulEngine.getContext(req.params.id);
    const recentDiagnostics = (session.diagnosticsLogs ?? []).slice(-20);
    if (!state) {
      return res.json({
        authHeaders: session.authHeaders,
        objectIds: [],
        visitedEndpoints: [],
        latestToken: null,
        budgetUsage: session.budgetUsage ?? {},
        coverageMetrics: session.coverageMetrics ?? null,
        recentDiagnostics,
      });
    }
    res.json({
      authHeaders: session.authHeaders,
      objectIds: state.getAvailableObjectIds(),
      visitedEndpoints: Array.from(state.visitedEndpoints),
      latestToken: state.getLatestToken(),
      budgetUsage: session.budgetUsage ?? {},
      coverageMetrics: session.coverageMetrics ?? null,
      recentDiagnostics,
    });
  } catch (err) {
    logger.error('Failed to get scan state', { error: err });
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.get('/scan/:id/attack-paths', async (req, res) => {
  try {
    const { PrismaClient } = await import('@prisma/client');
    const prisma = new PrismaClient();
    const chains = await prisma.attackChain.findMany({
      where: { scanId: req.params.id },
      orderBy: { confidence: 'desc' },
    });
    await prisma.$disconnect();
    res.json(chains.map((c: any) => ({
      id: c.id,
      scanId: c.scanId,
      name: c.name,
      nodes: JSON.parse(c.nodes),
      vulnerabilities: JSON.parse(c.vulnerabilities),
      privilegeTransitions: JSON.parse(c.privilegeTransitions),
      confidence: c.confidence,
      createdAt: c.createdAt,
    })));
  } catch {
    res.json([]);
  }
});

// ── Phase 5 AI Intelligence Observability APIs ──
app.get('/scan/:id/intelligence', async (req, res) => {
  try {
    const { PrismaClient } = await import('@prisma/client');
    const prisma = new PrismaClient();
    const artifacts = await prisma.intelligenceArtifact.findMany({
      where: { scanId: req.params.id },
      orderBy: { createdAt: 'desc' }
    });
    await prisma.$disconnect();
    res.json(artifacts.map((a: any) => ({
      ...a,
      metadata: JSON.parse(a.metadata)
    })));
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/scan/:id/deduplication', async (req, res) => {
  try {
    const { PrismaClient } = await import('@prisma/client');
    const prisma = new PrismaClient();
    const artifacts = await prisma.intelligenceArtifact.findMany({
      where: { scanId: req.params.id, category: 'deduplication' },
      orderBy: { createdAt: 'desc' }
    });
    await prisma.$disconnect();
    res.json(artifacts.map((a: any) => ({
      clusterId: a.referenceId,
      reasoning: a.reasoning,
      ...JSON.parse(a.metadata)
    })));
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/scan/:id/explanations', async (req, res) => {
  try {
    const { PrismaClient } = await import('@prisma/client');
    const prisma = new PrismaClient();
    const artifacts = await prisma.intelligenceArtifact.findMany({
      where: { scanId: req.params.id, category: 'explanation' },
      orderBy: { createdAt: 'desc' }
    });
    await prisma.$disconnect();
    res.json(artifacts.map((a: any) => ({
      chainId: a.referenceId,
      analystSummary: a.reasoning,
      ...JSON.parse(a.metadata)
    })));
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// ── Phase 6A: SaaS Multi-Tenant Organization APIs ──

app.get('/org/:orgId/metrics', requireOrgRole('viewer'), async (req, res) => {
  try {
    const authReq = req as AuthenticatedRequest;
    const metrics = await OrgService.getMetrics(authReq.currentOrgId!);
    res.json(metrics);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/org/:orgId/audit', requireOrgRole('admin'), async (req, res) => {
  try {
    const authReq = req as AuthenticatedRequest;
    const logs = await OrgService.getAuditLogs(authReq.currentOrgId!);
    res.json(logs);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/org/:orgId/members', requireOrgRole('viewer'), async (req, res) => {
  try {
    const authReq = req as AuthenticatedRequest;
    const members = await OrgService.getMembers(authReq.currentOrgId!);
    res.json(members);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

const server = app.listen(config.PORT, () => {
  logger.info(`VulnForge backend listening on http://localhost:${config.PORT}`);
});

process.on('SIGTERM', async () => {
  logger.info('SIGTERM signal received: closing HTTP server');
  await WorkerRegistry.shutdown();
  server.close(() => {
    logger.info('HTTP server closed');
  });
});

// Start workers
WorkerRegistry.start();
