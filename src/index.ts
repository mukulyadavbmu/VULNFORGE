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
import { config } from './config';
import { logger } from './utils/logger';
import { isValidTarget } from './utils/security';
import { OASTService } from './services/oast/OASTService';

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

// Auth middleware (applied to all routes below)
app.use((req: Request, res: Response, next: NextFunction) => {
  const provided = req.header('x-vulnforge-api-key');
  if (provided !== config.VULNFORGE_API_KEY) {
    logger.warn(`Unauthorized access attempt from ${req.ip}`);
    return res.status(401).json({ error: 'Unauthorized' });
  }
  return next();
});

app.post('/scan', async (req, res) => {
  const { targetUrl } = req.body as { targetUrl?: string };
  if (!targetUrl) {
    return res.status(400).json({ error: 'targetUrl is required' });
  }

  const validation = isValidTarget(targetUrl);
  if (!validation.valid) {
    return res.status(400).json({ error: validation.error });
  }

  logger.info(`Starting new scan for target: ${targetUrl}`);
  try {
    const session = await createScanSessionAsync(targetUrl);

    // kick off a lightweight crawl as guest in background
    void crawlTarget(session, 'guest', { maxPages: config.MAX_PAGES_PER_SCAN })
      .catch(err => logger.error('Background crawl failed', { error: err }));

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

app.listen(config.PORT, () => {
  logger.info(`VulnForge backend listening on http://localhost:${config.PORT}`);
});
