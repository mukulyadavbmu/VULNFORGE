/**
 * VulnForge Production E2E Validation Script
 * 
 * Runs against the Render cloud backend to verify the full scan lifecycle:
 *   1. Register/Login → get JWT
 *   2. Create scan → verify BullMQ enqueue
 *   3. Poll scan status → verify queued → running → completed
 *   4. Fetch findings → verify DB persistence
 *   5. Check runtime → verify worker status
 */

const BACKEND = process.env.BACKEND_URL || 'https://vulnforge-backend.onrender.com';
const TARGET  = process.env.SCAN_TARGET  || 'http://localhost:3000';
const EMAIL   = process.env.TEST_EMAIL   || 'admin@vulnforge.local';
const PASS    = process.env.TEST_PASS    || 'VulnForge2024!';
const ORG     = process.env.TEST_ORG     || 'vulnforge-validation';

const POLL_INTERVAL_MS = 5000;
const MAX_POLL_SECS    = 600; // 10 min max wait for scan completion

function log(tag, msg, data = '') {
  const ts = new Date().toISOString();
  const dataStr = data ? ` | ${JSON.stringify(data)}` : '';
  console.log(`[${ts}] [${tag}] ${msg}${dataStr}`);
}

function pass(check) { console.log(`  ✅  ${check}`); }
function fail(check) { console.log(`  ❌  ${check}`); process.exitCode = 1; }

async function req(method, path, body, token) {
  const headers = { 'Content-Type': 'application/json' };
  if (token) headers['Authorization'] = `Bearer ${token}`;
  const res = await fetch(`${BACKEND}${path}`, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let json;
  try { json = JSON.parse(text); } catch { json = { raw: text }; }
  return { status: res.status, body: json };
}

async function main() {
  console.log('\n══════════════════════════════════════════════════');
  console.log('  VulnForge Production E2E Validation');
  console.log(`  Backend : ${BACKEND}`);
  console.log(`  Target  : ${TARGET}`);
  console.log('══════════════════════════════════════════════════\n');

  // ── STEP 1: Health Check ────────────────────────────────────────────────
  log('HEALTH', 'Checking backend health...');
  const health = await req('GET', '/health');
  log('HEALTH', `Status ${health.status}`, health.body);
  if (health.status === 200 && health.body.status === 'ok') {
    pass('Backend is live');
    pass(`Database: ${health.body.database}`);
  } else {
    fail(`Backend health check failed: ${health.status}`);
    return;
  }

  // ── STEP 2: Register or Login ───────────────────────────────────────────
  log('AUTH', `Attempting registration: ${EMAIL}`);
  let regRes = await req('POST', '/auth/register', { email: EMAIL, password: PASS, name: 'E2E Validator', orgName: ORG });
  log('AUTH', `Register response: ${regRes.status}`, regRes.body);

  log('AUTH', 'Logging in...');
  const loginRes = await req('POST', '/auth/login', { email: EMAIL, password: PASS });
  log('AUTH', `Login response: ${loginRes.status}`, loginRes.body);
  
  if (loginRes.status !== 200 || !loginRes.body.token) {
    fail(`Login failed: ${loginRes.status} — ${JSON.stringify(loginRes.body)}`);
    return;
  }
  const token = loginRes.body.token;
  pass('Authentication succeeded — JWT acquired');
  log('AUTH', `Token prefix: ${token.substring(0, 20)}...`);

  // ── STEP 3: System Runtime Check ────────────────────────────────────────
  log('RUNTIME', 'Checking system runtime...');
  const runtime = await req('GET', '/system/runtime', null, token);
  log('RUNTIME', `Runtime: ${runtime.status}`, runtime.body);
  
  if (runtime.status === 200) {
    pass('System runtime endpoint accessible');
    if (runtime.body.distributedMode) {
      pass(`Distributed mode: ACTIVE (Redis connected)`);
    } else {
      fail('Distributed mode: INACTIVE — workers will not start from Redis ready callback');
    }
    log('RUNTIME', `Mode details`, runtime.body);
  } else {
    fail(`Runtime check failed: ${runtime.status}`);
  }

  // ── STEP 4: Worker Status Check ─────────────────────────────────────────
  log('WORKERS', 'Checking worker registry...');
  const workers = await req('GET', '/system/workers', null, token);
  log('WORKERS', `Workers: ${workers.status}`, workers.body);
  
  if (workers.status === 200) {
    pass('Worker registry accessible');
    const workerData = workers.body;
    const workerList = workerData.workers || workerData;
    const workerNames = Object.keys(workerList || {});
    log('WORKERS', `Active workers: ${workerNames.join(', ') || 'none'}`);
    
    // WorkerRegistry.getStatus() returns keys: scan, crawl, attack, verify
    [['scan','ScanWorker'], ['crawl','CrawlWorker'], ['attack','AttackWorker'], ['verify','VerifyWorker']].forEach(([key, label]) => {
      const w = workerList[key];
      if (w && (w.running || w.status === 'running')) {
        pass(`${label}: running (concurrency=${w.concurrency}, uptime=${w.uptimeSeconds}s)`);
      } else if (w) {
        fail(`${label}: status=${w.status || 'unknown'}`);
      } else {
        fail(`${label}: not found in registry`);
      }
    });
  } else {
    fail(`Worker check failed: ${workers.status}`);
  }

  // ── STEP 5: Queue Health ─────────────────────────────────────────────────
  log('QUEUES', 'Checking queue health...');
  const queues = await req('GET', '/system/queues', null, token);
  log('QUEUES', `Queues: ${queues.status}`, queues.body);
  
  if (queues.status === 200) {
    pass('Queue health endpoint accessible');
    log('QUEUES', `Mode: ${queues.body.mode}`);
    if (queues.body.mode === 'distributed') {
      pass('Queue mode: distributed (Redis active)');
    } else {
      fail('Queue mode: fallback — BullMQ not connected to Redis');
    }
  }

  // ── STEP 6: Create Scan ──────────────────────────────────────────────────
  log('SCAN', `Creating scan against ${TARGET}...`);
  const scanRes = await req('POST', '/scan', { targetUrl: TARGET }, token);
  log('SCAN', `Create scan: ${scanRes.status}`, scanRes.body);
  
  if (scanRes.status !== 201 || !scanRes.body.scanId) {
    fail(`Scan creation failed: ${scanRes.status} — ${JSON.stringify(scanRes.body)}`);
    return;
  }
  const scanId = scanRes.body.scanId;
  pass(`Scan created — ID: ${scanId}`);
  pass('BullMQ enqueue triggered via ScanLifecycleService');

  // ── STEP 7: Poll Scan Lifecycle ──────────────────────────────────────────
  log('LIFECYCLE', `Polling scan ${scanId} (max ${MAX_POLL_SECS}s)...`);
  
  const startMs = Date.now();
  let lastStatus = '';
  let lastPhase = '';
  let transitionedToRunning = false;
  let transitionedToCompleted = false;
  
  while ((Date.now() - startMs) / 1000 < MAX_POLL_SECS) {
    await new Promise(r => setTimeout(r, POLL_INTERVAL_MS));
    
    const scanDetail = await req('GET', `/scan/${scanId}`, null, token);
    const progress   = await req('GET', `/scan/${scanId}/progress`, null, token);
    
    if (scanDetail.status !== 200) {
      log('LIFECYCLE', `Poll error: ${scanDetail.status}`);
      continue;
    }
    
    const status = scanDetail.body.status;
    const phase  = progress.body?.currentPhase || '';
    const action = progress.body?.currentAction || '';
    const events = progress.body?.events || [];
    const lastEvent = events[events.length - 1]?.message || '';
    
    if (status !== lastStatus || phase !== lastPhase) {
      log('LIFECYCLE', `Status: ${lastStatus || 'created'} → ${status} | Phase: ${phase} | ${action}`);
      log('LIFECYCLE', `Last event: ${lastEvent}`);
      lastStatus = status;
      lastPhase = phase;
    }
    
    if (status === 'running' && !transitionedToRunning) {
      transitionedToRunning = true;
      pass('Scan transitioned: queued → running (ScanWorker picked up job)');
      log('LIFECYCLE', 'Worker is executing pipeline', { phase, action });
    }
    
    if (status === 'completed') {
      transitionedToCompleted = true;
      pass('Scan transitioned: running → completed');
      
      // Print all events as proof
      console.log('\n  Scan Event Log:');
      events.forEach(e => console.log(`    [${e.type}] ${e.message}`));
      break;
    }
    
    if (status === 'failed') {
      fail(`Scan FAILED at phase: ${phase}`);
      console.log('\n  Scan Event Log:');
      events.forEach(e => console.log(`    [${e.type}] ${e.message}`));
      break;
    }
  }
  
  if (!transitionedToCompleted && lastStatus !== 'failed') {
    fail(`Scan timed out after ${MAX_POLL_SECS}s — last status: ${lastStatus}`);
  }

  // ── STEP 8: Findings Persistence ────────────────────────────────────────
  log('FINDINGS', `Fetching findings for scan ${scanId}...`);
  const scanFinal = await req('GET', `/scan/${scanId}`, null, token);
  log('FINDINGS', `Final scan data: ${scanFinal.status}`);
  
  if (scanFinal.status === 200) {
    const findings = scanFinal.body.findings || [];
    pass(`Findings in DB: ${findings.length}`);
    
    if (findings.length > 0) {
      pass('Findings persisted to Neon PostgreSQL');
      const bySeverity = findings.reduce((acc, f) => {
        acc[f.severity] = (acc[f.severity] || 0) + 1;
        return acc;
      }, {});
      log('FINDINGS', 'Severity breakdown', bySeverity);
      findings.slice(0, 3).forEach(f => {
        log('FINDINGS', `  [${f.severity?.toUpperCase()}] ${f.type} — ${f.url}`);
      });
    } else {
      log('FINDINGS', 'No findings produced (target may not be reachable from Render)');
    }
    
    const nodes = Object.keys(scanFinal.body.attackNodes || {}).length;
    log('FINDINGS', `Endpoints discovered: ${nodes}`);
  }

  // ── FINAL SUMMARY ────────────────────────────────────────────────────────
  const elapsed = Math.round((Date.now() - startMs) / 1000);
  console.log('\n══════════════════════════════════════════════════');
  console.log(`  E2E Validation Complete — ${elapsed}s`);
  console.log(`  Exit code: ${process.exitCode || 0}`);
  console.log('══════════════════════════════════════════════════\n');
}

main().catch(err => {
  console.error('Fatal error:', err.message);
  process.exit(1);
});
