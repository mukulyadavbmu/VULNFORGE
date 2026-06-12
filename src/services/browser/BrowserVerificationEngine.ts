/**
 * BrowserVerificationEngine — Browser-based vulnerability verification.
 *
 * Launches headless browsers (Playwright) to detect DOM-based vulnerabilities
 * that cannot be discovered via static HTTP analysis. Injects payloads into
 * query parameters, monitors DOM changes, detects dangerous JS sinks (innerHTML,
 * eval, document.write), console errors, and alert() execution.
 *
 * Key capabilities:
 * - DOM XSS detection
 * - Reflected payload execution with evidence collection
 * - JS sink usage tracking (innerHTML, eval, document.write)
 * - Console error monitoring
 * - alert() execution detection
 *
 * Security: Headless mode only, bounded timeouts (per-endpoint), no eval.
 * Efficiency: Browser reuse, connection pooling via context, max 5 concurrent pages.
 */

import { chromium, Browser, Page, BrowserContext } from 'playwright';
import { AttackNode, FindingType, ScanFinding, ScanSession } from '../../types';
import { logger } from '../../utils/logger';

const log = logger.child({ module: 'BrowserVerificationEngine' });

// ─── Constants ──────────────────────────────────────────────────────────────

const MAX_CONCURRENT_PAGES = 5;
const TIMEOUT_PER_ENDPOINT_MS = 10000;
const PAYLOAD_INJECTION_TIMEOUT_MS = 5000;
const DOM_MONITOR_TIMEOUT_MS = 3000;

// ─── Types ──────────────────────────────────────────────────────────────────

export interface BrowserFinding {
  endpoint: string;
  payload: string;
  executionEvidence: string;
  sink: string;
  confidenceScore: number;
  findingType: FindingType;
}

export interface BrowserVerificationResult {
  endpointsProcessed: number;
  vulnerabilitiesDetected: number;
  durationMs: number;
  findings: BrowserFinding[];
}

interface DOMMonitorData {
  innerHTMLAccess: boolean;
  evalCalls: string[];
  documentWriteCalls: string[];
  consoleErrors: string[];
  alertCalls: string[];
  payloadReflected: boolean;
  reflectionSinks: string[];
}

// ─── Browser pool for connection reuse ──────────────────────────────────────

class BrowserPool {
  private browser: Browser | null = null;
  private context: BrowserContext | null = null;
  private pages: Page[] = [];

  async initialize(): Promise<void> {
    if (!this.browser) {
      this.browser = await chromium.launch({
        headless: true,
        args: [
          '--disable-blink-features=AutomationControlled',
          '--no-sandbox',
          '--disable-setuid-sandbox',
          '--disable-dev-shm-usage', // MED-6: prevent SIGBUS on Render's 64MB /dev/shm
          '--disable-gpu',
        ],
      });
      log.info('Browser initialized (headless mode)');
    }

    if (!this.context) {
      this.context = await this.browser!.newContext();
    }
  }

  async createPage(): Promise<Page> {
    await this.initialize();
    const page = await this.context!.newPage();
    this.pages.push(page);
    return page;
  }

  async close(): Promise<void> {
    for (const page of this.pages) {
      try {
        await page.close();
      } catch (err) {
        // Ignore errors when closing pages
      }
    }
    if (this.context) {
      await this.context.close();
      this.context = null;
    }
    if (this.browser) {
      await this.browser.close();
      this.browser = null;
    }
    log.info('Browser pool closed');
  }
}

// ─── DOM Monitoring Script ──────────────────────────────────────────────────
// Injected into each page to track dangerous operations

const DOM_MONITOR_SCRIPT = `
  window.__vulnforgeMonitor = {
    innerHTMLAccess: false,
    evalCalls: [],
    documentWriteCalls: [],
    consoleErrors: [],
    alertCalls: [],
    payloadReflected: false,
    reflectionSinks: [],
  };

  // Track innerHTML access
  const originalHTMLDescriptor = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
  if (originalHTMLDescriptor) {
    Object.defineProperty(Element.prototype, 'innerHTML', {
      get: originalHTMLDescriptor.get,
      set: function(value) {
        window.__vulnforgeMonitor.innerHTMLAccess = true;
        if (value.includes(window.__vulnforgePayload)) {
          window.__vulnforgeMonitor.payloadReflected = true;
          window.__vulnforgeMonitor.reflectionSinks.push('innerHTML');
        }
        originalHTMLDescriptor.set?.call(this, value);
      },
    });
  }

  // Track eval calls
  const originalEval = window.eval;
  window.eval = function(code) {
    window.__vulnforgeMonitor.evalCalls.push(code);
    if (typeof code === 'string' && code.includes(window.__vulnforgePayload)) {
      window.__vulnforgeMonitor.payloadReflected = true;
      window.__vulnforgeMonitor.reflectionSinks.push('eval');
    }
    return originalEval(code);
  };

  // Track document.write
  const originalWrite = Document.prototype.write;
  Document.prototype.write = function(str) {
    window.__vulnforgeMonitor.documentWriteCalls.push(str);
    if (typeof str === 'string' && str.includes(window.__vulnforgePayload)) {
      window.__vulnforgeMonitor.payloadReflected = true;
      window.__vulnforgeMonitor.reflectionSinks.push('document.write');
    }
    return originalWrite.call(this, str);
  };

  // Track console errors
  const originalError = console.error;
  console.error = function(...args) {
    window.__vulnforgeMonitor.consoleErrors.push(args.join(' '));
    originalError(...args);
  };

  // Track alert calls
  const originalAlert = window.alert;
  window.alert = function(msg) {
    window.__vulnforgeMonitor.alertCalls.push(msg);
    if (typeof msg === 'string' && msg.includes(window.__vulnforgePayload)) {
      window.__vulnforgeMonitor.payloadReflected = true;
      window.__vulnforgeMonitor.reflectionSinks.push('alert');
    }
    // Don't call original alert in headless
  };
`;

// ─── Engine ─────────────────────────────────────────────────────────────────

export class BrowserVerificationEngine {
  private pool = new BrowserPool();

  /**
   * Verify all eligible endpoints using browser-based analysis.
   */
  async verify(
    session: ScanSession,
    endpoints: AttackNode[],
  ): Promise<BrowserVerificationResult> {
    const start = Date.now();
    let endpointsProcessed = 0;
    let vulnerabilitiesDetected = 0;
    const findings: BrowserFinding[] = [];

    try {
      await this.pool.initialize();

      // Filter endpoints that can be visited in a browser
      const targetEndpoints = endpoints.filter(
        (ep) => ep.type === 'page' || (ep.type === 'api' && this.canBrowse(ep.url)),
      );

      log.info(`Browser verification starting on ${targetEndpoints.length} endpoints`);

      for (const endpoint of targetEndpoints) {
        try {
          const browserFindings = await this.verifyEndpoint(session, endpoint);
          if (browserFindings.length > 0) {
            vulnerabilitiesDetected += browserFindings.length;
            findings.push(...browserFindings);
          }
          endpointsProcessed++;
        } catch (err) {
          log.warn(`Browser verification failed for ${endpoint.url}: ${err}`);
        }
      }

      return {
        endpointsProcessed,
        vulnerabilitiesDetected,
        findings,
        durationMs: Date.now() - start,
      };
    } finally {
      await this.pool.close();
    }
  }

  /**
   * Verify a single endpoint by injecting payloads and monitoring DOM.
   */
  private async verifyEndpoint(session: ScanSession, endpoint: AttackNode): Promise<BrowserFinding[]> {
    const findings: BrowserFinding[] = [];
    const page = await this.pool.createPage();

    try {
      const authHeaders = session.authHeaders[endpoint.authContext] || {};
      if (Object.keys(authHeaders).length > 0) {
        await page.setExtraHTTPHeaders(authHeaders);
      }

      // Inject monitoring script before loading page
      await page.addInitScript(DOM_MONITOR_SCRIPT);

      // Probe payloads: primarily XSS payloads
      const probePayloads = [
        '<script>alert("vulnforge")</script>',
        '"><img src=x onerror=alert("vulnforge")>',
        "';alert('vulnforge');//",
        '<svg/onload=alert("vulnforge")>',
        '{{7*7}}', // Template injection
      ];

      for (const payload of probePayloads) {
        try {
          const url = new URL(endpoint.url);
          // Inject payload into first query parameter
          const params = Array.from(url.searchParams.keys());
          if (params.length === 0) {
            url.searchParams.set('q', encodeURIComponent(payload));
          } else {
            url.searchParams.set(params[0], encodeURIComponent(payload));
          }

          // Set payload in window for monitor script
          await page.goto(url.toString(), { waitUntil: 'networkidle', timeout: TIMEOUT_PER_ENDPOINT_MS });
          const paramValues = Array.from(url.searchParams.values());
          const payloadStr = paramValues.length > 0 ? paramValues[0] : payload;
          await page.evaluate((p: string) => {
            (window as any).__vulnforgePayload = decodeURIComponent(p);
          }, payloadStr);

          // Wait for DOM activity
          await page.waitForTimeout(DOM_MONITOR_TIMEOUT_MS);

          // Collect monitoring data
          const monitorData = await page.evaluate(() => (window as any).__vulnforgeMonitor);

          // Analyze findings
          const endpointFindings = this.analyzeMonitorData(endpoint.url, payload, monitorData);
          findings.push(...endpointFindings);
        } catch (err) {
          log.debug(`Payload injection failed for ${endpoint.url}: ${err}`);
        }
      }

      return findings;
    } finally {
      await page.close();
    }
  }

  /**
   * Analyze DOM monitor data to identify vulnerabilities.
   */
  private analyzeMonitorData(
    endpoint: string,
    payload: string,
    data: DOMMonitorData,
  ): BrowserFinding[] {
    const findings: BrowserFinding[] = [];

    // Detection 1: alert() execution = definite XSS
    if (data.alertCalls.length > 0) {
      findings.push({
        endpoint,
        payload,
        executionEvidence: `alert() executed with message: ${data.alertCalls[0]}`,
        sink: 'alert',
        confidenceScore: 1.0,
        findingType: 'dom_xss',
      });
      return findings; // High confidence, return early
    }

    // Detection 2: payload reflected in dangerous sinks
    if (data.payloadReflected && data.reflectionSinks.length > 0) {
      const sinkName = data.reflectionSinks[0];
      let confidence = 0.8;
      if (sinkName === 'eval') {
        confidence = 0.95; // eval is almost always exploitable
      }

      findings.push({
        endpoint,
        payload,
        executionEvidence: `Payload reflected in ${sinkName}`,
        sink: sinkName,
        confidenceScore: confidence,
        findingType: 'dom_xss',
      });
    }

    // Detection 3: innerHTML setter called (suspicious but not confirmed)
    if (data.innerHTMLAccess && data.payloadReflected) {
      findings.push({
        endpoint,
        payload,
        executionEvidence: 'Payload reflected via innerHTML',
        sink: 'innerHTML',
        confidenceScore: 0.7,
        findingType: 'dom_xss',
      });
    }

    // Detection 4: eval calls with payload
    if (data.evalCalls.length > 0) {
      findings.push({
        endpoint,
        payload,
        executionEvidence: `eval() called during page load`,
        sink: 'eval',
        confidenceScore: 0.9,
        findingType: 'dom_xss',
      });
    }

    // Detection 5: console errors (indicates JS execution)
    if (data.consoleErrors.length > 0) {
      findings.push({
        endpoint,
        payload,
        executionEvidence: `Console error: ${data.consoleErrors[0]}`,
        sink: 'console_error',
        confidenceScore: 0.6,
        findingType: 'xss',
      });
    }

    return findings;
  }

  /**
   * Check if an endpoint can be browsed (not binary, not large file).
   */
  private canBrowse(url: string): boolean {
    const lowerUrl = url.toLowerCase();
    const noBrowsePaths = ['.pdf', '.zip', '.exe', '.bin', '.tar', '.gz', '/download', '/export'];
    return !noBrowsePaths.some((p) => lowerUrl.includes(p));
  }
}
