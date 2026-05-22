import { Page, Request, Response } from '@playwright/test';
import { PrismaClient } from '@prisma/client';
import { logger } from '../../utils/logger';
import { 
  BrowserArtifactType, 
  InterceptedAPI, 
  RouteTransition, 
  WebSocketSummary, 
  StorageSnapshot,
  DOMSink
} from '../../types';

const prisma = new PrismaClient();
const log = logger.child({ module: 'BrowserInstrumenter' });

export class BrowserInstrumenter {
  private scanId: string;
  private page: Page;
  
  private apis = new Map<string, InterceptedAPI>();
  private websockets = new Map<string, WebSocketSummary>();
  private routes: RouteTransition[] = [];
  private domSinks: DOMSink[] = [];

  constructor(scanId: string, page: Page) {
    this.scanId = scanId;
    this.page = page;
  }

  /**
   * Instrument the page by injecting tracking scripts and attaching listeners.
   */
  public async instrument() {
    await this.injectRouteTracker();
    await this.injectDOMSinkTracker();
    this.attachNetworkListeners();
  }

  /**
   * Harvest all collected artifacts and save them to the database.
   */
  public async harvestAndSave() {
    const storage = await this.captureStorage();

    const artifacts = [
      { type: 'apis' as BrowserArtifactType, payload: Array.from(this.apis.values()) },
      { type: 'websockets' as BrowserArtifactType, payload: Array.from(this.websockets.values()) },
      { type: 'routes' as BrowserArtifactType, payload: this.routes },
      { type: 'dom_sinks' as BrowserArtifactType, payload: this.domSinks },
      { type: 'storage' as BrowserArtifactType, payload: storage }
    ];

    for (const artifact of artifacts) {
      if (Array.isArray(artifact.payload) && artifact.payload.length === 0) continue;
      
      try {
        await prisma.browserArtifact.create({
          data: {
            scanId: this.scanId,
            artifactType: artifact.type,
            payload: JSON.stringify(artifact.payload)
          }
        });
      } catch (err) {
        log.error(`Failed to save browser artifact: ${artifact.type}`, { error: err });
      }
    }
    
    log.info(`Harvested browser artifacts`, { scanId: this.scanId, apis: this.apis.size, websockets: this.websockets.size, routes: this.routes.length });
  }

  private async injectRouteTracker() {
    await this.page.exposeFunction('__vulnforge_route_transition', (data: RouteTransition) => {
      // Cap at 100 transitions to prevent memory explosion
      if (this.routes.length < 100) {
        this.routes.push(data);
      }
    });

    await this.page.addInitScript(() => {
      let lastPath = window.location.pathname;

      const notify = (type: string, toPath: string) => {
        if (lastPath !== toPath && (window as any).__vulnforge_route_transition) {
          (window as any).__vulnforge_route_transition({
            fromPath: lastPath,
            toPath,
            type,
            timestamp: Date.now()
          });
          lastPath = toPath;
        }
      };

      const originalPushState = history.pushState;
      history.pushState = function(...args) {
        const result = originalPushState.apply(this, args);
        notify('pushState', window.location.pathname);
        return result;
      };

      const originalReplaceState = history.replaceState;
      history.replaceState = function(...args) {
        const result = originalReplaceState.apply(this, args);
        notify('replaceState', window.location.pathname);
        return result;
      };

      window.addEventListener('popstate', () => {
        notify('popstate', window.location.pathname);
      });
    });
  }

  private async injectDOMSinkTracker() {
    await this.page.exposeFunction('__vulnforge_dom_sink', (data: Omit<DOMSink, 'url'>) => {
      if (this.domSinks.length < 50) {
        this.domSinks.push({ ...data, url: this.page.url() });
      }
    });

    await this.page.addInitScript(() => {
      // Example instrumentation for eval
      const originalEval = window.eval;
      window.eval = function(code) {
        if ((window as any).__vulnforge_dom_sink) {
          (window as any).__vulnforge_dom_sink({
            sinkType: 'eval',
            timestamp: Date.now(),
            stackTrace: new Error().stack
          });
        }
        return originalEval(code);
      };

      // Monkey patching document.write
      const originalWrite = document.write;
      document.write = function(...args) {
        if ((window as any).__vulnforge_dom_sink) {
          (window as any).__vulnforge_dom_sink({
            sinkType: 'document.write',
            timestamp: Date.now()
          });
        }
        return originalWrite.apply(this, args);
      };
    });
  }

  private attachNetworkListeners() {
    this.page.on('response', async (response: Response) => {
      const request = response.request();
      const url = request.url();
      const resourceType = request.resourceType();
      
      // We only care about APIs (fetch, xhr)
      if (resourceType !== 'fetch' && resourceType !== 'xhr') return;
      if (this.apis.size > 200) return; // Hard cap

      try {
        const method = request.method();
        const status = response.status();
        const headers = await request.allHeaders();
        
        let reqSchema = undefined;
        let resSchema = undefined;
        
        // Simple schema inference: if it's JSON, capture the top-level keys
        if (request.postDataJSON()) {
          reqSchema = JSON.stringify(Object.keys(request.postDataJSON() || {}));
        }
        
        const contentType = response.headers()['content-type'] || '';
        if (contentType.includes('application/json')) {
          try {
            const body = await response.json();
            if (body && typeof body === 'object') {
              resSchema = JSON.stringify(Object.keys(body));
            }
          } catch {
             // Ignore parsing errors
          }
        }

        const key = `${method} ${url}`;
        this.apis.set(key, {
          url,
          method,
          requestHeaders: Object.keys(headers),
          requestBodySchema: reqSchema,
          responseStatus: status,
          responseSchema: resSchema,
          authSensitive: !!headers['authorization'] || !!headers['cookie'],
          mutationCapable: ['POST', 'PUT', 'DELETE', 'PATCH'].includes(method.toUpperCase())
        });

      } catch {
        // Silently handle errors reading responses
      }
    });

    this.page.on('websocket', ws => {
      const url = ws.url();
      if (!this.websockets.has(url) && this.websockets.size < 20) {
        this.websockets.set(url, {
          url,
          protocols: '',
          messagesSent: 0,
          messagesReceived: 0,
          authTokensDetected: url.includes('token=') || url.includes('auth='),
          sampleFrames: []
        });
      }

      const summary = this.websockets.get(url);
      if (!summary) return;

      ws.on('framesent', data => {
        summary.messagesSent++;
        if (summary.sampleFrames.length < 5) {
          summary.sampleFrames.push({ dir: 'sent', payloadPreview: this.previewFrame(data.payload) });
        }
        if (typeof data.payload === 'string' && (data.payload.includes('Bearer ') || data.payload.includes('token'))) {
            summary.authTokensDetected = true;
        }
      });

      ws.on('framereceived', data => {
        summary.messagesReceived++;
        if (summary.sampleFrames.length < 5) {
          summary.sampleFrames.push({ dir: 'recv', payloadPreview: this.previewFrame(data.payload) });
        }
      });
    });
  }

  private previewFrame(payload: string | Buffer): string {
    if (typeof payload === 'string') {
      return payload.length > 100 ? payload.substring(0, 100) + '...' : payload;
    }
    return '[Binary Data]';
  }

  private async captureStorage(): Promise<StorageSnapshot> {
    return await this.page.evaluate(() => {
      const localStorageKeys = Object.keys(window.localStorage || {});
      const sessionStorageKeys = Object.keys(window.sessionStorage || {});
      const cookies = document.cookie.split(';').map(c => c.split('=')[0].trim()).filter(Boolean);
      
      // Look for entropy / auth indications in localstorage
      let hasHighEntropyTokens = false;
      for (const key of localStorageKeys) {
        const val = window.localStorage.getItem(key) || '';
        if (val.length > 30 && (val.includes('eyJ') || /^[a-zA-Z0-9-_]+$/.test(val))) {
          hasHighEntropyTokens = true;
        }
      }

      return {
        origin: window.location.origin,
        localStorageKeys,
        sessionStorageKeys,
        cookies,
        indexedDBDatabases: [], // Requires async enumerate, skipped for brevity
        hasHighEntropyTokens
      };
    });
  }
}
