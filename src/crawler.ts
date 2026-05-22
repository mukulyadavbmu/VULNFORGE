import { chromium, Browser, Page, Request } from '@playwright/test';
import { AttackNode, AuthContext, NodeType, ScanSession } from './types';
import { addAttackNode } from './scanOrchestrator';
import { logger } from './utils/logger';
import { config } from './config';
import { JobDispatcher as JobDispatcherService } from './services/queue/JobDispatcher';
import { endpointDiscovery } from './services/recon/EndpointDiscovery';
import { BrowserInstrumenter } from './services/recon/BrowserInstrumenter';
import { SecurityFileDiscovery } from './services/recon/SecurityFileDiscovery';

interface CrawlOptions {
  maxPages?: number;
}

/** Paths/extensions that should NEVER be crawled or attacked */
const SKIP_PATHS = [
  '/socket.io',
  '/assets',
  '/img',
  '/vendor.js',
  '/polyfills.js',
  '/static',
  '/favicon',
  '.css',
  '.js',
  '.woff',
  '.ttf',
  '.eot',
  '.svg',
  '.png',
  '.jpg',
  '.gif',
];

/** Check if a path should be skipped */
function shouldSkipPath(url: string): boolean {
  const path = new URL(url).pathname.toLowerCase();
  return SKIP_PATHS.some(skip => path.includes(skip));
}

/** Check if a path is a valid attack target */
function isValidAttackTarget(url: string): boolean {
  const path = new URL(url).pathname.toLowerCase();
  // Accept same-origin, non-static request paths as attack targets.
  if (!path || path === '/') return true;
  return !/\.(css|js|png|jpg|jpeg|gif|svg|ico|woff2?|ttf|eot|map)$/i.test(path);
}

function makeNodeId(url: string, authContext: AuthContext, type: NodeType) {
  return `${authContext}:${type}:${url}`;
}

async function explorePage(
  session: ScanSession,
  page: Page,
  authContext: AuthContext,
  visited: Set<string>,
  queue: string[],
  options: CrawlOptions,
) {
  const currentUrl = page.url();
  if (visited.has(currentUrl) || shouldSkipPath(currentUrl)) return;
  visited.add(currentUrl);

  const nodeId = makeNodeId(currentUrl, authContext, 'page');
  const tags: string[] = [];
  if (/admin|manage|internal|debug|export|report|billing/i.test(currentUrl)) {
    tags.push('sensitive_path');
  }

  const params = new URL(currentUrl).searchParams;
  const paramNames = Array.from(params.keys());

  const node: AttackNode = {
    id: nodeId,
    url: currentUrl,
    type: 'page',
    authContext,
    params: paramNames,
    tags,
  };
  await addAttackNode(session, node);

  // Collect links and simple forms for further crawling
  const links = await page.$$eval('a[href]', (elements) =>
    elements.map((el) => (el as HTMLAnchorElement).href),
  );

  for (const href of links) {
    try {
      const urlObj = new URL(href);
      if (urlObj.origin === new URL(session.targetUrl).origin) {
        if (!visited.has(urlObj.toString()) && !shouldSkipPath(urlObj.toString())) {
          queue.push(urlObj.toString());
        }
      }
    } catch {
      // ignore bad URLs
    }
  }

  // ENHANCEMENT: Extract HTML forms with parameters and hidden inputs
  const formData = await page.evaluate(() => {
    const forms = Array.from(document.querySelectorAll('form'));
    return forms.map((form) => {
      const inputs = Array.from(form.querySelectorAll('input, textarea, select'));
      const fields = inputs.map((inp: any) => ({
        name: inp.name || inp.id,
        type: inp.type || 'text',
        value: inp.value || '',
      }));
      
      // Extract CSRF tokens
      const csrfTokens = inputs
        .filter((inp: any) => /csrf|xsrf|nonce|token/i.test(inp.name))
        .map((inp: any) => ({ name: inp.name, value: inp.value }));

      return {
        action: form.action,
        method: form.method || 'GET',
        fields: fields.map(f => f.name),
        hasHiddenInputs: fields.some(f => f.type === 'hidden'),
        csrfTokens,
      };
    });
  });

  // Add form endpoints as attack nodes
  for (const form of formData) {
    try {
      const formUrl = new URL(form.action, currentUrl);
      const targetOrigin = new URL(session.targetUrl).origin;
      
      if (!shouldSkipPath(formUrl.toString()) && formUrl.origin === targetOrigin) {
        const formNodeId = makeNodeId(formUrl.toString(), authContext, 'api');
        const formNode: AttackNode = {
          id: formNodeId,
          url: formUrl.toString(),
          method: form.method.toUpperCase(),
          type: 'api',
          authContext,
          params: form.fields,
          tags: form.hasHiddenInputs ? ['has_hidden_fields'] : [],
        };
        await addAttackNode(session, formNode);
      }
    } catch {
      // ignore
    }
  }

  // ENHANCEMENT: Extract potential SPA routes from JavaScript
  const jsRoutes = await page.evaluate(() => {
    const scripts = Array.from(document.scripts);
    const routePatterns: string[] = [];
    
    for (const script of scripts) {
      if (script.textContent) {
        // Look for route-like patterns in JavaScript
        const matches = script.textContent.match(/["'`]\/[a-zA-Z0-9\-_./:?#&=~+%]+["'`]/g) || [];
        for (const match of matches) {
          const route = match.slice(1, -1); // Remove quotes
          routePatterns.push(route);
        }
      }
    }
    return [...new Set(routePatterns)].slice(0, 20); // Return unique routes
  });

  // Add discovered routes to queue
  for (const route of jsRoutes) {
    try {
      const fullUrl = new URL(route, session.targetUrl).toString();
      if (!visited.has(fullUrl) && !shouldSkipPath(fullUrl)) {
        queue.push(fullUrl);
      }
    } catch {
      // ignore invalid routes
    }
  }

  // Generic endpoint discovery from scripts/forms/routes/inferred API URLs.
  try {
    await endpointDiscovery.discoverAll(session, page, authContext);
  } catch (error) {
    logger.debug('Endpoint discovery round failed', { scanId: session.id, error });
  }

  // ENHANCEMENT: Extract event listener hints (click handlers, form submits)
  const clickableElements = await page.$$eval(
    'button, a[onclick], [onclick], form',
    (elements) => elements.length,
  );

  if (clickableElements > 5) {
    tags.push('interactive_heavy');
  }

  // Basic SPA route detection (hash / pushState)
  const path = new URL(currentUrl).pathname;
  if (path && !visited.has(currentUrl) && !shouldSkipPath(currentUrl)) {
    queue.push(currentUrl);
  }

  if (visited.size >= (options.maxPages ?? 20)) {
    return;
  }
}

export async function crawlTarget(
  session: ScanSession,
  authContext: AuthContext,
  options: CrawlOptions = {},
): Promise<void> {
  const maxPages = options.maxPages ?? config.MAX_PAGES_PER_SCAN;

  // Use JobDispatcher to limit concurrent browsers
  await JobDispatcherService.scheduleBrowser(async () => {
    let browser: Browser | null = null;
    try {
      logger.info(`Starting crawl for ${session.targetUrl} as ${authContext}`, { scanId: session.id });
      browser = await chromium.launch({
        args: ['--no-sandbox', '--disable-setuid-sandbox']
      });
      const authHeaders = session.authHeaders[authContext] || {};
      const extraHTTPHeaders: Record<string, string> = {};
      const cookiesToSet: Array<{ name: string; value: string; domain: string; path: string }> = [];

      for (const [key, value] of Object.entries(authHeaders)) {
        if (key.toLowerCase() === 'cookie') {
          // Parse cookie string into Playwright format
          const cookiePairs = value.split(';').map(c => c.trim());
          const domain = new URL(session.targetUrl).hostname;
          for (const pair of cookiePairs) {
            const match = /^([^=]+)=(.+)$/.exec(pair);
            if (match) {
              cookiesToSet.push({
                name: match[1],
                value: match[2],
                domain,
                path: '/'
              });
            }
          }
        } else {
          extraHTTPHeaders[key] = value;
        }
      }

      const context = await browser.newContext({ extraHTTPHeaders });
      if (cookiesToSet.length > 0) {
        await context.addCookies(cookiesToSet);
      }
      const page = await context.newPage();

      // PHASE 4: Attach Browser Instrumenter
      const instrumenter = new BrowserInstrumenter(session.id, page);
      await instrumenter.instrument();

      // PHASE 6C: Security File Discovery
      try {
        const securityFiles = await SecurityFileDiscovery.discoverAll(session.targetUrl, session.id);
        const { PrismaClient } = await import('@prisma/client');
        const prisma = new PrismaClient();
        for (const file of securityFiles) {
          if (file.exists) {
            await prisma.browserArtifact.create({
              data: {
                scanId: session.id,
                artifactType: 'security_files',
                payload: JSON.stringify(file)
              }
            });
          }
        }
        await prisma.$disconnect();
      } catch (err) {
        logger.error('Security file discovery failed', { error: err, scanId: session.id });
      }

      // Dynamic API endpoint discovery via network requests
      page.on('request', (req: Request) => {
        const resourceType = req.resourceType();
        if (resourceType !== 'xhr' && resourceType !== 'fetch') return;
        const url = req.url();
        try {
          const urlObj = new URL(url);
          if (urlObj.origin !== new URL(session.targetUrl).origin) return;
          if (shouldSkipPath(url)) return;
          if (!isValidAttackTarget(url)) return;

          logger.debug(`API endpoint discovered: ${url}`, { scanId: session.id });
          endpointDiscovery
            .registerNetworkEndpoint(session, authContext, urlObj.toString(), req.method())
            .catch(e => logger.error('Failed to add network endpoint', { error: e }));
        } catch {
          // ignore malformed URLs
        }
      });

      // Parse response bodies for embedded URLs/API paths.
      page.on('response', async (res) => {
        try {
          const req = res.request();
          const reqUrl = req.url();
          const origin = new URL(session.targetUrl).origin;
          if (!reqUrl.startsWith(origin)) return;

          const contentType = (res.headers()['content-type'] || '').toLowerCase();
          if (!contentType.includes('json') && !contentType.includes('text')) return;

          const body = await res.text();
          if (!body || body.length > 512_000) return;

          const matches = body.matchAll(/https?:\/\/[^"'\s]+|\/(?:api|graphql|auth|users?|admin|internal)[^"'\s]*/gi);
          for (const m of matches) {
            const candidate = m[0];
            endpointDiscovery
              .registerNetworkEndpoint(session, authContext, candidate, 'GET')
              .catch(() => undefined);
          }
        } catch {
          // Ignore response parsing failures.
        }
      });

      const queue: string[] = [session.targetUrl];
      const visited = new Set<string>();

      while (queue.length > 0 && visited.size < maxPages) {
        const nextUrl = queue.shift();
        if (!nextUrl || visited.has(nextUrl)) continue;

        logger.debug(`Crawling page: ${nextUrl}`, { scanId: session.id });
        try {
          await page.goto(nextUrl, { waitUntil: 'domcontentloaded', timeout: config.NAV_TIMEOUT_MS });
          await explorePage(session, page, authContext, visited, queue, options);
        } catch (err) {
          logger.warn(`Failed to crawl ${nextUrl}`, { error: err, scanId: session.id });
        }
      }
      
      // PHASE 4: Harvest browser artifacts
      if (typeof instrumenter !== 'undefined') {
        await instrumenter.harvestAndSave();
      }
    } catch (err) {
      logger.error('Crawl fatal error', { error: err, scanId: session.id });
    } finally {
      if (browser) {
        await browser.close();
        logger.info(`Crawl finished for ${session.targetUrl}`, { scanId: session.id });
      }
    }
  });
}
