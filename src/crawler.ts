import { chromium, Browser, Page, Request } from '@playwright/test';
import { AttackNode, AuthContext, NodeType, ScanSession } from './types';
import { addAttackNode } from './scanOrchestrator';
import { logger } from './utils/logger';
import { config } from './config';
import { JobDispatcher as JobDispatcherService } from './services/queue/JobDispatcher';

interface CrawlOptions {
  maxPages?: number;
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
  if (visited.has(currentUrl)) return;
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
        if (!visited.has(urlObj.toString())) {
          queue.push(urlObj.toString());
        }
      }
    } catch {
      // ignore bad URLs
    }
  }

  // Basic SPA route detection (hash / pushState)
  const path = new URL(currentUrl).pathname;
  if (path && !visited.has(currentUrl)) {
    queue.push(currentUrl);
  }

  // API endpoint discovery via network logs could be added here
  // to keep this MVP lightweight we focus on page URLs for now.

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
      browser = await chromium.launch();
      const context = await browser.newContext();
      const page = await context.newPage();

      // Dynamic API endpoint discovery via network requests
      page.on('request', (req: Request) => {
        const resourceType = req.resourceType();
        if (resourceType !== 'xhr' && resourceType !== 'fetch') return;
        const url = req.url();
        try {
          const urlObj = new URL(url);
          if (urlObj.origin !== new URL(session.targetUrl).origin) return;

          logger.debug(`API endpoint discovered: ${url}`, { scanId: session.id });

          const nodeId = makeNodeId(urlObj.toString(), authContext, 'api');
          const params = Array.from(urlObj.searchParams.keys());
          const tags: string[] = ['api'];
          if (/users?|accounts?|orders?|profile|token|auth|admin/i.test(url)) {
            tags.push('sensitive_api');
          }
          const node: AttackNode = {
            id: nodeId,
            url: urlObj.toString(),
            type: 'api',
            authContext,
            params,
            tags,
          };
          addAttackNode(session, node).catch(e => logger.error('Failed to add API node', { error: e }));
        } catch {
          // ignore malformed URLs
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
