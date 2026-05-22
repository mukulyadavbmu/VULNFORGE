import { Page } from '@playwright/test';
import axios from 'axios';
import { AttackNode, AuthContext, ScanSession } from '../../types';
import { addAttackNode } from '../../scanOrchestrator';
import { logger } from '../../utils/logger';

interface DiscoveredEndpoint {
  url: string;
  method: string;
  source: 'javascript' | 'spa_route' | 'form' | 'inferred_api' | 'robots' | 'sitemap' | 'network' | 'heuristic';
  confidence: number;
}

const GENERIC_API_HINTS = [
  '/api',
  '/api/v1',
  '/api/v2',
  '/graphql',
  '/auth',
  '/login',
  '/oauth',
  '/users',
  '/me',
  '/profile',
  '/admin',
  '/internal',
  '/health',
  '/metrics',
];

export class EndpointDiscovery {
  private discovered = new Set<string>();

  async discoverAll(session: ScanSession, page: Page, authContext: AuthContext): Promise<DiscoveredEndpoint[]> {
    const baseUrl = session.targetUrl;

    const [
      jsEndpoints,
      formEndpoints,
      routeEndpoints,
      inferredApiEndpoints,
      robotsEndpoints,
      sitemapEndpoints,
      heuristicEndpoints,
    ] = await Promise.all([
      this.discoverFromJavaScript(page, baseUrl),
      this.discoverFromForms(page, baseUrl),
      this.discoverFromSpaRoutes(page, baseUrl),
      this.discoverFromInlineApiResponses(page, baseUrl),
      this.discoverFromRobots(baseUrl),
      this.discoverFromSitemap(baseUrl),
      this.discoverFromGenericHeuristics(baseUrl),
    ]);

    const rawEndpoints = [
      ...jsEndpoints,
      ...formEndpoints,
      ...routeEndpoints,
      ...inferredApiEndpoints,
      ...robotsEndpoints,
      ...sitemapEndpoints,
      ...heuristicEndpoints,
    ];

    const filteredEndpoints = rawEndpoints.filter(e => !this.isNoise(e.url));
    const endpoints = this.deduplicateEndpoints(filteredEndpoints);

    for (const endpoint of endpoints) {
      await this.registerEndpoint(session, endpoint, authContext);
    }

    logger.info('[ENDPOINT DISCOVERY] Discovery round complete', {
      scanId: session.id,
      discoveredTotal: endpoints.length,
      bySource: {
        javascript: jsEndpoints.length,
        forms: formEndpoints.length,
        routes: routeEndpoints.length,
        inferredApi: inferredApiEndpoints.length,
        robots: robotsEndpoints.length,
        sitemap: sitemapEndpoints.length,
        heuristic: heuristicEndpoints.length,
      },
    });

    return endpoints;
  }

  // Parse JavaScript for fetch/axios/xhr/http client calls and GraphQL payloads.
  private async discoverFromJavaScript(page: Page, baseUrl: string): Promise<DiscoveredEndpoint[]> {
    const endpoints: DiscoveredEndpoint[] = [];

    try {
      const scriptUrls = await page.$$eval('script[src]', scripts =>
        scripts
          .map(s => (s as HTMLScriptElement).src)
          .filter(Boolean),
      );

      for (const scriptUrl of scriptUrls) {
        if (!scriptUrl) continue;

        try {
          const resolvedScriptUrl = new URL(scriptUrl, baseUrl).toString();
          const origin = new URL(baseUrl).origin;
          if (!resolvedScriptUrl.startsWith(origin)) continue;

          const response = await axios.get(resolvedScriptUrl, { timeout: 5000, validateStatus: () => true });
          if (response.status >= 400 || typeof response.data !== 'string') continue;

          endpoints.push(...this.extractEndpointsFromScript(response.data, baseUrl));
        } catch {
          // Ignore broken or inaccessible scripts.
        }
      }
    } catch {
      // Ignore script discovery failures.
    }

    return endpoints;
  }

  private extractEndpointsFromScript(content: string, baseUrl: string): DiscoveredEndpoint[] {
    const endpoints: DiscoveredEndpoint[] = [];

    const patterns: Array<{ regex: RegExp; methodGroup?: number; urlGroup: number; confidence: number }> = [
      { regex: /fetch\s*\(\s*["'`]([^"'`]+)["'`]/g, urlGroup: 1, confidence: 0.92 },
      { regex: /axios\s*\.\s*(get|post|put|patch|delete)\s*\(\s*["'`]([^"'`]+)["'`]/g, methodGroup: 1, urlGroup: 2, confidence: 0.95 },
      { regex: /(?:this\.)?http\s*\.\s*(get|post|put|patch|delete)\s*\(\s*["'`]([^"'`]+)["'`]/g, methodGroup: 1, urlGroup: 2, confidence: 0.95 },
      { regex: /\.open\s*\(\s*["'`](GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)["'`]\s*,\s*["'`]([^"'`]+)["'`]/g, methodGroup: 1, urlGroup: 2, confidence: 0.9 },
      { regex: /["'`]((?:\/|https?:\/\/)[^"'`]*(?:api|graphql|auth|login|token|user|admin)[^"'`]*)["'`]/gi, urlGroup: 1, confidence: 0.72 },
    ];

    for (const pattern of patterns) {
      const matches = content.matchAll(pattern.regex);
      for (const match of matches) {
        const rawUrl = match[pattern.urlGroup];
        if (!rawUrl) continue;

        const method = pattern.methodGroup ? (match[pattern.methodGroup] || 'GET').toUpperCase() : 'GET';
        const normalized = this.normalizePotentialUrl(rawUrl, baseUrl);
        if (!normalized) continue;

        endpoints.push({
          url: normalized,
          method,
          source: 'javascript',
          confidence: pattern.confidence,
        });
      }
    }

    // Detect GraphQL endpoint hints from query declarations.
    if (/query\s+[A-Za-z0-9_]+\s*\{|mutation\s+[A-Za-z0-9_]+\s*\{/i.test(content)) {
      const graphQlUrl = this.normalizePotentialUrl('/graphql', baseUrl);
      if (graphQlUrl) {
        endpoints.push({
          url: graphQlUrl,
          method: 'POST',
          source: 'javascript',
          confidence: 0.65,
        });
      }
    }

    return endpoints;
  }

  private async discoverFromForms(page: Page, baseUrl: string): Promise<DiscoveredEndpoint[]> {
    const endpoints: DiscoveredEndpoint[] = [];

    try {
      const forms = await page.$$eval('form', allForms =>
        allForms.map(f => {
          const form = f as HTMLFormElement;
          return {
            action: form.getAttribute('action') || '',
            method: (form.getAttribute('method') || 'GET').toUpperCase(),
          };
        }),
      );

      for (const form of forms) {
        const normalized = this.normalizePotentialUrl(form.action || page.url(), baseUrl);
        if (!normalized) continue;
        endpoints.push({
          url: normalized,
          method: form.method || 'GET',
          source: 'form',
          confidence: 0.9,
        });
      }
    } catch {
      // Ignore form parsing errors.
    }

    return endpoints;
  }

  private async discoverFromSpaRoutes(page: Page, baseUrl: string): Promise<DiscoveredEndpoint[]> {
    const endpoints: DiscoveredEndpoint[] = [];

    try {
      const routeCandidates = await page.evaluate(() => {
        const candidates = new Set<string>();

        const navElements = Array.from(document.querySelectorAll('a[href], [data-route], [routerLink], [to]'));
        for (const el of navElements) {
          const attrs = ['href', 'data-route', 'routerLink', 'to'];
          for (const attr of attrs) {
            const value = el.getAttribute(attr);
            if (value && value.startsWith('/')) {
              candidates.add(value);
            }
          }
        }

        const scripts = Array.from(document.querySelectorAll('script:not([src])'));
        for (const script of scripts) {
          const text = script.textContent || '';
          const routeMatches = text.matchAll(/["'`]\/(?!\/)([a-zA-Z0-9_\-./]{1,120})["'`]/g);
          for (const match of routeMatches) {
            candidates.add(`/${match[1]}`);
          }
        }

        return Array.from(candidates).slice(0, 80);
      });

      for (const route of routeCandidates) {
        const normalized = this.normalizePotentialUrl(route, baseUrl);
        if (!normalized) continue;
        endpoints.push({
          url: normalized,
          method: 'GET',
          source: 'spa_route',
          confidence: 0.78,
        });
      }
    } catch {
      // Ignore SPA route extraction errors.
    }

    return endpoints;
  }

  // Parse JSON blobs and inline script literals that include API URLs.
  private async discoverFromInlineApiResponses(page: Page, baseUrl: string): Promise<DiscoveredEndpoint[]> {
    const endpoints: DiscoveredEndpoint[] = [];

    try {
      const urlCandidates = await page.evaluate(() => {
        const candidates = new Set<string>();

        const jsonScripts = Array.from(document.querySelectorAll('script[type="application/json"], script[type="application/ld+json"]'));
        for (const script of jsonScripts) {
          const text = script.textContent || '';
          const matches = text.matchAll(/https?:\/\/[^"'\s]+|\/(?:api|graphql|auth|users?|admin|internal)[^"'\s]*/gi);
          for (const match of matches) {
            candidates.add(match[0]);
          }
        }

        const allHtml = document.documentElement?.outerHTML || '';
        const htmlMatches = allHtml.matchAll(/https?:\/\/[^"'\s]+|\/(?:api|graphql|auth|users?|admin|internal)[^"'\s]*/gi);
        for (const match of htmlMatches) {
          candidates.add(match[0]);
        }

        return Array.from(candidates).slice(0, 100);
      });

      for (const candidate of urlCandidates) {
        const normalized = this.normalizePotentialUrl(candidate, baseUrl);
        if (!normalized) continue;
        endpoints.push({
          url: normalized,
          method: 'GET',
          source: 'inferred_api',
          confidence: 0.74,
        });
      }
    } catch {
      // Ignore page extraction errors.
    }

    return endpoints;
  }

  private async discoverFromRobots(baseUrl: string): Promise<DiscoveredEndpoint[]> {
    const endpoints: DiscoveredEndpoint[] = [];

    try {
      const robotsUrl = new URL('/robots.txt', baseUrl).toString();
      const response = await axios.get(robotsUrl, { timeout: 3000, validateStatus: () => true });
      if (response.status >= 400 || typeof response.data !== 'string') return endpoints;

      const lines = response.data.split(/\r?\n/);
      for (const line of lines) {
        const m = line.match(/^(?:Allow|Disallow):\s*(.+)$/i);
        if (!m || !m[1]) continue;
        const normalized = this.normalizePotentialUrl(m[1].trim(), baseUrl);
        if (!normalized) continue;

        endpoints.push({
          url: normalized,
          method: 'GET',
          source: 'robots',
          confidence: 0.8,
        });
      }
    } catch {
      // Ignore robots errors.
    }

    return endpoints;
  }

  private async discoverFromSitemap(baseUrl: string): Promise<DiscoveredEndpoint[]> {
    const endpoints: DiscoveredEndpoint[] = [];

    try {
      const sitemapUrl = new URL('/sitemap.xml', baseUrl).toString();
      const response = await axios.get(sitemapUrl, { timeout: 3000, validateStatus: () => true });
      if (response.status >= 400 || typeof response.data !== 'string') return endpoints;

      const matches = response.data.matchAll(/<loc>([^<]+)<\/loc>/gi);
      for (const match of matches) {
        const normalized = this.normalizePotentialUrl(match[1], baseUrl);
        if (!normalized) continue;

        endpoints.push({
          url: normalized,
          method: 'GET',
          source: 'sitemap',
          confidence: 0.9,
        });
      }
    } catch {
      // Ignore sitemap errors.
    }

    return endpoints;
  }

  // Generic API inference probes only for broad/common API bases.
  private async discoverFromGenericHeuristics(baseUrl: string): Promise<DiscoveredEndpoint[]> {
    const endpoints: DiscoveredEndpoint[] = [];

    for (const path of GENERIC_API_HINTS) {
      const url = new URL(path, baseUrl).toString();

      try {
        const response = await axios.request({
          url,
          method: 'OPTIONS',
          timeout: 2500,
          validateStatus: () => true,
        });

        if (response.status !== 404 && response.status < 500) {
          endpoints.push({
            url,
            method: 'GET',
            source: 'heuristic',
            confidence: 0.58,
          });
        }
      } catch {
        // Ignore inaccessible inferred endpoints.
      }
    }

    return endpoints;
  }

  private normalizePotentialUrl(candidate: string, baseUrl: string): string | null {
    try {
      const cleaned = candidate
        .trim()
        .replace(/\$\{[^}]+\}/g, '1')
        .replace(/["'`]/g, '');

      if (!cleaned) return null;

      const absolute = new URL(cleaned, baseUrl);
      if (absolute.origin !== new URL(baseUrl).origin) return null;
      if (/\.(css|js|map|png|jpg|jpeg|gif|svg|ico|woff2?|ttf|eot)$/i.test(absolute.pathname)) return null;

      return absolute.toString();
    } catch {
      return null;
    }
  }

  private isNoise(urlStr: string): boolean {
    try {
      const url = new URL(urlStr);
      const path = url.pathname.toLowerCase();
      
      // Filter out common framework telemetry, socket.io, and metrics
      if (/socket\.io|websocket|\/telemetry|\/metrics|\/_next|\/webpack-hmr/.test(path)) return true;
      // Filter out extensive static asset patterns
      if (/\.(css|js|map|png|jpg|jpeg|gif|svg|ico|woff2?|ttf|eot|mp4|webm|wav|mp3|ogg)$/i.test(path)) return true;
      
      return false;
    } catch {
      return true;
    }
  }

  private deduplicateEndpoints(endpoints: DiscoveredEndpoint[]): DiscoveredEndpoint[] {
    const map = new Map<string, DiscoveredEndpoint>();

    for (const endpoint of endpoints) {
      let normalizedUrl = endpoint.url;
      try {
        const urlObj = new URL(endpoint.url);
        // Collapse SPA routes with numeric/UUID parameters to a common placeholder
        const pathSegments = urlObj.pathname.split('/');
        const collapsedSegments = pathSegments.map(segment => {
          if (/^[0-9]+$/.test(segment) || /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(segment)) {
            return '{id}';
          }
          return segment;
        });
        urlObj.pathname = collapsedSegments.join('/');
        normalizedUrl = urlObj.toString();
      } catch {
        // ignore malformed URLs
      }

      const key = `${endpoint.method}:${normalizedUrl}`;
      const current = map.get(key);
      if (!current || endpoint.confidence > current.confidence) {
        map.set(key, endpoint);
      }
    }

    return Array.from(map.values());
  }

  private async registerEndpoint(session: ScanSession, endpoint: DiscoveredEndpoint, authContext: AuthContext): Promise<void> {
    const tags = this.inferTags(endpoint);
    const prioritization = this.calculatePrioritization(endpoint, tags);
    
    const node: AttackNode = {
      id: `${authContext}:api:${endpoint.url}`,
      url: endpoint.url,
      method: endpoint.method,
      type: 'api',
      authContext,
      params: Array.from(new URL(endpoint.url).searchParams.keys()),
      tags,
      priorityScore: prioritization.score,
      attackDepthLevel: prioritization.depth,
      fuzzBudget: prioritization.budget,
    };

    await addAttackNode(session, node);
    this.discovered.add(endpoint.url);
  }

  private calculatePrioritization(endpoint: DiscoveredEndpoint, tags: string[]) {
    let score = 50; // Base score
    let depth = 2; // Default moderate depth
    let budget: {
      mutations: number;
      replays: number;
      verifyDepth: 'shallow' | 'deep';
      maxRoleTransitions: number;
      verificationRetries: number;
    } = { mutations: 10, replays: 1, verifyDepth: 'shallow', maxRoleTransitions: 4, verificationRetries: 1 };

    const urlObj = new URL(endpoint.url);
    const path = urlObj.pathname.toLowerCase();
    const paramCount = Array.from(urlObj.searchParams.keys()).length;

    // --- Tier 1 tags: Critical attack surface ---
    if (tags.includes('sensitive_api'))   { score += 30; depth = 5; }
    if (tags.includes('admin'))           { score += 35; depth = 5; }
    if (tags.includes('payment'))         { score += 40; depth = 5; }
    if (tags.includes('auth_related'))    { score += 20; depth = 4; }
    if (tags.includes('upload_surface'))  { score += 25; depth = 4; }
    if (tags.includes('user_mgmt'))       { score += 20; depth = 4; }

    // --- Tier 2 tags: Medium attack surface ---
    if (tags.includes('graphql'))         { score += 15; depth = Math.max(depth, 3); }
    if (tags.includes('websocket'))       { score += 15; depth = Math.max(depth, 3); }

    // --- Tier 3 tags: Low-value / deprioritize ---
    if (tags.includes('telemetry'))       { score = Math.max(score - 20, 10); depth = Math.min(depth, 2); }
    if (tags.includes('static'))          { score = Math.max(score - 40, 5);  depth = 1; }
    if (tags.includes('internal_infra'))  { score = Math.max(score - 30, 5);  depth = 1; }

    // High parameter count increases surface area risk
    if (paramCount > 2) {
      score += 10;
      depth = Math.min(depth + 1, 5);
    }

    // Aggressively deprioritize known noisy/health paths
    if (/\/(health|ping|status|favicon|robots\.txt|\/public\/)/i.test(path)) {
      score = Math.max(score - 50, 5);
      depth = 1;
    }

    score = Math.min(score, 100);

    // Finalize budget based on depth tier
    if (depth === 5) {
      budget = { mutations: 100, replays: 3, verifyDepth: 'deep',    maxRoleTransitions: 12, verificationRetries: 3 };
    } else if (depth === 4) {
      budget = { mutations: 50,  replays: 2, verifyDepth: 'deep',    maxRoleTransitions: 8,  verificationRetries: 2 };
    } else if (depth === 3) {
      budget = { mutations: 25,  replays: 1, verifyDepth: 'shallow', maxRoleTransitions: 4,  verificationRetries: 1 };
    } else if (depth === 2) {
      budget = { mutations: 10,  replays: 1, verifyDepth: 'shallow', maxRoleTransitions: 4,  verificationRetries: 1 };
    } else {
      budget = { mutations: 3,   replays: 0, verifyDepth: 'shallow', maxRoleTransitions: 2,  verificationRetries: 0 };
    }

    return { score, depth, budget };
  }

  private inferTags(endpoint: DiscoveredEndpoint): string[] {
    const path = new URL(endpoint.url).pathname.toLowerCase();
    const tags = [endpoint.source, 'api'];

    // Tier 1: Critical
    if (/\/admin|internal|debug|config|manage|system|panel|dashboard/.test(path)) {
      tags.push('sensitive_api', 'admin');
    }
    if (/payment|checkout|billing|invoice|wallet|purchase|order|cart|price/.test(path)) {
      tags.push('payment');
    }
    if (/\/auth|login|logout|token|session|oauth|sso|saml|password|register|signup/.test(path)) {
      tags.push('auth_related');
    }
    if (/\/user|account|profile|member|role|permission|group/.test(path)) {
      tags.push('user_mgmt');
    }
    if (/upload|file|document|media|attachment|import|export/.test(path)) {
      tags.push('upload_surface');
    }

    // Tier 2: Medium
    if (/graphql/.test(path)) tags.push('graphql');
    if (/websocket|ws\/|socket/.test(path)) tags.push('websocket');

    // Tier 3: Deprioritize
    if (/\/metrics|telemetry|healthz|readyz|livez|prometheus/.test(path)) tags.push('telemetry');
    if (/\.(css|js|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|map)$/.test(path)) tags.push('static');
    if (/\/actuator|\/swagger|\/openapi|\/docs|\/redoc/.test(path)) tags.push('internal_infra');

    return tags;
  }

  registerNetworkEndpoint(
    session: ScanSession,
    authContext: AuthContext,
    url: string,
    method: string,
  ): Promise<void> {
    const normalized = this.normalizePotentialUrl(url, session.targetUrl);
    if (!normalized) return Promise.resolve();

    return this.registerEndpoint(session, {
      url: normalized,
      method: method.toUpperCase(),
      source: 'network',
      confidence: 0.88,
    }, authContext);
  }

  getStats(): { totalDiscovered: number } {
    return { totalDiscovered: this.discovered.size };
  }

  reset(): void {
    this.discovered.clear();
  }
}

export const endpointDiscovery = new EndpointDiscovery();
