/**
 * SecurityFileDiscovery.ts
 *
 * Proactively fetches and parses security-relevant files from a target application.
 * Discovers: robots.txt, sitemap.xml, security.txt, /.well-known/*, API docs, etc.
 */

import { logger } from '../../utils/logger';

export interface SecurityFile {
  url: string;
  type: 'robots_txt' | 'sitemap_xml' | 'security_txt' | 'well_known' | 'openapi' | 'graphql' | 'admin' | 'backup';
  status: number;
  exists: boolean;
  content?: string;
  parsedData?: Record<string, any>;
  discoveredAt: number;
}

// Probes to run against every target
const SECURITY_PROBES: Array<{ path: string; type: SecurityFile['type'] }> = [
  { path: '/robots.txt', type: 'robots_txt' },
  { path: '/sitemap.xml', type: 'sitemap_xml' },
  { path: '/sitemap_index.xml', type: 'sitemap_xml' },
  { path: '/security.txt', type: 'security_txt' },
  { path: '/.well-known/security.txt', type: 'security_txt' },
  { path: '/.well-known/openid-configuration', type: 'well_known' },
  { path: '/.well-known/oauth-authorization-server', type: 'well_known' },
  { path: '/.well-known/jwks.json', type: 'well_known' },
  { path: '/api/swagger.json', type: 'openapi' },
  { path: '/api/openapi.json', type: 'openapi' },
  { path: '/openapi.yaml', type: 'openapi' },
  { path: '/swagger.json', type: 'openapi' },
  { path: '/swagger/v1/swagger.json', type: 'openapi' },
  { path: '/api-docs', type: 'openapi' },
  { path: '/api/docs', type: 'openapi' },
  { path: '/graphql', type: 'graphql' },
  { path: '/graphiql', type: 'graphql' },
  { path: '/api/graphql', type: 'graphql' },
  { path: '/admin', type: 'admin' },
  { path: '/admin/login', type: 'admin' },
  { path: '/administrator', type: 'admin' },
  { path: '/wp-admin', type: 'admin' },
  { path: '/wp-login.php', type: 'admin' },
  { path: '/phpmyadmin', type: 'admin' },
  { path: '/backup', type: 'backup' },
  { path: '/backup.zip', type: 'backup' },
  { path: '/backup.tar.gz', type: 'backup' },
  { path: '/.git/config', type: 'backup' },
  { path: '/.env', type: 'backup' },
  { path: '/.env.production', type: 'backup' },
  { path: '/config.json', type: 'backup' },
  { path: '/package.json', type: 'backup' },
];

export class SecurityFileDiscovery {
  /**
   * Probe all well-known security files for a target origin.
   */
  static async discoverAll(targetUrl: string, scanId: string): Promise<SecurityFile[]> {
    const origin = new URL(targetUrl).origin;
    const results: SecurityFile[] = [];

    logger.info(`SecurityFileDiscovery: probing ${SECURITY_PROBES.length} paths for ${origin}`, { scanId });

    // Run probes with controlled concurrency (4 at a time)
    const concurrency = 4;
    for (let i = 0; i < SECURITY_PROBES.length; i += concurrency) {
      const batch = SECURITY_PROBES.slice(i, i + concurrency);
      const batchResults = await Promise.allSettled(
        batch.map(probe => this.probeFile(origin, probe.path, probe.type, scanId))
      );
      for (const result of batchResults) {
        if (result.status === 'fulfilled' && result.value) {
          results.push(result.value);
        }
      }
    }

    const found = results.filter(r => r.exists).length;
    logger.info(`SecurityFileDiscovery: found ${found}/${results.length} files for ${origin}`, { scanId });
    return results;
  }

  private static async probeFile(
    origin: string,
    path: string,
    type: SecurityFile['type'],
    scanId: string
  ): Promise<SecurityFile | null> {
    const url = `${origin}${path}`;
    const discoveredAt = Date.now();

    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 8000);

      const res = await fetch(url, {
        method: 'GET',
        signal: controller.signal,
        headers: {
          'User-Agent': 'VulnForge-Security-Scanner/1.0',
          'Accept': 'text/plain,application/json,text/xml,*/*',
        },
        redirect: 'follow',
      });
      clearTimeout(timeout);

      const exists = res.status < 400;
      let content: string | undefined;
      let parsedData: Record<string, any> | undefined;

      if (exists && res.status === 200) {
        const rawContent = await res.text();
        // Truncate very large files
        content = rawContent.length > 50_000 ? rawContent.slice(0, 50_000) + '\n... [truncated]' : rawContent;

        // Parse structured files
        parsedData = this.parseContent(type, content);
      }

      return {
        url,
        type,
        status: res.status,
        exists,
        content,
        parsedData,
        discoveredAt,
      };
    } catch (err: any) {
      if (err?.name === 'AbortError') {
        logger.debug(`SecurityFileDiscovery: timeout for ${url}`, { scanId });
      }
      return {
        url,
        type,
        status: 0,
        exists: false,
        discoveredAt,
      };
    }
  }

  private static parseContent(type: SecurityFile['type'], content: string): Record<string, any> | undefined {
    try {
      if (type === 'robots_txt') {
        return this.parseRobotsTxt(content);
      }
      if (type === 'sitemap_xml') {
        return this.parseSitemapXml(content);
      }
      if (type === 'security_txt') {
        return this.parseSecurityTxt(content);
      }
      if (type === 'openapi') {
        // Best-effort JSON parse
        const parsed = JSON.parse(content);
        return {
          title: parsed?.info?.title,
          version: parsed?.info?.version,
          pathCount: Object.keys(parsed?.paths || {}).length,
        };
      }
      if (type === 'well_known') {
        return JSON.parse(content);
      }
    } catch {
      // Ignore parse errors
    }
    return undefined;
  }

  private static parseRobotsTxt(content: string): Record<string, any> {
    const lines = content.split('\n').map(l => l.trim()).filter(Boolean);
    const disallowed: string[] = [];
    const allowed: string[] = [];
    const sitemaps: string[] = [];
    let currentAgent = '*';

    for (const line of lines) {
      if (line.startsWith('#')) continue;
      const [directive, ...rest] = line.split(':');
      const value = rest.join(':').trim();
      const dir = directive.trim().toLowerCase();

      if (dir === 'user-agent') currentAgent = value;
      else if (dir === 'disallow' && value) disallowed.push(value);
      else if (dir === 'allow' && value) allowed.push(value);
      else if (dir === 'sitemap') sitemaps.push(value);
    }

    return {
      disallowed: [...new Set(disallowed)],
      allowed: [...new Set(allowed)],
      sitemaps,
      sensitivePathCount: disallowed.filter(p => 
        /admin|secret|internal|backup|config|debug|api|private/i.test(p)
      ).length,
    };
  }

  private static parseSitemapXml(content: string): Record<string, any> {
    const urlMatches = content.matchAll(/<loc>([^<]+)<\/loc>/g);
    const urls = [...urlMatches].map(m => m[1]);
    return {
      urlCount: urls.length,
      urls: urls.slice(0, 50), // First 50 for display
    };
  }

  private static parseSecurityTxt(content: string): Record<string, any> {
    const fields: Record<string, string[]> = {};
    const lines = content.split('\n').map(l => l.trim()).filter(l => l && !l.startsWith('#'));

    for (const line of lines) {
      const colonIdx = line.indexOf(':');
      if (colonIdx === -1) continue;
      const key = line.slice(0, colonIdx).trim().toLowerCase();
      const value = line.slice(colonIdx + 1).trim();
      if (!fields[key]) fields[key] = [];
      fields[key].push(value);
    }

    return fields;
  }
}
