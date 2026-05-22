/**
 * Part 5 — CorrelationEngine
 * Correlates findings to detect systemic weaknesses.
 * Uses finding summaries only — never raw DB scans.
 * O(n) single pass over findings.
 */
import { ScanFinding } from '../../types';
import { CorrelationResult } from '../../strategy.types';
import { strategyFlags } from '../../strategyConfig';
import { logger } from '../../utils/logger';

const log = logger.child({ module: 'CorrelationEngine' });

const INJECTION_TYPES: ReadonlySet<string> = new Set([
    'sqli', 'xss', 'ssti', 'csti', 'rce', 'lfi', 'proto_pollution',
]);

const AUTH_TYPES: ReadonlySet<string> = new Set([
    'bac', 'idor', 'csrf', 'cors', 'websocket', 'auth_weakness',
]);

export class CorrelationEngine {
    /**
     * Analyze findings for systemic patterns.
     * O(n) single pass. No DB calls.
     */
    static correlate(findings: ScanFinding[], scanId: string): CorrelationResult {
        if (!strategyFlags.ENABLE_CORRELATION_ENGINE) {
            return {
                systemicWeaknessScore: 0,
                recurringPatternList: [],
                injectionLikelihood: 0,
                authWeaknessLikelihood: 0,
            };
        }

        const start = Date.now();

        // Type frequency map — O(n) single pass
        const typeCount: Map<string, number> = new Map();
        const severityCount: Record<string, number> = { low: 0, medium: 0, high: 0, critical: 0 };
        let injectionFindings = 0;
        let authFindings = 0;

        for (const finding of findings) {
            // Count by type
            typeCount.set(finding.type, (typeCount.get(finding.type) ?? 0) + 1);
            // Count by severity
            severityCount[finding.severity]++;
            // Categorize
            if (INJECTION_TYPES.has(finding.type)) injectionFindings++;
            if (AUTH_TYPES.has(finding.type)) authFindings++;
        }

        // Recurring patterns: any type found 2+ times
        const recurringPatternList: string[] = [];
        for (const [type, count] of typeCount) {
            if (count >= 2) {
                recurringPatternList.push(`${type} (${count} occurrences)`);
            }
        }

        // Systemic weakness score: 0-100
        // Based on: variety of vuln types, severity distribution, recurrence
        const uniqueTypes = typeCount.size;
        const totalFindings = findings.length;
        const criticalRatio = totalFindings > 0 ? (severityCount.critical + severityCount.high) / totalFindings : 0;
        const recurrenceRatio = totalFindings > 0 ? recurringPatternList.length / uniqueTypes : 0;

        const systemicWeaknessScore = Math.min(
            Math.round(
                (uniqueTypes * 5) +          // More unique types = broader weakness
                (criticalRatio * 40) +       // High severity ratio
                (recurrenceRatio * 30) +     // Recurrence indicates systemic
                (totalFindings > 10 ? 20 : totalFindings * 2) // Volume factor
            ),
            100,
        );

        // Likelihood scores: 0-1
        const injectionLikelihood = totalFindings > 0
            ? Math.min(injectionFindings / totalFindings + (injectionFindings > 3 ? 0.2 : 0), 1)
            : 0;

        const authWeaknessLikelihood = totalFindings > 0
            ? Math.min(authFindings / totalFindings + (authFindings > 3 ? 0.2 : 0), 1)
            : 0;

        const durationMs = Date.now() - start;
        log.info('Correlation complete', {
            scanId,
            systemicWeaknessScore,
            patternCount: recurringPatternList.length,
            durationMs,
        });

        return {
            systemicWeaknessScore,
            recurringPatternList,
            injectionLikelihood,
            authWeaknessLikelihood,
        };
    }
}

export interface CorrelatedRoute {
  routePath: string;
  triggeredApis: any[]; // InterceptedAPI
  instantiatedWebSockets: any[]; // WebSocketSummary
}

export class FrontendCorrelationEngine {
  /**
   * Generates a correlation graph linking SPA routes to the backend APIs and
   * WebSockets they communicate with.
   * 
   * @param scanId The scan ID to process artifacts for
   * @returns Array of correlated routes
   */
  public static async correlate(scanId: string): Promise<CorrelatedRoute[]> {
    try {
      const { PrismaClient } = await import('@prisma/client');
      const prisma = new PrismaClient();
      const artifacts = await prisma.browserArtifact.findMany({
        where: { scanId },
        orderBy: { createdAt: 'asc' }
      });
      await prisma.$disconnect();

      const routes = this.parseArtifacts<any[]>(artifacts, 'routes');
      const apis = this.parseArtifacts<any[]>(artifacts, 'apis');
      const websockets = this.parseArtifacts<any[]>(artifacts, 'websockets');
      
      const routeMap = new Map<string, CorrelatedRoute>();
      
      const uniquePaths = new Set(routes.map(r => r.toPath));
      uniquePaths.add('/'); // default

      for (const path of uniquePaths) {
        routeMap.set(path, {
          routePath: path,
          triggeredApis: [],
          instantiatedWebSockets: []
        });
      }

      const rootRoute = routeMap.get('/')!;
      
      for (const api of apis) {
        rootRoute.triggeredApis.push(api);
      }
      
      for (const ws of websockets) {
        rootRoute.instantiatedWebSockets.push(ws);
      }

      return Array.from(routeMap.values());
    } catch (err) {
      log.error('Frontend Correlation Engine failed', { scanId, error: err });
      return [];
    }
  }

  private static parseArtifacts<T>(artifacts: any[], type: string): T {
    const matching = artifacts.filter(a => a.artifactType === type);
    if (matching.length === 0) return [] as unknown as T;
    
    let combined: any[] = [];
    for (const a of matching) {
      try {
        const parsed = JSON.parse(a.payload);
        if (Array.isArray(parsed)) {
          combined = combined.concat(parsed);
        }
      } catch {
        // ignore invalid JSON
      }
    }
    
    return this.deduplicate(combined, type) as unknown as T;
  }

  private static deduplicate(items: any[], type: string): any[] {
    const seen = new Set();
    return items.filter(item => {
      let key = '';
      if (type === 'routes') key = `${item.fromPath}->${item.toPath}`;
      else if (type === 'apis') key = `${item.method} ${item.url}`;
      else if (type === 'websockets') key = item.url;
      else return true;

      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }
}
