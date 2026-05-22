import { z } from 'zod';
import { PrismaClient } from '@prisma/client';
import { IntelligenceProvider } from '../ai/IntelligenceProvider';
import { ScanFinding } from '../../types';
import { logger } from '../../utils/logger';

const prisma = new PrismaClient();
const log = logger.child({ module: 'FindingDeduplicator' });

const DeduplicationSchema = z.object({
  clusters: z.array(
    z.object({
      clusterId: z.string(),
      reasoning: z.string(),
      findingIds: z.array(z.string()),
      confidence: z.number().min(0).max(100)
    })
  )
});

export class FindingDeduplicator {
  private ai: IntelligenceProvider;

  constructor() {
    this.ai = new IntelligenceProvider();
  }

  /**
   * Evaluates a list of findings and clusters structurally similar ones.
   */
  public async deduplicate(scanId: string, findings: ScanFinding[]): Promise<void> {
    if (findings.length < 2) return;

    // We only want to deduplicate findings of the same type
    const groupedByType = findings.reduce((acc, f) => {
      acc[f.type] = acc[f.type] || [];
      acc[f.type].push(f);
      return acc;
    }, {} as Record<string, ScanFinding[]>);

    for (const [type, typeFindings] of Object.entries(groupedByType)) {
      if (typeFindings.length < 2) continue;

      const summary = typeFindings.map(f => ({
        id: f.id,
        url: f.url,
        evidence: IntelligenceProvider.sanitizeInput(f.evidence)
      }));

      const prompt = `
Analyze the following vulnerabilities of type "${type}". 
Group findings together if they appear to be the EXACT same vulnerability manifesting on different URLs or parameters (e.g. same underlying IDOR or XSS root cause).

Findings:
${JSON.stringify(summary, null, 2)}

Return a JSON object conforming to this schema:
{
  "clusters": [
    {
      "clusterId": "unique_string",
      "reasoning": "Why these findings are considered duplicates",
      "findingIds": ["id1", "id2"],
      "confidence": 0-100
    }
  ]
}
`;

      const result = await this.ai.generateStructured(prompt, DeduplicationSchema, 'Finding Deduplication');
      
      if (result.success && result.data) {
        for (const cluster of result.data.clusters) {
          if (cluster.findingIds.length > 1) {
            await this.saveCluster(scanId, cluster);
          }
        }
      }
    }
  }

  private async saveCluster(scanId: string, cluster: any) {
    try {
      await prisma.intelligenceArtifact.create({
        data: {
          scanId,
          category: 'deduplication',
          referenceId: cluster.clusterId,
          reasoning: cluster.reasoning,
          metadata: JSON.stringify({
            findingIds: cluster.findingIds,
            confidence: cluster.confidence
          })
        }
      });
      log.info(`Saved deduplication cluster`, { scanId, clusterId: cluster.clusterId, size: cluster.findingIds.length });
    } catch (err) {
      log.error('Failed to save deduplication cluster', { scanId, error: err });
    }
  }
}
