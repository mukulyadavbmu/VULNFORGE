import { z } from 'zod';
import { PrismaClient } from '@prisma/client';
import { IntelligenceProvider } from '../ai/IntelligenceProvider';
import { logger } from '../../utils/logger';

const prisma = new PrismaClient();
const log = logger.child({ module: 'PrioritizationEngine' });

const PrioritizationSchema = z.object({
  rankedEndpoints: z.array(
    z.object({
      endpointUrl: z.string(),
      priorityScore: z.number().min(0).max(100),
      reasoning: z.string()
    })
  )
});

export class PrioritizationEngine {
  private ai: IntelligenceProvider;

  constructor() {
    this.ai = new IntelligenceProvider();
  }

  /**
   * Ranks discovered endpoints to guide future attack/crawl priorities.
   */
  public async prioritizeEndpoints(scanId: string): Promise<void> {
    const endpoints = await prisma.endpoint.findMany({ where: { scanId }, take: 100 });
    if (endpoints.length === 0) return;

    const summary = endpoints.map(ep => ({
      url: ep.url,
      method: ep.method,
      params: ep.params,
      type: ep.type
    }));

    const prompt = `
Analyze the following endpoints discovered during a web application security scan.
Rank them by their likelihood to contain high-impact vulnerabilities (e.g., IDOR, RCE, SQLi, Auth Bypass).
Consider parameters, methods, and RESTful structures in your analysis.

Endpoints:
${JSON.stringify(summary, null, 2)}

Return a JSON object conforming to this schema:
{
  "rankedEndpoints": [
    {
      "endpointUrl": "url",
      "priorityScore": 0-100,
      "reasoning": "Why this endpoint is a high/low priority target"
    }
  ]
}
`;

    const result = await this.ai.generateStructured(prompt, PrioritizationSchema, 'Endpoint Prioritization');

    if (result.success && result.data) {
      try {
        await prisma.intelligenceArtifact.create({
          data: {
            scanId,
            category: 'prioritization',
            referenceId: 'endpoint_ranking',
            reasoning: 'Batch endpoint prioritization analysis complete.',
            metadata: JSON.stringify(result.data.rankedEndpoints)
          }
        });
        log.info('Generated endpoint prioritization', { scanId, count: result.data.rankedEndpoints.length });
      } catch (err) {
        log.error('Failed to save prioritization', { scanId, error: err });
      }
    }
  }
}
