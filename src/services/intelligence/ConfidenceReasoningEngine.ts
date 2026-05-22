import { z } from 'zod';
import { PrismaClient } from '@prisma/client';
import { IntelligenceProvider } from '../ai/IntelligenceProvider';
import { ScanFinding } from '../../types';
import { logger } from '../../utils/logger';

const prisma = new PrismaClient();
const log = logger.child({ module: 'ConfidenceReasoningEngine' });

const ConfidenceSchema = z.object({
  reasoning: z.string(),
  adjustedConfidenceLevel: z.enum(['signal', 'probable', 'confirmed', 'reproducible', 'stateful_confirmed']),
  instabilityFactors: z.array(z.string()).optional()
});

export class ConfidenceReasoningEngine {
  private ai: IntelligenceProvider;

  constructor() {
    this.ai = new IntelligenceProvider();
  }

  /**
   * Analyzes a single finding and its evidence to provide explainable reasoning.
   */
  public async analyzeConfidence(scanId: string, finding: ScanFinding, context: any = {}): Promise<void> {
    const prompt = `
Analyze the following vulnerability finding. Explain WHY it is dangerous, or WHY it might be unreliable or a false positive based on the evidence provided.

Finding Type: ${finding.type}
URL: ${finding.url}
Severity: ${finding.severity}
Original Evidence (Sanitized):
${IntelligenceProvider.sanitizeInput(finding.evidence)}

Additional Context (e.g. Replay Success, Role Context):
${JSON.stringify(context, null, 2)}

Return a JSON object conforming to this schema:
{
  "reasoning": "Detailed explanation of exploitability and confidence",
  "adjustedConfidenceLevel": "signal | probable | confirmed | reproducible | stateful_confirmed",
  "instabilityFactors": ["List of reasons why this finding might fail to reproduce or be a false positive"]
}
`;

    const result = await this.ai.generateStructured(prompt, ConfidenceSchema, 'Exploit Confidence Reasoning');
    
    if (result.success && result.data) {
      try {
        await prisma.intelligenceArtifact.create({
          data: {
            scanId,
            category: 'confidence',
            referenceId: finding.id,
            reasoning: result.data.reasoning,
            metadata: JSON.stringify({
              adjustedLevel: result.data.adjustedConfidenceLevel,
              instabilityFactors: result.data.instabilityFactors || [],
              evidenceRef: 'deterministic_finding_payload'
            })
          }
        });
        log.debug(`Saved confidence reasoning`, { findingId: finding.id });
      } catch (err) {
        log.error('Failed to save confidence reasoning', { scanId, findingId: finding.id, error: err });
      }
    }
  }
}
