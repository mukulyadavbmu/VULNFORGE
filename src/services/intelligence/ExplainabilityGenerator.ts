import { z } from 'zod';
import { PrismaClient, Finding, AttackChain } from '@prisma/client';
import { IntelligenceProvider } from '../ai/IntelligenceProvider';
import { logger } from '../../utils/logger';

const prisma = new PrismaClient();
const log = logger.child({ module: 'ExplainabilityGenerator' });

const ExplanationSchema = z.object({
  analystSummary: z.string(),
  remediationAdvice: z.string(),
  businessImpact: z.string()
});

export class ExplainabilityGenerator {
  private ai: IntelligenceProvider;

  constructor() {
    this.ai = new IntelligenceProvider();
  }

  /**
   * Generates a high-level, human-readable analyst summary for a confirmed Attack Chain.
   */
  public async generateChainExplanation(scanId: string, chainId: string): Promise<void> {
    const chain = await prisma.attackChain.findUnique({ where: { id: chainId } });
    if (!chain) return;

    // Grab intelligence artifacts correlated to this chain if any
    const intelligence = await prisma.intelligenceArtifact.findFirst({
      where: { category: 'attack_path', referenceId: chain.id }
    });

    const prompt = `
Generate a professional, human-readable executive summary and remediation guide for the following verified attack chain.

Attack Chain Details:
Nodes: ${chain.nodes}
Vulnerabilities: ${chain.vulnerabilities}
Transitions: ${chain.privilegeTransitions}

Technical Context (if any):
${intelligence ? intelligence.reasoning : 'None'}

Return a JSON object conforming to this schema:
{
  "analystSummary": "A clear narrative explaining how the attack works and the risk involved.",
  "remediationAdvice": "Actionable steps to fix the root causes.",
  "businessImpact": "The potential impact on confidentiality, integrity, and availability."
}
`;

    const result = await this.ai.generateStructured(prompt, ExplanationSchema, 'Explainability Generator');

    if (result.success && result.data) {
      try {
        await prisma.intelligenceArtifact.create({
          data: {
            scanId,
            category: 'explanation',
            referenceId: chain.id,
            reasoning: result.data.analystSummary,
            metadata: JSON.stringify({
              remediation: result.data.remediationAdvice,
              impact: result.data.businessImpact
            })
          }
        });
        log.info('Generated analyst explanation', { scanId, chainId });
      } catch (err) {
        log.error('Failed to save explanation', { scanId, chainId, error: err });
      }
    }
  }
}
