import { z } from 'zod';
import { PrismaClient, AttackChain, BrowserArtifact } from '@prisma/client';
import { IntelligenceProvider } from '../ai/IntelligenceProvider';
import { logger } from '../../utils/logger';

const prisma = new PrismaClient();
const log = logger.child({ module: 'ContextualAttackPathEngine' });

const ContextualPathSchema = z.object({
  narrative: z.string(),
  frontendToBackendCorrelation: z.array(z.string()),
  escalationSteps: z.array(z.string()),
  confidence: z.number()
});

export class ContextualAttackPathEngine {
  private ai: IntelligenceProvider;

  constructor() {
    this.ai = new IntelligenceProvider();
  }

  /**
   * Enriches deterministic attack chains with browser intelligence to create a full contextual path.
   */
  public async enrichPaths(scanId: string): Promise<void> {
    const chains = await prisma.attackChain.findMany({ where: { scanId } });
    if (chains.length === 0) return;

    // Fetch browser correlation artifacts to feed the AI
    const browserArtifacts = await prisma.browserArtifact.findMany({
      where: { scanId, artifactType: 'correlation' },
      take: 50 // Limit to avoid blowing up token count
    });

    const contextMap = browserArtifacts.map(ba => ba.payload).join('\n');

    for (const chain of chains) {
      const prompt = `
Analyze the following deterministic attack chain and enrich it with the provided frontend browser intelligence.
Explain the attack path from the perspective of a user navigating the single-page application (SPA).

Deterministic Chain Nodes: ${chain.nodes}
Vulnerabilities: ${chain.vulnerabilities}
Privilege Transitions: ${chain.privilegeTransitions}

Frontend Intelligence Context (Routes to APIs):
${IntelligenceProvider.sanitizeInput(contextMap)}

Return a JSON object conforming to this schema:
{
  "narrative": "A readable explanation of how the attack flows from frontend UI to backend exploit",
  "frontendToBackendCorrelation": ["list of explicit linkages"],
  "escalationSteps": ["Step 1...", "Step 2..."],
  "confidence": 0-100
}
`;

      const result = await this.ai.generateStructured(prompt, ContextualPathSchema, 'Contextual Attack Path Analysis');

      if (result.success && result.data) {
        try {
          await prisma.intelligenceArtifact.create({
            data: {
              scanId,
              category: 'attack_path',
              referenceId: chain.id,
              reasoning: result.data.narrative,
              metadata: JSON.stringify({
                correlation: result.data.frontendToBackendCorrelation,
                escalation: result.data.escalationSteps,
                confidence: result.data.confidence
              })
            }
          });
          log.info('Generated contextual attack path', { scanId, chainId: chain.id });
        } catch (err) {
          log.error('Failed to save contextual attack path', { scanId, chainId: chain.id, error: err });
        }
      }
    }
  }
}
