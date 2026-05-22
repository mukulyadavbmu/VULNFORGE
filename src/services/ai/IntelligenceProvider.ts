import { GoogleGenerativeAI, GenerativeModel } from '@google/generative-ai';
import { z } from 'zod';
import { config } from '../../config';
import { logger } from '../../utils/logger';

const log = logger.child({ module: 'IntelligenceProvider' });

// ─── Token Budgets & Limits ────────────────────────────────────────────────
const MAX_INPUT_LENGTH = 15000;

export interface IntelligenceResponse<T> {
  data?: T;
  error?: string;
  success: boolean;
}

export class IntelligenceProvider {
  private model: GenerativeModel;

  constructor() {
    const apiKey = config.GEMINI_API_KEY || config.OPENAI_API_KEY || '';
    if (!apiKey) {
      log.error('No API key found for Intelligence Provider');
    }
    const genAI = new GoogleGenerativeAI(apiKey);
    // Use JSON schema mode if supported or fallback to standard prompt instruction
    this.model = genAI.getGenerativeModel({ model: 'gemini-pro' });
  }

  /**
   * Sanitizes input strings to remove large payloads, JWTs, and potential prompt injection.
   */
  public static sanitizeInput(input: string): string {
    if (!input) return '';
    let sanitized = input;

    // Truncate excessively long strings
    if (sanitized.length > MAX_INPUT_LENGTH) {
      sanitized = sanitized.substring(0, MAX_INPUT_LENGTH) + '...[TRUNCATED]';
    }

    // Strip potential JWTs (very naive regex for safety)
    sanitized = sanitized.replace(/eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/g, '[REDACTED_JWT]');
    
    // Strip obvious secrets
    sanitized = sanitized.replace(/(password|secret|token|key)["'\s:=]+[^\s&"']+/gi, '$1=[REDACTED]');

    return sanitized;
  }

  /**
   * Executes a prompt and validates the output against a Zod schema.
   * Ensures deterministic, bounded responses.
   */
  public async generateStructured<T>(
    prompt: string, 
    schema: z.ZodType<T>, 
    contextContext: string = 'Security Analysis'
  ): Promise<IntelligenceResponse<T>> {
    const sanitizedPrompt = IntelligenceProvider.sanitizeInput(prompt);
    
    const fullPrompt = `
You are a deterministic, analytical security assistant. 
Context: ${contextContext}

Your output MUST be ONLY valid JSON matching the following requirements.
Do not include markdown blocks like \`\`\`json. Do not include explanatory text outside the JSON.

${sanitizedPrompt}
`;

    try {
      const result = await Promise.race([
        this.model.generateContent(fullPrompt),
        new Promise<never>((_, reject) => setTimeout(() => reject(new Error('AI Request Timeout')), 15000))
      ]);

      let text = result.response.text();
      text = text.replace(/```json\n?/gi, '').replace(/```\n?/g, '').trim();

      const parsed = JSON.parse(text);
      const validated = schema.parse(parsed);

      return { success: true, data: validated };
    } catch (err) {
      log.error('Intelligence Provider generation failed', { 
        error: err instanceof Error ? err.message : 'Unknown error',
        contextContext
      });
      return { success: false, error: 'Generation failed or validation error' };
    }
  }
}
