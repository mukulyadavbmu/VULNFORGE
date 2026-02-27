import { GoogleGenerativeAI } from '@google/generative-ai';
import { AIProvider } from './types';
import { AIAttackAction, ScanSession } from '../../types';
import { config } from '../../config';
import { logger } from '../../utils/logger';

export class GeminiProvider implements AIProvider {
  private model: any;

  constructor() {
    // TEMPORARY DEBUG
    console.log('🔑 Gemini Key Exists:', !!process.env.GEMINI_API_KEY);
    console.log('🔑 Gemini Key from config:', !!config.GEMINI_API_KEY);
    
    const apiKey = config.GEMINI_API_KEY || config.OPENAI_API_KEY || '';
    if (!apiKey) {
      logger.error('No API key found for Gemini Provider');
    }
    const genAI = new GoogleGenerativeAI(apiKey);
    this.model = genAI.getGenerativeModel({ model: 'gemini-pro' });
  }

  getMetaData() {
    return { provider: 'Gemini', model: 'gemini-pro' };
  }

  async planNextActions(session: ScanSession, maxActions: number = 3): Promise<AIAttackAction[]> {
    const nodes = Object.values(session.attackNodes);
    logger.debug(`Gemini planning for session ${session.id} with ${nodes.length} nodes`);

    // Fetch Cross-Scan Knowledge
    let knowledgeContext = '';
    try {
      const { KnowledgeBase } = require('../knowledge/KnowledgeBase');
      const { FingerprintService } = require('../strategy/FingerprintService');

      const profile = await KnowledgeBase.getTargetProfile(session.targetUrl);

      // We can also analyze current session headers if we store them, 
      // but for now let's use the profile's techStack if available,
      // or assume we might have some fingerprinting data attached to the session in future.
      // For this step, we will use the profile.

      if (profile) {
        const successes = profile.successes.map((s: any) => `${s.vulnType} using ${s.context}`).join(', ');
        const fingerprint = profile.techStack ? JSON.parse(profile.techStack) : [];

        knowledgeContext = `
Target Knowledge Base:
- Known Tech Stack: ${fingerprint.join(', ') || 'Unknown'}
- Past Successful Attacks: ${successes || 'None'}
`;
      }
    } catch (e) {
      logger.warn('Failed to load knowledge context', { error: e });
    }

    const candidateNodes = nodes.slice(0, 30);

    const summary = candidateNodes.map((n) => ({
      id: n.id,
      url: n.url,
      method: n.method ?? 'GET',
      type: n.type,
      authContext: n.authContext,
      params: n.params,
      tags: n.tags,
      riskScore: n.riskScore ?? 0,
    }));

    const prompt = `
You are an offensive security expert. You are given an attack surface graph, CONFIRMED VULNERABILITIES, and SYSTEMIC INTELLIGENCE.

Your job:
- Choose up to ${maxActions} high-value exploration or ESCALATION actions.
- Prioritise:
  - ESCALATION: If a vulnerability is found (e.g., file upload), chain a new attack (e.g., rce_probe).
  - ACCESS: If IDOR/BAC found, try to access more sensitive data.
  - DEEP EXPLOIT: race_condition_probe, cache_deception_probe, proto_pollution_probe, graphql_deep_probe

- Available actions:
  cross_role_access, id_tamper, repeat_as_guest,
  xss_probe, sqli_probe, nosqli_probe, ssti_probe, csti_probe,
  rce_probe, path_traversal_probe, file_upload_probe, websocket_probe,
  csrf_probe, clickjacking_probe, oast_probe, ssrf_probe, cors_probe,
  graphql_probe, config_probe, anomaly_probe,
  race_condition_probe, cache_deception_probe, proto_pollution_probe, graphql_deep_probe

Return STRICT JSON:
{
  "actions": [
    {
      "id": "string",
      "targetNodeId": "string",
      "actionType": "<one of the above actions>",
      "riskScore": 1-5,
      "explanation": "rationale mentioning chaining if applicable",
      "expectedSignal": "what response difference would indicate success"
    }
  ]
}

Do not include any extra keys or commentary.`;

    // Phase 6: Intelligence Layer
    let intelligenceContext = '';
    try {
      const { PatternLearner } = require('../intelligence/PatternLearner');
      const { SystemicWeaknessDetector } = require('../intelligence/SystemicWeaknessDetector');

      const patterns = PatternLearner.analyzePatterns(session.findings);
      const systemicIssues = SystemicWeaknessDetector.detect(session.findings, nodes);

      if (patterns.length > 0 || systemicIssues.length > 0) {
        intelligenceContext = `
Systemic Intelligence:
${patterns.map((p: string) => `- [PATTERN] ${p}`).join('\n')}
${systemicIssues.map((i: string) => `- [SYSTEMIC] ${i}`).join('\n')}
`;
      }
    } catch (e) {
      logger.warn('Failed to load intelligence context', { error: e });
    }

    // Filter recent actions with results
    const recentActions = session.actions
      .filter(a => a.result)
      .slice(-10) // Last 10 actions
      .map(a => ({
        type: a.actionType,
        url: session.attackNodes[a.targetNodeId]?.url,
        result: a.result
      }));

    // Preshare confirmed findings for chaining
    const findings = session.findings.map(f => ({
      type: f.type,
      url: f.url,
      severity: f.severity,
      evidence: f.evidence
    }));

    const fullPrompt = `You return ONLY valid JSON that matches the requested schema. No explanations outside JSON.

Attack Surface Nodes:
${JSON.stringify({ nodes: summary }, null, 2)}

Confirmed Vulnerabilities (Use these to ESCALATE or CHAIN attacks):
${JSON.stringify(findings, null, 2)}

Recent Attack Feedback (Use this to refine your strategy):
${JSON.stringify(recentActions, null, 2)}

${knowledgeContext}

${intelligenceContext}

${prompt}

IMPORTANT: Return ONLY the JSON object, no markdown, no code blocks, no extra text.`;

    try {
      const result = await this.model.generateContent(fullPrompt);
      const response = result.response;
      let content = response.text();

      content = content.replace(/```json\n?/g, '').replace(/```\n?/g, '').trim();

      const parsed = JSON.parse(content);
      if (!parsed.actions || !Array.isArray(parsed.actions)) return [];

      logger.info(`Gemini planned ${parsed.actions.length} actions`, { scanId: session.id });
      return parsed.actions.slice(0, maxActions);
    } catch (error) {
      logger.error('Gemini Provider Error:', { error, scanId: session.id });
      return [];
    }
  }
}
