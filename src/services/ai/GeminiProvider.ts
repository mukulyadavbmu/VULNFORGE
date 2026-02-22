import { GoogleGenerativeAI } from '@google/generative-ai';
import { AIProvider } from './types';
import { AIAttackAction, ScanSession } from '../../types';
import { config } from '../../config';
import { logger } from '../../utils/logger';

export class GeminiProvider implements AIProvider {
  private model: any;

  constructor() {
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
You are an offensive security expert focusing on OWASP Top 10 style risks with emphasis on access control, injection, and chaining vulnerabilities.

You are given a partial attack surface graph and a list of CONFIRMED VULNERABILITIES.

Your job:
- Choose up to ${maxActions} high-value exploration or ESCALATION actions.
- Prioritise:
  - ESCALATION: If a vulnerability is found (e.g., file upload), chain a new attack (e.g., rce_probe or xss_probe on the uploaded file).
  - ACCESS: If IDOR/BAC found, try to access more sensitive data.
  - NEW PROBES:
    - file_upload_probe (on forms/APIs accepting files)
    - websocket_probe (on ws/wss endpoints)
    - csrf_probe / clickjacking_probe (on sensitive state-changing forms)
    - graphql_probe (on /graphql endpoints)
    - nosqli_probe (on JSON APIs)

- Focus on actions:
  - cross_role_access, id_tamper, repeat_as_guest (Access Control)
  - xss_probe, sqli_probe, nosqli_probe (Injection)
  - ssti_probe, csti_probe, rce_probe, path_traversal_probe (RCE/LFI)
  - file_upload_probe, websocket_probe (Advanced)
  - csrf_probe, clickjacking_probe (Client-side)
  - oast_probe, ssrf_probe (Out-of-band)
  - config_probe, anomaly_probe

Return STRICT JSON with this shape:
{
  "actions": [
    {
      "id": "string",
      "targetNodeId": "string",
      "actionType": "cross_role_access" | "id_tamper" | "repeat_as_guest" | "xss_probe" | "sqli_probe" | "ssti_probe" | "csti_probe" | "rce_probe" | "oast_probe" | "config_probe" | "anomaly_probe" | "ssrf_probe" | "path_traversal_probe" | "cors_probe" | "graphql_probe" | "nosqli_probe" | "file_upload_probe" | "websocket_probe" | "csrf_probe" | "clickjacking_probe",
      "riskScore": 1-5,
      "explanation": "rationale mentioning chaining if applicable (e.g., 'Escalating file upload finding to test RCE')",
      "expectedSignal": "what response difference would indicate success"
    }
  ]
}

Do not include any extra keys or commentary.`;

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
