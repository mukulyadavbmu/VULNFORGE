import axios, { AxiosRequestConfig } from 'axios';
import { AuthContext, ScanSession, ScanFinding, classifyFinding, FindingType, initialReliabilityTier } from '../types';
import { addFinding } from '../scanOrchestrator'; // This might cycle? scanOrchestrator -> detectionEngine -> ... 
// scanOrchestrator imports detectionEngine only for executeAction (runner).
// scanUtils imports addFinding from scanOrchestrator. This is fine.
import { logger } from './logger';
import { JobDispatcher as JobDispatcherService } from '../services/queue/JobDispatcher';

export interface HttpResult {
    status: number;
    bodySnippet: string;
    length: number;
    timeMs: number;
    headers?: Record<string, string>;
}

export async function httpRequest(
    session: ScanSession,
    url: string,
    ctx: AuthContext,
    config: AxiosRequestConfig = {},
): Promise<HttpResult> {
    const headers = {
        ...(session.authHeaders[ctx] ?? {}),
        ...(config.headers ?? {}),
    };
    const start = Date.now();
    try {
        return await JobDispatcherService.scheduleRequest(url, async () => {
            const res = await axios.request<string>({
                url,
                method: config.method ?? 'GET',
                data: config.data,
                headers,
                validateStatus: () => true,
            });
            const timeMs = Date.now() - start;
            const body = res.data ?? '';
            const bodySnippet = typeof body === 'string' ? body.slice(0, 1000) : '';

            logger.debug(`HTTP ${config.method ?? 'GET'} ${url} [${res.status}] ${timeMs}ms`);

            return {
                status: res.status,
                length: bodySnippet.length,
                bodySnippet,
                timeMs,
                headers: res.headers as Record<string, string>,
            };
        });
    } catch (err) {
        logger.debug(`HTTP Request failed: ${url}`, { error: err });
        return {
            status: 0,
            length: 0,
            bodySnippet: '',
            timeMs: Date.now() - start,
        };
    }
}

// Simple Ratcliff-Obershelp or Levenshtein would be better, but for MVP we use length/status ratio
// and Jaccard index on words.
export function calculateDiff(base: string, current: string): number {
    if (base === current) return 0;
    const baseWords = new Set(base.split(/\s+/));
    const currentWords = new Set(current.split(/\s+/));
    const intersection = new Set([...baseWords].filter(x => currentWords.has(x)));
    const union = new Set([...baseWords, ...currentWords]);
    return 1 - (intersection.size / union.size);
}

export async function maybeAddFinding(
    session: ScanSession,
    finding: Omit<ScanFinding, 'id' | 'classification'>,
) {
    const { ConfidenceScorer } = require('../services/scoring/ConfidenceScorer');
    const { BusinessImpactAnalyzer } = require('../services/scoring/BusinessImpactAnalyzer');

    // Calculate Scores using available data
    // We need endpoint risk score, which is on the node presumably. 
    // Finding has URL, we can look up node in session.attackNodes by URL (slow) or just assume default risk if not found.
    const node = Object.values(session.attackNodes).find(n => n.url === finding.url);
    const riskScore = node?.riskScore || 5;

    const confidence = ConfidenceScorer.calculateConfidence(finding);
    const impact = BusinessImpactAnalyzer.estimateImpact(finding, riskScore);

    const classification = classifyFinding(finding.type as FindingType);

    // Phase 2C: Set initial reliability tier based on confidence
    const reliabilityTier = finding.reliabilityTier ?? initialReliabilityTier(confidence);

    const enrichedFinding: ScanFinding = {
        ...finding,
        id: `${finding.type}:${finding.url}:${Date.now()}`,
        classification,
        reliabilityTier,
        replayStatus: finding.replayStatus ?? 'pending',
        verificationHistory: finding.verificationHistory ?? [],
        // Storing these new metrics in the existing 'metrics' object or creating new fields implies schema change.
        // For "Additive" no-migration constraint, we put them in 'metrics' as loose JSON.
        metrics: {
            ...finding.metrics,
            confidence,
            impact,
            riskScore
        }
    };

    logger.info(`Detected ${finding.type} on ${finding.url} [Confidence: ${confidence}%, Impact: ${impact}, Reliability: ${reliabilityTier}]`, { scanId: session.id });
    await addFinding(session, enrichedFinding);
}

export const detectors = {
    sqlError: (snippet: string) => /SQL|syntax error|ORA-|mysql|unclosed quotation/i.test(snippet),

    reflectedXss: (snippet: string, marker: string) => {
        if (!snippet.includes(marker)) return false;
        return /<[^>]*script|onerror=|onclick=|innerHTML/i.test(snippet);
    },

    templateError: (snippet: string) => /Jinja2|Twig|Freemarker|Velocity|Thymeleaf|Mustache|Handlebars/i.test(snippet),

    rceError: (snippet: string) => /(command not found|No such file or directory|Traceback \(most recent call last\)|System\.out\.println|ProcessBuilder)/i.test(snippet),

    configLeak: (snippet: string) => /(DEBUG = True|phpinfo\(|PRIVATE KEY|BEGIN RSA PRIVATE KEY|AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|DATABASE_URL)/i.test(snippet),
    
    // ENHANCED: Multi-signal SQLi detection
    sqliMultiSignal: (
        baseSnippet: string,
        injectedSnippet: string,
        timeDelta: number,
    ): { signals: string[]; confidence: number } => {
        const signals: string[] = [];
        
        // Signal 1: Error signature
        if (/SQL|syntax error|ORA-|mysql/i.test(injectedSnippet)) {
            signals.push('error_signature');
        }
        
        // Signal 2: Boolean difference (response structure change)
        const diff = calculateDiff(baseSnippet, injectedSnippet);
        if (diff > 0.3) {
            signals.push('boolean_difference');
        }
        
        // Signal 3: Timing difference (>2.5s indicates sleep()/delay)
        if (timeDelta > 2500) {
            signals.push('timing_difference');
        }
        
        // Signal 4: Response structure change (length + status code)
        if (injectedSnippet.length !== baseSnippet.length && diff > 0.2) {
            signals.push('response_structure_change');
        }
        
        const confidence = Math.min((signals.length / 4) * 100, 100);
        return { signals, confidence };
    },

    // ENHANCED: Multi-signal XSS detection
    xssMultiSignal: (
        baseSnippet: string,
        injectedSnippet: string,
        payload: string,
        marker: string,
    ): { signals: string[]; confidence: number } => {
        const signals: string[] = [];
        
        // Signal 1: Payload reflection (unencoded)
        if (injectedSnippet.includes(marker) && !injectedSnippet.includes('&lt;')) {
            signals.push('payload_reflection');
        }
        
        // Signal 2: DOM sink detected
        if (/<[^>]*script|onerror=|onclick=|innerHTML|eval|document\.write/i.test(injectedSnippet)) {
            signals.push('dom_sink');
        }
        
        // Signal 3: Encoding context (payload in JS string, attribute, etc)
        const inScriptContext = /([<]script[^>]*>[^<]*|['\"])[^'\"]*/.test(injectedSnippet);
        if (inScriptContext) {
            signals.push('encoding_context');
        }
        
        // Signal 4: Browser execution (alert/console patterns)
        if (/alert\(|console\.|window\.|document\.|eval\(/i.test(injectedSnippet)) {
            signals.push('browser_execution');
        }
        
        const confidence = Math.min((signals.length / 4) * 100, 100);
        return { signals, confidence };
    },
};
