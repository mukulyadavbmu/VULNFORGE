import { AIAttackAction, ScanSession } from '../types';
import { httpRequest, maybeAddFinding, detectors, calculateDiff } from '../utils/scanUtils';
import { PayloadFactory } from '../services/payload/PayloadFactory';

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
        const aRes = await httpRequest(session, url, 'userA');
        const bRes = await httpRequest(session, url, 'userB');
        if (
            aRes.status === bRes.status &&
            Math.abs(aRes.length - bRes.length) / (aRes.length || 1) < 0.2
        ) {
            await maybeAddFinding(session, {
                type: 'bac',
                url,
                severity: 'high',
                evidence: 'Endpoint returns similar data shape across different users; may indicate missing role checks.',
                aiExplanation: action.explanation,
            });
        }
    },

    sqli_probe: async (session: ScanSession, action: AIAttackAction, url: string) => {
        // Generate a set of payloads
        const basePayload = "' OR '1'='1";
        const payloads = PayloadFactory.getPayloads('sqli', basePayload, 'query_param');

        for (const payload of payloads) {
            const payloadUrl = url.includes('?')
                ? `${url}&sqli_test=${payload}`
                : `${url}?sqli_test=${payload}`;

            const base = await httpRequest(session, url, 'userA');
            const inj = await httpRequest(session, payloadUrl, 'userA');

            const diff = calculateDiff(base.bodySnippet, inj.bodySnippet);
            const timeDelta = inj.timeMs - base.timeMs;

            if (
                inj.status >= 500 ||
                detectors.sqlError(inj.bodySnippet) ||
                timeDelta > 2000 || // significant delay > 2s
                (diff > 0.8 && inj.status === base.status) // significant content change with same status
            ) {
                await maybeAddFinding(session, {
                    type: 'sqli',
                    url: payloadUrl,
                    severity: 'high',
                    evidence: `SQL injection indicators detected: Diff=${diff.toFixed(2)}, TimeDelta=${timeDelta}ms`,
                    aiExplanation: action.explanation,
                    metrics: {
                        diffScore: diff,
                        timeDelta,
                        errorSignature: detectors.sqlError(inj.bodySnippet) ? 'sql_error' : undefined
                    }
                });
                break;
            }
        }
    },

    xss_probe: async (session: ScanSession, action: AIAttackAction, url: string) => {
        const marker = 'XSS_TEST_123';
        const basePayload = `"><script>${marker}</script>`;
        const payloads = PayloadFactory.getPayloads('xss', basePayload, 'query_param');

        for (const payload of payloads) {
            const payloadUrl = url.includes('?')
                ? `${url}&xss_test=${payload}`
                : `${url}?xss_test=${payload}`;

            const res = await httpRequest(session, payloadUrl, 'userA');

            if (detectors.reflectedXss(res.bodySnippet, marker)) {
                await maybeAddFinding(session, {
                    type: 'xss',
                    url: payloadUrl,
                    severity: 'medium',
                    evidence: 'XSS marker appears reflected in a potentially executable context in the response.',
                    aiExplanation: action.explanation,
                });
                break;
            }
        }
    },

    id_tamper: async (session: ScanSession, action: AIAttackAction, url: string) => {
        const match = url.match(/(.*\/)(\d+)(\/?)$/);
        if (!match) return;
        const prefix = match[1];
        const id = parseInt(match[2], 10);
        const suffix = match[3] ?? '';
        const altId = id + 1;
        const tamperedUrl = `${prefix}${altId}${suffix}`;

        const base = await httpRequest(session, url, 'userA');
        const tampered = await httpRequest(session, tamperedUrl, 'userA');
        if (
            tampered.status === base.status &&
            Math.abs(tampered.length - base.length) / (base.length || 1) < 0.3
        ) {
            await maybeAddFinding(session, {
                type: 'idor',
                url: tamperedUrl,
                severity: 'high',
                evidence: 'Changing object ID in path returns similar content, suggesting possible IDOR/BOLA.',
                aiExplanation: action.explanation,
            });
        }
    },

    ssti_probe: async (session: ScanSession, action: AIAttackAction, url: string) => {
        const marker = '49';
        const payload = '{{7*7}}';
        const payloadUrl = url.includes('?')
            ? `${url}&tmpl_test=${encodeURIComponent(payload)}`
            : `${url}?tmpl_test=${encodeURIComponent(payload)}`;
        const res = await httpRequest(session, payloadUrl, 'userA');
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
        const payload = '$(id)';
        const payloadUrl = url.includes('?')
            ? `${url}&cmd_test=${encodeURIComponent(payload)}`
            : `${url}?cmd_test=${encodeURIComponent(payload)}`;
        const res = await httpRequest(session, payloadUrl, 'userA');
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
    }
};
