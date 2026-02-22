import { AttackNode } from '../../types';

export class RiskAnalyzer {
    static calculateNodeRisk(node: AttackNode): number {
        let score = 1; // Base score

        // 1. URL Sensitive Keywords
        const sensitiveKeywords = [
            'admin', 'login', 'passwd', 'password', 'config', 'user', 'account',
            'billing', 'payment', 'reset', 'auth', 'token', 'key', 'secret',
            'dashboard', 'private', 'upload', 'file', 'graphql'
        ];

        const lowerUrl = node.url.toLowerCase();
        for (const kw of sensitiveKeywords) {
            if (lowerUrl.includes(kw)) score += 2;
        }

        // 2. Auth Context
        // If an endpoint is accessible by Guest, it might be low risk unless it leaks data.
        // But if we found it while authenticated (context != guest), it implies it's behind auth.
        // Actually, AttackNode stores 'authContext' which is what context was used to FIND it or ACCESS it.
        // If this node accepts Auth headers (implied by context), it's higher value.
        if (node.authContext !== 'guest') {
            score += 1;
        }

        // 3. Parameters
        if (node.params && node.params.length > 0) {
            score += 1;
            // Risky params
            const riskyParams = ['id', 'uuid', 'file', 'path', 'url', 'redirect', 'cmd', 'exec', 'query', 'sql'];
            for (const p of node.params) {
                if (riskyParams.some(rp => p.toLowerCase().includes(rp))) {
                    score += 2;
                }
            }
        }

        // 4. Method
        if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(node.method || 'GET')) {
            score += 2; // State changing is higher risk
        }

        return Math.min(score, 10); // Cap at 10
    }
}
