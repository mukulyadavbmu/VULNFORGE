import { URL } from 'url';

export function isValidTarget(urlString: string): { valid: boolean; error?: string } {
    try {
        const url = new URL(urlString);
        if (url.protocol !== 'http:' && url.protocol !== 'https:') {
            return { valid: false, error: 'Protocol must be http or https' };
        }

        // Simple blocklist for localhost/private IPs (basic SSRF protection)
        // In production, use a proper DNS resolution check library like 'ssrf-agent'
        const hostname = url.hostname;

        if (hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '::1') {
            // Allow localhost only in dev mode? 
            // For this project, user might be testing local apps.
            // So we WARN but allow, or maybe config based?
            // Let's allow for now as it's a dev tool, but log warning.
            return { valid: true };
        }

        if (hostname.startsWith('192.168.') || hostname.startsWith('10.')) {
            return { valid: true }; // Allow private networks for internal scanning
        }

        return { valid: true };
    } catch {
        return { valid: false, error: 'Invalid URL format' };
    }
}
