import { logger } from '../../utils/logger';

export interface Fingerprint {
    techs: string[];
    framework?: string;
    server?: string;
}

export class FingerprintService {
    static analyze(headers: Record<string, string | string[] | undefined>, body?: string): Fingerprint {
        const techs: Set<string> = new Set();
        let framework: string | undefined;
        let server: string | undefined;

        // Normalizing headers
        const lowerHeaders: Record<string, string> = {};
        for (const [k, v] of Object.entries(headers)) {
            if (v) lowerHeaders[k.toLowerCase()] = Array.isArray(v) ? v.join(' ') : v.toString();
        }

        // 1. Server Header
        if (lowerHeaders['server']) {
            server = lowerHeaders['server'];
            techs.add(`Server:${server}`);
            if (server.includes('Express')) techs.add('Express');
            if (server.includes('nginx')) techs.add('Nginx');
            if (server.includes('Apache')) techs.add('Apache');
            if (server.includes('Werkzeug')) techs.add('Flask/Werkzeug');
        }

        // 2. X-Powered-By
        if (lowerHeaders['x-powered-by']) {
            const powered = lowerHeaders['x-powered-by'];
            techs.add(`PoweredBy:${powered}`);
            if (powered.includes('Express')) {
                framework = 'Express';
                techs.add('Node.js');
            }
            if (powered.includes('PHP')) techs.add('PHP');
            if (powered.includes('ASP.NET')) techs.add('ASP.NET');
            if (powered.includes('Next.js')) {
                framework = 'Next.js';
                techs.add('React');
            }
        }

        // 3. Cookie Names
        const cookies = lowerHeaders['set-cookie'] || '';
        if (cookies.includes('connect.sid')) {
            techs.add('Express/Connect');
            techs.add('Node.js');
        }
        if (cookies.includes('PHPSESSID')) techs.add('PHP');
        if (cookies.includes('csrftoken') && cookies.includes('sessionid')) {
            // Django often sets these
            framework = 'Django';
            techs.add('Python');
        }
        if (cookies.includes('laravel_session')) {
            framework = 'Laravel';
            techs.add('PHP');
        }
        if (cookies.includes('JSESSIONID')) techs.add('Java');

        // 4. Body Content (Heuristic)
        if (body) {
            if (body.includes('__NEXT_DATA__')) techs.add('Next.js');
            if (body.includes('react-root')) techs.add('React');
            if (body.includes('csrf_token') && body.includes('django')) techs.add('Django');
        }

        return {
            techs: Array.from(techs),
            framework,
            server
        };
    }
}
