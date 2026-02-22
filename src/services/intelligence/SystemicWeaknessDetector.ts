import { ScanFinding, AttackNode } from '../../types';

export class SystemicWeaknessDetector {
    static detect(findings: ScanFinding[], nodes: AttackNode[]): string[] {
        const issues: string[] = [];

        // 1. Missing Auth Systemic Issue
        // If > 50% of "admin" or "sensitive" nodes are accessible by guest
        const sensitiveNodes = nodes.filter(n =>
            n.url.includes('admin') ||
            n.url.includes('dashboard') ||
            n.url.includes('settings')
        );

        if (sensitiveNodes.length > 0) {
            // Check if we have findings on these nodes related to Auth or if they were accessed as guest successfully (AttackNode doesn't store success result directly, but we might infer from lack of 403/401 if we had that data).
            // Better heuristic: Do we have ANY auth findings?
            const authFindings = findings.filter(f => f.type === 'bac' || f.type === 'idor' || f.type === 'websocket' || f.type === 'csrf'); // websocket often implies auth bypass

            if (authFindings.length >= sensitiveNodes.length / 2 && sensitiveNodes.length > 2) {
                issues.push('Systemic Auth Failure: Multiple sensitive endpoints appear exposed or vulnerable.');
            }
        }

        // 2. Universal Config Leak
        const configLeaks = findings.filter(f => f.type === 'config' || f.type === 'info');
        if (configLeaks.length > 3) {
            issues.push('Systemic Information Leakage: App varies debug/config info across multiple points.');
        }

        // 3. Lack of CSRF Protection
        const csrfFindings = findings.filter(f => f.type === 'csrf');
        if (csrfFindings.length > 2) {
            issues.push('Systemic CSRF Gap: Multiple state-changing endpoints lack anti-CSRF controls.');
        }

        return issues;
    }
}
