import { ScanFinding } from '../../types';

export class BusinessImpactAnalyzer {
    static estimateImpact(finding: ScanFinding, endpointRiskScore: number = 5): 'Low' | 'Medium' | 'High' | 'Critical' {
        let impactScore = 0;

        // 1. Vulnerability Severity Baseline
        switch (finding.type) {
            case 'rce': impactScore += 10; break;
            case 'sqli': impactScore += 9; break;
            case 'ssrf': impactScore += 9; break;
            case 'bac': impactScore += 8; break;
            case 'idor': impactScore += 8; break;
            case 'file_upload': impactScore += 8; break;
            case 'proto_pollution': impactScore += 7; break;
            case 'lfi': impactScore += 7; break;
            case 'ssti': impactScore += 7; break;
            case 'xss': impactScore += 6; break;
            case 'race_condition': impactScore += 6; break;
            case 'cache_deception': impactScore += 6; break;
            case 'cors': impactScore += 5; break;
            case 'csrf': impactScore += 5; break;
            case 'config': impactScore += 5; break;
            case 'websocket': impactScore += 5; break;
            case 'graphql_deep': impactScore += 4; break;
            case 'clickjacking': impactScore += 3; break;
            case 'anomaly': impactScore += 3; break;
            default: impactScore += 4;
        }

        // 2. Endpoint Importance (Risk Score 1-10)
        // If vulnerability is on a critical endpoint (risk 8-10), amplify impact
        if (endpointRiskScore >= 8) impactScore += 3;
        else if (endpointRiskScore >= 5) impactScore += 1;

        // 3. Mapping to Levels
        if (impactScore >= 11) return 'Critical';
        if (impactScore >= 8) return 'High';
        if (impactScore >= 5) return 'Medium';
        return 'Low';
    }
}
