import React, { useEffect, useRef, useState } from 'react';
import {
    getScanProgress,
    getScanSummary,
    ProgressData,
    SummaryData,
    ScanEventDto,
} from '../api';

interface Props {
    scanId: string;
}

const EVENT_COLORS: Record<string, string> = {
    recon: '#3b82f6',
    attack: '#f97316',
    success: '#22c55e',
    info: '#6b7280',
    warning: '#eab308',
};

const SUMMARY_ROWS: Array<{
    key: keyof SummaryData;
    label: string;
    meaning: string;
}> = [
        { key: 'endpoints', label: 'Endpoints', meaning: 'Application routes discovered' },
        { key: 'sensitivePaths', label: 'Sensitive Paths', meaning: 'Admin/debug/billing endpoints found' },
        { key: 'vulnerabilities', label: 'Vulnerabilities', meaning: 'Total security findings detected' },
        { key: 'criticalFindings', label: 'Critical Findings', meaning: 'Maximum severity vulnerabilities' },
        { key: 'highFindings', label: 'High Findings', meaning: 'High risk vulnerabilities detected' },
        { key: 'confirmedExploits', label: 'Confirmed Exploits', meaning: 'Verified exploitable weaknesses' },
    ];

const PHASE_EXPLANATIONS: Record<string, string> = {
    'Reconnaissance': 'The crawler is discovering all pages, APIs, and analyzing JavaScript for deep endpoints, secrets, and tech fingerprints.',
    'Surface Mapping': 'VulnForge is mapping out the application architecture, grouping endpoints, identifying auth roles, and tagging sensitive paths.',
    'Hypothesis': 'The AI Hypothesis Engine is analyzing the attack surface to form specific theories about potential vulnerabilities.',
    'Attacking': 'Executing targeted attacks based on generated hypotheses, along with fallback baseline probes for all reachable endpoints.',
    'Verification': 'Verifying the reproducibility of all discovered vulnerabilities by re-executing high/critical exploits multiple times.',
    'Chain Analysis': 'The Attack Path Engine is correlating individual vulnerabilities to detect multi-step exploit chains and privilege escalation paths.',
    'Risk Scoring': 'Calculating final confidence scores and operational risk based on exploit reliability and contextual business impact.',
    'Completed': 'Scan finished. All endpoints tested and findings documented. Review the results below.',
};

export const ScanProgressPanel: React.FC<Props> = ({ scanId }) => {
    const [progress, setProgress] = useState<ProgressData | null>(null);
    const [summary, setSummary] = useState<SummaryData | null>(null);
    const feedRef = useRef<HTMLDivElement>(null);

    useEffect(() => {
        let active = true;

        const poll = async () => {
            if (!active) return;
            try {
                const [prog, sum] = await Promise.all([
                    getScanProgress(scanId),
                    getScanSummary(scanId),
                ]);
                if (active) {
                    setProgress(prog);
                    setSummary(sum);
                }
            } catch {
                // Silently ignore — next poll will retry
            }
        };

        void poll();
        const interval = setInterval(poll, 3000);

        return () => {
            active = false;
            clearInterval(interval);
        };
    }, [scanId]);

    // Auto-scroll feed to bottom
    useEffect(() => {
        if (feedRef.current) {
            feedRef.current.scrollTop = feedRef.current.scrollHeight;
        }
    }, [progress?.events?.length]);

    const phase = progress?.currentPhase || '';
    const action = progress?.currentAction || '';
    const events = progress?.events || [];
    const explanation = PHASE_EXPLANATIONS[phase] || '';

    return (
        <div className="flex flex-col gap-3 mb-4">
            {/* ── Part 6: Live Status Banner ── */}
            <div className="bg-gradient-to-br from-slate-900 to-indigo-950 border border-indigo-900 rounded-lg p-4 flex justify-between items-center shadow-lg">
                <div>
                    <div className="text-lg font-bold text-indigo-100">
                        {phase || 'Waiting...'}
                    </div>
                    <div className="text-sm text-indigo-300 mt-1">
                        {action || 'Initializing scanner...'}
                    </div>
                </div>
                <div className={`flex items-center gap-2 text-sm font-medium ${phase === 'Completed' ? 'text-success' : 'text-indigo-300'}`}>
                    <span className={`inline-block w-2.5 h-2.5 rounded-full ${phase === 'Completed' ? 'bg-success' : 'bg-indigo-400 animate-pulse'}`} />
                    {phase === 'Completed' ? 'Scan Complete' : 'System Active'}
                </div>
            </div>

            {/* ── Part 7: Notification Feed ── */}
            <div className="bg-surface border border-border rounded-lg shadow-sm flex flex-col">
                <div className="px-4 py-2 border-b border-border text-xs font-semibold text-textMuted uppercase tracking-wider">
                    Activity Feed
                </div>
                <div
                    ref={feedRef}
                    className="h-64 overflow-y-auto py-2 font-mono text-xs"
                >
                    {events.length === 0 && (
                        <div className="p-4 text-textMuted text-center">
                            Waiting for scan activity...
                        </div>
                    )}
                    {events.map((evt: ScanEventDto, i: number) => {
                        const evtColor = EVENT_COLORS[evt.type] || '#6b7280';
                        return (
                            <div
                                key={`${evt.timestamp}-${i}`}
                                className="flex px-4 py-1 mb-px"
                                style={{ borderLeft: `3px solid ${evtColor}` }}
                            >
                                <span className="text-textMuted mr-3 shrink-0">
                                    {new Date(evt.timestamp).toLocaleTimeString()}
                                </span>
                                <span style={{ color: evtColor }}>
                                    {evt.message}
                                </span>
                            </div>
                        );
                    })}
                </div>
            </div>

            {/* ── Part 9: Findings Summary Table ── */}
            {summary && (summary.endpoints > 0 || summary.vulnerabilities > 0) && (
                <div className="bg-surface border border-border rounded-lg shadow-sm overflow-hidden">
                    <div className="px-4 py-2 border-b border-border text-xs font-semibold text-textMuted uppercase tracking-wider bg-[#0D1117]/50">
                        Intelligence Summary
                    </div>
                    <div className="overflow-x-auto">
                        <table className="w-full text-sm text-left">
                            <thead className="bg-[#0D1117] text-textMuted">
                                <tr>
                                    <th className="px-4 py-2 font-normal">Metric</th>
                                    <th className="px-4 py-2 font-normal text-center">Value</th>
                                    <th className="px-4 py-2 font-normal">Meaning</th>
                                </tr>
                            </thead>
                            <tbody>
                                {SUMMARY_ROWS.map(row => {
                                    const value = summary[row.key];
                                    const isCritical = row.key === 'criticalFindings' && value > 0;
                                    const isHigh = row.key === 'highFindings' && value > 0;
                                    return (
                                        <tr key={String(row.key)} className="border-b border-border/50 hover:bg-[#0D1117]/20">
                                            <td className="px-4 py-2 text-textMain">{row.label}</td>
                                            <td className={`px-4 py-2 text-base font-bold text-center ${
                                                isCritical ? 'text-danger' : isHigh ? 'text-warning' : 'text-success'
                                            }`}>
                                                {value}
                                            </td>
                                            <td className="px-4 py-2 text-xs text-textMuted">{row.meaning}</td>
                                        </tr>
                                    );
                                })}
                            </tbody>
                        </table>
                    </div>
                </div>
            )}

            {/* ── Part 10: Explanation Panel ── */}
            {explanation && (
                <div className="bg-slate-900 border border-slate-700 rounded-lg p-4 max-h-64 overflow-y-auto">
                    <div className="text-xs font-semibold text-blue-400 uppercase tracking-wider mb-2">
                        What's happening
                    </div>
                    <div className="text-sm text-slate-300 leading-relaxed">
                        {explanation}
                    </div>
                    {phase === 'Reconnaissance' && summary && summary.sensitivePaths > 0 && (
                        <div className="mt-3 p-3 bg-blue-950 rounded text-xs text-blue-300">
                            <strong>Sensitive Endpoints Detected:</strong> Admin and configuration endpoints
                            often expose privileged functionality. Attackers prioritize these for escalation.
                        </div>
                    )}
                </div>
            )}
        </div>
    );
};
