import React, { useMemo } from 'react';

interface Header {
    name: string;
    value: string;
}

export interface ReplayTrace {
    id: string;
    request: {
        method: string;
        url: string;
        headers: Header[];
        body?: string;
    };
    response?: {
        status: number;
        headers: Header[];
        body?: string;
    };
    timestamp: string;
}

interface Props {
    trace: ReplayTrace;
}

// Sanitize sensitive headers (JWTs/Cookies)
const sanitizeHeaders = (headers: Header[]): Header[] => {
    return headers.map(h => {
        const name = h.name.toLowerCase();
        if (name === 'authorization' || name === 'cookie' || name === 'set-cookie' || name === 'x-api-key') {
            return { name: h.name, value: '[REDACTED FOR SECURITY]' };
        }
        return h;
    });
};

export const ReplayViewer: React.FC<Props> = ({ trace }) => {
    const safeReqHeaders = useMemo(() => sanitizeHeaders(trace.request.headers || []), [trace.request.headers]);
    const safeResHeaders = useMemo(() => sanitizeHeaders(trace.response?.headers || []), [trace.response?.headers]);

    return (
        <div className="flex flex-col gap-4">
            <div className="bg-surface border border-border rounded-lg overflow-hidden shadow-sm">
                <div className="px-4 py-2 border-b border-border bg-[#0D1117]/50 font-mono text-sm flex gap-3 items-center">
                    <span className="font-bold text-primary">{trace.request.method}</span>
                    <span className="text-textMain truncate">{trace.request.url}</span>
                </div>
                <div className="p-4 grid grid-cols-1 md:grid-cols-2 gap-4">
                    {/* Request */}
                    <div className="flex flex-col">
                        <h4 className="text-xs font-semibold text-textMuted uppercase mb-2">Request Headers</h4>
                        <div className="bg-[#0D1117] p-3 rounded border border-border font-mono text-xs overflow-x-auto text-textMain flex-1">
                            {safeReqHeaders.map((h, i) => (
                                <div key={i}>
                                    <span className="text-blue-400">{h.name}:</span> {h.value}
                                </div>
                            ))}
                        </div>
                        {trace.request.body && (
                            <>
                                <h4 className="text-xs font-semibold text-textMuted uppercase mt-4 mb-2">Request Body</h4>
                                <div className="bg-[#0D1117] p-3 rounded border border-border font-mono text-xs overflow-x-auto text-textMain max-h-48">
                                    {trace.request.body}
                                </div>
                            </>
                        )}
                    </div>

                    {/* Response */}
                    <div className="flex flex-col">
                        <h4 className="text-xs font-semibold text-textMuted uppercase mb-2 flex items-center gap-2">
                            Response Status
                            {trace.response && (
                                <span className={`px-2 py-0.5 rounded text-[10px] text-white ${
                                    trace.response.status >= 500 ? 'bg-danger' :
                                    trace.response.status >= 400 ? 'bg-warning' :
                                    trace.response.status >= 300 ? 'bg-primary' : 'bg-success'
                                }`}>
                                    {trace.response.status}
                                </span>
                            )}
                        </h4>
                        <div className="bg-[#0D1117] p-3 rounded border border-border font-mono text-xs overflow-x-auto text-textMain">
                            {safeResHeaders.map((h, i) => (
                                <div key={i}>
                                    <span className="text-blue-400">{h.name}:</span> {h.value}
                                </div>
                            ))}
                        </div>
                        {trace.response?.body && (
                            <>
                                <h4 className="text-xs font-semibold text-textMuted uppercase mt-4 mb-2">Response Body</h4>
                                <div className="bg-[#0D1117] p-3 rounded border border-border font-mono text-xs overflow-x-auto text-textMain max-h-48">
                                    {trace.response.body}
                                </div>
                            </>
                        )}
                    </div>
                </div>
            </div>
            <div className="text-xs text-textMuted text-right">
                Captured: {new Date(trace.timestamp).toLocaleString()}
            </div>
        </div>
    );
};
