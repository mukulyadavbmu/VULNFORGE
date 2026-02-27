/**
 * ServiceFingerprint — Detect HTTP server, TLS version, and open ports.
 *
 * Probes: ports 80, 443, 8080, 3000.
 * Methods: HTTP HEAD request for server header + TLS info.
 * Timeout: 3 seconds per probe. No raw sockets — uses fetch() only.
 * Security: Safe probing, no command injection, no SSRF expansion.
 */
import { z } from 'zod';
import https from 'https';
import http from 'http';
import { logger } from '../../utils/logger';

const log = logger.child({ module: 'ServiceFingerprint' });

// ─── Constants ──────────────────────────────────────────────────────────────

const PROBE_PORTS = [443, 80, 8080, 3000] as const;
const PROBE_TIMEOUT_MS = 3_000;
const MAX_HOST_LENGTH = 253;

// ─── Zod Schemas ────────────────────────────────────────────────────────────

const HostInputSchema = z.object({
    host: z.string()
        .min(1)
        .max(MAX_HOST_LENGTH)
        .regex(/^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$/, 'Invalid host format'),
}).strict();

// ─── Types ──────────────────────────────────────────────────────────────────

export interface PortResult {
    port: number;
    open: boolean;
    protocol: 'http' | 'https';
    server: string | null;
    tlsVersion: string | null;
    responseCode: number | null;
    headers: Record<string, string>;
    durationMs: number;
}

export interface FingerprintResult {
    host: string;
    ports: PortResult[];
    detectedServer: string | null;
    detectedTLS: string | null;
    openPorts: number[];
    durationMs: number;
}

// ─── Engine ─────────────────────────────────────────────────────────────────

export class ServiceFingerprint {
    /**
     * Fingerprint a host by probing standard ports.
     * Probes 80, 443, 8080, 3000 with 3s timeout each.
     */
    async fingerprint(host: string): Promise<FingerprintResult> {
        const validated = HostInputSchema.parse({ host });
        const start = Date.now();

        log.info('Service fingerprinting started', { host: validated.host });

        const portResults: PortResult[] = [];

        // Probe all ports concurrently
        const probes = PROBE_PORTS.map(port => this.probePort(validated.host, port));
        const results = await Promise.allSettled(probes);

        for (const result of results) {
            if (result.status === 'fulfilled') {
                portResults.push(result.value);
            }
        }

        // Aggregate results
        const openPorts = portResults.filter(p => p.open).map(p => p.port);
        const detectedServer = portResults.find(p => p.server)?.server ?? null;
        const detectedTLS = portResults.find(p => p.tlsVersion)?.tlsVersion ?? null;

        const durationMs = Date.now() - start;

        log.info('Service fingerprinting complete', {
            host: validated.host,
            openPorts,
            detectedServer,
            detectedTLS,
            durationMs,
        });

        return {
            host: validated.host,
            ports: portResults,
            detectedServer,
            detectedTLS,
            openPorts,
            durationMs,
        };
    }

    /**
     * Probe a single port with HEAD request.
     * Uses HTTPS for 443, HTTP for others.
     * Timeout: 3 seconds.
     */
    private probePort(host: string, port: number): Promise<PortResult> {
        const isHTTPS = port === 443;
        const protocol = isHTTPS ? 'https' : 'http';
        const start = Date.now();

        return new Promise<PortResult>((resolve) => {
            const timeout = setTimeout(() => {
                req.destroy();
                resolve({
                    port,
                    open: false,
                    protocol,
                    server: null,
                    tlsVersion: null,
                    responseCode: null,
                    headers: {},
                    durationMs: PROBE_TIMEOUT_MS,
                });
            }, PROBE_TIMEOUT_MS);

            const options = {
                hostname: host,
                port,
                path: '/',
                method: 'HEAD',
                timeout: PROBE_TIMEOUT_MS,
                rejectUnauthorized: false, // Allow self-signed for fingerprinting
                headers: {
                    'User-Agent': 'VulnForge/1.0 SecurityScanner',
                },
            };

            const handler = (res: http.IncomingMessage) => {
                clearTimeout(timeout);

                // Extract server header
                const server = this.extractServer(res.headers);

                // Extract TLS version (HTTPS only)
                let tlsVersion: string | null = null;
                if (isHTTPS && req instanceof Object) {
                    const socket = (res as { socket?: { getProtocol?: () => string } }).socket;
                    if (socket && typeof socket.getProtocol === 'function') {
                        tlsVersion = socket.getProtocol();
                    }
                }

                // Collect safe headers
                const safeHeaders: Record<string, string> = {};
                const interestingHeaders = [
                    'server', 'x-powered-by', 'x-frame-options', 'x-content-type-options',
                    'strict-transport-security', 'content-security-policy',
                    'x-xss-protection', 'access-control-allow-origin',
                ];

                for (const hdr of interestingHeaders) {
                    const val = res.headers[hdr];
                    if (typeof val === 'string') {
                        safeHeaders[hdr] = val.slice(0, 256); // Cap header value length
                    }
                }

                // Consume response body to free socket
                res.resume();

                resolve({
                    port,
                    open: true,
                    protocol,
                    server,
                    tlsVersion,
                    responseCode: res.statusCode ?? null,
                    headers: safeHeaders,
                    durationMs: Date.now() - start,
                });
            };

            const errorHandler = () => {
                clearTimeout(timeout);
                resolve({
                    port,
                    open: false,
                    protocol,
                    server: null,
                    tlsVersion: null,
                    responseCode: null,
                    headers: {},
                    durationMs: Date.now() - start,
                });
            };

            const req = isHTTPS
                ? https.request(options, handler)
                : http.request(options, handler);

            req.on('error', errorHandler);
            req.on('timeout', () => {
                req.destroy();
            });
            req.end();
        });
    }

    /**
     * Extract and normalize server header.
     */
    private extractServer(headers: http.IncomingHttpHeaders): string | null {
        const server = headers['server'];
        if (typeof server === 'string' && server.length > 0) {
            return server.slice(0, 128); // Cap length
        }

        const poweredBy = headers['x-powered-by'];
        if (typeof poweredBy === 'string' && poweredBy.length > 0) {
            return poweredBy.slice(0, 128);
        }

        return null;
    }
}
