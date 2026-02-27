/**
 * SubdomainDiscovery — Enumerate subdomains via crt.sh + DNS resolution.
 *
 * Uses crt.sh Certificate Transparency API (public, no auth required).
 * Resolves discovered subdomains via DNS.
 * Limit: 100 subdomains. Timeout: 10s for crt.sh, 3s per DNS resolve.
 * Security: Input validation, safe HTTP, no command injection.
 */
import { z } from 'zod';
import { logger } from '../../utils/logger';
import dns from 'dns';

const log = logger.child({ module: 'SubdomainDiscovery' });

// ─── Constants ──────────────────────────────────────────────────────────────

const MAX_SUBDOMAINS = 100;
const CRT_SH_TIMEOUT_MS = 10_000;
const DNS_TIMEOUT_MS = 3_000;
const MAX_DOMAIN_LENGTH = 253;

// ─── Zod Schemas ────────────────────────────────────────────────────────────

const DomainInputSchema = z.object({
    domain: z.string()
        .min(3)
        .max(MAX_DOMAIN_LENGTH)
        .regex(/^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$/, 'Invalid domain format'),
}).strict();

// ─── Types ──────────────────────────────────────────────────────────────────

export interface DiscoveredSubdomain {
    subdomain: string;
    resolved: boolean;
    ipAddresses: string[];
    source: 'crt.sh' | 'dns';
}

export interface SubdomainResult {
    domain: string;
    subdomains: DiscoveredSubdomain[];
    totalFound: number;
    totalResolved: number;
    durationMs: number;
}

interface CrtShEntry {
    name_value: string;
    common_name: string;
}

// ─── Engine ─────────────────────────────────────────────────────────────────

export class SubdomainDiscovery {
    /**
     * Discover subdomains for a domain via crt.sh + DNS resolution.
     * Returns up to MAX_SUBDOMAINS (100).
     */
    async discover(domain: string): Promise<SubdomainResult> {
        const validated = DomainInputSchema.parse({ domain });
        const start = Date.now();

        log.info('Subdomain discovery started', { domain: validated.domain });

        // 1. Query crt.sh
        const rawSubdomains = await this.queryCrtSh(validated.domain);

        // 2. Deduplicate and filter
        const uniqueSubdomains = this.deduplicateAndFilter(rawSubdomains, validated.domain);

        // 3. DNS resolution (limited to MAX_SUBDOMAINS)
        const limited = uniqueSubdomains.slice(0, MAX_SUBDOMAINS);
        const results: DiscoveredSubdomain[] = [];

        // Resolve in batches of 10 to avoid overwhelming DNS
        const batchSize = 10;
        for (let i = 0; i < limited.length; i += batchSize) {
            const batch = limited.slice(i, i + batchSize);
            const resolved = await Promise.allSettled(
                batch.map(sub => this.resolveSubdomain(sub)),
            );

            for (const result of resolved) {
                if (result.status === 'fulfilled') {
                    results.push(result.value);
                }
            }
        }

        const totalResolved = results.filter(r => r.resolved).length;
        const durationMs = Date.now() - start;

        log.info('Subdomain discovery complete', {
            domain: validated.domain,
            totalFound: results.length,
            totalResolved,
            durationMs,
        });

        return {
            domain: validated.domain,
            subdomains: results,
            totalFound: results.length,
            totalResolved,
            durationMs,
        };
    }

    /**
     * Query crt.sh Certificate Transparency logs.
     * Timeout: 10 seconds.
     */
    private async queryCrtSh(domain: string): Promise<string[]> {
        const url = `https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`;

        try {
            const controller = new AbortController();
            const timeout = setTimeout(() => controller.abort(), CRT_SH_TIMEOUT_MS);

            const response = await fetch(url, {
                signal: controller.signal,
                headers: { 'Accept': 'application/json' },
            });

            clearTimeout(timeout);

            if (!response.ok) {
                log.warn('crt.sh returned non-OK status', { status: response.status });
                return [];
            }

            const text = await response.text();

            // Safe JSON parsing with size limit (5MB max)
            if (text.length > 5 * 1024 * 1024) {
                log.warn('crt.sh response too large, truncating');
                return [];
            }

            const entries: CrtShEntry[] = JSON.parse(text);

            const subdomains: string[] = [];
            for (const entry of entries) {
                // name_value can contain multiple domains separated by newlines
                const names = entry.name_value.split('\n');
                for (const name of names) {
                    const cleaned = name.trim().toLowerCase().replace(/^\*\./, '');
                    if (cleaned && cleaned.endsWith(domain)) {
                        subdomains.push(cleaned);
                    }
                }
            }

            return subdomains;
        } catch (error) {
            if (error instanceof Error && error.name === 'AbortError') {
                log.warn('crt.sh request timed out', { timeoutMs: CRT_SH_TIMEOUT_MS });
            } else {
                log.warn('crt.sh request failed', {
                    error: error instanceof Error ? error.message : 'Unknown',
                });
            }
            return [];
        }
    }

    /**
     * Deduplicate and filter subdomain list.
     */
    private deduplicateAndFilter(subdomains: string[], parentDomain: string): string[] {
        const seen = new Set<string>();
        const filtered: string[] = [];

        for (const sub of subdomains) {
            const lower = sub.toLowerCase().trim();

            // Skip duplicates
            if (seen.has(lower)) continue;
            seen.add(lower);

            // Must end with parent domain
            if (!lower.endsWith(parentDomain)) continue;

            // Validate format (no special chars except hyphen and dot)
            if (!/^[a-z0-9.-]+$/.test(lower)) continue;

            // Reject overly long subdomains
            if (lower.length > MAX_DOMAIN_LENGTH) continue;

            filtered.push(lower);

            // Hard cap
            if (filtered.length >= MAX_SUBDOMAINS) break;
        }

        return filtered;
    }

    /**
     * Resolve a subdomain via DNS with timeout.
     */
    private async resolveSubdomain(subdomain: string): Promise<DiscoveredSubdomain> {
        return new Promise<DiscoveredSubdomain>((resolve) => {
            const timeout = setTimeout(() => {
                resolve({ subdomain, resolved: false, ipAddresses: [], source: 'crt.sh' });
            }, DNS_TIMEOUT_MS);

            dns.resolve4(subdomain, (err, addresses) => {
                clearTimeout(timeout);
                if (err) {
                    resolve({ subdomain, resolved: false, ipAddresses: [], source: 'crt.sh' });
                } else {
                    resolve({ subdomain, resolved: true, ipAddresses: addresses, source: 'crt.sh' });
                }
            });
        });
    }
}
