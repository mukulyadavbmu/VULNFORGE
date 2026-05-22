import { prisma } from '../db/prisma';
import { logger } from '../../utils/logger';

const log = logger.child({ module: 'KnowledgeBase' });

// ─── Types ──────────────────────────────────────────────────────────────────

export interface PayloadSuccessRate {
    vulnType: string;
    totalAttempts: number;
    successCount: number;
    rate: number;
}

export interface RecurringVulnerability {
    vulnType: string;
    occurrences: number;
    firstSeen: Date;
    lastSeen: Date;
}

export interface LearningSignals {
    topVulnTypes: PayloadSuccessRate[];
    recurringVulns: RecurringVulnerability[];
    techStack: string[];
    totalSuccesses: number;
}

// ─── Engine ─────────────────────────────────────────────────────────────────

export class KnowledgeBase {

    static async getTargetProfile(url: string) {
        try {
            const domain = new URL(url).hostname;
            const profile = await prisma.targetProfile.findUnique({
                where: { domain },
                include: { successes: true }
            });
            return profile;
        } catch (error) {
            log.warn('Failed to get target profile', { error, url });
            return null;
        }
    }

    static async recordSuccess(url: string, vulnType: string, payload: string, context: string) {
        try {
            const domain = new URL(url).hostname;
            let profile = await prisma.targetProfile.findUnique({ where: { domain } });
            if (!profile) {
                profile = await prisma.targetProfile.create({
                    data: { domain, techStack: '[]' }
                });
            }

            await prisma.payloadSuccess.create({
                data: {
                    targetProfileId: profile.id,
                    vulnType,
                    payload,
                    context
                }
            });
            log.info(`Recorded success for ${domain} - ${vulnType}`);
        } catch (error) {
            log.error('Failed to record success', { error, url });
        }
    }

    /**
     * Get payload success rates by vulnerability type for a domain.
     * Returns how often each vuln type has been successfully exploited.
     */
    static async getPayloadSuccessRate(url: string): Promise<PayloadSuccessRate[]> {
        try {
            const domain = new URL(url).hostname;
            const profile = await prisma.targetProfile.findUnique({
                where: { domain },
                include: { successes: true },
            });

            if (!profile || profile.successes.length === 0) return [];

            // Group successes by vulnType
            const typeMap = new Map<string, number>();
            for (const s of profile.successes) {
                typeMap.set(s.vulnType, (typeMap.get(s.vulnType) || 0) + 1);
            }

            const total = profile.successes.length;
            return Array.from(typeMap.entries()).map(([vulnType, count]) => ({
                vulnType,
                totalAttempts: total,
                successCount: count,
                rate: count / total,
            })).sort((a, b) => b.rate - a.rate);
        } catch (error) {
            log.warn('Failed to get payload success rates', { error });
            return [];
        }
    }

    /**
     * Get recurring vulnerabilities across scans for a domain.
     * Identifies patterns by counting finding types across time.
     */
    static async getRecurringVulnerabilities(url: string): Promise<RecurringVulnerability[]> {
        try {
            const domain = new URL(url).hostname;
            const profile = await prisma.targetProfile.findUnique({
                where: { domain },
                include: { successes: true },
            });

            if (!profile || profile.successes.length === 0) return [];

            // Group by vulnType and track time range
            const typeStats = new Map<string, { count: number; firstSeen: Date; lastSeen: Date }>();
            for (const s of profile.successes) {
                const existing = typeStats.get(s.vulnType);
                if (existing) {
                    existing.count++;
                    if (s.createdAt < existing.firstSeen) existing.firstSeen = s.createdAt;
                    if (s.createdAt > existing.lastSeen) existing.lastSeen = s.createdAt;
                } else {
                    typeStats.set(s.vulnType, {
                        count: 1,
                        firstSeen: s.createdAt,
                        lastSeen: s.createdAt,
                    });
                }
            }

            // Only return types with 2+ occurrences (recurring)
            return Array.from(typeStats.entries())
                .filter(([, stats]) => stats.count >= 2)
                .map(([vulnType, stats]) => ({
                    vulnType,
                    occurrences: stats.count,
                    firstSeen: stats.firstSeen,
                    lastSeen: stats.lastSeen,
                }))
                .sort((a, b) => b.occurrences - a.occurrences);
        } catch (error) {
            log.warn('Failed to get recurring vulnerabilities', { error });
            return [];
        }
    }

    /**
     * Update tech fingerprint for a domain.
     * Stores the detected tech stack so future scans can leverage it.
     */
    static async updateTechFingerprint(url: string, techStack: string[]): Promise<void> {
        try {
            const domain = new URL(url).hostname;
            const techJson = JSON.stringify(techStack);

            await prisma.targetProfile.upsert({
                where: { domain },
                update: { techStack: techJson },
                create: { domain, techStack: techJson },
            });

            log.info(`Updated tech fingerprint for ${domain}`, { techStack });
        } catch (error) {
            log.error('Failed to update tech fingerprint', { error, url });
        }
    }

    /**
     * Get aggregated learning signals for the AttackStrategyEngine.
     * Combines success rates, recurring vulns, and tech stack.
     */
    static async getLearningSignals(url: string): Promise<LearningSignals> {
        try {
            const [successRates, recurringVulns, profile] = await Promise.all([
                this.getPayloadSuccessRate(url),
                this.getRecurringVulnerabilities(url),
                this.getTargetProfile(url),
            ]);

            const techStack: string[] = [];
            if (profile?.techStack) {
                try {
                    const parsed = JSON.parse(profile.techStack);
                    if (Array.isArray(parsed)) techStack.push(...parsed);
                } catch { /* skip invalid JSON */ }
            }

            return {
                topVulnTypes: successRates.slice(0, 5),
                recurringVulns,
                techStack,
                totalSuccesses: profile?.successes?.length || 0,
            };
        } catch (error) {
            log.warn('Failed to get learning signals', { error });
            return { topVulnTypes: [], recurringVulns: [], techStack: [], totalSuccesses: 0 };
        }
    }
}
