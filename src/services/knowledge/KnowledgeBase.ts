import { prisma } from '../db/prisma';
import { logger } from '../../utils/logger';

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
            logger.warn('Failed to get target profile', { error, url });
            return null;
        }
    }

    static async recordSuccess(url: string, vulnType: string, payload: string, context: string) {
        try {
            const domain = new URL(url).hostname;
            // Upsert profile
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
            logger.info(`Recorded success for ${domain} - ${vulnType}`);
        } catch (error) {
            logger.error('Failed to record success', { error, url });
        }
    }
}
