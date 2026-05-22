import { PrismaClient } from '@prisma/client';
import { logger } from '../utils/logger';
import crypto from 'crypto';

const prisma = new PrismaClient();

async function main() {
    logger.info('Starting tenant migration script...');

    // 1. Create Default Organization
    let defaultOrg = await prisma.organization.findFirst({
        where: { name: 'Default Organization' }
    });

    if (!defaultOrg) {
        defaultOrg = await prisma.organization.create({
            data: {
                name: 'Default Organization',
                quotas: {
                    create: {
                        maxConcurrentScans: 5,
                        maxMonthlyScans: 1000,
                        maxAiTokens: 5000000
                    }
                }
            }
        });
        logger.info(`Created Default Organization: ${defaultOrg.id}`);
    } else {
        logger.info(`Found existing Default Organization: ${defaultOrg.id}`);
    }

    // 2. Create Default Admin User
    let defaultUser = await prisma.user.findFirst({
        where: { email: 'admin@vulnforge.local' }
    });

    if (!defaultUser) {
        defaultUser = await prisma.user.create({
            data: {
                email: 'admin@vulnforge.local',
                name: 'Default Admin',
                passwordHash: crypto.createHash('sha256').update('admin123').digest('hex'), // Temporary default
                memberships: {
                    create: {
                        orgId: defaultOrg.id,
                        role: 'owner'
                    }
                }
            }
        });
        logger.info(`Created Default User: ${defaultUser.id}`);
    }

    // 3. Migrate Scans
    const { count: scanCount } = await prisma.scan.updateMany({
        where: { orgId: null },
        data: {
            orgId: defaultOrg.id,
            userId: defaultUser.id
        }
    });
    logger.info(`Migrated ${scanCount} Scans to Default Organization`);

    // 4. Migrate Target Profiles
    const { count: profileCount } = await prisma.targetProfile.updateMany({
        where: { orgId: null },
        data: { orgId: defaultOrg.id }
    });
    logger.info(`Migrated ${profileCount} Target Profiles to Default Organization`);

    // 5. Create Audit Log Entry
    await prisma.auditLog.create({
        data: {
            orgId: defaultOrg.id,
            userId: defaultUser.id,
            action: 'tenant_migration_completed',
            details: JSON.stringify({ scansMigrated: scanCount, profilesMigrated: profileCount })
        }
    });

    logger.info('Tenant migration completed successfully.');
}

main()
    .catch((e) => {
        logger.error('Migration failed', { error: e });
        process.exit(1);
    })
    .finally(async () => {
        await prisma.$disconnect();
    });
