import { PrismaClient } from '@prisma/client';
import { logger } from '../../utils/logger';

const prisma = new PrismaClient();

export class OrgService {
  static async createOrganization(name: string, ownerUserId: string) {
    const org = await prisma.organization.create({
      data: {
        name,
        members: {
          create: {
            userId: ownerUserId,
            role: 'owner'
          }
        },
        quotas: {
          create: {
            maxConcurrentScans: 2,
            maxMonthlyScans: 50
          }
        }
      }
    });
    
    await prisma.auditLog.create({
      data: {
        orgId: org.id,
        userId: ownerUserId,
        action: 'org_created',
        details: JSON.stringify({ name })
      }
    });

    return org;
  }

  static async getMembers(orgId: string) {
    return await prisma.orgMembership.findMany({
      where: { orgId },
      include: { user: { select: { id: true, email: true, name: true } } }
    });
  }

  static async addMember(orgId: string, email: string, role: string, addedByUserId: string) {
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) throw new Error('User not found');

    const membership = await prisma.orgMembership.create({
      data: {
        orgId,
        userId: user.id,
        role
      }
    });

    await prisma.auditLog.create({
      data: {
        orgId,
        userId: addedByUserId,
        action: 'member_added',
        details: JSON.stringify({ addedUserId: user.id, role })
      }
    });

    return membership;
  }

  static async getMetrics(orgId: string) {
    const activeScans = await prisma.scan.count({
      where: { orgId, status: { in: ['running', 'pending'] } }
    });

    const totalFindings = await prisma.finding.count({
      where: { scan: { orgId } }
    });

    const quota = await prisma.quota.findUnique({ where: { orgId } });

    return {
      activeScans,
      totalFindings,
      quota
    };
  }

  static async getAuditLogs(orgId: string, limit = 50) {
    return await prisma.auditLog.findMany({
      where: { orgId },
      orderBy: { createdAt: 'desc' },
      take: limit,
      include: { user: { select: { email: true } } }
    });
  }
}
