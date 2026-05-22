import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { logger } from '../../utils/logger';

const prisma = new PrismaClient();

export class AuthService {
  static async registerUser(email: string, passwordRaw: string, name?: string) {
    const existing = await prisma.user.findUnique({ where: { email } });
    if (existing) {
      throw new Error('User already exists');
    }

    const passwordHash = await bcrypt.hash(passwordRaw, 10);
    
    // Create User + Default Org
    const user = await prisma.user.create({
      data: {
        email,
        name,
        passwordHash,
        memberships: {
          create: {
            role: 'owner',
            org: {
              create: {
                name: `${name || email}'s Organization`,
                quotas: {
                  create: {
                    maxConcurrentScans: 2,
                    maxMonthlyScans: 50
                  }
                }
              }
            }
          }
        }
      },
      include: { memberships: true }
    });

    const orgId = user.memberships[0].orgId;

    await prisma.auditLog.create({
      data: {
        orgId,
        userId: user.id,
        action: 'user_registered',
        details: JSON.stringify({ email })
      }
    });

    return user;
  }

  static async login(email: string, passwordRaw: string) {
    const user = await prisma.user.findUnique({ 
      where: { email },
      include: { memberships: true }
    });
    
    if (!user) {
      throw new Error('Invalid credentials');
    }

    const valid = await bcrypt.compare(passwordRaw, user.passwordHash);
    if (!valid) {
      throw new Error('Invalid credentials');
    }

    const secret = process.env.JWT_SECRET || 'fallback-secret';
    const token = jwt.sign({ userId: user.id }, secret, { expiresIn: '8h' });

    if (user.memberships.length > 0) {
      await prisma.auditLog.create({
        data: {
          orgId: user.memberships[0].orgId,
          userId: user.id,
          action: 'user_login'
        }
      });
    }

    return { token, user: { id: user.id, email: user.email, name: user.name, memberships: user.memberships } };
  }
}
