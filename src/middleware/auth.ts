import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { PrismaClient, OrgMembership, User } from '@prisma/client';
import { config } from '../config';
import { logger } from '../utils/logger';

const prisma = new PrismaClient();

export interface AuthenticatedRequest extends Request {
  user?: User & { memberships: OrgMembership[] };
  currentOrgId?: string;
  userRole?: string;
}

export const requireAuth = async (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing or invalid token' });
  }

  const token = authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Missing token' });

  try {
    const secret = process.env.JWT_SECRET || 'fallback-secret';
    const decoded = jwt.verify(token, secret) as { userId: string };

    const user = await prisma.user.findUnique({
      where: { id: decoded.userId },
      include: { memberships: true }
    });

    if (!user) {
      return res.status(401).json({ error: 'User not found' });
    }

    req.user = user;
    next();
  } catch (err) {
    logger.warn('Token verification failed', { error: err });
    return res.status(401).json({ error: 'Invalid token' });
  }
};

/**
 * Ensures the user has a specific role (or higher) within the specified organization.
 * Expects orgId either in req.params.orgId or req.body.orgId.
 */
export const requireOrgRole = (minRole: 'viewer' | 'analyst' | 'admin' | 'owner') => {
  return async (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    const orgId = req.params.orgId || req.body.orgId || req.query.orgId;

    if (!orgId) {
      return res.status(400).json({ error: 'Organization ID is required' });
    }

    if (!req.user) {
      return res.status(401).json({ error: 'Unauthenticated' });
    }

    const membership = req.user.memberships.find(m => m.orgId === orgId);
    if (!membership) {
      return res.status(403).json({ error: 'Access denied to this organization' });
    }

    const roles = ['viewer', 'analyst', 'admin', 'owner'];
    const userRoleIndex = roles.indexOf(membership.role);
    const minRoleIndex = roles.indexOf(minRole);

    if (userRoleIndex < minRoleIndex) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }

    req.currentOrgId = orgId as string;
    req.userRole = membership.role;
    next();
  };
};

/**
 * Validates access to a specific scan by ensuring it belongs to an org the user has access to.
 */
export const requireScanAccess = async (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
  const scanId = req.params.id;
  if (!scanId || !req.user) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  try {
    const scan = await prisma.scan.findUnique({
      where: { id: scanId },
      select: { orgId: true }
    });

    if (!scan) return res.status(404).json({ error: 'Scan not found' });
    
    // Legacy support for unassigned scans (or allow only if owner is null)
    // If it has an orgId, verify membership
    if (scan.orgId) {
      const membership = req.user.memberships.find(m => m.orgId === scan.orgId);
      if (!membership) {
        return res.status(403).json({ error: 'Access denied to this scan' });
      }
      req.currentOrgId = scan.orgId;
      req.userRole = membership.role;
    }

    next();
  } catch (err) {
    logger.error('Scan access check failed', { error: err });
    res.status(500).json({ error: 'Internal Server Error' });
  }
};
