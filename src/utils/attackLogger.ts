/**
 * Attack Logging Infrastructure
 * Provides detailed visibility into every attack attempt for debugging detection gaps
 */

import { logger } from './logger';
import { ScanSession } from '../types';

export interface AttackAttempt {
  scanId: string;
  endpoint: string;
  attackType: string;
  method?: string;
  payload?: string;
  responseStatus: number;
  responseTime: number;
  signals: string[];
  findingCreated: boolean;
  rejectionReason?: string;
  authContext?: string;
}

export class AttackLogger {
  private attempts: AttackAttempt[] = [];
  
  /**
   * Log an attack attempt with all relevant details
   */
  log(attempt: AttackAttempt): void {
    this.attempts.push(attempt);
    
    const logData = {
      endpoint: attempt.endpoint,
      attack: attempt.attackType,
      method: attempt.method || 'GET',
      payload: attempt.payload ? this.truncatePayload(attempt.payload) : undefined,
      status: attempt.responseStatus,
      time_ms: attempt.responseTime,
      signals: attempt.signals.join(',') || 'none',
      finding: attempt.findingCreated ? '✓' : '✗',
      reason: attempt.rejectionReason,
      auth: attempt.authContext || 'guest',
    };

    if (attempt.findingCreated) {
      logger.info('[ATTACK SUCCESS] Finding created', logData);
    } else {
      logger.debug('[ATTACK ATTEMPT] No finding', logData);
    }
  }

  /**
   * Log a detection failure with detailed reasoning
   */
  logRejection(
    session: ScanSession,
    endpoint: string,
    attackType: string,
    payload: string,
    reason: string,
    details?: Record<string, any>
  ): void {
    logger.debug('[DETECTION REJECTED]', {
      scanId: session.id,
      endpoint,
      attackType,
      payload: this.truncatePayload(payload),
      reason,
      ...details,
    });
  }

  /**
   * Get summary statistics
   */
  getSummary(): {
    totalAttempts: number;
    findingsCreated: number;
    attacksByType: Record<string, number>;
    rejectionReasons: Record<string, number>;
  } {
    const attacksByType: Record<string, number> = {};
    const rejectionReasons: Record<string, number> = {};

    for (const attempt of this.attempts) {
      attacksByType[attempt.attackType] = (attacksByType[attempt.attackType] || 0) + 1;
      
      if (!attempt.findingCreated && attempt.rejectionReason) {
        rejectionReasons[attempt.rejectionReason] = 
          (rejectionReasons[attempt.rejectionReason] || 0) + 1;
      }
    }

    return {
      totalAttempts: this.attempts.length,
      findingsCreated: this.attempts.filter(a => a.findingCreated).length,
      attacksByType,
      rejectionReasons,
    };
  }

  /**
   * Reset attack log (for new scan)
   */
  reset(): void {
    this.attempts = [];
  }

  private truncatePayload(payload: string, maxLength = 100): string {
    if (payload.length <= maxLength) return payload;
    return payload.substring(0, maxLength) + '...';
  }
}

// Global attack logger instance
export const attackLogger = new AttackLogger();
