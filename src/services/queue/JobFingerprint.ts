import { getRedisConnection } from './QueueManager';
import crypto from 'crypto';

const FINGERPRINT_TTL = 60 * 60 * 24 * 7; // 7 days

export class JobFingerprint {
    /**
     * Mark a job payload as processed. Returns true if it was already processed (duplicate).
     */
    static async isDuplicate(scanId: string, jobType: string, payload: any): Promise<boolean> {
        const redis = getRedisConnection();
        if (!redis) return false; // Fallback mode has no duplicate checking

        const hash = crypto.createHash('sha256').update(JSON.stringify(payload)).digest('hex');
        const key = `vulnforge:fp:${scanId}:${jobType}:${hash}`;

        // setnx returns 1 if key was set (new), 0 if key existed (duplicate)
        const set = await redis.setnx(key, '1');
        if (set === 1) {
            await redis.expire(key, FINGERPRINT_TTL);
            return false;
        }
        return true;
    }

    /**
     * Mark an exploit verification trace as processed to prevent redundant replays
     */
    static async isReplayDuplicate(scanId: string, findingId: string): Promise<boolean> {
        const redis = getRedisConnection();
        if (!redis) return false;

        const key = `vulnforge:fp:${scanId}:replay:${findingId}`;
        const set = await redis.setnx(key, '1');
        if (set === 1) {
            await redis.expire(key, FINGERPRINT_TTL);
            return false;
        }
        return true;
    }

    static async markCompleted(jobId: string): Promise<void> {
        const redis = getRedisConnection();
        if (!redis) return;
        await redis.setex(`vulnforge:job:${jobId}:completed`, FINGERPRINT_TTL, '1');
    }

    static async isCompleted(jobId: string): Promise<boolean> {
        const redis = getRedisConnection();
        if (!redis) return false;
        const exists = await redis.exists(`vulnforge:job:${jobId}:completed`);
        return exists === 1;
    }
}
