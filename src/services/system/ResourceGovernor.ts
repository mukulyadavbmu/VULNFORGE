import { queues, getQueueHealth } from '../queue/QueueManager';
import { logger } from '../../utils/logger';

const log = logger.child({ module: 'ResourceGovernor' });

export class ResourceGovernor {
    static async checkBackpressure(): Promise<boolean> {
        const health = await getQueueHealth();
        if (health.mode !== 'distributed' || !health.queues) return false;

        // If attack jobs queue is heavily backed up, throttle orchestration
        if (health.queues['attack-jobs']?.wait > 1000) {
            log.warn('Queue backpressure detected. Throttling orchestration.', { waitCount: health.queues['attack-jobs'].wait });
            return true;
        }
        return false;
    }

    static checkMemoryWarning(): boolean {
        const mem = process.memoryUsage();
        const heapUsedMB = Math.round(mem.heapUsed / 1024 / 1024);
        
        if (heapUsedMB > 700) { // Warning at 700MB
            log.warn('Global memory usage high', { heapUsedMB });
            if (global.gc) global.gc();
            return true;
        }
        return false;
    }

    static async waitIfThrottled(): Promise<void> {
        while (await this.checkBackpressure() || this.checkMemoryWarning()) {
            await new Promise(resolve => setTimeout(resolve, 5000));
        }
    }
}
