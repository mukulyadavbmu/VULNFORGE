import PQueue from 'p-queue';
import Bottleneck from 'bottleneck';
import { logger } from '../../utils/logger';
import { config } from '../../config';

class JobDispatcherService {
    // Global limit on concurrent browser instances (heavy resource)
    public browserQueue = new PQueue({ concurrency: config.MAX_CONCURRENT_SCANS });

    // Map of domain -> RateLimiter
    private limiters = new Map<string, Bottleneck>();

    private getLimiter(url: string): Bottleneck {
        try {
            const domain = new URL(url).hostname;
            if (!this.limiters.has(domain)) {
                logger.debug(`Creating new rate limiter for ${domain}`);
                this.limiters.set(domain, new Bottleneck({
                    minTime: 200, // Max 5 requests per second
                    maxConcurrent: 5, // Max 5 concurrent connections to same domain
                    reservoir: 100, // Initial reservoir
                    reservoirRefreshAmount: 100,
                    reservoirRefreshInterval: 60 * 1000 // Refill every minute
                }));
            }
            return this.limiters.get(domain)!;
        } catch {
            // Fallback for invalid URLs or IPs
            if (!this.limiters.has('global_fallback')) {
                this.limiters.set('global_fallback', new Bottleneck({ minTime: 500 }));
            }
            return this.limiters.get('global_fallback')!;
        }
    }

    /**
     * Schedule an HTTP-like task with rate limiting per domain.
     */
    async scheduleRequest<T>(url: string, task: () => Promise<T>, priority = 5): Promise<T> {
        const limiter = this.getLimiter(url);
        return limiter.schedule({ priority }, task);
    }

    /**
     * Schedule a heavy browser task with global concurrency limits.
     */
    async scheduleBrowser<T>(task: () => Promise<T>): Promise<T> {
        return this.browserQueue.add(task) as Promise<T>;
    }
}

export const JobDispatcher = new JobDispatcherService();
