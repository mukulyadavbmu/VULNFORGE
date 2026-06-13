import { logger } from './dist/utils/logger.js';
import { setOnRedisReady } from './dist/services/queue/QueueManager.js';
import { ScanLifecycleService } from './dist/services/scan/ScanLifecycleService.js';

logger.level = 'debug';
console.log('--- START QUEUE TEST ---');

setOnRedisReady(async () => {
  console.log('--- REDIS READY CALLBACK ---');
  await ScanLifecycleService.enqueueScan('test-queue-scan-id');
  setTimeout(() => process.exit(0), 1000);
});
