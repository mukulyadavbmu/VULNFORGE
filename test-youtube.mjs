import { crawlTarget } from './dist/crawler.js';
import { logger } from './dist/utils/logger.js';

const mockSession = {
  id: 'cm4v1dfoo0003y4abc1234567', // random cuuid format
  targetUrl: 'https://www.youtube.com/watch?v=qXNcrFshDNE',
  authHeaders: {},
  attackNodes: {},
  status: 'running',
  budget: { maxDuration: 60, maxRequests: 100 },
  startTime: new Date().toISOString()
};

async function run() {
  // Mock addAttackNode to avoid DB writes for attack nodes
  const { addAttackNode } = await import('./dist/scanOrchestrator.js');
  
  logger.level = 'debug';
  console.log('--- START YOUTUBE CRAWL ---');
  await crawlTarget(mockSession, 'guest', { maxPages: 2 });
  console.log('--- END YOUTUBE CRAWL ---');
  process.exit(0);
}

run().catch(console.error);
