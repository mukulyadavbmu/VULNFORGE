import { z } from 'zod';
import dotenv from 'dotenv';
import path from 'path';

// Load .env file
dotenv.config({ path: path.resolve(process.cwd(), '.env') });

const ConfigSchema = z.object({
  // Environment
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
  PORT: z.coerce.number().default(4000),

  // Security
  VULNFORGE_API_KEY: z.string().min(1, 'API Key is required'),
  FRONTEND_ORIGIN: z.string().default('http://localhost:5173'),

  // AI Configuration
  GEMINI_API_KEY: z.string().optional(),
  OPENAI_API_KEY: z.string().optional(),
  AI_PROVIDER: z.enum(['gemini', 'openai', 'local']).default('gemini'),

  // Database
  DATABASE_URL: z.string().default('file:./dev.db'),

  // Scanning Resources
  MAX_CONCURRENT_SCANS: z.coerce.number().default(2),
  MAX_PAGES_PER_SCAN: z.coerce.number().default(15),
  NAV_TIMEOUT_MS: z.coerce.number().default(30000),
});

// Validate and export
const parsed = ConfigSchema.safeParse(process.env);

if (!parsed.success) {
  console.error('❌ Invalid environment configuration:', parsed.error.format());
  process.exit(1);
}

export const config = parsed.data;
