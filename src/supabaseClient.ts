import { createClient, SupabaseClient } from '@supabase/supabase-js';
import { ScanSession } from './types';

let client: SupabaseClient | null = null;

function getClient(): SupabaseClient | null {
  if (client) return client;
  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!url || !key) return null;
  client = createClient(url, key);
  return client;
}

export async function persistScanSession(session: ScanSession): Promise<void> {
  const c = getClient();
  if (!c) return;
  try {
    await c.from('scans').upsert(
      {
        id: session.id,
        target_url: session.targetUrl,
        status: session.status,
        created_at: new Date(session.createdAt).toISOString(),
        findings_count: session.findings.length,
      },
      { onConflict: 'id' },
    );
  } catch {
    // ignore persistence failures in MVP
  }
}

