import { createClient } from '@/lib/supabase/server'

export const runtime = 'nodejs'

export async function POST() {
  const supabase = await createClient()
  await supabase.auth.signOut()
  return Response.json({ signedOut: true }, { headers: { 'Cache-Control': 'no-store' } })
}
