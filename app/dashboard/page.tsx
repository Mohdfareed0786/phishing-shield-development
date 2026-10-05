import { redirect } from 'next/navigation'
import { Dashboard } from '@/components/dashboard'
import { createClient } from '@/lib/supabase/server'
import type { ScanRecord } from '@/lib/security/types'

export const dynamic = 'force-dynamic'

export default async function DashboardPage() {
  const supabase = await createClient()
  const { data: { user }, error } = await supabase.auth.getUser()

  if (error || !user) redirect('/')

  const { data } = await supabase
    .from('scan_history')
    .select('id, scan_type, target_display, risk_score, confidence, classification, detection_reasons, security_checks, threat_sources, analysis, created_at')
    .order('created_at', { ascending: false })
    .limit(100)

  return (
    <Dashboard
      email={user.email ?? ''}
      phone={user.phone ?? ''}
      displayName={String(user.user_metadata?.display_name ?? '')}
      initialScans={(data ?? []) as ScanRecord[]}
      analyzerConfigured={Boolean(process.env.PHISHING_API_URL)}
    />
  )
}
