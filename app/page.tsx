import { redirect } from 'next/navigation'
import { AuthScreen } from '@/components/auth-screen'
import { createClient } from '@/lib/supabase/server'

export default async function HomePage() {
  const supabase = await createClient()
  const { data: { user } } = await supabase.auth.getUser()

  if (user) redirect('/dashboard')

  return <AuthScreen />
}

export const dynamic = 'force-dynamic'
