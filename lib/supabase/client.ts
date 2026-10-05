import { createBrowserClient } from '@supabase/ssr'

let browserClient: ReturnType<typeof createBrowserClient> | undefined

export function createClient() {
  if (!browserClient) {
    const url = process.env.NEXT_PUBLIC_SUPABASE_URL
    const key = process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY ?? process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY
    if (!url || !key) throw new Error('Supabase browser configuration is missing.')
    browserClient = createBrowserClient(url, key, {
      cookieOptions: { secure: process.env.NODE_ENV === 'production' },
    })
  }
  return browserClient
}

export function getSupabaseConfig() {
  return Boolean(
    process.env.NEXT_PUBLIC_SUPABASE_URL &&
      (process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY || process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY),
  )
}

export function getClientSupabaseConfig() {
  return {
    url: process.env.NEXT_PUBLIC_SUPABASE_URL,
    key: process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY ?? process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY,
  }
}

export type BrowserSupabaseClient = ReturnType<typeof createClient>

export function createConfiguredBrowserClient() {
  const { url, key } = getClientSupabaseConfig()
  if (!url || !key) return null
  return createClient()
}

export function getMissingSupabaseConfigMessage() {
  return 'Supabase is not configured for this deployment. Add the Supabase integration to enable secure sign-in and scanning.'
}

export function authRedirectUrl() {
  return (
    process.env.NEXT_PUBLIC_DEV_SUPABASE_REDIRECT_URL ??
    `${typeof window !== 'undefined' ? window.location.origin : ''}/auth/callback`
  )
}

export function authRedirectUrlServer(origin: string) {
  return process.env.NEXT_PUBLIC_DEV_SUPABASE_REDIRECT_URL ?? `${origin}/auth/callback`
}

export function clientConfigError() {
  return getSupabaseConfig() ? null : getMissingSupabaseConfigMessage()
}

export function browserSupabase() {
  return createConfiguredBrowserClient()
}

export function supabaseConfigPresent() {
  return getSupabaseConfig()
}

export function getBrowserClient() {
  return createConfiguredBrowserClient()
}

export function getAuthRedirectUrl() {
  return authRedirectUrl()
}

export function createSupabaseBrowserClient() {
  return createConfiguredBrowserClient()
}

export function clientAuthRedirectUrl() {
  return authRedirectUrl()
}

export function isSupabaseConfigured() {
  return getSupabaseConfig()
}

export function getSupabaseBrowserClient() {
  return createConfiguredBrowserClient()
}

export function getSupabaseAuthRedirectUrl() {
  return authRedirectUrl()
}
