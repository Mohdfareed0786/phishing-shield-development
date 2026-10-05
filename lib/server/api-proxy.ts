import { createClient } from '@/lib/supabase/server'

const noStore = { 'Cache-Control': 'no-store', 'Content-Type': 'application/json' }

export async function proxyAnalyzerRequest(request: Request, endpoint: string, method: 'GET' | 'POST' = 'GET') {
  const supabase = await createClient()
  const { data: { user }, error: userError } = await supabase.auth.getUser()

  if (userError || !user) {
    return Response.json({ error: 'Sign in to use this security feature.' }, { status: 401, headers: noStore })
  }

  const { data: { session } } = await supabase.auth.getSession()
  if (!session?.access_token) {
    return Response.json({ error: 'Your session has expired. Sign in again to continue.' }, { status: 401, headers: noStore })
  }

  const configuredUrl = process.env.PHISHING_API_URL
  if (!configuredUrl) {
    return Response.json({ error: 'The analysis service is not configured. No scan was performed.' }, { status: 503, headers: noStore })
  }

  let apiBase: string
  try {
    const serviceUrl = new URL(configuredUrl)
    const localDevelopmentHost = ['localhost', '127.0.0.1', '[::1]'].includes(serviceUrl.hostname)
    const secureTransport = serviceUrl.protocol === 'https:' || (process.env.NODE_ENV !== 'production' && serviceUrl.protocol === 'http:' && localDevelopmentHost)
    if (!secureTransport || serviceUrl.username || serviceUrl.password || serviceUrl.search || serviceUrl.hash) throw new Error('Invalid API origin')
    apiBase = `${serviceUrl.origin}${serviceUrl.pathname.replace(/\/+$/, '')}`
    if (!apiBase.endsWith('/api')) apiBase = `${apiBase}/api`
  } catch {
    return Response.json({ error: 'The analysis service URL must use HTTPS in production.' }, { status: 503, headers: noStore })
  }

  let body: string | undefined
  if (method === 'POST') {
    const maxBytes = 48 * 1024
    const declaredLength = Number(request.headers.get('content-length') ?? 0)
    if (declaredLength > maxBytes) {
      return Response.json({ error: 'The scan request is too large.' }, { status: 413, headers: noStore })
    }
    try {
      const reader = request.body?.getReader()
      const decoder = new TextDecoder()
      let decoded = ''
      let receivedBytes = 0
      if (reader) {
        while (true) {
          const { done, value } = await reader.read()
          if (done) break
          receivedBytes += value.byteLength
          if (receivedBytes > maxBytes) {
            await reader.cancel()
            return Response.json({ error: 'The scan request is too large.' }, { status: 413, headers: noStore })
          }
          decoded += decoder.decode(value, { stream: true })
        }
        decoded += decoder.decode()
      }
      body = JSON.stringify(JSON.parse(decoded))
    } catch {
      return Response.json({ error: 'The request body must be valid JSON.' }, { status: 400, headers: noStore })
    }
  }

  try {
    const upstream = await fetch(`${apiBase}/${endpoint}`, {
      method,
      headers: {
        Authorization: `Bearer ${session.access_token}`,
        ...(body ? { 'Content-Type': 'application/json' } : {}),
      },
      body,
      cache: 'no-store',
      signal: AbortSignal.timeout(35_000),
    })
    const payload = await upstream.json().catch(() => null)
    if (!payload || typeof payload !== 'object') {
      return Response.json({ error: 'The analysis service returned an unreadable response.' }, { status: 502, headers: noStore })
    }
    return Response.json(payload, { status: upstream.status, headers: noStore })
  } catch (error) {
    if (error instanceof Error && error.name === 'TimeoutError') {
      return Response.json({ error: 'The analysis timed out. No result was saved; please try again later.' }, { status: 504, headers: noStore })
    }
    return Response.json({ error: 'The analysis service is unreachable. No scan result was created.' }, { status: 502, headers: noStore })
  }
}
