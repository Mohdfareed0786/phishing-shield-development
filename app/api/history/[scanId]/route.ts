import { proxyAnalyzerRequest } from '@/lib/server/api-proxy'

export const runtime = 'nodejs'
export const dynamic = 'force-dynamic'

type RouteContext = { params: Promise<{ scanId: string }> }

export async function GET(request: Request, context: RouteContext) {
  const { scanId } = await context.params
  if (!/^[0-9a-f-]{36}$/i.test(scanId)) {
    return Response.json({ error: 'Scan report not found.' }, { status: 404, headers: { 'Cache-Control': 'no-store' } })
  }
  return proxyAnalyzerRequest(request, `history/${encodeURIComponent(scanId)}`, 'GET')
}
