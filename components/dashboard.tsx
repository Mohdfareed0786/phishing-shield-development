'use client'

import { useMemo, useState, type FormEvent } from 'react'
import { useRouter } from 'next/navigation'
import { Activity, ArrowRight, CheckCircle2, ChevronRight, CircleHelp, Clock3, FileBarChart2, Fingerprint, Globe2, LayoutDashboard, Link2, LockKeyhole, LogOut, Menu, MessageSquareText, Search, ShieldAlert, ShieldCheck, ShieldEllipsis, X } from 'lucide-react'
import type { ScanRecord, ScanResult } from '@/lib/security/types'
import { SecurityReport } from '@/components/security-report'

type Section = 'overview' | 'url' | 'message' | 'history' | 'reports' | 'profile'
type ScanKind = 'url' | 'message'

const navigation: Array<{ id: Section; label: string; icon: typeof LayoutDashboard }> = [
  { id: 'overview', label: 'Dashboard', icon: LayoutDashboard },
  { id: 'url', label: 'Scan URL', icon: Link2 },
  { id: 'message', label: 'Scan message', icon: MessageSquareText },
  { id: 'history', label: 'Scan history', icon: Clock3 },
  { id: 'reports', label: 'Security reports', icon: FileBarChart2 },
  { id: 'profile', label: 'Profile', icon: Fingerprint },
]

function riskTone(score: number) {
  if (score >= 80) return 'critical'
  if (score >= 60) return 'high'
  if (score >= 30) return 'medium'
  return 'low'
}

function formatDateTime(value: string) {
  return new Intl.DateTimeFormat('en-US', { dateStyle: 'medium', timeStyle: 'short', timeZone: 'UTC' }).format(new Date(value))
}

function formatDate(value: string) {
  return new Intl.DateTimeFormat('en-US', { dateStyle: 'medium', timeZone: 'UTC' }).format(new Date(value))
}

function recordFromResult(result: ScanResult): ScanRecord | null {
  if (!result.scanId) return null
  return {
    id: result.scanId,
    scan_type: result.scanType,
    target_display: result.targetDisplay ?? result.domain ?? (result.scanType === 'message' ? 'Message scan' : 'URL scan'),
    risk_score: result.riskScore,
    confidence: result.confidence,
    classification: result.classification,
    detection_reasons: result.reasons,
    security_checks: result.checks,
    threat_sources: result.threatSources,
    analysis: result,
    created_at: result.analyzedAt,
  }
}

export function Dashboard({ email, phone, displayName, initialScans, analyzerConfigured }: { email: string; phone: string; displayName: string; initialScans: ScanRecord[]; analyzerConfigured: boolean }) {
  const router = useRouter()
  const [section, setSection] = useState<Section>('overview')
  const [scans, setScans] = useState(initialScans)
  const [selectedScan, setSelectedScan] = useState<ScanRecord | null>(null)
  const [mobileNavOpen, setMobileNavOpen] = useState(false)
  const userName = displayName.trim() || email.split('@')[0] || 'there'
  const threats = scans.filter((scan) => scan.risk_score >= 60).length
  const averageRisk = scans.length ? Math.round(scans.reduce((sum, scan) => sum + scan.risk_score, 0) / scans.length) : 0
  const respondingSources = new Set(scans.flatMap((scan) => scan.threat_sources.filter((source) => ['clean', 'suspicious', 'malicious'].includes(source.status)).map((source) => source.name))).size

  async function logout() {
    await fetch('/api/logout', { method: 'POST' })
    router.replace('/')
    router.refresh()
  }

  function navigate(next: Section) {
    setSection(next)
    setSelectedScan(null)
    setMobileNavOpen(false)
  }

  return (
    <main className="app-frame">
      <aside className={`app-sidebar ${mobileNavOpen ? 'sidebar-open' : ''}`}>
        <a className="brand-lockup sidebar-brand" href="/dashboard"><span className="brand-mark"><ShieldCheck aria-hidden="true" /></span><span>PHISHING <strong>SHIELD</strong></span></a>
        <div className="workspace-label">WORKSPACE</div>
        <nav aria-label="Main navigation" className="sidebar-nav">
          {navigation.map(({ id, label, icon: Icon }) => <button key={id} className={`nav-item ${section === id && !selectedScan ? 'nav-active' : ''}`} onClick={() => navigate(id)} aria-current={section === id && !selectedScan ? 'page' : undefined}><Icon aria-hidden="true" /><span>{label}</span>{id === 'history' && scans.length > 0 && <span className="nav-count">{scans.length}</span>}</button>)}
        </nav>
        <div className="sidebar-spacer" />
        <div className="privacy-card"><span className="privacy-icon"><ShieldEllipsis aria-hidden="true" /></span><strong>Your scans stay yours</strong><p>Personal reports are visible only to your account.</p><span className="privacy-status"><span />PRIVATE WORKSPACE</span></div>
        <div className="sidebar-user"><span className="user-avatar">{userName.slice(0, 1).toUpperCase()}</span><span className="user-details"><strong>{userName}</strong><small>{email}</small></span><button className="icon-button user-logout" aria-label="Log out" title="Log out" onClick={logout}><LogOut aria-hidden="true" /></button></div>
      </aside>

      {mobileNavOpen && <button className="mobile-scrim" aria-label="Close menu" onClick={() => setMobileNavOpen(false)} />}
      <section className="app-main">
        <header className="topbar"><div className="topbar-left"><button className="mobile-menu icon-button" aria-label={mobileNavOpen ? 'Close menu' : 'Open menu'} onClick={() => setMobileNavOpen(!mobileNavOpen)}>{mobileNavOpen ? <X /> : <Menu />}</button><div className="breadcrumb"><span>Workspace</span><ChevronRight aria-hidden="true" /><strong>{navigation.find((item) => item.id === section)?.label ?? 'Report'}</strong></div></div><div className="topbar-actions"><span className={`service-indicator ${analyzerConfigured ? 'service-configured' : ''}`}><span />{analyzerConfigured ? 'Analyzer configured' : 'Analyzer unavailable'}</span><button className="icon-button help-button" aria-label="Help and documentation" title="Help"><CircleHelp aria-hidden="true" /></button><span className="topbar-avatar" aria-label={`Signed in as ${userName}`}>{userName.slice(0, 1).toUpperCase()}</span></div></header>
        <div className="page-content">
          {selectedScan ? <ReportDetail scan={selectedScan} onBack={() => setSelectedScan(null)} /> : section === 'overview' ? <Overview name={userName} scans={scans} threats={threats} averageRisk={averageRisk} respondingSources={respondingSources} onNavigate={navigate} onSelectScan={setSelectedScan} analyzerConfigured={analyzerConfigured} /> : section === 'url' ? <ScanWorkspace kind="url" analyzerConfigured={analyzerConfigured} onComplete={(record) => { if (record) setScans((current) => [record, ...current.filter((item) => item.id !== record.id)]) }} /> : section === 'message' ? <ScanWorkspace kind="message" analyzerConfigured={analyzerConfigured} onComplete={(record) => { if (record) setScans((current) => [record, ...current.filter((item) => item.id !== record.id)]) }} /> : section === 'history' ? <HistoryPage scans={scans} onSelect={setSelectedScan} /> : section === 'reports' ? <ReportsPage scans={scans} threats={threats} averageRisk={averageRisk} /> : <ProfilePage email={email} phone={phone} displayName={displayName} />}
        </div>
        <footer className="main-footer"><span>PHISHING SHIELD · DETECT. ANALYZE. PROTECT.</span><span>Results are evidence-based signals, not a guarantee of safety.</span></footer>
      </section>
    </main>
  )
}

function Overview({ name, scans, threats, averageRisk, respondingSources, onNavigate, onSelectScan, analyzerConfigured }: { name: string; scans: ScanRecord[]; threats: number; averageRisk: number; respondingSources: number; onNavigate: (section: Section) => void; onSelectScan: (scan: ScanRecord) => void; analyzerConfigured: boolean }) {
  const latest = scans.slice(0, 4)
  return <>
    <div className="welcome-row"><div><span className="eyebrow">SECURITY OVERVIEW</span><h1>Welcome back, {name}.</h1><p>Your security workspace, with every signal backed by visible evidence.</p></div><span className="date-chip"><Activity aria-hidden="true" /> LIVE WORKSPACE</span></div>
    {!analyzerConfigured && <div className="service-alert" role="status"><ShieldAlert aria-hidden="true" /><div><strong>Analysis service is not connected</strong><p>Scans are disabled until the FastAPI service URL is configured. No results will be fabricated.</p></div><span className="alert-pill">SETUP REQUIRED</span></div>}
    <div className="stat-grid">
      <StatCard icon={Search} label="Total scans" value={scans.length.toLocaleString()} note="Saved to your private history" tone="blue" />
      <StatCard icon={ShieldAlert} label="High-risk findings" value={threats.toLocaleString()} note="Based on scans in your history" tone={threats ? 'rose' : 'slate'} />
      <StatCard icon={Activity} label="Average risk score" value={scans.length ? `${averageRisk}/100` : '—'} note={scans.length ? 'Across completed scans' : 'Appears after your first scan'} tone="violet" />
      <StatCard icon={Globe2} label="Sources with results" value={respondingSources.toLocaleString()} note="Distinct providers with returned verdicts" tone="green" />
    </div>
    <div className="quick-actions-row"><button className="quick-action" onClick={() => onNavigate('url')}><span className="quick-icon blue-icon"><Link2 aria-hidden="true" /></span><span><strong>Scan a URL</strong><small>Inspect link structure and reputation</small></span><ArrowRight aria-hidden="true" /></button><button className="quick-action" onClick={() => onNavigate('message')}><span className="quick-icon violet-icon"><MessageSquareText aria-hidden="true" /></span><span><strong>Scan a message</strong><small>Find social engineering signals</small></span><ArrowRight aria-hidden="true" /></button></div>
    <div className="overview-grid">
      <section className="panel latest-panel"><div className="panel-heading"><div><span className="eyebrow">RECENT ACTIVITY</span><h2>Latest scans</h2></div><button className="quiet-link" onClick={() => onNavigate('history')}>View history <ArrowRight aria-hidden="true" /></button></div>
        {latest.length ? <div className="activity-list">{latest.map((scan) => <button className="activity-row" key={scan.id} onClick={() => onSelectScan(scan)}><span className={`activity-type ${scan.scan_type === 'url' ? 'blue-icon' : 'violet-icon'}`}>{scan.scan_type === 'url' ? <Link2 /> : <MessageSquareText />}</span><span className="activity-target"><strong>{scan.target_display}</strong><small>{formatDateTime(scan.created_at)}</small></span><span className={`risk-badge ${riskTone(scan.risk_score)}`}>{scan.classification}</span><span className={`activity-score ${riskTone(scan.risk_score)}`}>{scan.risk_score}<small>/100</small></span><ChevronRight className="row-chevron" aria-hidden="true" /></button>)}</div> : <EmptyState icon={Search} title="Your history starts here" description="Run a URL or message scan to see verified findings in this workspace." action="Scan a URL" onAction={() => onNavigate('url')} />}
      </section>
      <section className="panel overview-side-panel"><div className="panel-heading"><div><span className="eyebrow">COVERAGE</span><h2>What gets checked</h2></div><span className="coverage-seal"><ShieldCheck aria-hidden="true" /></span></div><div className="coverage-list">{[['URL structure', 'Local analysis'], ['DNS records', 'When analyzer is online'], ['Threat feeds', 'When configured'], ['Message signals', 'Local analysis']].map(([title, note]) => <div className="coverage-row" key={title}><CheckCircle2 aria-hidden="true" /><span><strong>{title}</strong><small>{note}</small></span><span className="coverage-check">READY</span></div>)}</div><div className="coverage-note"><CircleHelp aria-hidden="true" /><span>Unavailable sources are marked unknown—not clean.</span></div></section>
    </div>
  </>
}

function StatCard({ icon: Icon, label, value, note, tone }: { icon: typeof Activity; label: string; value: string; note: string; tone: string }) {
  return <article className="stat-card"><div className={`stat-icon ${tone}`}><Icon aria-hidden="true" /></div><span className="stat-label">{label}</span><strong className="stat-value">{value}</strong><span className="stat-note">{note}</span></article>
}

function EmptyState({ icon: Icon, title, description, action, onAction }: { icon: typeof Search; title: string; description: string; action?: string; onAction?: () => void }) {
  return <div className="empty-state"><span className="empty-icon"><Icon aria-hidden="true" /></span><strong>{title}</strong><p>{description}</p>{action && onAction && <button className="quiet-link" onClick={onAction}>{action} <ArrowRight aria-hidden="true" /></button>}</div>
}

function ScanWorkspace({ kind, analyzerConfigured, onComplete }: { kind: ScanKind; analyzerConfigured: boolean; onComplete: (record: ScanRecord | null) => void }) {
  const [input, setInput] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [result, setResult] = useState<ScanResult | null>(null)
  const isUrl = kind === 'url'

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setError('')
    setResult(null)
    setBusy(true)
    try {
      const response = await fetch(isUrl ? '/api/scan-url' : '/api/scan-message', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(isUrl ? { url: input.trim() } : { message: input.trim() }),
      })
      const body = await response.json().catch(() => ({}))
      if (!response.ok) throw new Error(body.error ?? 'The analysis service could not complete this scan.')
      const scanResult = body as ScanResult
      setResult(scanResult)
      onComplete(recordFromResult(scanResult))
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Could not reach the analysis service. No scan result was created.')
    } finally {
      setBusy(false)
    }
  }

  return <>
    <div className="welcome-row scan-heading"><div><span className="eyebrow">{isUrl ? 'LINK INTELLIGENCE' : 'MESSAGE INTELLIGENCE'}</span><h1>{isUrl ? 'Scan a URL' : 'Scan a message'}</h1><p>{isUrl ? 'Review a suspicious link with structural checks, DNS and configured threat feeds.' : 'Check suspicious text for social engineering and analyze any links it contains.'}</p></div><span className="date-chip"><ShieldCheck aria-hidden="true" /> EVIDENCE-LED</span></div>
    <div className="scanner-layout"><section className="panel scanner-panel"><div className="scanner-title"><span className={`scanner-title-icon ${isUrl ? 'blue-icon' : 'violet-icon'}`}>{isUrl ? <Link2 aria-hidden="true" /> : <MessageSquareText aria-hidden="true" />}</span><div><h2>{isUrl ? 'URL security check' : 'Message security check'}</h2><p>{isUrl ? 'Configured threat feeds may receive the full URL; its destination website is never opened.' : 'Message text stays in memory and is never saved; only extracted links may be sent to configured threat feeds.'}</p></div></div>
      <form className="scan-form" onSubmit={submit}><label htmlFor="scan-input">{isUrl ? 'Suspicious URL' : 'Message text'}</label>{isUrl ? <div className="scan-input-wrap"><Link2 aria-hidden="true" /><input id="scan-input" type="url" required maxLength={2048} placeholder="https://example.com/verify-account" value={input} onChange={(event) => setInput(event.target.value)} /></div> : <textarea id="scan-input" required maxLength={10000} rows={8} placeholder="Paste the suspicious SMS, email, or message here…" value={input} onChange={(event) => setInput(event.target.value)} />}
        <div className="form-helper"><span>{isUrl ? 'URLs may be shared with configured threat feeds; the submitted website is never opened.' : 'Up to 10,000 characters. Message text is not persisted.'}</span>{!isUrl && <span>{input.length.toLocaleString()} / 10,000</span>}</div>
        <button className="primary-button scan-submit" type="submit" disabled={busy || !analyzerConfigured}>{busy ? <><span className="button-spinner" />Analyzing evidence…</> : <>{isUrl ? 'Scan URL' : 'Analyze message'}<ArrowRight aria-hidden="true" /></>}</button>
      </form>
      {!analyzerConfigured && <div className="scanner-offline" role="status"><ShieldAlert aria-hidden="true" /><div><strong>Analysis service not configured</strong><p>Connect the FastAPI endpoint to run real scans. We will not display a fabricated result.</p></div></div>}
      {error && <div className="scan-error" role="alert"><ShieldAlert aria-hidden="true" /><span>{error}</span></div>}
      <div className="scanner-assurance"><LockKeyhole aria-hidden="true" /><span>Private to your account</span><span className="assurance-separator" /><span>Evidence shown for every finding</span></div>
    </section><aside className="panel scan-notes"><span className="eyebrow">HOW THIS WORKS</span><h2>Understand the signals.</h2><p>Risk is computed from observed indicators. A score is not a promise of safety or a guarantee of detection.</p><div className="notes-list"><div><span className="notes-number">01</span><span><strong>Local inspection</strong><small>URL structure and social engineering signals</small></span></div><div><span className="notes-number">02</span><span><strong>Live checks</strong><small>DNS and configured threat intelligence feeds</small></span></div><div><span className="notes-number">03</span><span><strong>Transparent report</strong><small>Evidence, source availability and next steps</small></span></div></div><div className="no-guarantee"><CircleHelp aria-hidden="true" />Threat checks can be incomplete or time-sensitive.</div></aside></div>
    {result && <div className="scan-result-wrap"><SecurityReport result={result} /></div>}
  </>
}

function HistoryPage({ scans, onSelect }: { scans: ScanRecord[]; onSelect: (scan: ScanRecord) => void }) {
  const [query, setQuery] = useState('')
  const filtered = useMemo(() => scans.filter((scan) => `${scan.target_display} ${scan.scan_type} ${scan.classification}`.toLowerCase().includes(query.toLowerCase())), [query, scans])
  return <><div className="welcome-row"><div><span className="eyebrow">YOUR ACTIVITY</span><h1>Scan history</h1><p>Saved reports are scoped to your signed-in account.</p></div><span className="date-chip"><Clock3 aria-hidden="true" /> {scans.length} SAVED</span></div><section className="panel history-panel"><div className="history-tools"><div className="history-title"><h2>All scans</h2><span>{filtered.length} records</span></div><div className="history-search"><Search aria-hidden="true" /><input aria-label="Search scan history" placeholder="Search history" value={query} onChange={(event) => setQuery(event.target.value)} /></div></div>{filtered.length ? <div className="history-table-wrap"><table className="history-table"><thead><tr><th>Type</th><th>Target</th><th>Date</th><th>Risk score</th><th>Classification</th><th><span className="sr-only">Open report</span></th></tr></thead><tbody>{filtered.map((scan) => <tr key={scan.id} onClick={() => onSelect(scan)} tabIndex={0} onKeyDown={(event) => { if (event.key === 'Enter') onSelect(scan) }}><td><span className="type-label">{scan.scan_type === 'url' ? <Link2 aria-hidden="true" /> : <MessageSquareText aria-hidden="true" />}{scan.scan_type === 'url' ? 'URL' : 'Message'}</span></td><td className="table-target">{scan.target_display}</td><td>{formatDate(scan.created_at)}</td><td><span className={`table-score ${riskTone(scan.risk_score)}`}>{scan.risk_score}<small>/100</small></span></td><td><span className={`risk-badge ${riskTone(scan.risk_score)}`}>{scan.classification}</span></td><td><ChevronRight className="row-chevron" aria-hidden="true" /></td></tr>)}</tbody></table></div> : <EmptyState icon={Search} title={query ? 'No matching scans' : 'No scans saved yet'} description={query ? 'Try another search term.' : 'Completed scans appear here after the analysis service saves them.'} />}</section></>
}

function ReportsPage({ scans, threats, averageRisk }: { scans: ScanRecord[]; threats: number; averageRisk: number }) {
  const counts = [
    { label: 'Low risk', count: scans.filter((scan) => scan.risk_score < 30).length, tone: 'bar-low' },
    { label: 'Medium risk', count: scans.filter((scan) => scan.risk_score >= 30 && scan.risk_score < 60).length, tone: 'bar-medium' },
    { label: 'High risk', count: scans.filter((scan) => scan.risk_score >= 60 && scan.risk_score < 80).length, tone: 'bar-high' },
    { label: 'Critical risk', count: scans.filter((scan) => scan.risk_score >= 80).length, tone: 'bar-critical' },
  ]
  const max = Math.max(1, ...counts.map((item) => item.count))
  return <><div className="welcome-row"><div><span className="eyebrow">SECURITY REPORTS</span><h1>Your security reports</h1><p>Aggregate views are based only on scans saved to this account.</p></div><span className="date-chip"><FileBarChart2 aria-hidden="true" /> {scans.length} SCANS</span></div><div className="report-stats"><StatCard icon={Search} label="Scans analyzed" value={String(scans.length)} note="Saved in your account" tone="blue" /><StatCard icon={ShieldAlert} label="Elevated findings" value={String(threats)} note="Risk score 60 and above" tone="rose" /><StatCard icon={Activity} label="Average score" value={scans.length ? `${averageRisk}/100` : '—'} note="No score is shown without a scan" tone="violet" /></div><section className="panel distribution-panel"><div className="panel-heading"><div><span className="eyebrow">RISK DISTRIBUTION</span><h2>Observed scan classifications</h2></div><span className="report-total">{scans.length} TOTAL</span></div>{scans.length ? <div className="distribution-list">{counts.map((item) => <div className="distribution-row" key={item.label}><span>{item.label}</span><div className="distribution-track"><span className={item.tone} style={{ width: `${(item.count / max) * 100}%` }} /></div><strong>{item.count}</strong></div>)}</div> : <EmptyState icon={FileBarChart2} title="Reports appear after your first scan" description="This view never uses sample or synthetic scan data." />}</section><p className="report-footnote"><CircleHelp aria-hidden="true" /> Risk score summarizes observed indicators; it is not a calibrated probability or guarantee.</p></>
}

function ProfilePage({ email, phone, displayName }: { email: string; phone: string; displayName: string }) {
  const display = displayName || email.split('@')[0] || 'Account holder'
  return <><div className="welcome-row"><div><span className="eyebrow">ACCOUNT SETTINGS</span><h1>Your profile</h1><p>Identity information comes from your authenticated Supabase account.</p></div><span className="date-chip"><LockKeyhole aria-hidden="true" /> SECURE ACCOUNT</span></div><section className="panel profile-panel"><div className="profile-hero"><span className="profile-avatar">{display.slice(0, 1).toUpperCase()}</span><div><h2>{display}</h2><p>{email || 'Email not supplied'}</p></div><span className="profile-verified"><ShieldCheck aria-hidden="true" /> AUTHENTICATED</span></div><div className="profile-fields"><div><span>Email address</span><strong>{email || 'Not provided by authentication provider'}</strong></div><div><span>Mobile number</span><strong>{phone || 'Not linked to this account'}</strong></div><div><span>Authentication</span><strong>Supabase Auth · session protected</strong></div></div><div className="profile-note"><LockKeyhole aria-hidden="true" /><span>Password hashes are managed by Supabase Auth and are never stored in scan history.</span></div></section></>
}

function ReportDetail({ scan, onBack }: { scan: ScanRecord; onBack: () => void }) {
  const result = scan.analysis && typeof scan.analysis === 'object' ? scan.analysis : null
  return <><button className="back-link" onClick={onBack}>‹ Back to scans</button><div className="welcome-row report-detail-heading"><div><span className="eyebrow">SAVED SECURITY REPORT</span><h1>{scan.target_display}</h1><p>{scan.scan_type === 'url' ? 'URL analysis' : 'Message analysis'} · {formatDateTime(scan.created_at)}</p></div><span className={`risk-badge ${riskTone(scan.risk_score)}`}>{scan.classification}</span></div>{result ? <SecurityReport result={result} /> : <section className="panel report-unavailable"><ShieldAlert aria-hidden="true" /><h2>Report details unavailable</h2><p>This saved record does not contain an analysis report.</p></section>}</>
}

