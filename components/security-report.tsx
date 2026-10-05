import { AlertTriangle, ArrowDownRight, CheckCircle2, CircleHelp, ExternalLink, Globe2, MessageSquareText, ShieldAlert } from 'lucide-react'
import type { ScanResult, CheckStatus } from '@/lib/security/types'

function scoreTone(score: number) {
  if (score >= 80) return 'critical'
  if (score >= 60) return 'high'
  if (score >= 30) return 'medium'
  return 'low'
}

function statusIcon(status: CheckStatus) {
  if (status === 'PASS') return CheckCircle2
  if (status === 'WARNING') return AlertTriangle
  if (status === 'DANGER') return ShieldAlert
  return CircleHelp
}

export function SecurityReport({ result }: { result: ScanResult }) {
  const tone = scoreTone(result.riskScore)
  return <section className="security-report" aria-label="Security scan report">
    {result.historySaved === false && <div className="history-save-warning" role="status"><AlertTriangle aria-hidden="true" /><span>{result.historyMessage ?? 'Analysis completed, but the report could not be saved to history.'}</span></div>}
    <div className="panel result-summary"><div className="result-gauge" data-tone={tone} style={{ '--risk-angle': `${result.riskScore * 3.6}deg` } as React.CSSProperties} role="img" aria-label={`Risk score ${result.riskScore} out of 100`}><div><strong>{result.riskScore}</strong><span> / 100</span></div></div><div className="result-overview"><span className="eyebrow">{result.scanType === 'url' ? 'URL ANALYSIS' : 'MESSAGE ANALYSIS'}</span><h2>{result.classification}</h2><p>{result.targetDisplay ?? result.domain ?? (result.scanType === 'message' ? 'Message scan' : 'Submitted URL')}</p><div className="result-meta"><span><strong>{result.confidence}%</strong> coverage</span><span><strong>{new Intl.DateTimeFormat('en-US', { dateStyle: 'medium', timeStyle: 'short', timeZone: 'UTC' }).format(new Date(result.analyzedAt))}</strong></span></div><small className="confidence-note">{result.confidenceMeaning ?? 'Confidence reflects analysis coverage, not guaranteed accuracy.'}</small></div><div className="result-action"><strong>Recommended action</strong><p>{result.recommendedAction ?? (result.riskScore >= 60 ? 'Do not interact with this content. Verify through an official channel.' : result.riskScore >= 30 ? 'Proceed with caution. Confirm the sender and destination independently.' : 'No elevated signal was found in completed checks. Stay alert.')}</p></div></div>
    {result.scanType === 'message' && <div className="message-signal-card"><div className="signal-icon"><MessageSquareText aria-hidden="true" /></div><div><strong>Phishing signal strength: {result.phishingLikelihood ?? result.riskScore}/100</strong><p>{result.likelihoodMeaning ?? 'Evidence-based heuristic score; not a calibrated statistical probability.'}</p></div></div>}
    <div className="result-grid"><section className="panel result-section"><div className="panel-heading"><div><span className="eyebrow">OBSERVED EVIDENCE</span><h3>Detection reasons <span className="section-count">{result.reasons.length}</span></h3></div></div>{result.reasons.length ? <div className="reason-list">{result.reasons.map((reason) => <article className="reason-row" key={reason.key}><span className={`reason-marker ${reason.points >= 25 ? 'reason-danger' : 'reason-warning'}`}><ArrowDownRight aria-hidden="true" /></span><div><strong>{reason.title}</strong><p>{reason.details}</p>{reason.evidence && <span className="evidence-line">Observed: {reason.evidence}</span>}</div><span className="reason-points">+{reason.points}</span></article>)}</div> : <div className="report-empty-note"><CheckCircle2 aria-hidden="true" /><span>No elevated indicators were found in the completed checks. Unknown checks are listed separately below.</span></div>}</section>
      <section className="panel result-section"><div className="panel-heading"><div><span className="eyebrow">CHECK RESULTS</span><h3>Security checks <span className="section-count">{result.checks.length}</span></h3></div></div><div className="checks-list">{result.checks.map((check) => { const Icon = statusIcon(check.status); return <div className="check-row" key={check.key}><Icon className={`check-status-icon status-${check.status.toLowerCase()}`} aria-hidden="true" /><div><strong>{check.label}</strong><p>{check.details}</p></div><span className={`status-pill status-${check.status.toLowerCase()}`}>{check.status}</span></div> })}</div></section></div>
    <section className="panel sources-panel"><div className="panel-heading"><div><span className="eyebrow">THREAT INTELLIGENCE</span><h3>Sources queried</h3></div><Globe2 aria-hidden="true" /></div><div className="sources-grid">{result.threatSources.map((source) => <div className="source-row" key={source.name}><span className={`source-dot source-${source.status}`} /><div><strong>{source.name}</strong><p>{source.details}</p></div><span className={`source-status source-text-${source.status}`}>{source.status.replaceAll('_', ' ')}</span></div>)}</div></section>
    {result.extractedUrls && result.extractedUrls.length > 0 && <section className="panel extracted-panel"><div className="panel-heading"><div><span className="eyebrow">LINKS FOUND IN MESSAGE</span><h3>Extracted URLs <span className="section-count">{result.extractedUrls.length}</span></h3></div></div><div className="extracted-list">{result.extractedUrls.map((item, index) => <div className="extracted-row" key={`${item.domain}-${index}`}><span className="extracted-link-icon"><ExternalLink aria-hidden="true" /></span><div><strong>{item.domain}</strong><span>{item.classification} · {item.riskScore}/100 risk · {item.confidence}% coverage</span>{item.reasons.length > 0 && <small>{item.reasons.map((reason) => reason.title).join(' · ')}</small>}</div><span className={`table-score ${scoreTone(item.riskScore)}`}>{item.riskScore}<small>/100</small></span></div>)}</div></section>}
    <p className="report-disclaimer"><CircleHelp aria-hidden="true" />A low score does not prove content is safe. Some checks may be unavailable, and threat intelligence can change over time.</p>
  </section>
}

