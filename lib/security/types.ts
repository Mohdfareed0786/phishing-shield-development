export type CheckStatus = 'PASS' | 'WARNING' | 'DANGER' | 'UNKNOWN'

export type SecurityCheck = {
  key: string
  label: string
  status: CheckStatus
  details: string
}

export type DetectionReason = {
  key: string
  title: string
  details: string
  evidence: string
  points: number
}

export type ThreatSource = {
  name: string
  status: 'clean' | 'suspicious' | 'malicious' | 'unknown' | 'not_configured' | 'error' | 'not_applicable'
  details: string
  detections?: string[]
}

export type UrlFinding = {
  domain: string
  riskScore: number
  confidence: number
  classification: string
  reasons: DetectionReason[]
  checks: SecurityCheck[]
  threatSources: ThreatSource[]
}

export type ScanResult = {
  scanType: 'url' | 'message'
  scanId?: string
  historySaved?: boolean
  historyMessage?: string
  submittedUrl?: string
  domain?: string
  targetDisplay?: string
  riskScore: number
  confidence: number
  confidenceMeaning?: string
  classification: string
  phishingLikelihood?: number
  likelihoodMeaning?: string
  recommendedAction?: string
  reasons: DetectionReason[]
  checks: SecurityCheck[]
  threatSources: ThreatSource[]
  extractedUrls?: UrlFinding[]
  analyzedAt: string
}

export type ScanRecord = {
  id: string
  scan_type: 'url' | 'message'
  target_display: string
  risk_score: number
  confidence: number
  classification: string
  detection_reasons: DetectionReason[]
  security_checks: SecurityCheck[]
  threat_sources: ThreatSource[]
  analysis: ScanResult
  created_at: string
}
