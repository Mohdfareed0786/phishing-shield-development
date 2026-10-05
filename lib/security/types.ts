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

export type UrlScanResult = {
  scanType: 'url'
  submittedUrl: string
  domain: string
  riskScore: number
  confidence: number
  classification: string
  reasons: DetectionReason[]
  checks: SecurityCheck[]
  threatSources: ThreatSource[]
  analyzedAt: string
}

export type MessageScanResult = {
  scanType: 'message'
  riskScore: number
  confidence: number
  classification: string
  phishingLikelihood: number
  reasons: DetectionReason[]
  checks: SecurityCheck[]
  extractedUrls: Array<{
    domain: string
    riskScore: number
    confidence: number
    classification: string
    reasons: DetectionReason[]
    checks: SecurityCheck[]
    threatSources: ThreatSource[]
  }>
  threatSources: ThreatSource[]
  analyzedAt: string
}

export type ScanResult = UrlScanResult | MessageScanResult

export type RiskFactor = DetectionReason

export type DnsAnalysis = {
  check: SecurityCheck
  addresses: string[]
  riskFactors: RiskFactor[]
}

export type ThreatAnalysis = {
  sources: ThreatSource[]
  urlCheck: SecurityCheck
  reputationCheck: SecurityCheck
  riskFactors: RiskFactor[]
}
