/**
 * MAILSENTINEL — Forensic Data Architecture
 * Types representing threat detection and digital forensics models.
 */

export type RiskLevel = 'benign' | 'suspicious' | 'malicious' | 'critical' | 'unassessed';

export type ThreatClassification = 
  | 'Phishing' 
  | 'Spoofing' 
  | 'Malicious' 
  | 'Suspicious' 
  | 'Benign' 
  | 'Pending';

export type CaseStatus = 'open' | 'under_review' | 'verified' | 'closed';

export type AuthResultStatus = 'pass' | 'fail' | 'softfail' | 'neutral' | 'none' | 'temperror' | 'permerror';

export interface EmailHeaderHop {
  hopNumber: number;
  fromHost: string;
  byHost: string;
  withProtocol?: string;
  forRecipient?: string;
  timestamp: string;
  delaySeconds?: number;
  ipAddress?: string;
  reverseDns?: string;
  rawHeader: string;
}

export interface EmailAuthentication {
  spf: {
    status: AuthResultStatus;
    details: string;
    ip?: string;
    domain?: string;
  };
  dkim: {
    status: AuthResultStatus;
    details: string;
    domain?: string;
    selector?: string;
  };
  dmarc: {
    status: AuthResultStatus;
    details: string;
    policy?: 'none' | 'quarantine' | 'reject';
    disposition?: string;
  };
  authResultsRaw?: string;
}

export interface URLIndicator {
  id: string;
  url: string;
  domain: string;
  scheme: string;
  risk: 'clean' | 'suspicious' | 'malicious';
  reputationScore?: number;
  status: string;
  relatedIp?: string;
  isShortened?: boolean;
  redirectTarget?: string;
}

export interface DomainIndicator {
  domain: string;
  registeredDate?: string;
  registrar?: string;
  risk: 'clean' | 'suspicious' | 'malicious';
  ageDays?: number;
  dnsRecords?: {
    a?: string[];
    mx?: string[];
    txt?: string[];
    ns?: string[];
  };
}

export interface IPIndicator {
  ip: string;
  version: 'v4' | 'v6';
  country?: string;
  countryCode?: string;
  region?: string;
  city?: string;
  asn?: string;
  asName?: string;
  organization?: string;
  network?: string;
  reputation?: 'clean' | 'suspicious' | 'malicious';
  threatScore?: number;
  isVpnOrProxy?: boolean;
  isTor?: boolean;
  latitude?: number;
  longitude?: number;
}

export interface AttachmentIndicator {
  id: string;
  filename: string;
  sizeBytes: number;
  mimeType: string;
  sha256: string;
  md5?: string;
  risk: 'clean' | 'suspicious' | 'malicious';
  fileType?: string;
}

export interface ThreatIndicator {
  id: string;
  type: 
    | 'sender_mismatch' 
    | 'reply_to_mismatch' 
    | 'suspicious_url' 
    | 'suspicious_ip' 
    | 'attachment' 
    | 'domain_anomaly' 
    | 'dmarc_failure' 
    | 'spf_failure' 
    | 'urgent_language';
  severity: 'low' | 'medium' | 'high' | 'critical';
  title: string;
  description: string;
  evidence: string;
}

export interface AIAnalysis {
  classification: ThreatClassification;
  riskLevel: RiskLevel;
  confidence: number;
  keyIndicators: string[];
  explanation: string;
  recommendedActions: string[];
  evidenceSources: string[];
}

export interface BlockchainVerification {
  status: 'verified' | 'pending' | 'unverified' | 'failed';
  network?: string;
  blockNumber?: number;
  transactionId?: string;
  merkleRoot?: string;
  timestamp?: string;
  disclaimer: string;
}

export interface EvidenceRecord {
  id: string;
  caseId: string;
  originalEmailSha256: string;
  headerEvidenceSha256: string;
  attachmentHashes: Array<{
    filename: string;
    sha256: string;
    sizeBytes?: number;
  }>;
  timestamp: string;
  investigator: string;
  blockchainVerification: BlockchainVerification;
}

export interface InfrastructureNode {
  id: string;
  label: string;
  type: 'email' | 'domain' | 'ip' | 'asn' | 'org';
  details?: Record<string, string>;
  risk?: 'clean' | 'suspicious' | 'malicious';
  x?: number;
  y?: number;
}

export interface InfrastructureEdge {
  id: string;
  source: string;
  target: string;
  relationship: string;
}

export interface InfrastructureGraph {
  nodes: InfrastructureNode[];
  edges: InfrastructureEdge[];
}

export interface EmailData {
  from: string;
  to: string;
  replyTo?: string;
  returnPath?: string;
  subject: string;
  date: string;
  messageId: string;
  bodyText: string;
  bodyHtml?: string;
  headersRaw: string;
  headersList: Array<{ name: string; value: string }>;
  hops: EmailHeaderHop[];
  authentication: EmailAuthentication;
  attachments: AttachmentIndicator[];
}

export interface InvestigationEvent {
  id: string;
  caseId: string;
  timestamp: string;
  actor: string;
  action: string;
  details?: string;
}

export interface Case {
  id: string;
  caseNumber: string;
  subject: string;
  sender: string;
  recipient: string;
  riskLevel: RiskLevel;
  riskScore?: number;
  classification: ThreatClassification;
  status: CaseStatus;
  createdAt: string;
  updatedAt: string;
  investigator?: string;
  emailData: EmailData;
  indicators: ThreatIndicator[];
  urls: URLIndicator[];
  ips: IPIndicator[];
  domains: DomainIndicator[];
  aiAnalysis?: AIAnalysis;
  evidence?: EvidenceRecord;
  infrastructure?: InfrastructureGraph;
  timeline?: InvestigationEvent[];
}

export interface ForensicReportSection {
  id: string;
  title: string;
  isIncluded: boolean;
  content?: string;
}

export interface ForensicReport {
  id: string;
  caseId: string;
  caseNumber: string;
  title: string;
  generatedAt: string;
  generatedBy: string;
  status: 'ready' | 'generating' | 'draft';
  classification?: ThreatClassification;
  riskLevel?: RiskLevel;
  sections: ForensicReportSection[];
  summaryNote?: string;
}

export type PipelineStageStatus = 'waiting' | 'running' | 'completed' | 'failed';

export interface PipelineStage {
  id: number;
  name: string;
  status: PipelineStageStatus;
  durationMs?: number;
  detail?: string;
}
