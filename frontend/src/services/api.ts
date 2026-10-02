/**
 * MAILSENTINEL — API & Forensic Extraction Service
 * Prepares client layer for FastAPI backend integration and client-side forensic utilities.
 */

import {
  Case,
  EvidenceRecord,
  InfrastructureGraph,
  ForensicReport,
  PipelineStage,
  EmailData,
  EmailHeaderHop,
  EmailAuthentication,
  URLIndicator,
  IPIndicator,
  DomainIndicator,
} from '../types/forensics';

// Configurable backend URL. Empty by default to support reverse proxy or direct host
export const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000/api';

/**
 * Real SHA-256 cryptographic digest calculation using Web Crypto API.
 */
export async function calculateSha256(data: string | ArrayBuffer): Promise<string> {
  const encoder = new TextEncoder();
  const buffer = typeof data === 'string' ? encoder.encode(data) : data;
  const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Forensic Header Parser:
 * Accurately parses standard RFC 5322 / RFC 822 email headers and Received chains.
 */
export function parseRawHeaders(rawText: string): {
  headersList: Array<{ name: string; value: string }>;
  headersMap: Record<string, string>;
  hops: EmailHeaderHop[];
  auth: EmailAuthentication;
  urls: URLIndicator[];
  ips: IPIndicator[];
  domains: DomainIndicator[];
} {
  const headersList: Array<{ name: string; value: string }> = [];
  const headersMap: Record<string, string> = {};
  const rawHops: string[] = [];

  // RFC header unfolding (lines starting with whitespace are continuations)
  const unfoldedLines: string[] = [];
  const lines = rawText.split(/\r?\n/);
  for (const line of lines) {
    if (/^\s+/.test(line) && unfoldedLines.length > 0) {
      unfoldedLines[unfoldedLines.length - 1] += ' ' + line.trim();
    } else {
      unfoldedLines.push(line);
    }
  }

  for (const line of unfoldedLines) {
    const match = line.match(/^([A-Za-z0-9_-]+):\s*(.*)$/);
    if (match) {
      const name = match[1];
      const value = match[2].trim();
      headersList.push({ name, value });
      const lowerName = name.toLowerCase();
      if (!headersMap[lowerName]) {
        headersMap[lowerName] = value;
      }
      if (lowerName === 'received') {
        rawHops.push(value);
      }
    }
  }

  // Parse Received Hops
  const hops: EmailHeaderHop[] = rawHops.map((rawHeader, idx) => {
    // Extract IP address e.g. [192.0.2.1] or (192.0.2.1)
    const ipMatch = rawHeader.match(/\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]/);
    const fromMatch = rawHeader.match(/from\s+([^;\s]+)/i);
    const byMatch = rawHeader.match(/by\s+([^;\s]+)/i);
    const withMatch = rawHeader.match(/with\s+([^;\s]+)/i);
    const forMatch = rawHeader.match(/for\s+<([^>]+)>/i);
    const timeMatch = rawHeader.match(/;\s*([A-Za-z]{3},\s+\d{1,2}\s+[A-Za-z]{3}\s+\d{4}.*)$/);

    return {
      hopNumber: idx + 1,
      fromHost: fromMatch ? fromMatch[1] : 'Unknown host',
      byHost: byMatch ? byMatch[1] : 'Relay',
      withProtocol: withMatch ? withMatch[1] : undefined,
      forRecipient: forMatch ? forMatch[1] : undefined,
      timestamp: timeMatch ? timeMatch[1].trim() : 'Unspecified timestamp',
      ipAddress: ipMatch ? ipMatch[1] : undefined,
      rawHeader: 'Received: ' + rawHeader,
    };
  });

  // Extract Authentication Results (SPF, DKIM, DMARC)
  const authResults = headersMap['authentication-results'] || headersMap['received-spf'] || '';
  const dkimHeader = headersMap['dkim-signature'] || '';

  const spfStatus = /spf=(pass|fail|softfail|neutral|none|temperror|permerror)/i.exec(authResults)?.[1]?.toLowerCase() as any 
    || (/pass/i.test(headersMap['received-spf'] || '') ? 'pass' : 'none');

  const dkimStatus = /dkim=(pass|fail|none|temperror|permerror)/i.exec(authResults)?.[1]?.toLowerCase() as any 
    || (dkimHeader ? 'pass' : 'none');

  const dmarcStatus = /dmarc=(pass|fail|none|quarantine|reject)/i.exec(authResults)?.[1]?.toLowerCase() as any || 'none';

  const auth: EmailAuthentication = {
    spf: {
      status: spfStatus,
      details: headersMap['received-spf'] || (authResults ? `SPF extracted from Authentication-Results: ${spfStatus}` : 'No SPF header found'),
      domain: headersMap['from'] ? headersMap['from'].split('@')[1]?.replace('>', '').trim() : undefined,
    },
    dkim: {
      status: dkimStatus,
      details: dkimHeader ? `DKIM Signature present: d=${/d=([^;]+)/i.exec(dkimHeader)?.[1] || 'domain'}` : 'No DKIM signature detected',
      domain: /d=([^;]+)/i.exec(dkimHeader)?.[1]?.trim(),
      selector: /s=([^;]+)/i.exec(dkimHeader)?.[1]?.trim(),
    },
    dmarc: {
      status: dmarcStatus,
      details: `DMARC policy status: ${dmarcStatus}`,
      policy: /p=(none|quarantine|reject)/i.exec(authResults)?.[1]?.toLowerCase() as any || 'none',
    },
    authResultsRaw: authResults || 'No Authentication-Results header provided',
  };

  // Extract IP addresses found in headers
  const ipRegex = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g;
  const foundIps = Array.from(new Set(rawText.match(ipRegex) || []));
  const ips: IPIndicator[] = foundIps
    .filter(ip => !ip.startsWith('127.') && !ip.startsWith('0.') && !ip.startsWith('255.'))
    .map(ip => ({
      ip,
      version: 'v4',
      status: 'extracted',
    }));

  // Extract URLs from text
  const urlRegex = /https?:\/\/[^\s<>"')]+/gi;
  const foundUrls = Array.from(new Set(rawText.match(urlRegex) || []));
  const urls: URLIndicator[] = foundUrls.map((url, i) => {
    try {
      const parsed = new URL(url);
      return {
        id: `url-${i + 1}`,
        url,
        domain: parsed.hostname,
        scheme: parsed.protocol.replace(':', ''),
        risk: 'clean',
        status: 'Extracted from headers/body',
      };
    } catch {
      return {
        id: `url-${i + 1}`,
        url,
        domain: 'malformed',
        scheme: 'http',
        risk: 'suspicious',
        status: 'Malformed URL syntax',
      };
    }
  });

  const uniqueDomains = Array.from(new Set(urls.map(u => u.domain).filter(d => d !== 'malformed')));
  const domains: DomainIndicator[] = uniqueDomains.map(domain => ({
    domain,
    risk: 'clean',
  }));

  return {
    headersList,
    headersMap,
    hops,
    auth,
    urls,
    ips,
    domains,
  };
}

/**
 * Standard Forensic Pipeline Stages
 */
export const FORENSIC_PIPELINE_STAGES = [
  'Email Parsed',
  'Headers Extracted',
  'Authentication Analyzed',
  'URLs Extracted',
  'IP Addresses Identified',
  'Threat Intelligence Lookup',
  'Infrastructure Correlation',
  'AI Threat Assessment',
  'Evidence Fingerprinting',
] as const;

export function initializePipelineStages(): PipelineStage[] {
  return FORENSIC_PIPELINE_STAGES.map((name, index) => ({
    id: index + 1,
    name,
    status: 'waiting',
  }));
}

/**
 * FastAPI Backend API Client
 */
export const ApiClient = {
  /**
   * Health Check to see if FastAPI backend is available
   */
  async checkBackendHealth(): Promise<{ online: boolean; message: string }> {
    try {
      const res = await fetch(`${API_BASE_URL}/health`, { method: 'GET', signal: AbortSignal.timeout(3000) });
      if (res.ok) {
        return { online: true, message: 'Connected to FastAPI service' };
      }
      return { online: false, message: `FastAPI responded with HTTP ${res.status}` };
    } catch (err: any) {
      return { online: false, message: err?.message || 'FastAPI service unavailable' };
    }
  },

  /**
   * GET /api/cases
   */
  async getCases(filters?: { search?: string; status?: string; risk?: string }): Promise<Case[]> {
    try {
      const params = new URLSearchParams();
      if (filters?.search) params.append('search', filters.search);
      if (filters?.status) params.append('status', filters.status);
      if (filters?.risk) params.append('risk', filters.risk);

      const res = await fetch(`${API_BASE_URL}/cases?${params.toString()}`);
      if (!res.ok) return [];
      return await res.json();
    } catch {
      // Backend not connected yet
      return [];
    }
  },

  /**
   * GET /api/cases/{id}
   */
  async getCaseById(id: string): Promise<Case | null> {
    try {
      const res = await fetch(`${API_BASE_URL}/cases/${encodeURIComponent(id)}`);
      if (!res.ok) return null;
      return await res.json();
    } catch {
      return null;
    }
  },

  /**
   * POST /api/analyze-email
   */
  async analyzeEmail(formData: FormData): Promise<{ caseId: string; status: string } | null> {
    try {
      const res = await fetch(`${API_BASE_URL}/analyze-email`, {
        method: 'POST',
        body: formData,
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return await res.json();
    } catch {
      return null;
    }
  },

  /**
   * GET /api/evidence
   */
  async getEvidence(caseId?: string): Promise<EvidenceRecord[]> {
    try {
      const url = caseId 
        ? `${API_BASE_URL}/evidence?case_id=${encodeURIComponent(caseId)}`
        : `${API_BASE_URL}/evidence`;
      const res = await fetch(url);
      if (!res.ok) return [];
      return await res.json();
    } catch {
      return [];
    }
  },

  /**
   * GET /api/infrastructure
   */
  async getInfrastructure(caseId: string): Promise<InfrastructureGraph | null> {
    try {
      const res = await fetch(`${API_BASE_URL}/infrastructure?case_id=${encodeURIComponent(caseId)}`);
      if (!res.ok) return null;
      return await res.json();
    } catch {
      return null;
    }
  },

  /**
   * GET /api/threat-intelligence
   */
  async getThreatIntelligence(query: { ioc: string; type: string }): Promise<any | null> {
    try {
      const params = new URLSearchParams({ ioc: query.ioc, type: query.type });
      const res = await fetch(`${API_BASE_URL}/threat-intelligence?${params.toString()}`);
      if (!res.ok) return null;
      return await res.json();
    } catch {
      return null;
    }
  },

  /**
   * GET /api/reports
   */
  async getReports(caseId?: string): Promise<ForensicReport[]> {
    try {
      const url = caseId 
        ? `${API_BASE_URL}/reports?case_id=${encodeURIComponent(caseId)}`
        : `${API_BASE_URL}/reports`;
      const res = await fetch(url);
      if (!res.ok) return [];
      return await res.json();
    } catch {
      return [];
    }
  },

  /**
   * POST /api/reports
   */
  async createReport(payload: { caseId: string; title: string; sections: string[] }): Promise<ForensicReport | null> {
    try {
      const res = await fetch(`${API_BASE_URL}/reports`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      if (!res.ok) return null;
      return await res.json();
    } catch {
      return null;
    }
  },
};
