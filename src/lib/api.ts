import type { Agent, Scan, Finding, Report, ScanResults, ScanStats } from '@/types';

const API_URL = (import.meta.env.VITE_API_URL || 'http://localhost:8000').replace(/\/$/, '');

export function apiUrl(path = ''): string {
  return `${API_URL}${path}`;
}

export async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(apiUrl(path), {
    ...init,
    headers: {
      'Content-Type': 'application/json',
      ...(init?.headers || {}),
    },
  });
  if (!response.ok) {
    let detail = response.statusText;
    try {
      const body = await response.json();
      detail = body.detail || JSON.stringify(body);
    } catch {
      detail = await response.text();
    }
    throw new Error(typeof detail === 'string' ? detail : 'Request failed');
  }
  if (response.status === 204) {
    return undefined as T;
  }
  return response.json();
}

function qs(params: Record<string, string | number | undefined>): string {
  const search = new URLSearchParams();
  Object.entries(params).forEach(([k, v]) => {
    if (v !== undefined && v !== '') search.set(k, String(v));
  });
  const s = search.toString();
  return s ? `?${s}` : '';
}

/** Typed REST client for the NetSentinel FastAPI backend (Render). */
export const Api = {
  // agents
  listAgents: () => api<Agent[]>('/api/agents'),
  getAgent: (agentUuid: string) => api<Agent>(`/api/agents/${agentUuid}`),

  // scans
  listScans: (limit = 50) => api<Scan[]>(`/api/scans${qs({ limit })}`),
  getScan: (scanId: string) => api<Scan>(`/api/scans/${scanId}`),
  getScanStats: (scanId: string) => api<ScanStats>(`/api/scans/${scanId}/stats`),
  getScanResults: (scanId: string) => api<ScanResults>(`/api/scans/${scanId}/results`),
  createScan: (body: { agent_id: string; target: string; scan_type: string; ports?: string | null }) =>
    api<Scan>('/api/scans', { method: 'POST', body: JSON.stringify(body) }),
  cancelScan: (scanId: string) =>
    api<Scan>(`/api/scans/${scanId}/cancel`, { method: 'POST' }),

  // findings
  listFindings: (scanId: string, severity?: string) =>
    api<Finding[]>(`/api/findings${qs({ scan_id: scanId, severity })}`),

  // reports
  listReports: () => api<Report[]>('/api/reports'),
  generateReport: (scanId: string, reportType: 'html' | 'json' | 'csv' = 'html') =>
    api<Report>(`/api/reports/generate/${scanId}${qs({ report_type: reportType })}`, {
      method: 'POST',
    }),
  downloadReportUrl: (reportId: string) => apiUrl(`/api/reports/download/${reportId}`),
};
