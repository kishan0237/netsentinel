import { useEffect, useState } from 'react';
import { Server, Activity, Cpu, Bug, AlertTriangle, ChevronDown, ChevronRight, Wifi, Monitor, Shield, ArrowLeft, RefreshCw, FileText } from 'lucide-react';
import { Api } from '@/lib/api';
import type { Scan, HostWithPorts, Finding } from '@/types';
import type { Page } from '@/components/Navbar';
import { formatRelativeTime, formatDuration, severityBadgeClass, severityOrder } from '@/lib/utils';
import { useScanPoll } from '@/hooks/useScanPolling';

interface ResultsPageProps {
  onNavigate: (page: Page) => void;
  selectedScanId: string | null;
  onSelectScan: (scanId: string) => void;
}

type HostWithDetails = HostWithPorts;

export function ResultsPage({ onNavigate, selectedScanId, onSelectScan }: ResultsPageProps) {
  const [results, setResults] = useState<{ scan: Scan; hosts: HostWithDetails[]; findings: Finding[] } | null>(null);
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [expandedHosts, setExpandedHosts] = useState<Set<string>>(new Set());
  const [activeTab, setActiveTab] = useState<'hosts' | 'findings' | 'summary'>('summary');

  const liveScan = useScanPoll(selectedScanId);
  const scan = liveScan || results?.scan || null;
  const isLive = scan?.status === 'running' || scan?.status === 'pending';

  useEffect(() => {
    const loadScansList = async () => {
      try {
        const data = await Api.listScans();
        setScans(data);
        if (!selectedScanId && data.length > 0) {
          onSelectScan(data[0].id);
        }
      } catch {
        /* transient — poller will retry */
      }
    };
    loadScansList();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (!selectedScanId) {
      setResults(null);
      setLoading(false);
      return;
    }
    setLoading(true);
    setLoadError(null);
    Api.getScanResults(selectedScanId)
      .then(setResults)
      .catch((e) => setLoadError(e instanceof Error ? e.message : 'Failed to load results'))
      .finally(() => setLoading(false));
  }, [selectedScanId]);

  // Reload the results tree once when the live scan completes
  useEffect(() => {
    if (liveScan?.status === 'completed' && selectedScanId) {
      Api.getScanResults(selectedScanId).then(setResults).catch(() => undefined);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [liveScan?.status]);

  const toggleHost = (hostId: string) => {
    setExpandedHosts((prev) => {
      const next = new Set(prev);
      if (next.has(hostId)) next.delete(hostId);
      else next.add(hostId);
      return next;
    });
  };

  const hosts = results?.hosts ?? [];
  const findings = results?.findings ?? [];
  const totalPorts = hosts.reduce((sum, h) => sum + h.ports.length, 0);
  const totalServices = hosts.reduce((sum, h) => sum + h.ports.reduce((s, p) => s + p.services.length, 0), 0);
  const totalVulns = hosts.reduce(
    (sum, h) => sum + h.ports.reduce((s, p) => s + p.services.reduce((s2, svc) => s2 + svc.vulnerabilities.length, 0), 0),
    0
  );

  const sortedFindings = [...findings].sort((a, b) => severityOrder(a.severity) - severityOrder(b.severity));

  if (loading) {
    return (
      <div className="min-h-screen pt-24 flex items-center justify-center">
        <div className="flex items-center gap-3 text-base-500">
          <RefreshCw className="w-5 h-5 animate-spin" />
          <span>Loading results...</span>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen pt-20 pb-16 px-4 sm:px-6 lg:px-8">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-6">
          <div className="flex items-center gap-4">
            <button
              onClick={() => onNavigate('dashboard')}
              className="p-2 rounded-lg text-base-400 hover:text-base-200 hover:bg-base-800/50 transition-colors"
            >
              <ArrowLeft className="w-5 h-5" />
            </button>
            <div>
              <h1 className="text-2xl sm:text-3xl font-bold text-base-50 mb-1">Scan Results</h1>
              {scan && (
                <div className="flex items-center gap-3 text-sm text-base-500">
                  <span className="font-mono text-brand-400">{scan.target}</span>
                  <span>·</span>
                  <span className="capitalize">{scan.scan_type}</span>
                  <span>·</span>
                  <span>{formatRelativeTime(scan.started_at || scan.created_at)}</span>
                </div>
              )}
            </div>
          </div>
          <div className="flex items-center gap-3">
            {scans.length > 1 && (
              <select
                value={selectedScanId || ''}
                onChange={(e) => onSelectScan(e.target.value)}
                className="input-field text-sm py-2 w-auto"
              >
                {scans.map((s) => (
                  <option key={s.id} value={s.id}>
                    {s.target} · {s.scan_type} · {s.status}
                  </option>
                ))}
              </select>
            )}
            <button
              onClick={() => onNavigate('reports')}
              className="btn-secondary text-sm"
            >
              <FileText className="w-4 h-4" />
              Reports
            </button>
          </div>
        </div>

        {/* Live progress banner */}
        {isLive && scan && (
          <div className="card p-4 mb-6 border-brand-500/30 bg-brand-500/5">
            <div className="flex items-center gap-3">
              <RefreshCw className="w-4 h-4 text-brand-400 animate-spin" />
              <div className="flex-1">
                <div className="flex justify-between text-sm mb-1">
                  <span className="text-base-200 capitalize">
                    {scan.status === 'pending' ? 'Waiting for agent' : (scan.current_stage?.replace(/_/g, ' ') || 'Scanning')}
                  </span>
                  <span className="font-mono text-base-400">{scan.progress}%</span>
                </div>
                <div className="w-full h-1.5 rounded-full bg-base-800 overflow-hidden">
                  <div className="h-full rounded-full bg-brand-400 animate-pulse transition-all" style={{ width: `${scan.progress}%` }} />
                </div>
              </div>
            </div>
          </div>
        )}

        {loadError && (
          <div className="card p-4 mb-6 border-danger-500/30 bg-danger-500/5">
            <p className="text-sm text-danger-400">{loadError}</p>
          </div>
        )}

        {scan?.status === 'failed' && (
          <div className="card p-4 mb-6 border-danger-500/30 bg-danger-500/5">
            <p className="text-sm text-danger-400">
              Scan failed: {scan.error || 'unknown error'}
            </p>
          </div>
        )}

        {/* Stats Bar */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
          {[
            { icon: Server, label: 'Hosts', value: hosts.length, color: 'text-brand-400' },
            { icon: Activity, label: 'Open Ports', value: totalPorts, color: 'text-accent-400' },
            { icon: Cpu, label: 'Services', value: totalServices, color: 'text-info-400' },
            { icon: Bug, label: 'Vulnerabilities', value: totalVulns, color: 'text-warning-400' },
          ].map((stat, i) => {
            const Icon = stat.icon;
            return (
              <div key={i} className="card p-4">
                <div className="flex items-center gap-2 mb-2">
                  <Icon className={`w-4 h-4 ${stat.color}`} />
                  <span className="text-xs text-base-500">{stat.label}</span>
                </div>
                <div className="text-2xl font-bold text-base-50 font-mono">{stat.value}</div>
              </div>
            );
          })}
        </div>

        {/* Tabs */}
        <div className="flex items-center gap-1 mb-6 border-b border-base-800">
          {[
            { key: 'summary' as const, label: 'Summary', icon: Shield },
            { key: 'hosts' as const, label: 'Hosts & Services', icon: Server },
            { key: 'findings' as const, label: `Findings (${findings.length})`, icon: AlertTriangle },
          ].map((tab) => {
            const Icon = tab.icon;
            const active = activeTab === tab.key;
            return (
              <button
                key={tab.key}
                onClick={() => setActiveTab(tab.key)}
                className={`flex items-center gap-2 px-4 py-2.5 text-sm font-medium border-b-2 transition-colors ${
                  active
                    ? 'text-brand-400 border-brand-400'
                    : 'text-base-500 border-transparent hover:text-base-300'
                }`}
              >
                <Icon className="w-4 h-4" />
                {tab.label}
              </button>
            );
          })}
        </div>

        {/* Summary Tab */}
        {activeTab === 'summary' && (
          <div className="space-y-6 animate-fade-in">
            {scan && (
              <div className="card p-6">
                <h3 className="text-base-50 font-semibold mb-4">Scan Details</h3>
                <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
                  <div>
                    <div className="text-xs text-base-500 mb-1">Target</div>
                    <div className="text-sm text-base-200 font-mono">{scan.target}</div>
                  </div>
                  <div>
                    <div className="text-xs text-base-500 mb-1">Type</div>
                    <div className="text-sm text-base-200 capitalize">{scan.scan_type}</div>
                  </div>
                  <div>
                    <div className="text-xs text-base-500 mb-1">Duration</div>
                    <div className="text-sm text-base-200">{formatDuration(scan.started_at, scan.completed_at)}</div>
                  </div>
                  <div>
                    <div className="text-xs text-base-500 mb-1">Status</div>
                    <span className={`badge ${scan.status === 'completed' ? 'badge-success' : scan.status === 'failed' ? 'badge-high' : 'badge-info'}`}>
                      {scan.status}
                    </span>
                  </div>
                </div>
              </div>
            )}

            {sortedFindings.length > 0 ? (
              <div className="card p-6">
                <h3 className="text-base-50 font-semibold mb-4">Findings Overview</h3>
                <div className="space-y-3">
                  {sortedFindings.map((finding) => (
                    <div
                      key={finding.id}
                      className="p-4 rounded-lg bg-base-950/50 border border-base-800 hover:border-base-700 transition-colors"
                    >
                      <div className="flex items-start gap-3">
                        <span className={`badge ${severityBadgeClass(finding.severity)} flex-shrink-0`}>
                          {finding.severity}
                        </span>
                        <div className="flex-1">
                          <h4 className="text-base-100 font-medium mb-1">{finding.title}</h4>
                          {finding.description && (
                            <p className="text-sm text-base-400 mb-2">{finding.description}</p>
                          )}
                          {finding.recommendation && (
                            <div className="flex items-start gap-2 mt-2 p-2 rounded-md bg-accent-500/5 border border-accent-500/10">
                              <Shield className="w-4 h-4 text-accent-400 flex-shrink-0 mt-0.5" />
                              <p className="text-xs text-base-300">{finding.recommendation}</p>
                            </div>
                          )}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            ) : (
              <div className="card p-12 text-center">
                <Shield className="w-12 h-12 text-accent-400 mx-auto mb-4 opacity-50" />
                <h3 className="text-base-100 font-medium mb-1">No findings</h3>
                <p className="text-sm text-base-500">
                  {scan?.status === 'completed' ? 'This scan did not produce any risk findings.' : 'Findings appear when the scan completes.'}
                </p>
              </div>
            )}
          </div>
        )}

        {/* Hosts Tab */}
        {activeTab === 'hosts' && (
          <div className="space-y-3 animate-fade-in">
            {hosts.length === 0 ? (
              <div className="card p-12 text-center">
                <Server className="w-12 h-12 text-base-600 mx-auto mb-4" />
                <h3 className="text-base-100 font-medium mb-1">No hosts discovered</h3>
                <p className="text-sm text-base-500">
                  {isLive ? 'Hosts appear as the agent discovers them.' : 'This scan did not find any live hosts.'}
                </p>
              </div>
            ) : (
              hosts.map((host) => {
                const isExpanded = expandedHosts.has(host.id);
                const hostVulns = host.ports.reduce(
                  (s, p) => s + p.services.reduce((s2, svc) => s2 + svc.vulnerabilities.length, 0), 0
                );
                return (
                  <div key={host.id} className="card overflow-hidden">
                    <button
                      onClick={() => toggleHost(host.id)}
                      className="w-full flex items-center gap-4 p-4 hover:bg-base-800/30 transition-colors text-left"
                    >
                      {isExpanded ? (
                        <ChevronDown className="w-5 h-5 text-base-500 flex-shrink-0" />
                      ) : (
                        <ChevronRight className="w-5 h-5 text-base-500 flex-shrink-0" />
                      )}
                      <div className="flex-shrink-0 w-10 h-10 rounded-lg bg-base-800 flex items-center justify-center">
                        <Monitor className="w-5 h-5 text-base-400" />
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-3">
                          <span className="font-mono text-sm text-base-100 font-medium">{host.ip_address}</span>
                          {host.hostname && (
                            <span className="text-sm text-base-500 truncate">{host.hostname}</span>
                          )}
                        </div>
                        {host.os_estimate && (
                          <div className="text-xs text-base-500 mt-0.5">{host.os_estimate}</div>
                        )}
                      </div>
                      <div className="hidden sm:flex items-center gap-4 text-xs text-base-500">
                        <span className="flex items-center gap-1">
                          <Activity className="w-3.5 h-3.5" />
                          {host.ports.length} ports
                        </span>
                        {hostVulns > 0 && (
                          <span className="flex items-center gap-1 text-warning-400">
                            <Bug className="w-3.5 h-3.5" />
                            {hostVulns} vulns
                          </span>
                        )}
                      </div>
                      <span className={`badge ${host.status === 'up' ? 'badge-success' : 'badge-info'}`}>
                        <span className={`w-1.5 h-1.5 rounded-full ${host.status === 'up' ? 'bg-accent-400' : 'bg-base-500'}`} />
                        {host.status}
                      </span>
                    </button>

                    {isExpanded && (
                      <div className="border-t border-base-800 p-4 space-y-2 animate-fade-in">
                        {host.mac_address && (
                          <div className="flex items-center gap-2 text-xs text-base-500 mb-3">
                            <Wifi className="w-3.5 h-3.5" />
                            <span className="font-mono">{host.mac_address}</span>
                          </div>
                        )}
                        {host.ports.length === 0 ? (
                          <p className="text-sm text-base-500 py-2">No open ports detected.</p>
                        ) : (
                          host.ports.map((port) => (
                            <div key={port.id} className="rounded-lg bg-base-950/50 border border-base-800 overflow-hidden">
                              <div className="flex items-center gap-3 p-3">
                                <div className="flex-shrink-0 w-12 text-center">
                                  <div className="text-sm font-mono font-bold text-brand-400">{port.port_number}</div>
                                  <div className="text-xs text-base-600 uppercase">{port.protocol}</div>
                                </div>
                                <div className="flex-1">
                                  {port.services.map((svc) => (
                                    <div key={svc.id} className="flex flex-wrap items-center gap-2">
                                      <span className="text-sm text-base-100 font-medium">{svc.service_name}</span>
                                      {svc.product && (
                                        <span className="text-xs text-base-400">{svc.product}</span>
                                      )}
                                      {svc.version && (
                                        <span className="text-xs text-base-500 font-mono">v{svc.version}</span>
                                      )}
                                      {svc.vulnerabilities.map((vuln) => (
                                        <span key={vuln.id} className={`badge ${severityBadgeClass(vuln.severity)}`}>
                                          {vuln.cve_id}
                                        </span>
                                      ))}
                                    </div>
                                  ))}
                                </div>
                                <span className={`badge ${port.state === 'open' ? 'badge-success' : 'badge-info'}`}>
                                  {port.state}
                                </span>
                              </div>

                              {port.services.some((svc) => svc.vulnerabilities.length > 0) && (
                                <div className="border-t border-base-800 p-3 space-y-2">
                                  {port.services.flatMap((svc) =>
                                    svc.vulnerabilities.map((vuln) => (
                                      <div key={vuln.id} className="flex items-start gap-3 p-2 rounded-md bg-base-900/50">
                                        <span className={`badge ${severityBadgeClass(vuln.severity)} flex-shrink-0`}>
                                          {vuln.severity}
                                        </span>
                                        <div className="flex-1">
                                          <div className="flex items-center gap-2 mb-1">
                                            <span className="text-xs font-mono text-brand-300">{vuln.cve_id}</span>
                                            <span className="text-xs text-base-500">CVSS: {vuln.cvss_score ?? '—'}</span>
                                            <span className="text-xs text-base-600">·</span>
                                            <span className="text-xs text-base-500">Confidence: {vuln.confidence}</span>
                                          </div>
                                          {vuln.description && (
                                            <p className="text-xs text-base-400">{vuln.description}</p>
                                          )}
                                          {vuln.solution && (
                                            <p className="text-xs text-accent-400 mt-1">
                                              <span className="font-medium">Fix:</span> {vuln.solution}
                                            </p>
                                          )}
                                        </div>
                                      </div>
                                    ))
                                  )}
                                </div>
                              )}
                            </div>
                          ))
                        )}
                      </div>
                    )}
                  </div>
                );
              })
            )}
          </div>
        )}

        {/* Findings Tab */}
        {activeTab === 'findings' && (
          <div className="space-y-3 animate-fade-in">
            {sortedFindings.length === 0 ? (
              <div className="card p-12 text-center">
                <Shield className="w-12 h-12 text-accent-400 mx-auto mb-4 opacity-50" />
                <h3 className="text-base-100 font-medium mb-1">No findings</h3>
                <p className="text-sm text-base-500">No security findings were generated for this scan.</p>
              </div>
            ) : (
              sortedFindings.map((finding) => {
                const host = hosts.find((h) => h.id === finding.host_id);
                return (
                  <div key={finding.id} className="card p-5">
                    <div className="flex items-start gap-4">
                      <span className={`badge ${severityBadgeClass(finding.severity)} flex-shrink-0`}>
                        {finding.severity}
                      </span>
                      <div className="flex-1">
                        <h4 className="text-base-100 font-medium mb-1">{finding.title}</h4>
                        {finding.description && (
                          <p className="text-sm text-base-400 mb-2">{finding.description}</p>
                        )}
                        <div className="flex items-center gap-3 text-xs text-base-500">
                          {host && (
                            <span className="flex items-center gap-1">
                              <Server className="w-3 h-3" />
                              <span className="font-mono">{host.ip_address}</span>
                            </span>
                          )}
                        </div>
                        {finding.recommendation && (
                          <div className="flex items-start gap-2 mt-3 p-3 rounded-md bg-accent-500/5 border border-accent-500/10">
                            <Shield className="w-4 h-4 text-accent-400 flex-shrink-0 mt-0.5" />
                            <p className="text-xs text-base-300">{finding.recommendation}</p>
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        )}
      </div>
    </div>
  );
}
