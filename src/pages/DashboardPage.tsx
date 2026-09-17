import { useEffect, useMemo, useState } from 'react';
import { Activity, Radar, Server, Bug, AlertTriangle, Clock, Cpu, Wifi, ArrowRight, RefreshCw, Radio } from 'lucide-react';
import { Api } from '@/lib/api';
import type { Finding, Scan } from '@/types';
import type { Page } from '@/components/Navbar';
import { formatRelativeTime, formatDuration, severityBadgeClass } from '@/lib/utils';
import { useAgent } from '@/hooks/useAgent';

interface DashboardPageProps {
  onNavigate: (page: Page) => void;
  selectedScanId: string | null;
  onSelectScan: (scanId: string) => void;
}

interface StatsWithCounts {
  hosts: number;
  open_ports: number;
  services: number;
  vulnerabilities: number;
  findings: number;
  severity_counts: Record<string, number>;
}

export function DashboardPage({ onNavigate, onSelectScan }: DashboardPageProps) {
  const { agent, loading: agentLoading, error: agentError, reload: reloadAgent } = useAgent();
  const [scans, setScans] = useState<Scan[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [stats, setStats] = useState<StatsWithCounts | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      try {
        const scansData = await Api.listScans();
        if (cancelled) return;
        setScans(scansData);

        const completed = scansData.find((s) => s.status === 'completed');

        if (completed) {
          const [statsData, findingsData] = await Promise.all([
            Api.getScanStats(completed.id),
            Api.listFindings(completed.id),
          ]);
          if (cancelled) return;
          setStats(statsData);
          setFindings(findingsData);
        } else {
          setStats(null);
          setFindings([]);
        }
      } catch {
        /* keep old data on transient errors */
      } finally {
        if (!cancelled) setLoading(false);
      }
    };
    load();
    const t = setInterval(load, 10000);
    return () => {
      cancelled = true;
      clearInterval(t);
    };
  }, []);

  const handleScanClick = (scanId: string) => {
    onSelectScan(scanId);
    onNavigate('results');
  };

  const severityCounts = useMemo(() => ({
    critical: stats?.severity_counts?.critical ?? 0,
    high: stats?.severity_counts?.high ?? 0,
    medium: stats?.severity_counts?.medium ?? 0,
    low: stats?.severity_counts?.low ?? 0,
  }), [stats]);

  if (agentLoading && loading) {
    return (
      <div className="min-h-screen pt-24 flex items-center justify-center">
        <div className="flex items-center gap-3 text-base-500">
          <RefreshCw className="w-5 h-5 animate-spin" />
          <span>Loading dashboard...</span>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen pt-20 pb-16 px-4 sm:px-6 lg:px-8">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-8">
          <div>
            <h1 className="text-2xl sm:text-3xl font-bold text-base-50 mb-1">Dashboard</h1>
            <p className="text-base-500">Monitor your agent and scan history</p>
          </div>
          <div className="flex items-center gap-3">
            <button onClick={() => { reloadAgent(); }} className="btn-ghost text-sm">
              <RefreshCw className="w-4 h-4" />
              Refresh
            </button>
            <button onClick={() => onNavigate('scan')} className="btn-primary text-sm">
              <Radar className="w-4 h-4" />
              New Scan
            </button>
          </div>
        </div>

        {/* Agent status / setup prompt */}
        {agentError && !agent && (
          <div className="card p-6 mb-6 border-warning-500/30 bg-warning-500/5">
            <div className="flex items-start gap-3">
              <AlertTriangle className="w-5 h-5 text-warning-400 flex-shrink-0 mt-0.5" />
              <div>
                <h3 className="text-base-100 font-medium mb-1">No agent connected</h3>
                <p className="text-sm text-base-400">{agentError}</p>
              </div>
            </div>
          </div>
        )}

        {agent && (
          <div className="card p-6 mb-6">
            <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6">
              <div className="flex items-center gap-4">
                <div className="relative">
                  <div className="w-14 h-14 rounded-xl bg-brand-500/10 border border-brand-500/20 flex items-center justify-center">
                    <Radio className="w-7 h-7 text-brand-400" />
                  </div>
                  {agent.status === 'online' && (
                    <div className="absolute -bottom-1 -right-1 w-4 h-4 rounded-full bg-accent-500 border-2 border-base-900" />
                  )}
                </div>
                <div>
                  <div className="flex items-center gap-2 mb-1">
                    <h2 className="text-lg font-semibold text-base-50">{agent.agent_name}</h2>
                    <span className={`badge ${agent.status === 'online' ? 'badge-success' : 'badge-info'}`}>
                      <span className={`w-1.5 h-1.5 rounded-full ${agent.status === 'online' ? 'bg-accent-400 animate-pulse' : 'bg-base-500'}`} />
                      {agent.status}
                    </span>
                  </div>
                  <div className="flex items-center gap-4 text-sm text-base-500">
                    <span className="font-mono text-brand-400">{agent.agent_uuid}</span>
                    <span className="hidden sm:flex items-center gap-1">
                      <Cpu className="w-3.5 h-3.5" />
                      {agent.platform || 'Unknown'}
                    </span>
                    <span className="hidden sm:flex items-center gap-1">
                      <Wifi className="w-3.5 h-3.5" />
                      {agent.hostname || 'Unknown'}
                    </span>
                  </div>
                </div>
              </div>

              <div className="flex items-center gap-6 text-sm">
                <div>
                  <div className="text-base-500 text-xs mb-0.5">Agent Version</div>
                  <div className="text-base-200 font-mono">v{agent.agent_version}</div>
                </div>
                <div>
                  <div className="text-base-500 text-xs mb-0.5">Last Heartbeat</div>
                  <div className="text-base-200">{formatRelativeTime(agent.last_heartbeat)}</div>
                </div>
                <div>
                  <div className="text-base-500 text-xs mb-0.5">Created</div>
                  <div className="text-base-200">{formatRelativeTime(agent.created_at)}</div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Stats Grid */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
          {[
            { icon: Server, label: 'Hosts Discovered', value: stats?.hosts ?? 0, color: 'text-brand-400' },
            { icon: Activity, label: 'Open Ports', value: stats?.open_ports ?? 0, color: 'text-accent-400' },
            { icon: Cpu, label: 'Services Detected', value: stats?.services ?? 0, color: 'text-info-400' },
            { icon: Bug, label: 'Vulnerabilities', value: stats?.vulnerabilities ?? 0, color: 'text-warning-400' },
          ].map((stat, i) => {
            const Icon = stat.icon;
            return (
              <div key={i} className="card p-5">
                <div className="flex items-center justify-between mb-3">
                  <Icon className={`w-5 h-5 ${stat.color}`} />
                </div>
                <div className="text-3xl font-bold text-base-50 font-mono">{stat.value}</div>
                <div className="text-sm text-base-500 mt-1">{stat.label}</div>
              </div>
            );
          })}
        </div>

        {/* Findings Summary */}
        {findings.length > 0 && (
          <div className="card p-6 mb-6">
            <div className="flex items-center gap-2 mb-4">
              <AlertTriangle className="w-5 h-5 text-warning-400" />
              <h3 className="text-base-50 font-semibold">Latest Scan Findings</h3>
            </div>
            <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 mb-4">
              {[
                { label: 'Critical', count: severityCounts.critical, class: 'text-danger-400', bg: 'bg-danger-500/10', border: 'border-danger-500/20' },
                { label: 'High', count: severityCounts.high, class: 'text-orange-400', bg: 'bg-orange-500/10', border: 'border-orange-500/20' },
                { label: 'Medium', count: severityCounts.medium, class: 'text-warning-400', bg: 'bg-warning-500/10', border: 'border-warning-500/20' },
                { label: 'Low', count: severityCounts.low, class: 'text-info-400', bg: 'bg-info-500/10', border: 'border-info-500/20' },
              ].map((item) => (
                <div key={item.label} className={`p-4 rounded-lg ${item.bg} border ${item.border}`}>
                  <div className={`text-2xl font-bold font-mono ${item.class}`}>{item.count}</div>
                  <div className="text-sm text-base-400 mt-0.5">{item.label}</div>
                </div>
              ))}
            </div>
            <div className="space-y-2">
              {findings.slice(0, 5).map((finding) => (
                <div
                  key={finding.id}
                  className="flex items-center gap-3 p-3 rounded-lg bg-base-950/50 border border-base-800 hover:border-base-700 transition-colors cursor-pointer"
                  onClick={() => handleScanClick(finding.scan_id)}
                >
                  <span className={`badge ${severityBadgeClass(finding.severity)}`}>
                    {finding.severity}
                  </span>
                  <span className="text-sm text-base-200 flex-1 truncate">{finding.title}</span>
                  <ArrowRight className="w-4 h-4 text-base-600" />
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Scan History */}
        <div className="card p-6">
          <div className="flex items-center gap-2 mb-4">
            <Clock className="w-5 h-5 text-brand-400" />
            <h3 className="text-base-50 font-semibold">Scan History</h3>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="text-left text-xs text-base-500 border-b border-base-800">
                  <th className="pb-3 pr-4 font-medium">Target</th>
                  <th className="pb-3 pr-4 font-medium">Type</th>
                  <th className="pb-3 pr-4 font-medium">Status</th>
                  <th className="pb-3 pr-4 font-medium">Progress</th>
                  <th className="pb-3 pr-4 font-medium">Stage</th>
                  <th className="pb-3 pr-4 font-medium">Duration</th>
                  <th className="pb-3 font-medium"></th>
                </tr>
              </thead>
              <tbody>
                {scans.length === 0 && (
                  <tr>
                    <td colSpan={7} className="py-8 text-center text-sm text-base-500">
                      No scans yet — start one from the New Scan page.
                    </td>
                  </tr>
                )}
                {scans.map((scan) => (
                  <tr
                    key={scan.id}
                    className="border-b border-base-800/50 hover:bg-base-800/30 transition-colors cursor-pointer"
                    onClick={() => handleScanClick(scan.id)}
                  >
                    <td className="py-3 pr-4">
                      <span className="font-mono text-sm text-base-200">{scan.target}</span>
                    </td>
                    <td className="py-3 pr-4">
                      <span className="text-sm text-base-400 capitalize">{scan.scan_type}</span>
                    </td>
                    <td className="py-3 pr-4">
                      <span className={`badge ${
                        scan.status === 'completed' ? 'badge-success' :
                        scan.status === 'running' ? 'badge-critical' :
                        scan.status === 'failed' ? 'badge-high' : 'badge-info'
                      }`}>
                        {scan.status === 'running' && (
                          <span className="w-1.5 h-1.5 rounded-full bg-danger-400 animate-pulse" />
                        )}
                        {scan.status}
                      </span>
                    </td>
                    <td className="py-3 pr-4">
                      <div className="flex items-center gap-2">
                        <div className="w-16 h-1.5 rounded-full bg-base-800 overflow-hidden">
                          <div
                            className={`h-full rounded-full ${scan.status === 'running' ? 'bg-brand-400 animate-pulse' : 'bg-brand-500'}`}
                            style={{ width: `${scan.progress}%` }}
                          />
                        </div>
                        <span className="text-xs text-base-500 font-mono">{scan.progress}%</span>
                      </div>
                    </td>
                    <td className="py-3 pr-4">
                      <span className="text-xs text-base-500 font-mono">{scan.current_stage || '—'}</span>
                    </td>
                    <td className="py-3 pr-4 text-sm text-base-400">
                      {formatDuration(scan.started_at, scan.completed_at)}
                    </td>
                    <td className="py-3">
                      <ArrowRight className="w-4 h-4 text-base-600" />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}
