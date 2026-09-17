import { useState } from 'react';
import { Radar, Zap, Search, Layers, Crosshair, ArrowRight, Activity, Server, Bug, AlertTriangle, CheckCircle2, Clock, ShieldAlert } from 'lucide-react';
import { Api } from '@/lib/api';
import type { Scan } from '@/types';
import type { Page } from '@/components/Navbar';
import { useAgent } from '@/hooks/useAgent';

interface ScanPageProps {
  onNavigate: (page: Page) => void;
  onSelectScan: (scanId: string) => void;
}

type ScanType = 'quick' | 'standard' | 'full' | 'custom';

const scanTypes: { type: ScanType; label: string; desc: string; icon: typeof Zap; ports: string; time: string }[] = [
  { type: 'quick', label: 'Quick', desc: 'Top 100 common ports', icon: Zap, ports: '100 ports', time: '~30s' },
  { type: 'standard', label: 'Standard', desc: 'Top 1,000 ports + service detection', icon: Search, ports: '1,000 ports', time: '~2m' },
  { type: 'full', label: 'Full', desc: 'All 65,536 ports + OS fingerprint', icon: Layers, ports: '65,536 ports', time: '~10m' },
  { type: 'custom', label: 'Custom', desc: 'Specify port range and options', icon: Crosshair, ports: 'Variable', time: 'Variable' },
];

export function ScanPage({ onNavigate, onSelectScan }: ScanPageProps) {
  const { agent, error: agentError } = useAgent();
  const [target, setTarget] = useState('192.168.1.0/24');
  const [scanType, setScanType] = useState<ScanType>('standard');
  const [customPorts, setCustomPorts] = useState('1-1000');
  const [starting, setStarting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleStartScan = async () => {
    if (!agent || !target) return;
    setStarting(true);
    setError(null);
    try {
      const scan: Scan = await Api.createScan({
        agent_id: agent.id,
        target: target.trim(),
        scan_type: scanType,
        ports: scanType === 'custom' ? customPorts.trim() : null,
      });
      onSelectScan(scan.id);
      onNavigate('results');
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to create scan');
    } finally {
      setStarting(false);
    }
  };

  const selectedScan = scanTypes.find((s) => s.type === scanType)!;
  const disabled = !target || starting || !agent;

  return (
    <div className="min-h-screen pt-20 pb-16 px-4 sm:px-6 lg:px-8">
      <div className="absolute inset-0 grid-bg opacity-10 pointer-events-none" />
      <div className="relative max-w-4xl mx-auto">
        <div className="mb-8">
          <h1 className="text-2xl sm:text-3xl font-bold text-base-50 mb-1">New Scan</h1>
          <p className="text-base-500">Configure and launch a network scan</p>
        </div>

        {/* Agent prerequisite */}
        {!agent && (
          <div className="card p-6 mb-6 border-warning-500/30 bg-warning-500/5">
            <div className="flex items-start gap-3">
              <ShieldAlert className="w-5 h-5 text-warning-400 flex-shrink-0 mt-0.5" />
              <div>
                <h3 className="text-base-100 font-medium mb-1">No agent available</h3>
                <p className="text-sm text-base-400">
                  {agentError ||
                    'Install and start the NetSentinel agent first — scans are executed by the agent on your machine.'}
                </p>
              </div>
            </div>
          </div>
        )}

        {agent && (
          <div className="card p-4 mb-6 flex items-center gap-3">
            <span className={`w-2 h-2 rounded-full ${agent.status === 'online' ? 'bg-accent-400 animate-pulse' : 'bg-base-500'}`} />
            <span className="text-sm text-base-300">
              Scan will run on <span className="font-mono text-brand-400">{agent.agent_uuid}</span>
              {agent.status !== 'online' && (
                <span className="text-base-500"> (offline — the job will run when the agent reconnects)</span>
              )}
            </span>
          </div>
        )}

        {/* Target Input */}
        <div className="card p-6 mb-6">
          <label className="block text-sm font-medium text-base-300 mb-2">
            Target
          </label>
          <input
            type="text"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="192.168.1.0/24"
            className="input-field font-mono"
          />
          <p className="text-xs text-base-500 mt-2">
            Enter a CIDR range (192.168.1.0/24), single IP (192.168.1.1), or hostname (scanme.local). Only scan networks you own.
          </p>
        </div>

        {/* Scan Type Selection */}
        <div className="card p-6 mb-6">
          <label className="block text-sm font-medium text-base-300 mb-4">
            Scan Type
          </label>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            {scanTypes.map((st) => {
              const Icon = st.icon;
              const active = scanType === st.type;
              return (
                <button
                  key={st.type}
                  onClick={() => setScanType(st.type)}
                  className={`flex items-start gap-3 p-4 rounded-lg border text-left transition-all duration-200 ${
                    active
                      ? 'border-brand-500 bg-brand-500/10'
                      : 'border-base-800 bg-base-950/50 hover:border-base-700'
                  }`}
                >
                  <div className={`flex-shrink-0 w-9 h-9 rounded-lg flex items-center justify-center ${active ? 'bg-brand-500/20' : 'bg-base-800'}`}>
                    <Icon className={`w-4.5 h-4.5 ${active ? 'text-brand-400' : 'text-base-500'}`} />
                  </div>
                  <div className="flex-1">
                    <div className="flex items-center justify-between">
                      <span className={`font-medium ${active ? 'text-base-50' : 'text-base-200'}`}>{st.label}</span>
                      {active && <CheckCircle2 className="w-4 h-4 text-brand-400" />}
                    </div>
                    <p className="text-xs text-base-500 mt-0.5">{st.desc}</p>
                    <div className="flex items-center gap-3 mt-2 text-xs text-base-600">
                      <span className="font-mono">{st.ports}</span>
                      <span>·</span>
                      <span className="flex items-center gap-1">
                        <Clock className="w-3 h-3" />
                        {st.time}
                      </span>
                    </div>
                  </div>
                </button>
              );
            })}
          </div>
        </div>

        {/* Custom Options */}
        {scanType === 'custom' && (
          <div className="card p-6 mb-6 animate-fade-in">
            <label className="block text-sm font-medium text-base-300 mb-2">
              Port Range
            </label>
            <input
              type="text"
              value={customPorts}
              onChange={(e) => setCustomPorts(e.target.value)}
              placeholder="1-1000 or 22,80,443,445"
              className="input-field font-mono"
            />
            <p className="text-xs text-base-500 mt-2">
              Enter a range (1-1000) or comma-separated ports (22,80,443). Max 20,000 ports.
            </p>
          </div>
        )}

        {/* Pipeline Preview */}
        <div className="card p-6 mb-6">
          <div className="flex items-center gap-2 mb-4">
            <Activity className="w-5 h-5 text-brand-400" />
            <h3 className="text-base-50 font-semibold">Scan Pipeline</h3>
          </div>
          <div className="space-y-2">
            {[
              { icon: Search, label: 'Host Discovery', desc: 'ICMP, ARP and TCP probes' },
              { icon: Radar, label: 'Port Scanning', desc: selectedScan.ports },
              { icon: Server, label: 'Service Detection', desc: 'Banner grabbing + version' },
              { icon: Crosshair, label: 'OS Fingerprinting', desc: scanType === 'full' ? 'TTL analysis + nmap -O when available' : 'TTL heuristics' },
              { icon: Bug, label: 'CVE Enrichment', desc: 'Match against vulnerability database' },
              { icon: AlertTriangle, label: 'Risk Engine', desc: 'Severity scoring + findings' },
            ].map((stage, i) => {
              const Icon = stage.icon;
              return (
                <div key={i} className="flex items-center gap-3 p-3 rounded-lg">
                  <div className="flex-shrink-0 w-8 h-8 rounded-lg bg-base-800 flex items-center justify-center">
                    <Icon className="w-4 h-4 text-base-400" />
                  </div>
                  <div className="flex-1">
                    <span className="text-sm text-base-200 font-medium">{stage.label}</span>
                    <span className="text-xs text-base-500 ml-2">{stage.desc}</span>
                  </div>
                  <div className="w-1.5 h-1.5 rounded-full bg-accent-500" />
                </div>
              );
            })}
          </div>
        </div>

        {/* Error */}
        {error && (
          <div className="card p-4 mb-6 border-danger-500/30 bg-danger-500/5">
            <p className="text-sm text-danger-400">{error}</p>
          </div>
        )}

        {/* Start Button */}
        <div className="flex flex-col sm:flex-row items-center gap-4">
          <button
            onClick={handleStartScan}
            disabled={disabled}
            className="btn-primary w-full sm:w-auto justify-center disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {starting ? (
              <>
                <Activity className="w-5 h-5 animate-pulse" />
                Creating scan...
              </>
            ) : (
              <>
                <Radar className="w-5 h-5" />
                Start Scan
                <ArrowRight className="w-4 h-4" />
              </>
            )}
          </button>
          {starting && (
            <p className="text-sm text-base-500">
              Scan queued. The agent picks it up within seconds and results stream in automatically.
            </p>
          )}
        </div>
      </div>
    </div>
  );
}
