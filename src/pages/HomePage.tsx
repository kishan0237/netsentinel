import { Shield, Download, BookOpen, Radar, Search, Bug, Server, Activity, ArrowRight, Terminal, Cpu, Lock, Zap, FileText } from 'lucide-react';
import type { Page } from '@/components/Navbar';

interface HomePageProps {
  onNavigate: (page: Page) => void;
}

export function HomePage({ onNavigate }: HomePageProps) {
  return (
    <div className="relative">
      {/* Hero Section */}
      <section className="relative min-h-screen flex items-center justify-center overflow-hidden pt-16">
        <div className="absolute inset-0 grid-bg opacity-40" />
        <div className="absolute inset-0 radial-glow" />
        <div className="absolute top-1/4 left-1/2 -translate-x-1/2 w-[600px] h-[600px] bg-brand-500/5 rounded-full blur-[120px]" />

        <div className="relative max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 text-center">
          <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-base-900/60 border border-base-800 mb-8 animate-fade-in">
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-accent-400 opacity-75" />
              <span className="relative inline-flex rounded-full h-2 w-2 bg-accent-500" />
            </span>
            <span className="text-xs font-medium text-base-400">Agent online · NS-7F42-A91C</span>
          </div>

          <h1 className="text-5xl sm:text-6xl lg:text-7xl font-bold tracking-tight text-base-50 mb-6 animate-fade-in">
            Discover your network.
            <br />
            <span className="text-brand-400 glow-text">Identify vulnerabilities.</span>
          </h1>

          <p className="text-lg sm:text-xl text-base-400 max-w-2xl mx-auto mb-10 leading-relaxed animate-fade-in">
            NetSentinel is an agent-centric network scanner. Install the agent on your machine,
            scan your local network, and get instant visibility into hosts, services, and security risks.
          </p>

          <div className="flex flex-col sm:flex-row items-center justify-center gap-4 animate-fade-in">
            <button
              onClick={() => onNavigate('download')}
              className="btn-primary text-base w-full sm:w-auto justify-center"
            >
              <Download className="w-5 h-5" />
              Download Agent
            </button>
            <button
              onClick={() => onNavigate('docs')}
              className="btn-secondary w-full sm:w-auto justify-center"
            >
              <BookOpen className="w-5 h-5" />
              Documentation
            </button>
          </div>

          <div className="mt-16 flex items-center justify-center gap-8 text-xs text-base-500">
            <div className="flex items-center gap-2">
              <Lock className="w-4 h-4" />
              No accounts needed
            </div>
            <div className="hidden sm:flex items-center gap-2">
              <Terminal className="w-4 h-4" />
              Runs locally
            </div>
            <div className="flex items-center gap-2">
              <Zap className="w-4 h-4" />
              Real-time results
            </div>
          </div>
        </div>

        {/* Scan line animation */}
        <div className="absolute bottom-0 left-0 right-0 h-px overflow-hidden">
          <div className="h-full w-full bg-gradient-to-r from-transparent via-brand-400 to-transparent animate-scan-line" />
        </div>
      </section>

      {/* Pipeline Section */}
      <section className="relative py-24 px-4 sm:px-6 lg:px-8">
        <div className="max-w-6xl mx-auto">
          <div className="text-center mb-16">
            <h2 className="text-3xl sm:text-4xl font-bold text-base-50 mb-4">
              The scanning pipeline
            </h2>
            <p className="text-base-400 max-w-2xl mx-auto">
              From target to findings, NetSentinel runs a complete pipeline on your local machine.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            {[
              { icon: Search, title: 'Host Discovery', desc: 'Identify live hosts on your network using ARP, ICMP, and TCP probes.', step: '01' },
              { icon: Server, title: 'Port Scanning', desc: 'TCP/UDP async scanning across all 65,536 ports with state detection.', step: '02' },
              { icon: Activity, title: 'Service Detection', desc: 'Banner grabbing and version detection for every open port.', step: '03' },
              { icon: Bug, title: 'CVE Enrichment', desc: 'Match detected services against known vulnerabilities and risk scoring.', step: '04' },
            ].map((item, i) => {
              const Icon = item.icon;
              return (
                <div
                  key={i}
                  className="card card-hover p-6 relative group"
                >
                  <div className="absolute top-4 right-4 text-xs font-mono text-base-700 group-hover:text-base-600 transition-colors">
                    {item.step}
                  </div>
                  <div className="w-10 h-10 rounded-lg bg-brand-500/10 border border-brand-500/20 flex items-center justify-center mb-4">
                    <Icon className="w-5 h-5 text-brand-400" />
                  </div>
                  <h3 className="text-base-50 font-semibold mb-2">{item.title}</h3>
                  <p className="text-sm text-base-400 leading-relaxed">{item.desc}</p>
                </div>
              );
            })}
          </div>
        </div>
      </section>

      {/* Architecture Section */}
      <section className="relative py-24 px-4 sm:px-6 lg:px-8 border-t border-base-800">
        <div className="max-w-5xl mx-auto">
          <div className="text-center mb-16">
            <h2 className="text-3xl sm:text-4xl font-bold text-base-50 mb-4">
              How it works
            </h2>
            <p className="text-base-400 max-w-2xl mx-auto">
              No login. No registration. Just install the agent and scan.
            </p>
          </div>

          <div className="space-y-4">
            {[
              {
                icon: Download,
                title: 'Install the agent',
                desc: 'Download NetSentinel Agent for your platform. Run it once — it generates a unique installation ID like NS-7F42-A91C.',
              },
              {
                icon: Radar,
                title: 'Start a scan',
                desc: 'Open the dashboard, enter a target like 192.168.1.0/24, choose a scan type, and hit start. The agent does the rest.',
              },
              {
                icon: Activity,
                title: 'Watch results stream in',
                desc: 'Hosts, ports, services, and vulnerabilities appear in real-time as the scanner progresses through the pipeline.',
              },
              {
                icon: FileText,
                title: 'Review and report',
                desc: 'Get a complete risk assessment with CVSS scores, CVE references, and actionable remediation recommendations.',
              },
            ].map((item, i) => {
              const Icon = item.icon;
              return (
                <div key={i} className="flex items-start gap-4 p-6 card card-hover">
                  <div className="flex-shrink-0 w-12 h-12 rounded-xl bg-brand-500/10 border border-brand-500/20 flex items-center justify-center">
                    <Icon className="w-6 h-6 text-brand-400" />
                  </div>
                  <div className="flex-1">
                    <h3 className="text-base-50 font-semibold mb-1">{item.title}</h3>
                    <p className="text-sm text-base-400 leading-relaxed">{item.desc}</p>
                  </div>
                  <div className="text-2xl font-mono text-base-700 hidden sm:block">
                    {String(i + 1).padStart(2, '0')}
                  </div>
                </div>
              );
            })}
          </div>

          <div className="mt-12 text-center">
            <button
              onClick={() => onNavigate('dashboard')}
              className="btn-primary"
            >
              Go to Dashboard
              <ArrowRight className="w-5 h-5" />
            </button>
          </div>
        </div>
      </section>

      {/* Stats Section */}
      <section className="relative py-20 px-4 sm:px-6 lg:px-8 border-t border-base-800">
        <div className="max-w-5xl mx-auto">
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-6">
            {[
              { value: '65,536', label: 'Ports scanned', icon: Server },
              { value: '8', label: 'Pipeline stages', icon: Cpu },
              { value: '0', label: 'Accounts required', icon: Lock },
              { value: '100%', label: 'Local execution', icon: Shield },
            ].map((stat, i) => {
              const Icon = stat.icon;
              return (
                <div key={i} className="text-center">
                  <Icon className="w-6 h-6 text-brand-400 mx-auto mb-3 opacity-60" />
                  <div className="text-3xl font-bold text-base-50 font-mono">{stat.value}</div>
                  <div className="text-sm text-base-500 mt-1">{stat.label}</div>
                </div>
              );
            })}
          </div>
        </div>
      </section>
    </div>
  );
}


