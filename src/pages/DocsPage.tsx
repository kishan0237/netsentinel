import { BookOpen, Terminal, Radio, Server, Shield, Zap, Layers, Activity, Download, ArrowRight, Code } from 'lucide-react';
import type { Page } from '@/components/Navbar';

interface DocsPageProps {
  onNavigate: (page: Page) => void;
}

const sections = [
  {
    id: 'getting-started',
    title: 'Getting Started',
    icon: Zap,
    content: [
      { type: 'text', value: 'NetSentinel is an agent-centric network scanner. There are no user accounts, no logins, and no registration. You install the agent on your machine, and it identifies itself with a unique installation ID.' },
      { type: 'heading', value: 'Quick Start' },
      { type: 'text', value: '1. Download the agent for your platform (Linux or Windows).' },
      { type: 'text', value: '2. Run the agent. It generates an installation ID like NS-7F42-A91C.' },
      { type: 'text', value: '3. Open the dashboard and start a scan.' },
      { type: 'code', value: '# Linux install\ncurl -sSL https://netsentinel.io/install.sh | sh\n\n# Start the agent\nnetsentinel agent start' },
    ],
  },
  {
    id: 'architecture',
    title: 'Architecture',
    icon: Radio,
    content: [
      { type: 'text', value: 'NetSentinel uses a simple, agent-centric architecture with no authentication layer:' },
      { type: 'heading', value: 'Components' },
      { type: 'list', value: ['Web Dashboard — presentation layer, served from Vercel', 'FastAPI Backend — API coordination, hosted on Render', 'Supabase — persistent scan data storage', 'Local Agent — runs on your machine, performs the actual scanning'] },
      { type: 'heading', value: 'Data Flow' },
      { type: 'text', value: 'User → Website → Render API → Agent → Local Scanner → Results → Render → Supabase → Dashboard' },
      { type: 'text', value: 'Scanning happens entirely on the agent. The cloud never touches your network directly.' },
    ],
  },
  {
    id: 'agent-identity',
    title: 'Agent Identity',
    icon: Shield,
    content: [
      { type: 'text', value: 'Instead of user accounts, NetSentinel identifies installations. When you first run the agent, it generates a UUID and registers with the server.' },
      { type: 'code', value: '# Agent ID format\nNS-7F42-A91C\n\n# The agent ID is stored locally and persists across restarts.\n# It identifies which installation is sending scan results.' },
      { type: 'text', value: 'This is not user authentication. It simply identifies which NetSentinel agent installation is making a request. The agent can have its own machine-specific token for API access.' },
    ],
  },
  {
    id: 'scan-types',
    title: 'Scan Types',
    icon: Layers,
    content: [
      { type: 'heading', value: 'Quick Scan' },
      { type: 'text', value: 'Scans the top 100 most common TCP ports. Fast — typically completes in under 30 seconds.' },
      { type: 'heading', value: 'Standard Scan' },
      { type: 'text', value: 'Scans the top 1,000 TCP ports with service detection. Balanced — about 2 minutes per /24 network.' },
      { type: 'heading', value: 'Full Scan' },
      { type: 'text', value: 'Scans all 65,536 TCP ports with service detection and OS fingerprinting. Thorough — about 10 minutes per /24 network.' },
      { type: 'heading', value: 'Custom Scan' },
      { type: 'text', value: 'Specify your own port range or comma-separated port list. Full control over what gets scanned.' },
    ],
  },
  {
    id: 'pipeline',
    title: 'Scanner Pipeline',
    icon: Activity,
    content: [
      { type: 'text', value: 'Every scan runs through a multi-stage pipeline:' },
      { type: 'list', value: [
        'Target Validation — validate CIDR, IP, or hostname',
        'Host Discovery — ARP, ICMP, TCP probes to find live hosts',
        'Port Discovery — TCP/UDP async scanning for open ports',
        'Service Detection — banner grabbing and version identification',
        'OS Fingerprint — TCP/IP stack analysis (full scan only)',
        'CVE Enrichment — match services against vulnerability database',
        'Risk Engine — severity scoring and finding generation',
        'Reports — generate HTML, JSON, and CSV exports',
      ]},
    ],
  },
  {
    id: 'api',
    title: 'API Reference',
    icon: Code,
    content: [
      { type: 'heading', value: 'Agent Endpoints' },
      { type: 'code', value: 'POST /api/agents/register\nPOST /api/agents/heartbeat\n\nPOST /api/scans\nGET  /api/scans/{scan_id}\nPOST /api/scans/{scan_id}/results\nGET  /api/scans/{scan_id}/results\nGET  /api/scans/{scan_id}/report' },
      { type: 'heading', value: 'Scan Progress' },
      { type: 'text', value: 'The agent sends progress updates as it moves through the pipeline. The frontend polls every 1-3 seconds for updates.' },
      { type: 'code', value: '// Agent sends progress\n{ "progress": 45, "stage": "service_detection" }\n\n// Frontend polls\nGET /api/scans/{id}\n→ { "status": "running", "progress": 45 }' },
    ],
  },
  {
    id: 'database',
    title: 'Database Schema',
    icon: Server,
    content: [
      { type: 'text', value: 'NetSentinel uses 8 tables. No users table, no authentication tables.' },
      { type: 'list', value: [
        'agents — installation identity and status',
        'scans — scan jobs and progress',
        'hosts — discovered network hosts',
        'ports — open and closed ports per host',
        'services — detected services per port',
        'vulnerabilities — CVEs matched to services',
        'findings — risk engine output per scan',
        'reports — generated report metadata',
      ]},
    ],
  },
];

export function DocsPage({ onNavigate }: DocsPageProps) {
  return (
    <div className="min-h-screen pt-20 pb-16 px-4 sm:px-6 lg:px-8">
      <div className="max-w-5xl mx-auto">
        {/* Header */}
        <div className="mb-8">
          <div className="flex items-center gap-3 mb-4">
            <div className="w-10 h-10 rounded-lg bg-brand-500/10 border border-brand-500/20 flex items-center justify-center">
              <BookOpen className="w-5 h-5 text-brand-400" />
            </div>
            <h1 className="text-2xl sm:text-3xl font-bold text-base-50">Documentation</h1>
          </div>
          <p className="text-base-500">Everything you need to know about NetSentinel</p>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-4 gap-8">
          {/* Sidebar */}
          <aside className="lg:col-span-1">
            <nav className="sticky top-24 space-y-1">
              {sections.map((section) => {
                const Icon = section.icon;
                return (
                  <a
                    key={section.id}
                    href={`#${section.id}`}
                    className="flex items-center gap-2.5 px-3 py-2 rounded-lg text-sm text-base-400 hover:text-base-200 hover:bg-base-800/50 transition-colors"
                  >
                    <Icon className="w-4 h-4" />
                    {section.title}
                  </a>
                );
              })}
              <div className="pt-2 mt-2 border-t border-base-800">
                <button
                  onClick={() => onNavigate('download')}
                  className="flex items-center gap-2.5 px-3 py-2 rounded-lg text-sm text-brand-400 hover:bg-brand-500/10 transition-colors w-full"
                >
                  <Download className="w-4 h-4" />
                  Download Agent
                  <ArrowRight className="w-3.5 h-3.5 ml-auto" />
                </button>
              </div>
            </nav>
          </aside>

          {/* Content */}
          <div className="lg:col-span-3 space-y-12">
            {sections.map((section) => {
              const Icon = section.icon;
              return (
                <section key={section.id} id={section.id} className="scroll-mt-24">
                  <div className="flex items-center gap-3 mb-4">
                    <div className="w-9 h-9 rounded-lg bg-base-800 flex items-center justify-center">
                      <Icon className="w-4.5 h-4.5 text-brand-400" />
                    </div>
                    <h2 className="text-xl font-semibold text-base-50">{section.title}</h2>
                  </div>
                  <div className="space-y-3 pl-1">
                    {section.content.map((block, i) => {
                      if (block.type === 'text') {
                        return <p key={i} className="text-base-400 leading-relaxed">{block.value}</p>;
                      }
                      if (block.type === 'heading') {
                        return <h3 key={i} className="text-base-200 font-medium pt-2">{block.value}</h3>;
                      }
                      if (block.type === 'list') {
                        return (
                          <ul key={i} className="space-y-1.5">
                            {(block.value as string[]).map((item, j) => (
                              <li key={j} className="flex items-start gap-2 text-base-400">
                                <span className="text-brand-400 mt-1.5 flex-shrink-0">•</span>
                                <span>{item}</span>
                              </li>
                            ))}
                          </ul>
                        );
                      }
                      if (block.type === 'code') {
                        return (
                          <div key={i} className="rounded-lg bg-base-950 border border-base-800 p-4 overflow-x-auto">
                            <pre className="text-sm font-mono text-brand-300 whitespace-pre-wrap">{block.value}</pre>
                          </div>
                        );
                      }
                      return null;
                    })}
                  </div>
                </section>
              );
            })}

            {/* CTA */}
            <div className="card p-8 text-center">
              <Terminal className="w-10 h-10 text-brand-400 mx-auto mb-4" />
              <h3 className="text-lg font-semibold text-base-50 mb-2">Ready to scan?</h3>
              <p className="text-base-400 mb-4">Download the agent and start scanning your network in minutes.</p>
              <button
                onClick={() => onNavigate('download')}
                className="btn-primary"
              >
                <Download className="w-5 h-5" />
                Get Started
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
