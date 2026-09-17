import { Download, Check, Terminal, Monitor, Shield, Copy, Laptop } from 'lucide-react';
import { useState } from 'react';
import type { Page } from '@/components/Navbar';

interface DownloadPageProps {
  onNavigate: (page: Page) => void;
}

interface Platform {
  name: string;
  icon: typeof Terminal;
  status: 'available' | 'coming-soon';
  command: string;
  size: string;
  version: string;
}

const platforms: Platform[] = [
  {
    name: 'Linux',
    icon: Terminal,
    status: 'available',
    command: 'curl -sSL https://netsentinel.io/install.sh | sh',
    size: '12.4 MB',
    version: '1.0.0',
  },
  {
    name: 'Windows',
    icon: Monitor,
    status: 'available',
    command: 'irm https://netsentinel.io/install.ps1 | iex',
    size: '14.8 MB',
    version: '1.0.0',
  },
  {
    name: 'macOS',
    icon: Laptop,
    status: 'coming-soon',
    command: 'brew install netsentinel',
    size: '—',
    version: '—',
  },
];

export function DownloadPage({ onNavigate }: DownloadPageProps) {
  const [copied, setCopied] = useState<string | null>(null);

  const copyCommand = (cmd: string, name: string) => {
    navigator.clipboard.writeText(cmd);
    setCopied(name);
    setTimeout(() => setCopied(null), 2000);
  };

  return (
    <div className="relative min-h-screen pt-24 pb-16 px-4 sm:px-6 lg:px-8">
      <div className="absolute inset-0 grid-bg opacity-20" />
      <div className="absolute top-0 left-1/2 -translate-x-1/2 w-[500px] h-[300px] bg-brand-500/5 rounded-full blur-[100px]" />

      <div className="relative max-w-5xl mx-auto">
        <div className="text-center mb-12">
          <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-base-900/60 border border-base-800 mb-6">
            <Shield className="w-4 h-4 text-brand-400" />
            <span className="text-xs font-medium text-base-400">Version 1.0.0</span>
          </div>
          <h1 className="text-4xl sm:text-5xl font-bold text-base-50 mb-4">
            Download NetSentinel Agent
          </h1>
          <p className="text-lg text-base-400 max-w-2xl mx-auto">
            Install the agent on your machine to start scanning. No account required —
            the agent generates its own installation ID on first run.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-12">
          {platforms.map((platform) => {
            const Icon = platform.icon;
            const isAvailable = platform.status === 'available';
            return (
              <div
                key={platform.name}
                className={`card p-6 ${isAvailable ? 'card-hover' : 'opacity-60'}`}
              >
                <div className="flex items-center gap-3 mb-4">
                  <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${isAvailable ? 'bg-brand-500/10 border border-brand-500/20' : 'bg-base-800 border border-base-700'}`}>
                    <Icon className={`w-5 h-5 ${isAvailable ? 'text-brand-400' : 'text-base-500'}`} />
                  </div>
                  <div>
                    <h3 className="text-base-50 font-semibold">{platform.name}</h3>
                    {isAvailable ? (
                      <span className="text-xs text-accent-400">Available</span>
                    ) : (
                      <span className="text-xs text-base-500">Coming Soon</span>
                    )}
                  </div>
                </div>

                {isAvailable ? (
                  <>
                    <div className="space-y-2 mb-4 text-sm">
                      <div className="flex justify-between">
                        <span className="text-base-500">Version</span>
                        <span className="text-base-300 font-mono">{platform.version}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-base-500">Size</span>
                        <span className="text-base-300 font-mono">{platform.size}</span>
                      </div>
                    </div>

                    <div className="mb-4">
                      <div className="text-xs text-base-500 mb-2">Install command</div>
                      <div className="relative">
                        <div className="flex items-center gap-2 px-3 py-2.5 rounded-lg bg-base-950 border border-base-800 font-mono text-xs text-brand-300 overflow-x-auto">
                          <span className="text-base-600">$</span>
                          <span className="flex-1 whitespace-nowrap">{platform.command}</span>
                        </div>
                        <button
                          onClick={() => copyCommand(platform.command, platform.name)}
                          className="absolute top-1.5 right-1.5 p-1.5 rounded-md text-base-500 hover:text-base-300 hover:bg-base-800 transition-colors"
                        >
                          {copied === platform.name ? (
                            <Check className="w-3.5 h-3.5 text-accent-400" />
                          ) : (
                            <Copy className="w-3.5 h-3.5" />
                          )}
                        </button>
                      </div>
                    </div>

                    <button
                      onClick={() => onNavigate('dashboard')}
                      className="btn-primary w-full justify-center text-sm"
                    >
                      <Download className="w-4 h-4" />
                      Download Agent
                    </button>
                  </>
                ) : (
                  <div className="py-8 text-center">
                    <Monitor className="w-8 h-8 text-base-600 mx-auto mb-2" />
                    <p className="text-sm text-base-500">In development</p>
                  </div>
                )}
              </div>
            );
          })}
        </div>

        {/* Post-install section */}
        <div className="card p-8">
          <h2 className="text-xl font-semibold text-base-50 mb-6">After installation</h2>
          <div className="space-y-4">
            {[
              {
                step: '1',
                title: 'Run the agent',
                desc: 'The agent starts and generates a unique installation ID (e.g., NS-7F42-A91C).',
              },
              {
                step: '2',
                title: 'Open the dashboard',
                desc: 'Go to the dashboard and enter your agent ID to connect.',
              },
              {
                step: '3',
                title: 'Start scanning',
                desc: 'Enter a network target and choose a scan type. Results stream in real-time.',
              },
            ].map((item) => (
              <div key={item.step} className="flex items-start gap-4">
                <div className="flex-shrink-0 w-8 h-8 rounded-lg bg-brand-500/10 border border-brand-500/20 flex items-center justify-center font-mono text-sm text-brand-400 font-semibold">
                  {item.step}
                </div>
                <div>
                  <h3 className="text-base-200 font-medium mb-0.5">{item.title}</h3>
                  <p className="text-sm text-base-400">{item.desc}</p>
                </div>
              </div>
            ))}
          </div>

          <div className="mt-6 p-4 rounded-lg bg-base-950 border border-base-800 font-mono text-sm">
            <div className="text-base-600 mb-1"># Agent output on first run</div>
            <div className="text-accent-400">$ netsentinel agent start</div>
            <div className="text-base-400 mt-1">
              <span className="text-base-600">[INFO]</span> NetSentinel Agent v1.0.0
            </div>
            <div className="text-base-400">
              <span className="text-base-600">[INFO]</span> Generating installation ID...
            </div>
            <div className="text-brand-400">
              <span className="text-base-600">[INFO]</span> Agent ID: <span className="font-bold">NS-7F42-A91C</span>
            </div>
            <div className="text-base-400">
              <span className="text-base-600">[INFO]</span> Registering with server...
            </div>
            <div className="text-accent-400">
              <span className="text-base-600">[INFO]</span> Agent registered. Waiting for scan jobs.
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
