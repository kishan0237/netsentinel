import { Shield, Github, Terminal } from 'lucide-react';

export function Footer() {
  return (
    <footer className="border-t border-base-800 bg-base-950">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-10">
        <div className="flex flex-col md:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-2.5">
            <Shield className="w-5 h-5 text-brand-400" strokeWidth={2.5} />
            <span className="text-sm font-semibold text-base-300">
              Net<span className="text-brand-400">Sentinel</span>
            </span>
            <span className="text-xs text-base-600 ml-2">v1.0.0</span>
          </div>
          <p className="text-xs text-base-500">
            Agent-centric network scanning. No accounts. No logins. Just scan.
          </p>
          <div className="flex items-center gap-4">
            <a
              href="#"
              className="text-base-500 hover:text-base-300 transition-colors"
              aria-label="GitHub"
            >
              <Github className="w-5 h-5" />
            </a>
            <a
              href="#"
              className="text-base-500 hover:text-base-300 transition-colors"
              aria-label="CLI"
            >
              <Terminal className="w-5 h-5" />
            </a>
          </div>
        </div>
      </div>
    </footer>
  );
}
