import { useEffect, useState } from 'react';
import { Shield, Menu, X, Activity, Download, FileText, LayoutDashboard, Radar, BookOpen } from 'lucide-react';

export type Page = 'home' | 'download' | 'dashboard' | 'scan' | 'results' | 'reports' | 'docs';

interface NavbarProps {
  currentPage: Page;
  onNavigate: (page: Page) => void;
}

const navItems: { page: Page; label: string; icon: typeof Activity }[] = [
  { page: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
  { page: 'scan', label: 'New Scan', icon: Radar },
  { page: 'results', label: 'Results', icon: Activity },
  { page: 'reports', label: 'Reports', icon: FileText },
  { page: 'download', label: 'Download', icon: Download },
  { page: 'docs', label: 'Docs', icon: BookOpen },
];

export function Navbar({ currentPage, onNavigate }: NavbarProps) {
  const [scrolled, setScrolled] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);

  useEffect(() => {
    const handler = () => setScrolled(window.scrollY > 12);
    window.addEventListener('scroll', handler);
    return () => window.removeEventListener('scroll', handler);
  }, []);

  const handleNav = (page: Page) => {
    onNavigate(page);
    setMobileOpen(false);
  };

  return (
    <header
      className={`fixed top-0 left-0 right-0 z-50 transition-all duration-300 ${
        scrolled
          ? 'bg-base-950/80 backdrop-blur-lg border-b border-base-800'
          : 'bg-transparent border-b border-transparent'
      }`}
    >
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          <button
            onClick={() => handleNav('home')}
            className="flex items-center gap-2.5 group"
          >
            <div className="relative">
              <div className="absolute inset-0 bg-brand-400 blur-lg opacity-40 group-hover:opacity-60 transition-opacity" />
              <Shield className="relative w-7 h-7 text-brand-400" strokeWidth={2.5} />
            </div>
            <span className="text-lg font-bold text-base-50 tracking-tight">
              Net<span className="text-brand-400">Sentinel</span>
            </span>
          </button>

          <nav className="hidden md:flex items-center gap-1">
            {navItems.map((item) => {
              const Icon = item.icon;
              const active = currentPage === item.page;
              return (
                <button
                  key={item.page}
                  onClick={() => handleNav(item.page)}
                  className={`flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium transition-all duration-200 ${
                    active
                      ? 'text-brand-400 bg-brand-500/10'
                      : 'text-base-400 hover:text-base-200 hover:bg-base-800/50'
                  }`}
                >
                  <Icon className="w-4 h-4" />
                  {item.label}
                </button>
              );
            })}
          </nav>

          <button
            onClick={() => setMobileOpen(!mobileOpen)}
            className="md:hidden p-2 rounded-lg text-base-400 hover:text-base-200 hover:bg-base-800/50"
          >
            {mobileOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
          </button>
        </div>
      </div>

      {mobileOpen && (
        <nav className="md:hidden bg-base-950/95 backdrop-blur-lg border-t border-base-800 px-4 py-3 space-y-1">
          {navItems.map((item) => {
            const Icon = item.icon;
            const active = currentPage === item.page;
            return (
              <button
                key={item.page}
                onClick={() => handleNav(item.page)}
                className={`flex items-center gap-3 w-full px-3 py-2.5 rounded-lg text-sm font-medium transition-colors ${
                  active
                    ? 'text-brand-400 bg-brand-500/10'
                    : 'text-base-400 hover:text-base-200 hover:bg-base-800/50'
                }`}
              >
                <Icon className="w-4 h-4" />
                {item.label}
              </button>
            );
          })}
        </nav>
      )}
    </header>
  );
}
