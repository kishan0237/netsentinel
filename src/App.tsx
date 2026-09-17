import { useState, useEffect } from 'react';
import { Navbar, type Page } from '@/components/Navbar';
import { Footer } from '@/components/Footer';
import { HomePage } from '@/pages/HomePage';
import { DownloadPage } from '@/pages/DownloadPage';
import { DashboardPage } from '@/pages/DashboardPage';
import { ScanPage } from '@/pages/ScanPage';
import { ResultsPage } from '@/pages/ResultsPage';
import { ReportsPage } from '@/pages/ReportsPage';
import { DocsPage } from '@/pages/DocsPage';

function App() {
  const [page, setPage] = useState<Page>('home');
  const [selectedScanId, setSelectedScanId] = useState<string | null>(null);

  const handleNavigate = (next: Page) => {
    setPage(next);
    window.scrollTo({ top: 0, behavior: 'instant' });
  };

  useEffect(() => {
    window.scrollTo({ top: 0 });
  }, [page]);

  return (
    <div className="min-h-screen bg-base-950 flex flex-col">
      <Navbar currentPage={page} onNavigate={handleNavigate} />

      <main className="flex-1">
        {page === 'home' && <HomePage onNavigate={handleNavigate} />}
        {page === 'download' && <DownloadPage onNavigate={handleNavigate} />}
        {page === 'dashboard' && (
          <DashboardPage
            onNavigate={handleNavigate}
            selectedScanId={selectedScanId}
            onSelectScan={setSelectedScanId}
          />
        )}
        {page === 'scan' && (
          <ScanPage onNavigate={handleNavigate} onSelectScan={setSelectedScanId} />
        )}
        {page === 'results' && (
          <ResultsPage
            onNavigate={handleNavigate}
            selectedScanId={selectedScanId}
            onSelectScan={setSelectedScanId}
          />
        )}
        {page === 'reports' && (
          <ReportsPage onNavigate={handleNavigate} selectedScanId={selectedScanId} />
        )}
        {page === 'docs' && <DocsPage onNavigate={handleNavigate} />}
      </main>

      {page === 'home' && <Footer />}
    </div>
  );
}

export default App;
