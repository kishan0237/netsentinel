import { useEffect, useState } from 'react';
import { FileText, Download, FileJson, FileCode, FileSpreadsheet, Clock, ArrowLeft, Loader2, AlertTriangle } from 'lucide-react';
import { Api } from '@/lib/api';
import type { Scan, Report } from '@/types';
import type { Page } from '@/components/Navbar';
import { formatRelativeTime } from '@/lib/utils';

interface ReportsPageProps {
  onNavigate: (page: Page) => void;
  selectedScanId: string | null;
}

export function ReportsPage({ onNavigate, selectedScanId }: ReportsPageProps) {
  const [scans, setScans] = useState<Scan[]>([]);
  const [reports, setReports] = useState<Report[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedScan, setSelectedScan] = useState(selectedScanId || '');
  const [reportType, setReportType] = useState<'html' | 'json' | 'csv'>('html');
  const [generating, setGenerating] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    load();
  }, []);

  const load = async () => {
    setLoading(true);
    try {
      const [scansData, reportsData] = await Promise.all([
        Api.listScans(100),
        Api.listReports(),
      ]);
      setScans(scansData);
      setReports(reportsData);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to load reports');
    } finally {
      setLoading(false);
    }
  };

  const handleGenerate = async () => {
    if (!selectedScan) return;
    setGenerating(true);
    setError(null);
    try {
      await Api.generateReport(selectedScan, reportType);
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to generate report');
    } finally {
      setGenerating(false);
    }
  };

  const handleDownload = (report: Report) => {
    window.open(Api.downloadReportUrl(report.id), '_blank');
  };

  const scanMap: Record<string, Scan> = {};
  scans.forEach((s) => { scanMap[s.id] = s; });

  const reportIcons: Record<string, typeof FileText> = {
    html: FileCode,
    json: FileJson,
    csv: FileSpreadsheet,
    pdf: FileText,
  };

  return (
    <div className="min-h-screen pt-20 pb-16 px-4 sm:px-6 lg:px-8">
      <div className="max-w-5xl mx-auto">
        {/* Header */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-8">
          <div className="flex items-center gap-4">
            <button
              onClick={() => onNavigate('dashboard')}
              className="p-2 rounded-lg text-base-400 hover:text-base-200 hover:bg-base-800/50 transition-colors"
            >
              <ArrowLeft className="w-5 h-5" />
            </button>
            <div>
              <h1 className="text-2xl sm:text-3xl font-bold text-base-50 mb-1">Reports</h1>
              <p className="text-base-500">Generated scan reports and exports</p>
            </div>
          </div>
        </div>

        {/* Generate Report Card */}
        <div className="card p-6 mb-6">
          <div className="flex items-center gap-3 mb-4">
            <div className="w-10 h-10 rounded-lg bg-brand-500/10 border border-brand-500/20 flex items-center justify-center">
              <FileText className="w-5 h-5 text-brand-400" />
            </div>
            <div>
              <h3 className="text-base-50 font-semibold">Generate New Report</h3>
              <p className="text-sm text-base-500">Create a report from a completed scan</p>
            </div>
          </div>
          <div className="flex flex-col sm:flex-row gap-3">
            <select
              value={selectedScan}
              onChange={(e) => setSelectedScan(e.target.value)}
              className="input-field text-sm flex-1"
            >
              <option value="">Select a completed scan...</option>
              {scans.filter((s) => s.status === 'completed').map((s) => (
                <option key={s.id} value={s.id}>
                  {s.target} · {s.scan_type} · {formatRelativeTime(s.completed_at)}
                </option>
              ))}
            </select>
            <select
              value={reportType}
              onChange={(e) => setReportType(e.target.value as 'html' | 'json' | 'csv')}
              className="input-field text-sm w-full sm:w-40"
            >
              <option value="html">HTML</option>
              <option value="json">JSON</option>
              <option value="csv">CSV</option>
            </select>
            <button
              onClick={handleGenerate}
              disabled={!selectedScan || generating}
              className="btn-primary justify-center text-sm disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {generating ? (
                <Loader2 className="w-4 h-4 animate-spin" />
              ) : (
                <FileText className="w-4 h-4" />
              )}
              Generate {reportType.toUpperCase()} Report
            </button>
          </div>
        </div>

        {error && (
          <div className="card p-4 mb-6 border-danger-500/30 bg-danger-500/5">
            <div className="flex items-center gap-2 text-sm text-danger-400">
              <AlertTriangle className="w-4 h-4" />
              {error}
            </div>
          </div>
        )}

        {/* Reports List */}
        {loading ? (
          <div className="card p-12 text-center text-base-500">
            <Clock className="w-8 h-8 mx-auto mb-3 animate-spin" />
            Loading reports...
          </div>
        ) : reports.length === 0 ? (
          <div className="card p-12 text-center">
            <FileText className="w-12 h-12 text-base-600 mx-auto mb-4" />
            <h3 className="text-base-100 font-medium mb-1">No reports yet</h3>
            <p className="text-sm text-base-500">Generate a report from a completed scan to see it here.</p>
          </div>
        ) : (
          <div className="space-y-3">
            {reports.map((report) => {
              const Icon = reportIcons[report.report_type] || FileText;
              const scan = scanMap[report.scan_id];
              return (
                <div key={report.id} className="card card-hover p-5 flex items-center gap-4">
                  <div className="flex-shrink-0 w-10 h-10 rounded-lg bg-base-800 flex items-center justify-center">
                    <Icon className="w-5 h-5 text-brand-400" />
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <h3 className="text-base-100 font-medium truncate">
                        {scan ? scan.target : 'Unknown scan'} · {report.report_type.toUpperCase()}
                      </h3>
                      <span className="badge badge-info">{report.report_type}</span>
                    </div>
                    <div className="flex items-center gap-3 text-xs text-base-500">
                      {scan && (
                        <span className="font-mono">{scan.target}</span>
                      )}
                      <span>·</span>
                      <span className="flex items-center gap-1">
                        <Clock className="w-3 h-3" />
                        {formatRelativeTime(report.created_at)}
                      </span>
                    </div>
                  </div>
                  <button
                    onClick={() => handleDownload(report)}
                    className="btn-secondary text-sm flex-shrink-0"
                  >
                    <Download className="w-4 h-4" />
                    Download
                  </button>
                </div>
              );
            })}
          </div>
        )}

        {/* Export Formats Info */}
        <div className="card p-6 mt-6">
          <h3 className="text-base-50 font-semibold mb-4">Available Export Formats</h3>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            {[
              { icon: FileCode, type: 'HTML', desc: 'Interactive, styled report with findings and host table' },
              { icon: FileJson, type: 'JSON', desc: 'Raw structured data for API integration' },
              { icon: FileSpreadsheet, type: 'CSV', desc: 'Spreadsheet-compatible port and service listing' },
            ].map((fmt) => {
              const Icon = fmt.icon;
              return (
                <div key={fmt.type} className="p-4 rounded-lg bg-base-950/50 border border-base-800">
                  <Icon className="w-5 h-5 text-brand-400 mb-2" />
                  <h4 className="text-sm text-base-100 font-medium mb-1">{fmt.type}</h4>
                  <p className="text-xs text-base-500">{fmt.desc}</p>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
}
