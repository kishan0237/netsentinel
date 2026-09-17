import type { Severity } from '@/types';

export function severityBadgeClass(severity: string): string {
  switch (severity.toLowerCase()) {
    case 'critical':
      return 'badge-critical';
    case 'high':
      return 'badge-high';
    case 'medium':
      return 'badge-medium';
    case 'low':
      return 'badge-low';
    case 'info':
      return 'badge-info';
    default:
      return 'badge-info';
  }
}

export function severityDotClass(severity: string): string {
  switch (severity.toLowerCase()) {
    case 'critical':
      return 'bg-danger-500';
    case 'high':
      return 'bg-orange-500';
    case 'medium':
      return 'bg-warning-500';
    case 'low':
      return 'bg-info-500';
    default:
      return 'bg-base-500';
  }
}

export function severityOrder(severity: string): number {
  const order: Record<string, number> = {
    critical: 0,
    high: 1,
    medium: 2,
    low: 3,
    info: 4,
  };
  return order[severity.toLowerCase()] ?? 5;
}

export function formatRelativeTime(dateStr: string | null): string {
  if (!dateStr) return '—';
  const date = new Date(dateStr);
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffMin = Math.floor(diffMs / 60000);
  const diffHr = Math.floor(diffMin / 60);
  const diffDay = Math.floor(diffHr / 24);

  if (diffMin < 1) return 'just now';
  if (diffMin < 60) return `${diffMin}m ago`;
  if (diffHr < 24) return `${diffHr}h ago`;
  if (diffDay === 1) return 'yesterday';
  if (diffDay < 7) return `${diffDay}d ago`;
  return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
}

export function formatDuration(start: string | null, end: string | null): string {
  if (!start || !end) return '—';
  const diffMs = new Date(end).getTime() - new Date(start).getTime();
  const sec = Math.floor(diffMs / 1000);
  if (sec < 60) return `${sec}s`;
  const min = Math.floor(sec / 60);
  const remSec = sec % 60;
  return `${min}m ${remSec}s`;
}

export type { Severity };
