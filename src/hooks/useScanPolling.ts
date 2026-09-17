import { useCallback, useEffect, useRef, useState } from 'react';
import { Api } from '@/lib/api';
import type { Scan } from '@/types';

/**
 * Polls the scans list (and optionally one scan) on an interval.
 * Matches the architecture: frontend polls the API every 1-3 seconds while a
 * scan runs; 10s when idle.
 */
export function useScanPolling(pollMs = 10000, activePollMs = 2000) {
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);
  const interval = pollMs;
  const activeInterval = activePollMs;
  const timer = useRef<ReturnType<typeof setInterval> | null>(null);
  const hasActive = useRef(false);

  const load = useCallback(async () => {
    try {
      const data = await Api.listScans();
      setScans(data);
      hasActive.current = data.some((s) => s.status === 'running' || s.status === 'pending');
    } catch {
      // keep previous data on transient errors
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
    const schedule = () => {
      timer.current = setInterval(load, hasActive.current ? activeInterval : interval);
    };
    schedule();
    return () => {
      if (timer.current) clearInterval(timer.current);
    };
  }, [load, interval, activeInterval]);

  return { scans, loading, reload: load };
}

/** Polls a single scan until it leaves the running/pending state. */
export function useScanPoll(scanId: string | null, pollMs = 2000) {
  const [scan, setScan] = useState<Scan | null>(null);
  const timer = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    if (!scanId) {
      setScan(null);
      return;
    }
    let cancelled = false;
    const tick = async () => {
      try {
        const s = await Api.getScan(scanId);
        if (!cancelled) setScan(s);
      } catch {
        /* transient */
      }
    };
    tick();
    timer.current = setInterval(tick, pollMs);
    return () => {
      cancelled = true;
      if (timer.current) clearInterval(timer.current);
    };
  }, [scanId, pollMs]);

  return scan;
}
