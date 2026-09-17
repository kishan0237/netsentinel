import { useCallback, useEffect, useRef, useState } from 'react';
import { Api } from '@/lib/api';
import type { Agent } from '@/types';

const AGENT_KEY = 'netsentinel.agent_uuid';

/**
 * Resolves the dashboard's agent.
 *
 * No user auth: the dashboard picks the agent by a locally-stored
 * agent_uuid (set on first load from the server's agent list). If the server
 * has no agents yet (agent never installed), we create a lightweight
 * "dashboard-side" registration so scan jobs can be queued and picked up by
 * the first agent that registers with that same UUID — or by the user's
 * installed agent whose ID they enter.
 */
export function useAgent() {
  const [agent, setAgent] = useState<Agent | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const timer = useRef<ReturnType<typeof setInterval> | null>(null);

  const load = useCallback(async () => {
    try {
      const stored = localStorage.getItem(AGENT_KEY);
      if (stored) {
        try {
          const a = await Api.getAgent(stored);
          setAgent(a);
          setError(null);
          return;
        } catch {
          localStorage.removeItem(AGENT_KEY); // stale
        }
      }
      const agents = await Api.listAgents();
      if (agents.length > 0) {
        const preferred = agents.find((a) => a.status === 'online') || agents[0];
        localStorage.setItem(AGENT_KEY, preferred.agent_uuid);
        setAgent(preferred);
        setError(null);
      } else {
        setAgent(null);
        setError(
          'No agent registered yet. Install and start the NetSentinel agent — it will appear here automatically.'
        );
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to reach API');
    } finally {
      setLoading(false);
    }
  }, []);

  const setAgentById = useCallback((agentUuid: string) => {
    localStorage.setItem(AGENT_KEY, agentUuid);
    return load();
  }, [load]);

  useEffect(() => {
    load();
    timer.current = setInterval(load, 15000); // keep status/heartbeat fresh
    return () => {
      if (timer.current) clearInterval(timer.current);
    };
  }, [load]);

  return { agent, loading, error, reload: load, setAgentById };
}
