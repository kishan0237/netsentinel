export interface Agent {
  id: string;
  agent_uuid: string;
  agent_name: string;
  hostname: string | null;
  platform: string | null;
  agent_version: string;
  status: string;
  last_heartbeat: string | null;
  created_at: string;
  updated_at: string;
}

export interface Scan {
  id: string;
  agent_id: string | null;
  target: string;
  scan_type: string;
  ports: string | null;
  status: 'pending' | 'running' | 'completed' | 'failed' | 'cancelled' | string;
  progress: number;
  current_stage: string | null;
  error: string | null;
  started_at: string | null;
  completed_at: string | null;
  created_at: string;
}

export interface Host {
  id: string;
  scan_id: string;
  ip_address: string;
  mac_address: string | null;
  hostname: string | null;
  status: string;
  os_estimate: string | null;
  created_at: string;
}

export interface Port {
  id: string;
  host_id: string;
  port_number: number;
  protocol: string;
  state: string;
  created_at: string;
}

export interface Service {
  id: string;
  port_id: string;
  service_name: string;
  product: string | null;
  version: string | null;
  created_at: string;
}

export interface Vulnerability {
  id: string;
  service_id: string;
  cve_id: string;
  severity: string;
  cvss_score: number | null;
  confidence: string;
  description: string | null;
  solution: string | null;
  created_at: string;
}

export interface Finding {
  id: string;
  scan_id: string;
  host_id: string | null;
  service_id: string | null;
  title: string;
  description: string | null;
  severity: string;
  recommendation: string | null;
  created_at: string;
}

export interface Report {
  id: string;
  scan_id: string;
  report_type: string;
  file_path: string | null;
  created_at: string;
}

export interface ScanWithDetails extends Scan {
  agents?: Pick<Agent, 'agent_uuid' | 'agent_name'>;
}

export interface ServiceWithVulns extends Service {
  vulnerabilities: Vulnerability[];
}

export interface PortWithServices extends Port {
  services: ServiceWithVulns[];
}

export interface HostWithPorts extends Host {
  ports: PortWithServices[];
}

export interface ScanResults {
  scan: Scan;
  hosts: HostWithPorts[];
  findings: Finding[];
}

export interface ScanStats {
  hosts: number;
  open_ports: number;
  services: number;
  vulnerabilities: number;
  findings: number;
  severity_counts: Record<string, number>;
}

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
