export interface User {
  id: string
  email: string
  full_name: string
  role: string
  permissions: string[]
  mfa_enabled: boolean
}

export interface Asset {
  id: string
  hostname: string
  ip_address: string
  os: string
  os_version: string
  asset_type: string
  risk_score: number
  tags: string[]
  open_ports: number[]
  services: { port: number; name: string }[]
  first_seen: string
  last_seen: string
}

export interface Vulnerability {
  id: string
  asset_id: string
  cve_id: string
  cvss_score: number
  severity: string
  description: string
  exploit_available: boolean
  remediation: string
  status: string
  asset_hostname?: string
  asset_ip?: string
}

export interface Alert {
  id: string
  source: string
  title: string
  description: string
  severity: string
  status: string
  mitre_techniques: string[]
  risk_score: number
  ai_summary: string
  ai_recommendation: string
  created_at: string
}

export interface Incident {
  id: string
  title: string
  description: string
  severity: string
  status: string
  alert_ids: string[]
  assignee_id: string
  assignee_name: string
  timeline: TimelineEntry[]
  ai_narrative: string
  created_at: string
  resolved_at: string
}

export interface TimelineEntry {
  timestamp: string
  action: string
  actor: string
  description: string
}

export interface IOC {
  id: string
  ioc_type: string
  ioc_value: string
  threat_score: number
  source: string
  tags: string[]
  is_active: boolean
}

export interface DashboardStats {
  active_alerts: number
  total_assets: number
  critical_vulns: number
  open_incidents: number
  risk_score: number
  events_per_second: number
  active_iocs: number
}

export interface ChatMessage {
  role: 'user' | 'assistant' | 'system'
  content: string
  timestamp?: string
}

export interface Action {
  label: string
  action: string
  severity: string
}

export interface MenuItem {
  id: string
  label: string
  icon: string
  path: string
  badge?: number | string
}
