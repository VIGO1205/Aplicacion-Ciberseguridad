export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type AlertStatus =
  | "pending"
  | "triaging"
  | "triaged"
  | "escalated"
  | "false_positive"
  | "closed";
export type Verdict = "true_positive" | "false_positive" | "suspicious" | "benign";
export type IncidentStatus = "open" | "investigating" | "contained" | "resolved" | "closed";
export type ReportType = "operational" | "management" | "audit";
export type ReportFormat = "pdf" | "docx" | "xlsx";

export interface Permission {
  id: string;
  code: string;
  module: string;
  description: string;
}

export interface Role {
  id: string;
  name: string;
  description: string;
  color: string;
  is_system: boolean;
  permissions: Permission[];
}

export interface RoleBrief {
  id: string;
  name: string;
  color: string;
}

export interface User {
  id: string;
  email: string;
  full_name: string;
  is_active: boolean;
  job_title: string;
  department: string;
  phone: string;
  last_login_at: string | null;
  created_at: string;
  role: Role;
}

export interface UserBrief {
  id: string;
  full_name: string;
  email: string;
  role: RoleBrief | null;
}

export interface Asset {
  id: string;
  hostname: string;
  ip_address: string | null;
  criticality: Severity;
  owner: string;
  environment: string;
  operating_system: string;
  tags: string[];
}

export interface TriageAction {
  priority: number;
  action: string;
  owner: string;
  sla_minutes: number;
  type: string;
}

export interface TriageResult {
  id: string;
  verdict: Verdict;
  recommended_severity: Severity;
  confidence: number;
  risk_score: number;
  summary: string;
  reasoning: string;
  recommended_actions: TriageAction[];
  mitre_techniques: string[];
  should_escalate: boolean;
  false_positive_reason: string | null;
  engine: string;
  model_name: string;
  prompt_version: string;
  latency_ms: number;
  tokens_used: number;
  created_at: string;
}

export interface Enrichment {
  id: string;
  provider: string;
  indicator: string;
  indicator_type: string;
  status: string;
  risk_score: number | null;
  summary: string;
  payload: Record<string, unknown>;
  fetched_at: string;
  expires_at: string | null;
}

export interface IncidentBrief {
  id: string;
  code: string;
  title: string;
  severity: Severity;
  status: IncidentStatus;
  sla_due_at: string | null;
  opened_at: string;
  closed_at: string | null;
}

export interface OsticketTicketBrief {
  ticket_number: string;
  status_state: "open" | "closed";
  status_name: string;
  last_synced_at: string;
}

export interface Alert {
  id: string;
  external_id: string | null;
  source: string;
  title: string;
  description: string;
  rule_id: string | null;
  rule_level: number;
  severity: Severity;
  status: AlertStatus;
  source_ip: string | null;
  destination_ip: string | null;
  hostname: string | null;
  agent_name: string | null;
  username: string | null;
  mitre_techniques: string[];
  tags: string[];
  received_at: string;
  first_seen_at: string;
  last_seen_at: string;
  closed_at: string | null;
  asset: Asset | null;
  assigned_to: UserBrief | null;
  triage_result: TriageResult | null;
  incident: IncidentBrief | null;
  osticket_link: OsticketTicketBrief | null;
}

export interface AlertDetail extends Alert {
  raw_payload: Record<string, unknown>;
  enrichment_data: Enrichment[];
  fingerprint: string;
}

export interface AlertPage {
  items: Alert[];
  total: number;
  page: number;
  page_size: number;
  pages: number;
}

export interface Incident {
  id: string;
  code: string;
  alert_id: string | null;
  title: string;
  description: string;
  severity: Severity;
  status: IncidentStatus;
  containment_actions: string;
  ticket_external_id: string | null;
  sla_due_at: string | null;
  opened_at: string;
  closed_at: string | null;
  created_at: string;
  owner: UserBrief | null;
}

export interface IncidentPage {
  items: Incident[];
  total: number;
  page: number;
  page_size: number;
  pages: number;
}

export interface KPIBlock {
  total_alerts: number;
  open_alerts: number;
  critical_open: number;
  high_open: number;
  false_positive_rate: number;
  triage_coverage: number;
  automation_rate: number;
  mttt_minutes: number;
  mttr_hours: number;
  sla_compliance: number;
  open_incidents: number;
  total_incidents: number;
}

export interface SeriesPoint {
  label: string;
  value: number;
}

export interface NamedCount {
  name: string;
  value: number;
}

export interface DashboardOverview {
  period_days: number;
  generated_at: string;
  kpis: KPIBlock;
  alerts_by_day: SeriesPoint[];
  by_severity: NamedCount[];
  by_status: NamedCount[];
  by_source: NamedCount[];
  by_verdict: NamedCount[];
  top_source_ips: NamedCount[];
  top_rules: NamedCount[];
  top_mitre: NamedCount[];
  incidents_by_status: NamedCount[];
  recent_alerts: Alert[];
}

export interface Report {
  id: string;
  name: string;
  report_type: ReportType;
  format: ReportFormat;
  period_start: string;
  period_end: string;
  file_name: string;
  size_bytes: number;
  created_at: string;
  download_url: string | null;
  generated_by: UserBrief | null;
}

export interface ReportPage {
  items: Report[];
  total: number;
  page: number;
  page_size: number;
  pages: number;
}

export interface AuditLog {
  id: string;
  user_id: string | null;
  actor_email: string;
  actor_role: string;
  event_type: string;
  module: string;
  action: string;
  direction: "IN" | "OUT" | null;
  entity_type: string | null;
  entity_id: string | null;
  description: string;
  method: string | null;
  path: string | null;
  status_code: number | null;
  ip_address: string | null;
  user_agent: string | null;
  request_id: string | null;
  detail: Record<string, unknown>;
  duration_ms: number | null;
  created_at: string;
}

export interface AuditPage {
  items: AuditLog[];
  total: number;
  page: number;
  page_size: number;
  pages: number;
}

export interface AuditStats {
  period_days: number;
  total_events: number;
  active_users: number;
  by_module: NamedCount[];
  by_event: NamedCount[];
  by_direction: NamedCount[];
}

export interface UserPage {
  items: User[];
  total: number;
  page: number;
  page_size: number;
  pages: number;
}

export interface TokenResponse {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
  user: User;
}

export interface CatalogOption {
  value: string;
  label: string;
}

export interface Catalog {
  severity: CatalogOption[];
  alert_status: CatalogOption[];
  incident_status: CatalogOption[];
  verdict: CatalogOption[];
  report_type: CatalogOption[];
  report_format: string[];
}

export interface DemoAccount {
  email: string;
  password: string;
  name: string;
  role: string;
}
