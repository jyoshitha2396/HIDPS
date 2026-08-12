export type AlertSeverity = 'Critical' | 'High' | 'Medium' | 'Low';
export type AlertDisposition =
  | 'unreviewed'
  | 'true_positive'
  | 'false_positive'
  | 'benign_expected';

export interface GeoLocation {
  country: string;
  lat: number;
  lon: number;
}

export interface MitreTechnique {
  tactic: string;
  technique_id: string;
  technique_name: string;
}

export interface ZeroTrustContext {
  identity_risk: string;
  device_trust: string;
  asset_criticality: string;
  network_zone: string;
  privilege_context: string;
  policy_state: string;
}

export interface EvidenceItem {
  timestamp: number;
  source: string;
  artifact_type: string;
  summary: string;
  artifact_ref: string;
}

export interface FeedbackRecord {
  verdict: AlertDisposition | string;
  analyst: string;
  note?: string | null;
  timestamp: number;
}

export interface AlertData {
  id: string;
  timestamp: number;
  source_ip: string;
  dest_ip: string;
  source_geo: GeoLocation;
  dest_geo: GeoLocation;
  attack_type: string;
  severity: AlertSeverity;
  confidence: number;
  edge_node_id: string;
  source_type: string;
  telemetry_source: string;
  asset_name: string;
  status: string;
  queue_level: string;
  assigned_team: string;
  assigned_analyst?: string | null;
  assigned_at?: number | null;
  report_excerpt?: string | null;
  disposition: AlertDisposition | string;
  correlation_score: number;
  correlated_case_id?: string | null;
  mitre: MitreTechnique[];
  zero_trust: ZeroTrustContext;
  evidence: EvidenceItem[];
  feedback?: FeedbackRecord | null;
  flow_features?: Record<string, number | string>;
}

export interface DashboardStats {
  total_alerts_24h: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  system_status: string;
  active_edge_nodes: number;
  cloud_sync: string;
}

export interface ShapFeatureImportance {
  feature: string;
  importance: number;
}

export interface ExplainabilityModel {
  alert_id: string;
  shap_values: ShapFeatureImportance[];
  explanation: string;
}

export interface ThreatCoverageItem {
  tactic: string;
  technique_id: string;
  technique_name: string;
  detections: number;
  avg_confidence: number;
}

export interface ThreatCoverageSummary {
  total_alerts: number;
  covered_tactics: number;
  covered_techniques: number;
  coverage_ratio: number;
  items: ThreatCoverageItem[];
}

export interface TelemetrySourceStatus {
  source_id: string;
  kind: string;
  status: string;
  records_seen: number;
  last_seen: number;
  coverage: string;
  notes: string;
}

export interface CorrelationCase {
  case_id: string;
  title: string;
  summary: string;
  status: string;
  risk_score: number;
  tactic_chain: string[];
  source_types: string[];
  alert_ids: string[];
  recommended_playbook: string;
}

export interface ForensicsRecord {
  alert_id: string;
  packet_fingerprint: string;
  raw_features: Record<string, number | string>;
  evidence: EvidenceItem[];
  related_alerts: string[];
  timeline: EvidenceItem[];
}

export interface ThreatIntelIndicator {
  indicator_type: string;
  value: string;
  confidence: string;
  context: string;
}

export interface PlaybookStep {
  step: number;
  title: string;
  instruction: string;
  status: string;
}

export interface InvestigationPlaybook {
  name: string;
  objective: string;
  steps: PlaybookStep[];
}

export interface AnalysisReport {
  title: string;
  summary: string;
  findings: string[];
  impact: string;
  recommendation: string;
  disposition: string;
  author: string;
  updated_at: number;
}

export interface EscalationEvent {
  from_queue: string;
  to_queue: string;
  analyst: string;
  reason: string;
  timestamp: number;
}

export interface InvestigationWorkspace {
  alert: AlertData;
  playbook: InvestigationPlaybook;
  threat_intel: ThreatIntelIndicator[];
  report: AnalysisReport;
  escalation_history: EscalationEvent[];
  next_actions: string[];
}

export interface FeedbackSummaryItem {
  verdict: string;
  count: number;
}

export interface FeedbackSummary {
  total_reviewed: number;
  latest_feedback: FeedbackRecord[];
  verdicts: FeedbackSummaryItem[];
}

export interface PendingAction {
  action_id: string;
  action_type: string;
  target_ip: string;
  alert_id?: string | null;
  requested_by: string;
  approved_by?: string | null;
  risk_level: string;
  requires_approval: boolean;
  status: string;
  recommended_playbook: string;
  created_at: number;
  executed_at?: number | null;
}

export interface ActionResponse {
  status: string;
  msg: string;
  executed_at?: number;
  action_id?: string;
  requires_approval: boolean;
  recommended_playbook?: string | null;
}

export interface FeedbackSubmissionResponse {
  status: string;
  feedback: FeedbackRecord;
  alert_id: string;
  verdict: string;
}

export interface WorkflowUpdateRequest {
  alert_id: string;
  analyst: string;
  verdict?: string;
  queue_level?: string;
  status?: string;
  assigned_analyst?: string;
  report_summary?: string;
  report_recommendation?: string;
  escalation_reason?: string;
  close_reason?: string;
}

export interface AuthUser {
  user_id: string;
  name: string;
  email: string;
  role: string;
  team: string;
  shift: string;
  queue_level: string;
  permissions: string[];
}

export interface LoginRequest {
  identifier: string;
  password: string;
}

export interface LoginResponse {
  status: string;
  token: string;
  expires_at: number;
  user: AuthUser;
}

export interface AuthSession {
  token: string;
  expires_at: number;
  user: AuthUser;
}

export interface UserAccount {
  user_id: string;
  name: string;
  email: string;
  role: string;
  team: string;
  shift: string;
  status: string;
  queue_level: string;
  permissions: string[];
  temporary_password?: string | null;
}

export interface CreateUserRequest {
  name: string;
  email: string;
  role: string;
  team: string;
  shift: string;
  queue_level: string;
}

export interface AnalystPerformance {
  analyst: string;
  role: string;
  queue_level: string;
  assigned_alerts: number;
  investigating_alerts: number;
  escalated_alerts: number;
  closed_alerts: number;
  true_positive_rate: number;
  false_positive_rate: number;
  mtta_seconds: number;
  mttd_seconds: number;
  mttr_seconds: number;
  workload_score: number;
}

export interface SocManagerOverview {
  total_users: number;
  active_users: number;
  open_alerts: number;
  escalated_alerts: number;
  pending_approvals: number;
  average_mtta_seconds: number;
  average_mttd_seconds: number;
  average_mttr_seconds: number;
  users: UserAccount[];
  performance: AnalystPerformance[];
}

export interface BenchmarkMetrics {
  precision: number;
  recall: number;
  f1_score: number;
  false_positive_rate: number;
  mttd_seconds: number;
  mttr_seconds: number;
  model_latency_ms: number;
  attack_coverage_ratio: number;
}

export interface CloudIntel {
  model_version: string;
  last_retraining: string;
  gan_augmentation: string;
  adversarial_training: string;
  mitre_mapping?: string;
  zero_trust_fusion?: string;
}

export interface ModelStatus {
  runtime: string;
  enabled: boolean;
  error?: string | null;
  feature_order: string[];
  labels: string[];
  input_name?: string | null;
  output_names: string[];
  model_path?: string | null;
  alert_threshold: number;
  prevent_threshold: number;
  auto_response_enabled: boolean;
}

export interface MonitoredEventResponse {
  status: string;
  page_url?: string | null;
  request_path?: string | null;
  attack_type: string;
  confidence: number;
  threat_score: number;
  severity: AlertSeverity;
  should_alert: boolean;
  recommended_action?: string | null;
  prevention_status: string;
  prevention_message?: string | null;
  alert_id?: string | null;
  alert?: AlertData | null;
}

export interface AlertSocketMessage {
  type: 'NEW_ALERT';
  data: AlertData;
}

export type AppView =
  | 'dashboard'
  | 'alerts'
  | 'threat-intelligence'
  | 'edge-nodes'
  | 'analytics'
  | 'logs-forensics'
  | 'access-control'
  | 'settings'
  | 'demo-lab';

export type ConnectionState = 'connecting' | 'online' | 'offline';
export type SimulationCommand = 'START_SIMULATION' | 'STOP_SIMULATION' | 'NORMAL_TRAFFIC';
