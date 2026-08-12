from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class GeoLocation(BaseModel):
    country: str
    lat: float
    lon: float


class MitreTechnique(BaseModel):
    tactic: str
    technique_id: str
    technique_name: str


class ZeroTrustContext(BaseModel):
    identity_risk: str
    device_trust: str
    asset_criticality: str
    network_zone: str
    privilege_context: str
    policy_state: str


class EvidenceItem(BaseModel):
    timestamp: float
    source: str
    artifact_type: str
    summary: str
    artifact_ref: str


class FeedbackRecord(BaseModel):
    verdict: str
    analyst: str
    note: Optional[str] = None
    timestamp: float


class AlertModel(BaseModel):
    id: str
    timestamp: float
    source_ip: str
    dest_ip: str
    source_geo: GeoLocation
    dest_geo: GeoLocation
    attack_type: str = Field(
        ...,
        description="Classification category: Normal, DoS, Brute Force, Zero-day (GAN), etc.",
    )
    severity: str = Field(..., description="Critical, High, Medium, Low")
    confidence: float = Field(..., ge=0.0, le=1.0)
    edge_node_id: str
    source_type: str = Field(
        default="network-flow",
        description="Telemetry class such as network-flow, web-access, dns, identity, or cloud-audit.",
    )
    telemetry_source: str = Field(
        default="edge-sensor",
        description="Specific upstream collector or log source.",
    )
    asset_name: str = Field(default="core-edge-cluster")
    status: str = Field(default="open", description="open, investigating, escalated, closed")
    queue_level: str = Field(default="L1", description="SOC workflow queue: L1, L2, L3")
    assigned_team: str = Field(default="SOC L1")
    assigned_analyst: Optional[str] = None
    assigned_at: Optional[float] = None
    report_excerpt: Optional[str] = None
    disposition: str = Field(
        default="unreviewed",
        description="Analyst verdict: unreviewed, true_positive, false_positive, benign_expected.",
    )
    correlation_score: float = Field(default=0.0, ge=0.0, le=1.0)
    correlated_case_id: Optional[str] = None
    mitre: List[MitreTechnique] = Field(default_factory=list)
    zero_trust: ZeroTrustContext
    evidence: List[EvidenceItem] = Field(default_factory=list)
    feedback: Optional[FeedbackRecord] = None
    flow_features: Dict[str, Any] = Field(
        default_factory=dict,
        description="Raw feature vector from network or application telemetry.",
    )


class ShapFeatureImportance(BaseModel):
    feature: str
    importance: float


class ExplainabilityModel(BaseModel):
    alert_id: str
    shap_values: List[ShapFeatureImportance]
    explanation: str


class DashboardStats(BaseModel):
    total_alerts_24h: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    system_status: str
    active_edge_nodes: int
    cloud_sync: str


class ActionRequest(BaseModel):
    action_type: str
    target_ip: str
    alert_id: Optional[str] = None
    requested_by: str = "Admin-01"
    approved_by: Optional[str] = None


class ActionApprovalRequest(BaseModel):
    action_id: str
    analyst: str


class PendingAction(BaseModel):
    action_id: str
    action_type: str
    target_ip: str
    alert_id: Optional[str] = None
    requested_by: str
    approved_by: Optional[str] = None
    risk_level: str
    requires_approval: bool
    status: str
    recommended_playbook: str
    created_at: float
    executed_at: Optional[float] = None


class ActionResponse(BaseModel):
    status: str
    msg: str
    executed_at: Optional[float] = None
    action_id: Optional[str] = None
    requires_approval: bool = False
    recommended_playbook: Optional[str] = None


class ThreatCoverageItem(BaseModel):
    tactic: str
    technique_id: str
    technique_name: str
    detections: int
    avg_confidence: float


class ThreatCoverageSummary(BaseModel):
    total_alerts: int
    covered_tactics: int
    covered_techniques: int
    coverage_ratio: float
    items: List[ThreatCoverageItem]


class TelemetrySourceStatus(BaseModel):
    source_id: str
    kind: str
    status: str
    records_seen: int
    last_seen: float
    coverage: str
    notes: str


class CorrelationCase(BaseModel):
    case_id: str
    title: str
    summary: str
    status: str
    risk_score: float
    tactic_chain: List[str]
    source_types: List[str]
    alert_ids: List[str]
    recommended_playbook: str


class ForensicsRecord(BaseModel):
    alert_id: str
    packet_fingerprint: str
    raw_features: Dict[str, Any]
    evidence: List[EvidenceItem]
    related_alerts: List[str]
    timeline: List[EvidenceItem]


class FeedbackRequest(BaseModel):
    alert_id: str
    verdict: str
    analyst: str
    note: Optional[str] = None


class FeedbackSummaryItem(BaseModel):
    verdict: str
    count: int


class FeedbackSummary(BaseModel):
    total_reviewed: int
    latest_feedback: List[FeedbackRecord]
    verdicts: List[FeedbackSummaryItem]


class BenchmarkMetrics(BaseModel):
    precision: float
    recall: float
    f1_score: float
    false_positive_rate: float
    mttd_seconds: float
    mttr_seconds: float
    model_latency_ms: float
    attack_coverage_ratio: float


class ThreatIntelIndicator(BaseModel):
    indicator_type: str
    value: str
    confidence: str
    context: str


class PlaybookStep(BaseModel):
    step: int
    title: str
    instruction: str
    status: str


class InvestigationPlaybook(BaseModel):
    name: str
    objective: str
    steps: List[PlaybookStep]


class AnalysisReport(BaseModel):
    title: str
    summary: str
    findings: List[str]
    impact: str
    recommendation: str
    disposition: str
    author: str
    updated_at: float


class EscalationEvent(BaseModel):
    from_queue: str
    to_queue: str
    analyst: str
    reason: str
    timestamp: float


class InvestigationWorkspace(BaseModel):
    alert: AlertModel
    playbook: InvestigationPlaybook
    threat_intel: List[ThreatIntelIndicator]
    report: AnalysisReport
    escalation_history: List[EscalationEvent]
    next_actions: List[str]


class WorkflowUpdateRequest(BaseModel):
    alert_id: str
    analyst: str
    verdict: Optional[str] = None
    queue_level: Optional[str] = None
    status: Optional[str] = None
    assigned_analyst: Optional[str] = None
    report_summary: Optional[str] = None
    report_recommendation: Optional[str] = None
    escalation_reason: Optional[str] = None
    close_reason: Optional[str] = None


class LoginRequest(BaseModel):
    identifier: str
    password: str


class AuthUser(BaseModel):
    user_id: str
    name: str
    email: str
    role: str
    team: str
    shift: str
    queue_level: str
    permissions: List[str]


class LoginResponse(BaseModel):
    status: str
    token: str
    expires_at: float
    user: AuthUser


class IngestFeatureRequest(BaseModel):
    attack_type: str = Field(default="Normal")
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    source_type: str = Field(default="network-flow")
    telemetry_source: str = Field(default="custom-ingest")
    asset_name: Optional[str] = None
    edge_node_id: Optional[str] = None
    severity: Optional[str] = None
    confidence: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    correlation_score: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    timestamp: Optional[float] = None
    features: Dict[str, Any] = Field(default_factory=dict)


class IngestResponse(BaseModel):
    status: str
    msg: str
    alert_id: str
    alert: AlertModel


class ModelStatusResponse(BaseModel):
    runtime: str
    enabled: bool
    error: Optional[str] = None
    feature_order: List[str] = Field(default_factory=list)
    labels: List[str] = Field(default_factory=list)
    input_name: Optional[str] = None
    output_names: List[str] = Field(default_factory=list)
    model_path: Optional[str] = None
    alert_threshold: float
    prevent_threshold: float
    auto_response_enabled: bool


class MonitoredEventRequest(BaseModel):
    page_url: Optional[str] = None
    request_path: Optional[str] = None
    http_method: Optional[str] = None
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    source_type: str = Field(default="web-access")
    telemetry_source: str = Field(default="web-monitor")
    asset_name: Optional[str] = None
    edge_node_id: Optional[str] = None
    attack_type: str = Field(default="AUTO")
    requested_by: str = Field(default="web-monitor")
    auto_prevent: bool = False
    timestamp: Optional[float] = None
    features: Dict[str, Any] = Field(default_factory=dict)


class MonitoredEventResponse(BaseModel):
    status: str
    page_url: Optional[str] = None
    request_path: Optional[str] = None
    attack_type: str
    confidence: float = Field(ge=0.0, le=1.0)
    threat_score: float = Field(ge=0.0, le=1.0)
    severity: str
    should_alert: bool
    recommended_action: Optional[str] = None
    prevention_status: str
    prevention_message: Optional[str] = None
    alert_id: Optional[str] = None
    alert: Optional[AlertModel] = None


class UserAccount(BaseModel):
    user_id: str
    name: str
    email: str
    role: str
    team: str
    shift: str
    status: str
    queue_level: str
    permissions: List[str]
    temporary_password: Optional[str] = None


class CreateUserRequest(BaseModel):
    name: str
    email: str
    role: str
    team: str
    shift: str
    queue_level: str


class AnalystPerformance(BaseModel):
    analyst: str
    role: str
    queue_level: str
    assigned_alerts: int
    investigating_alerts: int
    escalated_alerts: int
    closed_alerts: int
    true_positive_rate: float
    false_positive_rate: float
    mtta_seconds: float
    mttd_seconds: float
    mttr_seconds: float
    workload_score: float


class SocManagerOverview(BaseModel):
    total_users: int
    active_users: int
    open_alerts: int
    escalated_alerts: int
    pending_approvals: int
    average_mtta_seconds: float
    average_mttd_seconds: float
    average_mttr_seconds: float
    users: List[UserAccount]
    performance: List[AnalystPerformance]
