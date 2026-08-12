import asyncio
import os
import time
from typing import Callable, List

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from config import get_allowed_origins, get_database_env_source
from engine import engine
from schemas import (
    ActionApprovalRequest,
    ActionRequest,
    ActionResponse,
    AuthUser,
    AlertModel,
    BenchmarkMetrics,
    CorrelationCase,
    CreateUserRequest,
    DashboardStats,
    ExplainabilityModel,
    FeedbackRequest,
    FeedbackSummary,
    ForensicsRecord,
    LoginRequest,
    LoginResponse,
    IngestFeatureRequest,
    IngestResponse,
    InvestigationWorkspace,
    ModelStatusResponse,
    MonitoredEventRequest,
    MonitoredEventResponse,
    PendingAction,
    SocManagerOverview,
    TelemetrySourceStatus,
    ThreatCoverageSummary,
    UserAccount,
    WorkflowUpdateRequest,
)

def get_bearer_token(authorization: str | None) -> str:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Authentication required.")
    return authorization.split(" ", 1)[1].strip()


def require_auth(authorization: str | None = Header(default=None)) -> AuthUser:
    token = get_bearer_token(authorization)
    user = engine.get_user_for_token(token)
    if not user:
        raise HTTPException(status_code=401, detail="Session expired or invalid.")
    return user


def require_roles(*allowed_roles: str) -> Callable[[AuthUser], AuthUser]:
    def dependency(current_user: AuthUser = Depends(require_auth)) -> AuthUser:
        if current_user.role not in allowed_roles:
            raise HTTPException(status_code=403, detail="You do not have access to this resource.")
        return current_user

    return dependency


app = FastAPI(title="Edge-Cloud SOC Telemetry Server", version="3.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=get_allowed_origins(),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class TrafficBroadcaster:
    def __init__(self):
        self.active_sockets: list[WebSocket] = []
        self.simulation_active = True
        self.frequency = 1.0

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active_sockets.append(ws)
        for alert in reversed(engine.get_recent_alerts(limit=24)):
            await ws.send_json({"type": "NEW_ALERT", "data": alert.model_dump()})

    def disconnect(self, ws: WebSocket):
        if ws in self.active_sockets:
            self.active_sockets.remove(ws)

    async def broadcast(self, data: dict):
        stale_connections: list[WebSocket] = []
        for connection in self.active_sockets:
            try:
                await connection.send_json(data)
            except Exception:
                stale_connections.append(connection)

        for connection in stale_connections:
            self.disconnect(connection)


broadcaster = TrafficBroadcaster()


async def simulate_edge_inferencing():
    while True:
        if broadcaster.simulation_active and broadcaster.active_sockets:
            burst_size = 1 if broadcaster.frequency >= 1.0 else 4
            for _ in range(burst_size):
                alert_obj = engine.generate_simulated_alert()
                await broadcaster.broadcast({"type": "NEW_ALERT", "data": alert_obj.model_dump()})
        await asyncio.sleep(broadcaster.frequency)


@app.on_event("startup")
async def start_background_jobs():
    engine.initialize_storage()
    asyncio.create_task(simulate_edge_inferencing())


@app.get("/api/health")
async def health_check():
    database_env_source = get_database_env_source()
    return {
        "status": "ok",
        "simulation_active": broadcaster.simulation_active,
        "connected_clients": len(broadcaster.active_sockets),
        "generated_alerts": len(engine.alert_history),
        "pending_approvals": len(engine.pending_actions),
        "storage": engine.storage_status(),
        "database_configured": engine.database.enabled,
        "database_env_source": database_env_source,
        "allowed_origins": get_allowed_origins(),
    }


@app.get("/api/model/status", response_model=ModelStatusResponse)
async def fetch_model_status(current_user: AuthUser = Depends(require_auth)):
    return engine.get_model_status()


@app.post("/api/auth/login", response_model=LoginResponse)
async def login(req: LoginRequest, request: Request):
    client_ip = request.client.host if request.client else "unknown"
    try:
        auth_result = engine.authenticate_user(req.identifier, req.password, client_ip=client_ip)
    except PermissionError as exc:
        raise HTTPException(status_code=423, detail=str(exc)) from None
    except ValueError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from None

    return LoginResponse(
        status="success",
        token=auth_result["token"],
        expires_at=auth_result["expires_at"],
        user=auth_result["user"],
    )


@app.get("/api/auth/me", response_model=AuthUser)
async def me(current_user: AuthUser = Depends(require_auth)):
    return current_user


@app.post("/api/auth/logout")
async def logout(authorization: str | None = Header(default=None)):
    token = get_bearer_token(authorization)
    engine.revoke_session(token)
    return {"status": "success"}


@app.websocket("/ws/alerts")
async def alert_websocket(ws: WebSocket, token: str = Query(default="")):
    if not token or not engine.get_user_for_token(token):
        await ws.close(code=4401, reason="Authentication required.")
        return
    await broadcaster.connect(ws)
    try:
        while True:
            cmd = await ws.receive_text()
            if cmd == "START_SIMULATION":
                broadcaster.simulation_active = True
                broadcaster.frequency = 0.5
            elif cmd == "STOP_SIMULATION":
                broadcaster.simulation_active = False
            elif cmd == "NORMAL_TRAFFIC":
                broadcaster.simulation_active = True
                broadcaster.frequency = 2.0
    except WebSocketDisconnect:
        broadcaster.disconnect(ws)


@app.get("/api/alerts", response_model=List[AlertModel])
async def fetch_recent_alerts(limit: int = 80, current_user: AuthUser = Depends(require_auth)):
    return engine.get_recent_alerts(limit=limit)


@app.get("/api/stats/dashboard", response_model=DashboardStats)
async def fetch_dashboard_stats(current_user: AuthUser = Depends(require_auth)):
    return engine.get_dashboard_stats()


@app.get("/api/mitre/coverage", response_model=ThreatCoverageSummary)
async def fetch_mitre_coverage(current_user: AuthUser = Depends(require_auth)):
    return engine.get_threat_coverage()


@app.get("/api/telemetry/sources", response_model=List[TelemetrySourceStatus])
async def fetch_telemetry_sources(current_user: AuthUser = Depends(require_auth)):
    return engine.get_telemetry_sources()


@app.get("/api/correlation/cases", response_model=List[CorrelationCase])
async def fetch_correlation_cases(current_user: AuthUser = Depends(require_auth)):
    return engine.get_correlation_cases()


@app.get("/api/forensics/{alert_id}", response_model=ForensicsRecord)
async def fetch_forensics_record(alert_id: str, current_user: AuthUser = Depends(require_auth)):
    record = engine.get_forensics_record(alert_id)
    if not record:
        raise HTTPException(status_code=404, detail="Alert not found.")
    return record


@app.get("/api/investigation/{alert_id}", response_model=InvestigationWorkspace)
async def fetch_investigation_workspace(alert_id: str, current_user: AuthUser = Depends(require_auth)):
    workspace = engine.get_investigation_workspace(alert_id)
    if not workspace:
        raise HTTPException(status_code=404, detail="Alert not found.")
    return workspace


@app.get("/api/shap-values/{attack_type}", response_model=ExplainabilityModel)
async def fetch_shap_explainability(
    attack_type: str,
    alert_id: str = "alert-mock-1",
    current_user: AuthUser = Depends(require_auth),
):
    shap_vals = engine.compute_shap_values(alert_id, attack_type)

    explanation = "High packet rate and uncharacteristic latency identified."
    if "Zero-day" in attack_type:
        explanation = "Classifier linked exploit-like payload patterns with masquerading behavior and elevated zero-trust risk."
    elif "Adversarial" in attack_type:
        explanation = "Model-evasion features were elevated, and DNS callback behavior aligned with the control-plane watchlist."

    return ExplainabilityModel(
        alert_id=alert_id,
        shap_values=shap_vals,
        explanation=explanation,
    )


@app.post("/api/feedback/submit")
async def submit_feedback(req: FeedbackRequest, current_user: AuthUser = Depends(require_auth)):
    try:
        feedback = engine.submit_feedback(req)
    except KeyError:
        raise HTTPException(status_code=404, detail="Alert not found.") from None
    return {
        "status": "success",
        "feedback": feedback.model_dump(),
        "alert_id": req.alert_id,
        "verdict": req.verdict,
    }


@app.post("/api/ingest/features", response_model=IngestResponse)
async def ingest_feature_event(req: IngestFeatureRequest):
    alert = engine.ingest_feature_event(req)
    await broadcaster.broadcast({"type": "NEW_ALERT", "data": alert.model_dump()})
    return IngestResponse(
        status="success",
        msg=f"Ingested {alert.source_type} telemetry from {alert.telemetry_source}.",
        alert_id=alert.id,
        alert=alert,
    )


@app.post("/api/model/evaluate", response_model=MonitoredEventResponse)
async def evaluate_monitored_event(req: MonitoredEventRequest):
    decision = engine.evaluate_monitored_event(req)
    if decision.alert:
        await broadcaster.broadcast({"type": "NEW_ALERT", "data": decision.alert.model_dump()})
    return decision


@app.post("/api/alerts/workflow", response_model=AlertModel)
async def update_alert_workflow(req: WorkflowUpdateRequest, current_user: AuthUser = Depends(require_auth)):
    try:
        return engine.update_alert_workflow(req)
    except KeyError:
        raise HTTPException(status_code=404, detail="Alert not found.") from None


@app.get("/api/manager/overview", response_model=SocManagerOverview)
async def fetch_soc_manager_overview(
    current_user: AuthUser = Depends(require_roles("SOC Manager", "Compliance Lead")),
):
    return engine.get_soc_manager_overview()


@app.post("/api/manager/users", response_model=UserAccount)
async def create_soc_user(
    req: CreateUserRequest,
    current_user: AuthUser = Depends(require_roles("SOC Manager")),
):
    return engine.add_user(req)


@app.get("/api/feedback/summary", response_model=FeedbackSummary)
async def fetch_feedback_summary(current_user: AuthUser = Depends(require_auth)):
    return engine.get_feedback_summary()


@app.post("/api/action/execute", response_model=ActionResponse)
async def execute_mitigation(
    req: ActionRequest,
    current_user: AuthUser = Depends(require_roles("IR Engineer", "SOC Manager")),
):
    return engine.request_action(req)


@app.get("/api/action/pending", response_model=List[PendingAction])
async def fetch_pending_actions(current_user: AuthUser = Depends(require_auth)):
    return engine.get_pending_actions()


@app.post("/api/action/approve", response_model=ActionResponse)
async def approve_mitigation(
    req: ActionApprovalRequest,
    current_user: AuthUser = Depends(require_roles("SOC Manager")),
):
    try:
        return engine.approve_action(req)
    except KeyError:
        raise HTTPException(status_code=404, detail="Pending action not found.") from None


@app.get("/api/metrics/benchmark", response_model=BenchmarkMetrics)
async def fetch_benchmark_metrics(current_user: AuthUser = Depends(require_auth)):
    return engine.get_benchmark_metrics()


@app.get("/api/cloud-intel")
async def fetch_cloud_neural_status(current_user: AuthUser = Depends(require_auth)):
    return {
        "model_version": "v3.0.0-GAN-BiLSTM-Correlator",
        "last_retraining": "2026-03-24T00:00:00Z",
        "gan_augmentation": "Active - Live Updating",
        "adversarial_training": "Fully Converged (PGD tested)",
        "mitre_mapping": "Enabled",
        "zero_trust_fusion": "Enabled",
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host=os.getenv("HOST", "0.0.0.0"),
        port=int(os.getenv("PORT", "8000")),
        reload=os.getenv("RELOAD", "false").lower() == "true",
    )
