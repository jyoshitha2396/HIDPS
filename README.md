# AI-Powered SOC Dashboard

Production-oriented SOC dashboard for an edge-cloud IDPS workflow. The project includes a React frontend, a FastAPI backend, live WebSocket alert streaming, investigation workflows, mitigation actions, and production packaging assets for containerized deployment.

## What is included

- Real-time dashboard with attack map, alert stream, investigation panel, response actions, and analytics.
- Additional operational sections for Threat Intelligence, Edge Nodes, Logs & Forensics, Access Control, and Settings.
- FastAPI telemetry server with health, stats, explainability, cloud intel, and mitigation endpoints.
- Dockerfiles for both services and a root `docker-compose.yml`.
- Environment variable examples for frontend and backend production configuration.

## Frontend

Path: `frontend`

Important commands:

```bash
npm install
npm run dev
npm run lint
npm run build
```

Environment variables:

- `VITE_API_BASE_URL`
- `VITE_WS_BASE_URL`

Example values are available in `frontend/.env.example`.

## Backend

Path: `backend`

Recommended local setup:

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python main.py
```

Backend environment variables:

- `HOST`
- `PORT`
- `RELOAD`
- `ALLOWED_ORIGINS`
- `DATABASE_URL`
- `NETLIFY_DATABASE_URL_UNPOOLED`
- `NETLIFY_DATABASE_URL`

Example values are available in `backend/.env.example`.

## PostgreSQL database setup

This project now supports PostgreSQL-backed authentication and user storage.

Use your hosted Neon or Netlify DB connection string on the backend host.

Recommended priority for this project:

1. `DATABASE_URL`
2. `NETLIFY_DATABASE_URL_UNPOOLED`
3. `NETLIFY_DATABASE_URL`

Example:

```env
DATABASE_URL=postgresql://username:password@host/database?sslmode=require
```

If you are reusing the database created by Netlify DB, you can set either:

```env
NETLIFY_DATABASE_URL_UNPOOLED=postgresql://username:password@host/database?sslmode=require
```

or:

```env
NETLIFY_DATABASE_URL=postgresql://username:password@host/database?sslmode=require
```

What is stored in PostgreSQL:

- analyst and manager users
- password hashes
- lockout state for repeated login failures
- active dashboard sessions

What still remains in app memory:

- simulated alerts
- transient investigation state
- pending response actions

Important:

- do not commit the real Neon connection string into Git
- set the connection string only in your backend hosting provider's environment variables
- set `ALLOWED_ORIGINS` to your Netlify domain, for example:

```env
ALLOWED_ORIGINS=https://soc-dashbaord.netlify.app
```

On startup, the backend auto-creates the auth tables and seeds the default users if the database is empty.

You can confirm production wiring by opening the backend health endpoint:

```text
GET /api/health
```

The response now includes:

- `storage`
- `database_configured`
- `database_env_source`
- `allowed_origins`

## Using your `.pth` model with ONNX

If your intrusion model currently exists as a PyTorch checkpoint (`.pth`), the practical path for this project is:

1. Export the model to ONNX.
2. Deploy the ONNX model behind an inference service or load it directly in the backend.
3. Send real website or network features into this backend.
4. Let the backend turn model predictions into alerts for the webapp.

### 1. Export `.pth` to `.onnx`

Install the optional ML packages first:

```bash
pip install torch onnx onnxruntime numpy
```

Generic export script:

```bash
python backend/examples/export_pth_to_onnx.py --checkpoint path\to\model.pth --output path\to\model.onnx --factory my_model:create_model --input-shape 1,16
```

Use `--factory module_name:callable_name` to point the exporter to your real model builder.

If your checkpoint wraps the weights, add `--state-dict-key state_dict` or the matching key name.

This repo now also includes a concrete exporter for your `hardened_ids_vfinal.pth` checkpoint:

```bash
python backend/examples/export_hardened_ids_to_onnx.py
```

That command writes the deployable model to:

```text
backend/models/hardened_ids_vfinal.onnx
```

### 2. Enable ONNX inference in this backend

Optional runtime adapter:

- [backend/model_adapter.py](/D:/IDPSProject/backend/model_adapter.py)
- [backend/.env.example](/D:/IDPSProject/backend/.env.example)

Set these environment variables:

```env
MODEL_RUNTIME=onnx
ONNX_MODEL_PATH=
MODEL_FEATURE_ORDER=destination_port,flow_duration,total_fwd_packets,total_backward_packets,total_length_fwd_packets,total_length_bwd_packets,fwd_packet_length_max,bwd_packet_length_mean,flow_bytes_per_s,flow_packets_per_s,packet_length_mean,avg_packet_size,subflow_fwd_packets
MODEL_LABELS=Normal,Intrusion
MODEL_ALERT_THRESHOLD=0.55
MODEL_PREVENT_THRESHOLD=0.85
MODEL_AUTO_RESPONSE=false
```

If `ONNX_MODEL_PATH` is left blank and `backend/models/hardened_ids_vfinal.onnx` exists, the backend will load that bundled model automatically.

When `MODEL_RUNTIME=onnx` is enabled, the backend can infer the attack type automatically if you send:

```json
{
  "attack_type": "AUTO",
  "source_ip": "203.0.113.25",
  "source_type": "web-access",
  "telemetry_source": "nginx-prod",
  "asset_name": "checkout-api",
  "features": {
    "packet_rate": 1200,
    "avg_packet_size": 512,
    "duration": 8.2,
    "entropy": 4.1,
    "connection_rate": 12.4,
    "failed_logins": 18,
    "payload_kb": 2.9
  }
}
```

The integration point is the live inference hook in [backend/engine.py](/D:/IDPSProject/backend/engine.py), where `attack_type: "AUTO"` will try the ONNX adapter first and then blend in request-context heuristics so the dashboard still produces understandable alert categories for demos.

You can verify the runtime from the backend with:

```text
GET /api/model/status
```

The response includes:

- runtime mode
- whether the ONNX model loaded successfully
- feature order
- labels
- alert and prevention thresholds

### 3. Deploy the model in cloud

You have two common deployment options:

- Load the ONNX model directly inside this FastAPI backend.
- Deploy the ONNX model as a separate cloud inference service and have this backend call it.

Recommended cloud approach:

1. Package the ONNX model in a small inference API.
2. Expose a `/predict` endpoint that accepts feature vectors.
3. Return `attack_type` and `confidence`.
4. Keep this SOC backend responsible for alerting, investigation workflow, and dashboard streaming.

That separation is usually cleaner because:

- model scaling is independent from SOC UI traffic
- model versioning is easier
- rollbacks are safer
- you can replace the model without changing the dashboard

### 4. Integrate the model with this webapp

This webapp does not run the model in the browser. The integration is:

- website logs or network sensors generate features
- backend receives the features through `/api/ingest/features`
- monitored webpages can also send scored events through `/api/model/evaluate`
- backend runs ONNX inference or uses the provided `attack_type`
- backend creates an alert
- frontend receives the alert over WebSocket and renders it in the SOC dashboard

For CICIDS replay demos, you can send a real dataset row straight into the monitored-event endpoint:

```bash
python backend/examples/send_cicids_event.py --api http://localhost:8000 --label-contains "Web Attack"
```

That helper extracts the 13-feature vector, adds a `threat_hint` derived from the dataset label, and lets the backend turn it into a dashboard alert.

Note:

- the bundled ONNX model is deployed and scored by the backend
- the original training-time scaler / feature-selection metadata was not present with the checkpoint
- for labeled dataset replays, `threat_hint` keeps the dashboard category aligned with the row label while the ONNX runtime still contributes live model metadata and confidence

That means your real model should connect to the backend, not directly to the React frontend.

### 5. Demo page monitoring and threat-score prevention

For a monitored webpage or demo endpoint, call:

```text
POST /api/model/evaluate
```

This endpoint will:

- score the event with ONNX when `MODEL_RUNTIME=onnx`
- fall back to heuristic web-risk scoring if the model is disabled
- compute a threat score
- create a live dashboard alert when the score crosses `MODEL_ALERT_THRESHOLD`
- recommend or trigger a prevention action when the score crosses `MODEL_PREVENT_THRESHOLD`

Example payload:

```json
{
  "page_url": "https://demo.yourapp.com/login",
  "request_path": "/login",
  "http_method": "POST",
  "source_ip": "203.0.113.25",
  "asset_name": "checkout-web",
  "auto_prevent": true,
  "features": {
    "failed_logins": 12,
    "packet_rate": 1800,
    "payload_kb": 4.6,
    "entropy": 3.9
  }
}
```

Helper script:

```bash
python backend/examples/send_monitored_web_event.py --endpoint https://hidps.onrender.com --page-url https://demo.yourapp.com/login --request-path /login --http-method POST --feature failed_logins=12 --feature packet_rate=1800 --feature payload_kb=4.6 --auto-prevent
```

## Analyst login

The dashboard now starts with a login page and token-based analyst sessions.

Default demo accounts:

- `admin-01@nexussoc.local` / `NexusAdmin!2026`
- `analyst-07@nexussoc.local` / `NexusHunter!2026`
- `responder-03@nexussoc.local` / `NexusRespond!2026`
- `auditor-02@nexussoc.local` / `NexusAudit!2026`

Implemented security controls:

- PBKDF2 password hashing
- session expiry
- repeated-failure account lockout
- role-based access for manager and response operations

## Real telemetry ingestion

You can push website or network telemetry into the backend at:

```bash
POST /api/ingest/features
```

Example website event:

```bash
curl -X POST http://localhost:8000/api/ingest/features ^
  -H "Content-Type: application/json" ^
  -d "{\"attack_type\":\"Web Attack\",\"source_ip\":\"203.0.113.25\",\"source_type\":\"web-access\",\"telemetry_source\":\"nginx-prod\",\"asset_name\":\"checkout-api\",\"features\":{\"request_path\":\"/login\",\"status_code\":401,\"failed_logins\":12,\"payload_kb\":3.8}}"
```

Example network event:

```bash
curl -X POST http://localhost:8000/api/ingest/features ^
  -H "Content-Type: application/json" ^
  -d "{\"attack_type\":\"DoS\",\"source_ip\":\"198.51.100.77\",\"dest_ip\":\"10.0.10.25\",\"source_type\":\"network-flow\",\"telemetry_source\":\"suricata-edge\",\"asset_name\":\"edge-gateway\",\"features\":{\"packet_rate\":9800,\"burst_score\":0.96,\"syn_ratio\":0.91}}"
```

Helper scripts are included in `backend/examples`:

```bash
python backend/examples/send_ingest_event.py --source-ip 198.51.100.77 --attack-type DoS --telemetry-source netflow-lab --feature packet_rate=9800 --feature burst_score=0.96
python backend/examples/send_nginx_log.py --log-file C:\logs\nginx\access.log --telemetry-source nginx-prod --asset-name checkout-api
```

Integration pattern:

- Website: tail Nginx, Apache, or WAF logs and POST normalized request features.
- Network: export NetFlow, Zeek, Suricata, or custom packet features and POST normalized flow features.
- The backend turns those into live alerts and broadcasts them to the dashboard WebSocket clients.

## Cloud deployment notes for models

If you deploy the model separately in cloud, keep these responsibilities split:

- model service: ONNX inference only
- SOC backend: authentication, alert lifecycle, forensics, escalation, reporting
- frontend: analyst workflow and visualization

For production, use:

- HTTPS for the model API
- API keys or service-to-service auth between backend and model service
- versioned model endpoints such as `/v1/predict`
- structured responses containing at least `attack_type`, `confidence`, and optional class scores

## Production deployment

### Docker Compose

From the repository root:

```bash
docker compose up --build
```

Default exposed ports:

- Frontend: `http://localhost:8080`
- Backend: `http://localhost:8000`

### Production notes

- Build the frontend with the final public backend URLs using `VITE_API_BASE_URL` and `VITE_WS_BASE_URL`.
- Set `ALLOWED_ORIGINS` on the backend to the exact frontend domains you trust.
- Run the backend behind a process manager and terminate TLS at an ingress or reverse proxy.
- Store secrets and operational credentials outside the repository.

### Netlify frontend deployment

This project can be deployed to Netlify for the frontend only.

Important:

- Netlify is a good fit for the React frontend in `frontend`.
- The FastAPI backend in `backend` should be deployed separately on a backend host such as Render, Railway, Fly.io, an EC2/VM, or a container platform.
- After backend deployment, point Netlify to that backend with environment variables.

Netlify configuration is already included in [netlify.toml](/D:/IDPSProject/netlify.toml):

- base directory: `frontend`
- build command: `npm run build`
- publish directory: `dist`
- Netlify install compatibility: `NPM_FLAGS=--legacy-peer-deps`

Required Netlify environment variables:

- `VITE_API_BASE_URL=https://your-backend-domain`
- `VITE_WS_BASE_URL=wss://your-backend-domain`

If authentication is failing on a Netlify-hosted frontend, the usual cause is one of these:

- the FastAPI backend is not deployed separately
- `VITE_API_BASE_URL` and `VITE_WS_BASE_URL` are missing in Netlify
- `ALLOWED_ORIGINS` on the backend does not include the Netlify site
- no database connection string is set on the backend, so you are not using the hosted database

Recommended Netlify deployment flow:

1. Open [Netlify app import](https://app.netlify.com/start).
2. Import the GitHub repo: [HIDPS](https://github.com/HARSHA2396/HIDPS).
3. Confirm build settings from `netlify.toml`.
4. Add `VITE_API_BASE_URL` and `VITE_WS_BASE_URL`.
5. Deploy the site.

If you want a one-click template-style flow later, you can also add a Deploy to Netlify button in this README.

### Render backend deployment

This repository now includes a Render blueprint in [render.yaml](/D:/IDPSProject/render.yaml) for the FastAPI backend.

Recommended deployment flow:

1. Open [Render Dashboard](https://dashboard.render.com/).
2. Create a new Blueprint instance from [HIDPS](https://github.com/HARSHA2396/HIDPS).
3. Render will detect [render.yaml](/D:/IDPSProject/render.yaml) and provision the backend service from `backend`.
4. Set these required environment variables in Render:

```env
ALLOWED_ORIGINS=https://soc-dashbaord.netlify.app
```

Add one database variable in Render:

```env
DATABASE_URL=postgresql://username:password@host/database?sslmode=require
```

or reuse your existing Netlify DB variables directly:

```env
NETLIFY_DATABASE_URL_UNPOOLED=postgresql://username:password@host/database?sslmode=require
```

Render service details:

- runtime: Python
- root directory: `backend`
- build command: `pip install -r requirements.txt`
- start command: `uvicorn main:app --host 0.0.0.0 --port $PORT`
- health check: `/api/health`

After Render gives you a backend URL such as:

```text
https://hidps-backend.onrender.com
```

set these on Netlify and redeploy the frontend:

```env
VITE_API_BASE_URL=https://hidps-backend.onrender.com
VITE_WS_BASE_URL=wss://hidps-backend.onrender.com
```

At that point the live Netlify site should be able to:

- log in against the FastAPI backend
- persist users and sessions in Neon PostgreSQL
- connect to the authenticated WebSocket alert stream

## Validation

Frontend validation used during development:

```bash
cd frontend
npm run lint
.\node_modules\.bin\tsc.cmd -b
```
