import { useEffect, useState } from 'react';
import { Bot, CheckCheck, CloudCog, GlobeLock, PlugZap, Radar } from 'lucide-react';
import { API_BASE_URL, WS_BASE_URL } from '../lib/api';
import type { ConnectionState, ModelStatus } from '../types';

interface SettingsPageProps {
  connectionState: ConnectionState;
  simulationActive: boolean;
}

const checklist = [
  'Deploy the FastAPI backend separately from the Netlify frontend.',
  'Set VITE_API_BASE_URL and VITE_WS_BASE_URL on the frontend host before each production build.',
  'Expose /api/model/status so the dashboard can verify ONNX runtime, labels, and feature order.',
  'Use DATABASE_URL on the backend host only and keep frontend builds free of database credentials.',
  'Run monitored web events through /api/model/evaluate to generate alerts from live page activity.',
];

export function SettingsPage({ connectionState, simulationActive }: SettingsPageProps) {
  const [modelStatus, setModelStatus] = useState<ModelStatus | null>(null);

  useEffect(() => {
    let ignore = false;

    const loadStatus = async () => {
      try {
        const stored = globalThis.localStorage?.getItem('nexus-soc-auth-session');
        const token = stored ? JSON.parse(stored)?.token : '';
        const response = await fetch(`${API_BASE_URL}/api/model/status`, {
          headers: token ? { Authorization: `Bearer ${token}` } : {},
        });
        if (!response.ok) {
          throw new Error('Model status unavailable.');
        }
        const data = (await response.json()) as ModelStatus;
        if (!ignore) {
          setModelStatus(data);
        }
      } catch {
        if (!ignore) {
          setModelStatus(null);
        }
      }
    };

    void loadStatus();

    return () => {
      ignore = true;
    };
  }, []);

  return (
    <main className="flex-1 overflow-auto p-4 md:p-5 space-y-5">
      <section className="rounded-[28px] border border-white/6 bg-[radial-gradient(circle_at_top_left,rgba(34,211,238,0.12),transparent_34%),linear-gradient(180deg,rgba(15,23,42,0.98),rgba(8,15,28,0.98))] p-5">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <div className="inline-flex items-center gap-2 rounded-full border border-cyan-400/16 bg-cyan-400/10 px-4 py-2 text-[11px] font-semibold uppercase tracking-[0.22em] text-cyan-200">
              <Radar className="h-4 w-4" />
              Deployment Control Plane
            </div>
            <h1 className="mt-4 text-3xl font-semibold text-white">Runtime, model, and demo wiring</h1>
            <p className="mt-3 max-w-3xl text-sm leading-7 text-slate-300">
              Use this view to verify your public API endpoints, WebSocket stream, ONNX runtime
              readiness, and the exact integration path for monitored web events during the demo.
            </p>
          </div>
          <div className="rounded-2xl border border-white/6 bg-slate-950/70 px-4 py-3 text-sm text-slate-200">
            Control plane {connectionState} • Simulation {simulationActive ? 'active' : 'paused'}
          </div>
        </div>
      </section>

      <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <div className="space-y-4 xl:col-span-7">
          <div className="rounded-[26px] border border-white/6 bg-[linear-gradient(180deg,rgba(15,23,42,0.96),rgba(8,15,28,0.96))] p-5">
            <div className="mb-4">
              <h2 className="text-lg font-bold text-white tracking-wide">Runtime Configuration</h2>
              <p className="text-xs uppercase tracking-[0.18em] text-slate-500">
                Current public endpoints and operational state
              </p>
            </div>

            <div className="space-y-3">
              <div className="rounded-2xl border border-white/6 bg-slate-950/70 p-4">
                <div className="flex items-center gap-2">
                  <CloudCog className="h-4 w-4 text-cyan-300" />
                  <span className="text-sm font-semibold text-white">REST API</span>
                </div>
                <p className="mt-2 break-all font-mono text-sm text-slate-300">{API_BASE_URL}</p>
              </div>

              <div className="rounded-2xl border border-white/6 bg-slate-950/70 p-4">
                <div className="flex items-center gap-2">
                  <PlugZap className="h-4 w-4 text-fuchsia-300" />
                  <span className="text-sm font-semibold text-white">WebSocket Stream</span>
                </div>
                <p className="mt-2 break-all font-mono text-sm text-slate-300">{WS_BASE_URL}</p>
              </div>

              <div className="rounded-2xl border border-white/6 bg-slate-950/70 p-4">
                <div className="flex items-center gap-2">
                  <GlobeLock className="h-4 w-4 text-emerald-300" />
                  <span className="text-sm font-semibold text-white">Operational State</span>
                </div>
                <p className="mt-2 text-sm text-slate-300">
                  Dashboard connection is <span className="font-semibold">{connectionState}</span>.
                  Simulation is <span className="font-semibold">{simulationActive ? 'active' : 'paused'}</span>.
                </p>
              </div>
            </div>
          </div>

          <div className="rounded-[26px] border border-white/6 bg-[linear-gradient(180deg,rgba(15,23,42,0.96),rgba(8,15,28,0.96))] p-5">
            <div className="mb-4 flex items-center gap-2">
              <Bot className="h-4 w-4 text-cyan-300" />
              <div>
                <h2 className="text-lg font-bold text-white tracking-wide">Model Runtime</h2>
                <p className="text-xs uppercase tracking-[0.18em] text-slate-500">
                  ONNX deployment, feature order, and scoring thresholds
                </p>
              </div>
            </div>

            {modelStatus ? (
              <div className="grid gap-3 md:grid-cols-2">
                <div className="rounded-2xl border border-white/6 bg-slate-950/70 p-4">
                  <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Runtime</p>
                  <p className="mt-2 text-lg font-semibold text-white">
                    {modelStatus.enabled ? modelStatus.runtime.toUpperCase() : 'Disabled'}
                  </p>
                  <p className="mt-2 text-xs text-slate-400">
                    {modelStatus.error || 'Runtime ready for monitored-event scoring.'}
                  </p>
                </div>
                <div className="rounded-2xl border border-white/6 bg-slate-950/70 p-4">
                  <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Thresholds</p>
                  <p className="mt-2 text-sm font-semibold text-white">
                    Alert {modelStatus.alert_threshold.toFixed(2)} • Prevent{' '}
                    {modelStatus.prevent_threshold.toFixed(2)}
                  </p>
                  <p className="mt-2 text-xs text-slate-400">
                    Auto response {modelStatus.auto_response_enabled ? 'enabled' : 'analyst-gated'}.
                  </p>
                </div>
                <div className="rounded-2xl border border-white/6 bg-slate-950/70 p-4 md:col-span-2">
                  <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Feature Order</p>
                  <p className="mt-2 text-sm text-slate-300">
                    {modelStatus.feature_order.length > 0
                      ? modelStatus.feature_order.join(', ')
                      : 'Set MODEL_FEATURE_ORDER on the backend to match your exported ONNX input vector.'}
                  </p>
                </div>
                <div className="rounded-2xl border border-white/6 bg-slate-950/70 p-4 md:col-span-2">
                  <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Labels</p>
                  <p className="mt-2 text-sm text-slate-300">
                    {modelStatus.labels.length > 0
                      ? modelStatus.labels.join(', ')
                      : 'Set MODEL_LABELS so the backend can map scores to attack families.'}
                  </p>
                </div>
              </div>
            ) : (
              <div className="rounded-2xl border border-white/6 bg-slate-950/70 p-4 text-sm text-slate-400">
                Model status is not available from the backend yet.
              </div>
            )}
          </div>
        </div>

        <div className="space-y-4 xl:col-span-5">
          <div className="rounded-[26px] border border-white/6 bg-[linear-gradient(180deg,rgba(15,23,42,0.96),rgba(8,15,28,0.96))] p-5">
            <div className="mb-4">
              <h2 className="text-lg font-bold text-white tracking-wide">Production Readiness</h2>
              <p className="text-xs uppercase tracking-[0.18em] text-slate-500">
                Deployment checks before going live
              </p>
            </div>
            <div className="space-y-3">
              {checklist.map((item) => (
                <div key={item} className="flex gap-3 rounded-2xl border border-white/6 bg-slate-950/70 p-4">
                  <CheckCheck className="mt-0.5 h-4 w-4 shrink-0 text-cyan-300" />
                  <p className="text-sm text-slate-300">{item}</p>
                </div>
              ))}
            </div>
          </div>

          <div className="rounded-[26px] border border-white/6 bg-[linear-gradient(180deg,rgba(15,23,42,0.96),rgba(8,15,28,0.96))] p-5">
            <div className="mb-4">
              <h2 className="text-lg font-bold text-white tracking-wide">Demo Endpoint Flow</h2>
              <p className="text-xs uppercase tracking-[0.18em] text-slate-500">
                Use this from a monitored webpage or browser script
              </p>
            </div>
            <div className="rounded-2xl border border-white/6 bg-slate-950/70 p-4">
              <p className="text-xs uppercase tracking-[0.18em] text-slate-500">POST /api/model/evaluate</p>
              <pre className="mt-3 overflow-x-auto rounded-2xl bg-slate-950 p-4 text-xs text-slate-300">
{`{
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
}`}
              </pre>
            </div>
            <button
              onClick={() => {
                globalThis.location.hash = '#/demo-lab';
              }}
              className="mt-4 rounded-2xl border border-emerald-500/20 bg-emerald-500/10 px-4 py-3 text-sm font-semibold text-emerald-100 transition hover:bg-emerald-500/18"
            >
              Open hosted demo webpage
            </button>
          </div>
        </div>
      </section>
    </main>
  );
}
