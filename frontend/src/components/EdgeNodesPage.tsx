import { useEffect, useState } from 'react';
import { CheckCircle2, Cpu, ShieldAlert, TimerReset } from 'lucide-react';
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import { apiFetch } from '../lib/api';
import { formatRelativeTime, getEdgeNodeSnapshots } from '../lib/insights';
import type { AlertData, ConnectionState, TelemetrySourceStatus } from '../types';

interface EdgeNodesPageProps {
  alerts: AlertData[];
  connectionState: ConnectionState;
}

export function EdgeNodesPage({ alerts, connectionState }: EdgeNodesPageProps) {
  const [telemetrySources, setTelemetrySources] = useState<TelemetrySourceStatus[]>([]);
  const nodes = getEdgeNodeSnapshots(alerts);

  useEffect(() => {
    let ignore = false;

    const loadTelemetry = async () => {
      try {
        const response = await apiFetch('/api/telemetry/sources');
        if (!response.ok) {
          throw new Error('Telemetry source service unavailable.');
        }
        const data = (await response.json()) as TelemetrySourceStatus[];
        if (!ignore) {
          setTelemetrySources(data);
        }
      } catch {
        if (!ignore) {
          setTelemetrySources([]);
        }
      }
    };

    void loadTelemetry();

    return () => {
      ignore = true;
    };
  }, []);

  return (
    <main className="flex-1 space-y-4 overflow-auto p-4">
      <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:col-span-8">
          {nodes.map((node) => (
            <div key={node.nodeId} className="glass-panel rounded-xl border border-slate-800 bg-slate-900 p-4">
              <div className="flex items-start justify-between">
                <div>
                  <p className="text-sm font-semibold text-white">{node.nodeId}</p>
                  <p className="text-xs text-slate-500">Last seen {formatRelativeTime(node.lastSeen)}</p>
                </div>
                <span
                  className={`rounded-full px-2 py-1 text-xs font-semibold ${
                    node.status === 'Critical'
                      ? 'bg-red-500/10 text-red-300'
                      : node.status === 'Monitoring'
                        ? 'bg-amber-500/10 text-amber-300'
                        : 'bg-emerald-500/10 text-emerald-300'
                  }`}
                >
                  {node.status}
                </span>
              </div>

              <div className="mt-4 grid grid-cols-2 gap-3">
                <div className="rounded-lg border border-slate-800 bg-slate-950 p-3">
                  <p className="text-[10px] uppercase tracking-wider text-slate-500">Alerts Processed</p>
                  <p className="mt-2 text-2xl font-bold text-white">{node.totalAlerts}</p>
                </div>
                <div className="rounded-lg border border-slate-800 bg-slate-950 p-3">
                  <p className="text-[10px] uppercase tracking-wider text-slate-500">Critical / High</p>
                  <p className="mt-2 text-2xl font-bold text-red-300">{node.highRiskAlerts}</p>
                </div>
                <div className="rounded-lg border border-slate-800 bg-slate-950 p-3">
                  <p className="text-[10px] uppercase tracking-wider text-slate-500">Latency</p>
                  <p className="mt-2 text-2xl font-bold text-cyan-300">{node.latencyMs}ms</p>
                </div>
                <div className="rounded-lg border border-slate-800 bg-slate-950 p-3">
                  <p className="text-[10px] uppercase tracking-wider text-slate-500">Avg Confidence</p>
                  <p className="mt-2 text-2xl font-bold text-white">{(node.averageConfidence * 100).toFixed(1)}%</p>
                </div>
              </div>

              <div className="mt-4 flex items-center justify-between text-xs text-slate-400">
                <span>Sync {node.syncState}</span>
                <span>Throughput {node.throughputMbps.toFixed(1)} Mbps</span>
              </div>
            </div>
          ))}
        </div>

        <div className="glass-panel rounded-xl border border-slate-800 bg-slate-900 p-4 xl:col-span-4">
          <div className="mb-4">
            <h2 className="text-lg font-bold tracking-wide text-white">Node Operations</h2>
            <p className="text-xs uppercase tracking-wider text-slate-400">Deployment posture summary</p>
          </div>
          <div className="space-y-3">
            <div className="rounded-lg border border-slate-800 bg-slate-950 p-3">
              <div className="flex items-center justify-between">
                <span className="text-xs uppercase tracking-wider text-slate-500">Control Plane</span>
                <span className="text-sm font-semibold text-white">{connectionState}</span>
              </div>
            </div>
            <div className="rounded-lg border border-slate-800 bg-slate-950 p-3">
              <div className="flex items-center gap-2">
                <Cpu className="h-4 w-4 text-cyan-400" />
                <span className="text-sm font-semibold text-white">GAN + BiLSTM v3.0.0</span>
              </div>
              <p className="mt-2 text-xs text-slate-400">
                Nodes now enrich detections with ATT&CK, zero-trust, and case-correlation signals.
              </p>
            </div>
            <div className="rounded-lg border border-slate-800 bg-slate-950 p-3">
              <div className="flex items-center gap-2">
                <CheckCircle2 className="h-4 w-4 text-emerald-400" />
                <span className="text-sm font-semibold text-white">Deployment integrity</span>
              </div>
              <p className="mt-2 text-xs text-slate-400">
                Node images are aligned, signatures synced, and approval-safe playbooks are armed.
              </p>
            </div>
            <div className="rounded-lg border border-slate-800 bg-slate-950 p-3">
              <div className="flex items-center gap-2">
                <ShieldAlert className="h-4 w-4 text-red-400" />
                <span className="text-sm font-semibold text-white">Containment threshold</span>
              </div>
              <p className="mt-2 text-xs text-slate-400">
                Automatic response is gated when crown-jewel assets or critical alerts are involved.
              </p>
            </div>
            <div className="rounded-lg border border-slate-800 bg-slate-950 p-3">
              <div className="flex items-center gap-2">
                <TimerReset className="h-4 w-4 text-amber-400" />
                <span className="text-sm font-semibold text-white">Retraining cadence</span>
              </div>
              <p className="mt-2 text-xs text-slate-400">
                Cloud sync pushes updated weights and suppression context on the next rollout window.
              </p>
            </div>
          </div>
        </div>
      </section>

      <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <div className="glass-panel rounded-xl border border-slate-800 bg-slate-900 p-4 xl:col-span-7">
          <div className="mb-4">
            <h2 className="text-lg font-bold tracking-wide text-white">Node Throughput and Risk</h2>
            <p className="text-xs uppercase tracking-wider text-slate-400">
              Edge appliance load across the detection mesh
            </p>
          </div>
          <div className="h-80">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={nodes} margin={{ top: 0, right: 16, left: 0, bottom: 8 }}>
                <CartesianGrid stroke="#1e293b" vertical={false} />
                <XAxis dataKey="nodeId" stroke="#64748b" fontSize={10} tickLine={false} />
                <YAxis stroke="#64748b" fontSize={10} tickLine={false} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#0f172a', borderColor: '#1e293b' }}
                  labelStyle={{ color: '#94a3b8' }}
                />
                <Bar dataKey="throughputMbps" fill="#06b6d4" radius={[8, 8, 0, 0]} />
                <Bar dataKey="highRiskAlerts" fill="#ef4444" radius={[8, 8, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="glass-panel rounded-xl border border-slate-800 bg-slate-900 p-4 xl:col-span-5">
          <div className="mb-4">
            <h2 className="text-lg font-bold tracking-wide text-white">Telemetry Sources</h2>
            <p className="text-xs uppercase tracking-wider text-slate-400">
              Multi-source ingestion health and coverage
            </p>
          </div>
          <div className="space-y-3">
            {telemetrySources.map((source) => (
              <div key={source.source_id} className="rounded-lg border border-slate-800 bg-slate-950 p-3">
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <p className="text-sm font-semibold text-white">{source.source_id}</p>
                    <p className="text-xs text-slate-500">
                      {source.kind} | Last seen {formatRelativeTime(source.last_seen)}
                    </p>
                  </div>
                  <span
                    className={`rounded-full px-2 py-1 text-xs font-semibold ${
                      source.status === 'Online'
                        ? 'bg-emerald-500/10 text-emerald-300'
                        : source.status === 'Monitoring'
                          ? 'bg-amber-500/10 text-amber-300'
                          : 'bg-orange-500/10 text-orange-300'
                    }`}
                  >
                    {source.status}
                  </span>
                </div>
                <p className="mt-2 text-xs text-slate-400">{source.coverage}</p>
                <p className="mt-2 text-xs text-cyan-300">{source.records_seen} records observed</p>
                <p className="mt-2 text-xs text-slate-500">{source.notes}</p>
              </div>
            ))}
          </div>
        </div>
      </section>
    </main>
  );
}
