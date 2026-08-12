import { useEffect, useMemo, useState } from 'react';
import {
  BellRing,
  Bot,
  CheckCircle2,
  Cpu,
  Network,
  ShieldAlert,
  ShieldCheck,
} from 'lucide-react';
import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from 'recharts';
import { apiFetch } from '../lib/api';
import {
  formatRelativeTime,
  getSeverityMix,
  getSeverityTone,
  getThreatFamilies,
  sortAlertsNewest,
} from '../lib/insights';
import { GlobalMap } from './GlobalMap';
import type {
  AlertData,
  CorrelationCase,
  ModelStatus,
  PendingAction,
  TelemetrySourceStatus,
} from '../types';

interface DashboardPageProps {
  alerts: AlertData[];
}

type ChartMode = 'types' | 'severity';
type QueueSort = 'severity' | 'newest';

const typeColors = ['#ff5d73', '#ffc24b', '#89d229', '#44b8ff', '#7e79ff', '#f98d3b'];
const severityColors = ['#ff5d73', '#ff8f4d', '#ffc24b', '#89d229'];

function formatPercent(value: number) {
  return `${(value * 100).toFixed(0)}%`;
}

function severityRank(severity: AlertData['severity']) {
  switch (severity) {
    case 'Critical':
      return 4;
    case 'High':
      return 3;
    case 'Medium':
      return 2;
    default:
      return 1;
  }
}

export function DashboardPage({ alerts }: DashboardPageProps) {
  const [telemetrySources, setTelemetrySources] = useState<TelemetrySourceStatus[]>([]);
  const [pendingActions, setPendingActions] = useState<PendingAction[]>([]);
  const [cases, setCases] = useState<CorrelationCase[]>([]);
  const [modelStatus, setModelStatus] = useState<ModelStatus | null>(null);
  const [chartMode, setChartMode] = useState<ChartMode>('types');
  const [queueSort, setQueueSort] = useState<QueueSort>('severity');

  useEffect(() => {
    let ignore = false;

    const loadOverview = async () => {
      try {
        const [telemetryResponse, pendingResponse, casesResponse, modelResponse] = await Promise.all([
          apiFetch('/api/telemetry/sources'),
          apiFetch('/api/action/pending'),
          apiFetch('/api/correlation/cases'),
          apiFetch('/api/model/status'),
        ]);
        if (!telemetryResponse.ok || !pendingResponse.ok || !casesResponse.ok || !modelResponse.ok) {
          throw new Error('Overview services unavailable.');
        }

        const [telemetryData, pendingData, casesData, modelData] = (await Promise.all([
          telemetryResponse.json(),
          pendingResponse.json(),
          casesResponse.json(),
          modelResponse.json(),
        ])) as [TelemetrySourceStatus[], PendingAction[], CorrelationCase[], ModelStatus];

        if (!ignore) {
          setTelemetrySources(telemetryData);
          setPendingActions(pendingData);
          setCases(casesData);
          setModelStatus(modelData);
        }
      } catch {
        if (!ignore) {
          setTelemetrySources([]);
          setPendingActions([]);
          setCases([]);
          setModelStatus(null);
        }
      }
    };

    void loadOverview();
    const intervalId = window.setInterval(() => {
      void loadOverview();
    }, 15_000);

    return () => {
      ignore = true;
      window.clearInterval(intervalId);
    };
  }, [alerts.length]);

  const activeAlerts = alerts.filter((alert) => alert.status !== 'closed');
  const closedAlerts = alerts.filter((alert) => alert.status === 'closed');
  const truePositives = closedAlerts.filter((alert) => alert.disposition === 'true_positive');
  const falsePositives = closedAlerts.filter((alert) => alert.disposition === 'false_positive');
  const latestAlerts = sortAlertsNewest(activeAlerts);
  const topThreat = latestAlerts[0]?.attack_type || 'Live intrusion monitoring';

  const chartData = useMemo(() => {
    const base = chartMode === 'types' ? getThreatFamilies(activeAlerts) : getSeverityMix(activeAlerts);
    const palette = chartMode === 'types' ? typeColors : severityColors;
    return base
      .filter((item) => item.value > 0)
      .map((item, index) => ({ ...item, color: palette[index % palette.length] }));
  }, [activeAlerts, chartMode]);

  const openAlertRows = useMemo(() => {
    const sorted = [...activeAlerts].sort((left, right) => {
      if (queueSort === 'severity') {
        return severityRank(right.severity) - severityRank(left.severity) || right.timestamp - left.timestamp;
      }
      return right.timestamp - left.timestamp;
    });
    return sorted.slice(0, 6);
  }, [activeAlerts, queueSort]);

  const averageConfidence =
    alerts.length === 0 ? 0 : alerts.reduce((sum, alert) => sum + alert.confidence, 0) / alerts.length;

  const summaryCards = [
    {
      label: 'Total alerts',
      value: alerts.length,
      sublabel: 'captured in this run',
      icon: BellRing,
    },
    {
      label: 'Closed alerts',
      value: closedAlerts.length,
      sublabel: 'completed by the team',
      icon: CheckCircle2,
    },
    {
      label: 'Closed as TP',
      value: truePositives.length,
      sublabel: 'confirmed malicious',
      icon: ShieldAlert,
    },
    {
      label: 'Closed as FP',
      value: falsePositives.length,
      sublabel: 'suppressed after review',
      icon: ShieldCheck,
    },
  ];

  return (
    <main className="flex-1 overflow-auto px-4 py-5 md:px-6 lg:px-8">
      <div className="mx-auto flex w-full max-w-[1480px] flex-col gap-4">
        <section className="overflow-hidden rounded-[24px] border border-white/6 bg-[#1c2943]">
          <div className="flex flex-col gap-6 px-6 py-6 lg:flex-row lg:items-start lg:justify-between">
            <div className="flex gap-4">
              <div className="flex h-14 w-14 shrink-0 items-center justify-center rounded-full border border-[#8fd11f]/18 bg-[#2a1830] text-xl">
                <span role="img" aria-label="scenario">
                  {'\u{1F6E1}'}
                </span>
              </div>
              <div>
                <h1 className="text-[28px] font-semibold leading-tight text-white">{topThreat}</h1>
                <p className="mt-2 max-w-3xl text-sm leading-7 text-slate-300">
                  Follow live detections as they move from model scoring into analyst review,
                  threat validation, containment approval, and case reporting inside one SOC workflow.
                </p>
              </div>
            </div>

            <div className="flex flex-col gap-3">
              <div className="rounded-xl border border-[#8fd11f]/20 bg-[#8fd11f]/10 px-4 py-2 text-sm font-semibold text-[#c6f36d]">
                Runtime {modelStatus?.enabled ? modelStatus.runtime.toUpperCase() : 'OFFLINE'}
              </div>
              <div className="rounded-xl border border-white/6 bg-[#121d33] px-4 py-3 text-sm text-slate-300">
                <p>Telemetry sources: {telemetrySources.length || 0}</p>
                <p className="mt-1">
                  Prevention: {modelStatus?.auto_response_enabled ? 'automatic' : 'analyst gated'}
                </p>
              </div>
            </div>
          </div>

          <div className="border-t border-white/6 bg-[#1a2640] px-6 py-4 text-sm text-[#9ddb24]">
            Scenario details
          </div>
        </section>

        <section className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
          {summaryCards.map((card) => (
            <div key={card.label} className="rounded-[20px] border border-white/6 bg-[#1c2943] p-5">
              <div className="flex items-center gap-3 text-[#9ddb24]">
                <card.icon className="h-5 w-5" />
                <p className="text-xl font-semibold text-white">{card.label}</p>
              </div>
              <p className="mt-2 text-sm text-slate-400">{card.sublabel}</p>
              <p className="mt-8 text-5xl font-semibold text-white">
                {card.value}
                <span className="ml-2 text-2xl font-medium text-slate-300">
                  {card.label === 'Total alerts' || card.label === 'Closed alerts' ? 'alerts' : ''}
                </span>
              </p>
            </div>
          ))}
        </section>

        <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
          <div className="rounded-[20px] border border-white/6 bg-[#1c2943] p-5 xl:col-span-6">
            <div className="mb-5 flex items-center justify-between gap-4">
              <h2 className="text-[18px] font-semibold text-white">Alert insights</h2>
              <div className="overflow-hidden rounded-lg border border-[#8fd11f]/25">
                <button
                  onClick={() => setChartMode('types')}
                  className={`px-4 py-2 text-sm font-medium transition ${
                    chartMode === 'types'
                      ? 'bg-[#8fd11f] text-[#152033]'
                      : 'bg-transparent text-slate-300'
                  }`}
                >
                  Alert types
                </button>
                <button
                  onClick={() => setChartMode('severity')}
                  className={`px-4 py-2 text-sm font-medium transition ${
                    chartMode === 'severity'
                      ? 'bg-[#8fd11f] text-[#152033]'
                      : 'bg-transparent text-slate-300'
                  }`}
                >
                  Alert severity
                </button>
              </div>
            </div>

            <div className="grid gap-4 lg:grid-cols-[1.05fr_0.95fr]">
              <div className="h-[320px]">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={chartData}
                      dataKey="value"
                      nameKey="label"
                      innerRadius={84}
                      outerRadius={118}
                      paddingAngle={2}
                    >
                      {chartData.map((entry) => (
                        <Cell key={entry.label} fill={entry.color} />
                      ))}
                    </Pie>
                    <Tooltip
                      contentStyle={{
                        backgroundColor: '#121d33',
                        borderColor: 'rgba(255,255,255,0.08)',
                        color: '#e5edf8',
                      }}
                    />
                  </PieChart>
                </ResponsiveContainer>
              </div>

              <div className="flex flex-col justify-center gap-3">
                <div className="rounded-2xl border border-white/6 bg-[#121d33] px-5 py-6 text-center">
                  <p className="text-5xl font-semibold text-white">{activeAlerts.length}</p>
                  <p className="mt-2 text-lg text-slate-300">Active alerts</p>
                </div>

                {chartData.map((item) => (
                  <div key={item.label} className="rounded-xl border border-white/6 bg-[#121d33] p-3">
                    <div className="flex items-center justify-between gap-3">
                      <div className="flex items-center gap-3">
                        <span
                          className="h-3 w-3 rounded-full"
                          style={{ backgroundColor: item.color }}
                        />
                        <span className="text-sm font-medium text-slate-200">{item.label}</span>
                      </div>
                      <span className="text-sm font-semibold text-white">{item.value}</span>
                    </div>
                  </div>
                ))}

                {chartData.length === 0 && (
                  <div className="rounded-xl border border-white/6 bg-[#121d33] p-4 text-sm text-slate-400">
                    Waiting for enough alerts to build chart slices.
                  </div>
                )}
              </div>
            </div>
          </div>

          <div className="rounded-[20px] border border-white/6 bg-[#1c2943] p-5 xl:col-span-6">
            <div className="mb-5 flex items-center justify-between gap-4">
              <div>
                <h2 className="text-[18px] font-semibold text-white">Open alerts</h2>
                <p className="mt-2 text-sm text-slate-400">
                  Access the alert queue to monitor new alerts as they arrive.
                </p>
              </div>
              <label className="flex items-center gap-2 text-sm text-slate-300">
                <span>Sort by</span>
                <select
                  value={queueSort}
                  onChange={(event) => setQueueSort(event.target.value as QueueSort)}
                  className="rounded-lg border border-white/8 bg-[#121d33] px-3 py-2 text-sm text-white outline-none"
                >
                  <option value="severity">Severity</option>
                  <option value="newest">Newest</option>
                </select>
              </label>
            </div>

            <div className="space-y-2">
              {openAlertRows.map((alert) => (
                <div
                  key={alert.id}
                  className="grid grid-cols-[72px_minmax(0,1fr)_100px_110px] items-center gap-4 rounded-xl bg-[#18243c] px-4 py-4"
                >
                  <p className="text-sm font-medium text-slate-300">{alert.id}</p>
                  <div className="min-w-0">
                    <p className="truncate text-sm font-semibold text-white">{alert.attack_type}</p>
                    <p className="mt-1 truncate text-xs text-slate-500">
                      {alert.asset_name} | {alert.source_ip}
                    </p>
                  </div>
                  <span className={`inline-flex justify-center rounded-full border px-2 py-1 text-xs font-semibold ${getSeverityTone(alert.severity)}`}>
                    {alert.severity}
                  </span>
                  <p className="text-sm text-slate-300">{alert.source_type}</p>
                </div>
              ))}

              {openAlertRows.length === 0 && (
                <div className="rounded-xl border border-white/6 bg-[#121d33] p-4 text-sm text-slate-400">
                  No open alerts yet. Start the simulation or post to `/api/model/evaluate`.
                </div>
              )}
            </div>
          </div>
        </section>

        <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
          <div className="rounded-[20px] border border-white/6 bg-[#1c2943] p-5 xl:col-span-4">
            <div className="mb-4 flex items-center gap-2">
              <Bot className="h-4 w-4 text-[#c6f36d]" />
              <h2 className="text-[18px] font-semibold text-white">Model runtime</h2>
            </div>
            {modelStatus ? (
              <div className="space-y-3">
                <div className="rounded-xl border border-white/6 bg-[#121d33] p-4">
                  <p className="text-xs uppercase tracking-[0.18em] text-slate-500">State</p>
                  <p className="mt-2 text-lg font-semibold text-white">
                    {modelStatus.enabled ? `${modelStatus.runtime.toUpperCase()} active` : 'Disabled'}
                  </p>
                </div>
                <div className="grid grid-cols-2 gap-3">
                  <div className="rounded-xl border border-white/6 bg-[#121d33] p-4">
                    <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Alert threshold</p>
                    <p className="mt-2 text-lg font-semibold text-white">
                      {modelStatus.alert_threshold.toFixed(2)}
                    </p>
                  </div>
                  <div className="rounded-xl border border-white/6 bg-[#121d33] p-4">
                    <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Average confidence</p>
                    <p className="mt-2 text-lg font-semibold text-white">
                      {formatPercent(averageConfidence)}
                    </p>
                  </div>
                </div>
                <div className="rounded-xl border border-white/6 bg-[#121d33] p-4 text-sm text-slate-300">
                  Labels:{' '}
                  {modelStatus.labels.length > 0 ? modelStatus.labels.join(', ') : 'not configured'}
                </div>
              </div>
            ) : (
              <div className="rounded-xl border border-white/6 bg-[#121d33] p-4 text-sm text-slate-400">
                Model status is unavailable right now.
              </div>
            )}
          </div>

          <div className="rounded-[20px] border border-white/6 bg-[#1c2943] p-5 xl:col-span-4">
            <div className="mb-4 flex items-center gap-2">
              <Cpu className="h-4 w-4 text-[#c6f36d]" />
              <h2 className="text-[18px] font-semibold text-white">Response queue</h2>
            </div>
            <div className="space-y-3">
              {pendingActions.slice(0, 4).map((action) => (
                <div key={action.action_id} className="rounded-xl border border-white/6 bg-[#121d33] p-4">
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <p className="text-sm font-semibold text-white">{action.action_type}</p>
                      <p className="mt-1 text-xs text-slate-500">
                        {action.target_ip} | {action.requested_by}
                      </p>
                    </div>
                    <span className="rounded-full border border-amber-500/20 bg-amber-500/10 px-2 py-1 text-xs font-semibold text-amber-200">
                      {action.status}
                    </span>
                  </div>
                  <p className="mt-3 text-sm text-slate-300">{action.recommended_playbook}</p>
                </div>
              ))}
              {pendingActions.length === 0 && (
                <div className="rounded-xl border border-white/6 bg-[#121d33] p-4 text-sm text-slate-400">
                  No mitigation approvals are waiting right now.
                </div>
              )}
            </div>
          </div>

          <div className="rounded-[20px] border border-white/6 bg-[#1c2943] p-5 xl:col-span-4">
            <div className="mb-4 flex items-center gap-2">
              <Network className="h-4 w-4 text-[#c6f36d]" />
              <h2 className="text-[18px] font-semibold text-white">Telemetry and cases</h2>
            </div>
            <div className="space-y-3">
              {telemetrySources.slice(0, 2).map((source) => (
                <div key={source.source_id} className="rounded-xl border border-white/6 bg-[#121d33] p-4">
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <p className="text-sm font-semibold text-white">{source.source_id}</p>
                      <p className="mt-1 text-xs text-slate-500">{source.kind}</p>
                    </div>
                    <span className="rounded-full border border-[#8fd11f]/20 bg-[#8fd11f]/10 px-2 py-1 text-xs font-semibold text-[#c6f36d]">
                      {source.status}
                    </span>
                  </div>
                  <p className="mt-3 text-sm text-slate-300">{source.coverage}</p>
                  <p className="mt-2 text-xs text-slate-500">
                    Last seen {formatRelativeTime(source.last_seen)}
                  </p>
                </div>
              ))}

              {cases.slice(0, 2).map((item) => (
                <div key={item.case_id} className="rounded-xl border border-white/6 bg-[#121d33] p-4">
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <p className="text-sm font-semibold text-white">{item.title}</p>
                      <p className="mt-2 text-sm text-slate-300">{item.summary}</p>
                    </div>
                    <span className="rounded-full border border-fuchsia-500/20 bg-fuchsia-500/10 px-2 py-1 text-xs font-semibold text-fuchsia-200">
                      {formatPercent(item.risk_score)}
                    </span>
                  </div>
                </div>
              ))}

              {telemetrySources.length === 0 && cases.length === 0 && (
                <div className="rounded-xl border border-white/6 bg-[#121d33] p-4 text-sm text-slate-400">
                  Collector health and correlation cases will appear here once live detections build up.
                </div>
              )}
            </div>
          </div>
        </section>

        <section>
          <GlobalMap alerts={alerts.slice(0, 24)} />
        </section>
      </div>
    </main>
  );
}
