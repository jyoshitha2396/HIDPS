import { useEffect, useState } from 'react';
import { AlertTriangle, Fingerprint, Gauge, ShieldCheck } from 'lucide-react';
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { apiFetch } from '../lib/api';
import {
  getAverageConfidence,
  getHourlySeries,
  getSeverityMix,
  getTopSourceIps,
  getUniqueSourceCount,
} from '../lib/insights';
import type { AlertData, BenchmarkMetrics } from '../types';

interface FullAnalyticsPageProps {
  alerts: AlertData[];
}

const severityColors = ['#ef4444', '#f97316', '#eab308', '#10b981'];

export function FullAnalyticsPage({ alerts }: FullAnalyticsPageProps) {
  const [metrics, setMetrics] = useState<BenchmarkMetrics | null>(null);
  const severityMix = getSeverityMix(alerts);
  const hourlySeries = getHourlySeries(alerts);
  const topIps = getTopSourceIps(alerts);
  const averageConfidence = getAverageConfidence(alerts);
  const uniqueSources = getUniqueSourceCount(alerts);
  const criticalRatio =
    alerts.length === 0
      ? 0
      : alerts.filter((alert) => alert.severity === 'Critical').length / alerts.length;

  useEffect(() => {
    let ignore = false;

    const loadMetrics = async () => {
      try {
        const response = await apiFetch('/api/metrics/benchmark');
        if (!response.ok) {
          throw new Error('Benchmark metrics unavailable.');
        }
        const data = (await response.json()) as BenchmarkMetrics;
        if (!ignore) {
          setMetrics(data);
        }
      } catch {
        if (!ignore) {
          setMetrics(null);
        }
      }
    };

    void loadMetrics();

    return () => {
      ignore = true;
    };
  }, []);

  return (
    <main className="flex-1 space-y-4 overflow-auto p-4">
      <section className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
        <div className="glass-panel rounded-xl border border-slate-800 bg-slate-900 p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-xs uppercase tracking-wider text-slate-500">Alert Volume</p>
              <p className="mt-2 text-3xl font-bold text-white">{alerts.length}</p>
            </div>
            <Gauge className="h-6 w-6 text-cyan-400" />
          </div>
        </div>
        <div className="glass-panel rounded-xl border border-slate-800 bg-slate-900 p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-xs uppercase tracking-wider text-slate-500">Critical Ratio</p>
              <p className="mt-2 text-3xl font-bold text-white">{(criticalRatio * 100).toFixed(1)}%</p>
            </div>
            <AlertTriangle className="h-6 w-6 text-red-400" />
          </div>
        </div>
        <div className="glass-panel rounded-xl border border-slate-800 bg-slate-900 p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-xs uppercase tracking-wider text-slate-500">Avg Confidence</p>
              <p className="mt-2 text-3xl font-bold text-white">{(averageConfidence * 100).toFixed(1)}%</p>
            </div>
            <ShieldCheck className="h-6 w-6 text-emerald-400" />
          </div>
        </div>
        <div className="glass-panel rounded-xl border border-slate-800 bg-slate-900 p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-xs uppercase tracking-wider text-slate-500">Unique Sources</p>
              <p className="mt-2 text-3xl font-bold text-white">{uniqueSources}</p>
            </div>
            <Fingerprint className="h-6 w-6 text-fuchsia-400" />
          </div>
        </div>
      </section>

      <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <div className="glass-panel rounded-xl border border-slate-800 bg-slate-900 p-4 xl:col-span-7">
          <div className="mb-4">
            <h2 className="text-lg font-bold tracking-wide text-white">Severity Trendline</h2>
            <p className="text-xs uppercase tracking-wider text-slate-400">
              Detection volume over the live telemetry window
            </p>
          </div>
          <div className="h-80">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={hourlySeries} margin={{ top: 0, right: 16, left: 0, bottom: 8 }}>
                <defs>
                  <linearGradient id="analytics-total" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.35} />
                    <stop offset="95%" stopColor="#06b6d4" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="analytics-critical" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#ef4444" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid stroke="#1e293b" vertical={false} />
                <XAxis dataKey="time" stroke="#64748b" fontSize={10} tickLine={false} />
                <YAxis stroke="#64748b" fontSize={10} tickLine={false} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#0f172a', borderColor: '#1e293b' }}
                  labelStyle={{ color: '#94a3b8' }}
                />
                <Area type="monotone" dataKey="total" stroke="#06b6d4" fill="url(#analytics-total)" strokeWidth={2} />
                <Area
                  type="monotone"
                  dataKey="critical"
                  stroke="#ef4444"
                  fill="url(#analytics-critical)"
                  strokeWidth={2}
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="glass-panel rounded-xl border border-slate-800 bg-slate-900 p-4 xl:col-span-5">
          <div className="mb-4">
            <h2 className="text-lg font-bold tracking-wide text-white">Severity Mix</h2>
            <p className="text-xs uppercase tracking-wider text-slate-400">
              Current distribution across the incident queue
            </p>
          </div>
          <div className="h-80">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie data={severityMix} dataKey="value" nameKey="label" innerRadius={64} outerRadius={98}>
                  {severityMix.map((entry, index) => (
                    <Cell key={entry.label} fill={severityColors[index % severityColors.length]} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{ backgroundColor: '#0f172a', borderColor: '#1e293b' }}
                  labelStyle={{ color: '#94a3b8' }}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>
      </section>

      <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <div className="glass-panel rounded-xl border border-slate-800 bg-slate-900 p-4 xl:col-span-7">
          <div className="mb-4">
            <h2 className="text-lg font-bold tracking-wide text-white">Top Source IPs</h2>
            <p className="text-xs uppercase tracking-wider text-slate-400">
              Repeated offenders across the current telemetry set
            </p>
          </div>
          <div className="h-72">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={topIps} layout="vertical" margin={{ top: 0, right: 16, left: 20, bottom: 8 }}>
                <CartesianGrid stroke="#1e293b" horizontal={false} />
                <XAxis type="number" stroke="#64748b" fontSize={10} tickLine={false} />
                <YAxis dataKey="label" type="category" width={120} stroke="#64748b" fontSize={10} tickLine={false} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#0f172a', borderColor: '#1e293b' }}
                  labelStyle={{ color: '#94a3b8' }}
                />
                <Bar dataKey="value" fill="#a855f7" radius={[0, 8, 8, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="glass-panel rounded-xl border border-slate-800 bg-slate-900 p-4 xl:col-span-5">
          <div className="mb-4">
            <h2 className="text-lg font-bold tracking-wide text-white">Benchmark Scorecard</h2>
            <p className="text-xs uppercase tracking-wider text-slate-400">
              Detection quality and response performance
            </p>
          </div>
          <div className="grid grid-cols-2 gap-3 text-sm text-slate-300">
            <div className="rounded-lg border border-slate-800 bg-slate-950 p-3">
              <p className="text-xs uppercase tracking-wider text-slate-500">Precision</p>
              <p className="mt-2 text-2xl font-bold text-white">
                {metrics ? `${(metrics.precision * 100).toFixed(1)}%` : '--'}
              </p>
            </div>
            <div className="rounded-lg border border-slate-800 bg-slate-950 p-3">
              <p className="text-xs uppercase tracking-wider text-slate-500">Recall</p>
              <p className="mt-2 text-2xl font-bold text-white">
                {metrics ? `${(metrics.recall * 100).toFixed(1)}%` : '--'}
              </p>
            </div>
            <div className="rounded-lg border border-slate-800 bg-slate-950 p-3">
              <p className="text-xs uppercase tracking-wider text-slate-500">False Positive Rate</p>
              <p className="mt-2 text-2xl font-bold text-white">
                {metrics ? `${(metrics.false_positive_rate * 100).toFixed(1)}%` : '--'}
              </p>
            </div>
            <div className="rounded-lg border border-slate-800 bg-slate-950 p-3">
              <p className="text-xs uppercase tracking-wider text-slate-500">F1 Score</p>
              <p className="mt-2 text-2xl font-bold text-white">
                {metrics ? metrics.f1_score.toFixed(3) : '--'}
              </p>
            </div>
            <div className="rounded-lg border border-slate-800 bg-slate-950 p-3">
              <p className="text-xs uppercase tracking-wider text-slate-500">MTTD</p>
              <p className="mt-2 text-2xl font-bold text-white">
                {metrics ? `${metrics.mttd_seconds.toFixed(0)}s` : '--'}
              </p>
            </div>
            <div className="rounded-lg border border-slate-800 bg-slate-950 p-3">
              <p className="text-xs uppercase tracking-wider text-slate-500">MTTR</p>
              <p className="mt-2 text-2xl font-bold text-white">
                {metrics ? `${metrics.mttr_seconds.toFixed(0)}s` : '--'}
              </p>
            </div>
          </div>
          <div className="mt-4 space-y-3 text-sm text-slate-300">
            <div className="rounded-lg border border-slate-800 bg-slate-950 p-3">
              Model latency is {metrics ? `${metrics.model_latency_ms.toFixed(1)} ms` : 'pending'} across the live telemetry mix.
            </div>
            <div className="rounded-lg border border-slate-800 bg-slate-950 p-3">
              ATT&CK coverage is {metrics ? `${(metrics.attack_coverage_ratio * 100).toFixed(0)}%` : 'pending'}, which helps explain how broad the current detection surface is.
            </div>
            <div className="rounded-lg border border-slate-800 bg-slate-950 p-3">
              Analyst verdicts directly tune the benchmark view by shifting precision and false-positive readings.
            </div>
          </div>
        </div>
      </section>
    </main>
  );
}
