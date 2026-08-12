import { useEffect, useState } from 'react';
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  CartesianGrid,
  PieChart,
  Pie,
  Cell,
} from 'recharts';
import { Activity, BrainCircuit, CheckCircle, Database, ShieldAlert, TrendingUp } from 'lucide-react';
import { apiFetch } from '../lib/api';
import type { AlertData, CloudIntel, DashboardStats } from '../types';

interface AnalyticsPanelProps {
  alerts: AlertData[];
}

interface TrendPoint {
  time: string;
  total: number;
  highRisk: number;
  ai: number;
}

interface AttackDistributionPoint {
  name: string;
  value: number;
  color: string;
}

const ATTACK_COLORS = ['#ef4444', '#f97316', '#a855f7', '#eab308', '#06b6d4'];

function buildTrendData(alerts: AlertData[]): TrendPoint[] {
  if (alerts.length === 0) {
    return [
      { time: '10:00', total: 12, highRisk: 4, ai: 1 },
      { time: '10:05', total: 18, highRisk: 7, ai: 2 },
      { time: '10:10', total: 14, highRisk: 5, ai: 1 },
      { time: '10:15', total: 22, highRisk: 8, ai: 3 },
      { time: '10:20', total: 26, highRisk: 9, ai: 4 },
      { time: '10:25', total: 19, highRisk: 6, ai: 2 },
    ];
  }

  const buckets = new Map<string, TrendPoint>();

  [...alerts].reverse().forEach((alert) => {
    const time = new Date(alert.timestamp * 1000).toLocaleTimeString([], {
      hour: '2-digit',
      minute: '2-digit',
    });
    const current = buckets.get(time) || { time, total: 0, highRisk: 0, ai: 0 };
    current.total += 1;
    if (alert.severity === 'Critical' || alert.severity === 'High') {
      current.highRisk += 1;
    }
    if (alert.attack_type.includes('Zero-day') || alert.attack_type.includes('Adversarial')) {
      current.ai += 1;
    }
    buckets.set(time, current);
  });

  return Array.from(buckets.values()).slice(-6);
}

function buildAttackDistribution(alerts: AlertData[]): AttackDistributionPoint[] {
  const counts = new Map<string, number>();
  alerts.forEach((alert) => {
    if (alert.attack_type === 'Normal') {
      return;
    }
    counts.set(alert.attack_type, (counts.get(alert.attack_type) || 0) + 1);
  });

  if (counts.size === 0) {
    return [
      { name: 'DoS', value: 4, color: ATTACK_COLORS[0] },
      { name: 'Brute Force', value: 3, color: ATTACK_COLORS[1] },
      { name: 'Zero-Day', value: 2, color: ATTACK_COLORS[2] },
      { name: 'Web Attack', value: 2, color: ATTACK_COLORS[3] },
    ];
  }

  return Array.from(counts.entries())
    .sort((left, right) => right[1] - left[1])
    .slice(0, 4)
    .map(([name, value], index) => ({
      name,
      value,
      color: ATTACK_COLORS[index % ATTACK_COLORS.length],
    }));
}

export function AnalyticsPanel({ alerts }: AnalyticsPanelProps) {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [intel, setIntel] = useState<CloudIntel | null>(null);

  useEffect(() => {
    let ignore = false;

    const loadTelemetry = async () => {
      try {
        const statsResponse = await apiFetch('/api/stats/dashboard');
        if (statsResponse.ok && !ignore) {
          setStats((await statsResponse.json()) as DashboardStats);
        }
      } catch {
        if (!ignore) {
          setStats(null);
        }
      }

      try {
        const intelResponse = await apiFetch('/api/cloud-intel');
        if (intelResponse.ok && !ignore) {
          setIntel((await intelResponse.json()) as CloudIntel);
        }
      } catch {
        if (!ignore) {
          setIntel(null);
        }
      }
    };

    loadTelemetry();

    return () => {
      ignore = true;
    };
  }, []);

  const trendData = buildTrendData(alerts);
  const attackDistribution = buildAttackDistribution(alerts);
  const criticalAndHigh = alerts.filter(
    (alert) => alert.severity === 'Critical' || alert.severity === 'High',
  ).length;
  const criticalCount = alerts.filter((alert) => alert.severity === 'Critical').length;
  const summaryCards = [
    {
      label: 'Total Intercepts',
      value: stats?.total_alerts_24h.toLocaleString() || alerts.length.toLocaleString(),
      accent: 'text-white',
      icon: Database,
    },
    {
      label: 'Live Queue',
      value: alerts.length.toString(),
      accent: 'text-cyan-400',
      icon: Activity,
    },
    {
      label: 'Critical / High',
      value: criticalAndHigh.toString(),
      accent: 'text-red-400',
      icon: ShieldAlert,
    },
    {
      label: 'Healthy Nodes',
      value: (stats?.active_edge_nodes || 4).toString(),
      accent: 'text-green-400',
      icon: CheckCircle,
    },
  ];

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
      <div className="glass-panel p-4 rounded-xl border border-slate-800 bg-slate-900 shadow-md">
        <h3 className="text-sm font-semibold uppercase text-slate-400 tracking-wider mb-4 flex items-center gap-2">
          <TrendingUp className="w-4 h-4" /> Global Threat Trend
        </h3>
        <div className="h-48">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={trendData} margin={{ top: 5, right: 0, left: -20, bottom: 0 }}>
              <defs>
                <linearGradient id="colorThreatVolume" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.35} />
                  <stop offset="95%" stopColor="#06b6d4" stopOpacity={0} />
                </linearGradient>
                <linearGradient id="colorHighRisk" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#ef4444" stopOpacity={0.35} />
                  <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
                </linearGradient>
                <linearGradient id="colorAi" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#a855f7" stopOpacity={0.25} />
                  <stop offset="95%" stopColor="#a855f7" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
              <XAxis dataKey="time" stroke="#475569" fontSize={10} tickMargin={10} />
              <YAxis stroke="#475569" fontSize={10} tickMargin={10} />
              <Tooltip
                contentStyle={{ backgroundColor: '#0f172a', borderColor: '#1e293b', padding: '10px' }}
                itemStyle={{ fontSize: '12px' }}
                labelStyle={{ color: '#94a3b8', fontSize: '12px' }}
              />
              <Area type="monotone" dataKey="total" stroke="#06b6d4" fillOpacity={1} fill="url(#colorThreatVolume)" strokeWidth={2} />
              <Area type="monotone" dataKey="highRisk" stroke="#ef4444" fillOpacity={1} fill="url(#colorHighRisk)" strokeWidth={2} />
              <Area type="monotone" dataKey="ai" stroke="#a855f7" fillOpacity={1} fill="url(#colorAi)" strokeWidth={2} />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="flex flex-col gap-4">
        <div className="glass-panel p-4 rounded-xl border border-slate-800 bg-slate-900 shadow-md flex-1 grid grid-cols-2 gap-4">
          {summaryCards.map((card) => (
            <div key={card.label} className="bg-slate-950 rounded p-3 border border-slate-800/50 flex flex-col justify-center">
              <div className="flex items-center gap-2 mb-2">
                <card.icon className="w-4 h-4 text-slate-400" />
                <span className="text-xs text-slate-500 uppercase font-semibold">{card.label}</span>
              </div>
              <span className={`text-2xl font-bold font-mono ${card.accent}`}>{card.value}</span>
            </div>
          ))}
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <div className="glass-panel p-4 rounded-xl border border-slate-800 bg-slate-900 shadow-md">
            <div className="flex items-center gap-2 mb-3">
              <ShieldAlert className="w-4 h-4 text-red-400" />
              <span className="text-xs uppercase text-slate-400 font-semibold tracking-wide">Attack Mix</span>
            </div>
            <div className="h-44">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={attackDistribution}
                    dataKey="value"
                    nameKey="name"
                    innerRadius={42}
                    outerRadius={64}
                    paddingAngle={4}
                  >
                    {attackDistribution.map((entry) => (
                      <Cell key={entry.name} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{ backgroundColor: '#0f172a', borderColor: '#1e293b', padding: '10px' }}
                    itemStyle={{ fontSize: '12px' }}
                    labelStyle={{ color: '#94a3b8', fontSize: '12px' }}
                  />
                </PieChart>
              </ResponsiveContainer>
            </div>
            <div className="space-y-2">
              {attackDistribution.map((entry) => (
                <div key={entry.name} className="flex items-center justify-between text-xs font-mono">
                  <div className="flex items-center gap-2 text-slate-300">
                    <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: entry.color }} />
                    {entry.name}
                  </div>
                  <span className="text-slate-400">{entry.value}</span>
                </div>
              ))}
            </div>
          </div>

          <div className="glass-panel p-4 rounded-xl border border-slate-800 bg-slate-900 shadow-md flex-1 flex flex-col justify-center">
            <div className="flex items-center gap-2 mb-3">
              <BrainCircuit className="w-4 h-4 text-cyan-400" />
              <span className="text-xs uppercase text-slate-400 font-semibold tracking-wide">Cloud Neural Core</span>
            </div>
            {intel ? (
              <div className="space-y-1 text-xs font-mono">
                <div className="flex justify-between items-center bg-slate-800/50 px-2 py-1.5 rounded">
                  <span className="text-slate-400">Model Ver:</span>
                  <span className="text-cyan-400 font-bold">{intel.model_version}</span>
                </div>
                <div className="flex justify-between items-center bg-slate-800/50 px-2 py-1.5 rounded mt-1">
                  <span className="text-slate-400">GAN Synthesis:</span>
                  <span className="text-green-400 font-bold">{intel.gan_augmentation}</span>
                </div>
                <div className="flex justify-between items-center bg-slate-800/50 px-2 py-1.5 rounded mt-1">
                  <span className="text-slate-400">Robustness Check:</span>
                  <span className="text-purple-400 font-bold">{intel.adversarial_training}</span>
                </div>
                <div className="flex justify-between items-center bg-slate-800/50 px-2 py-1.5 rounded mt-1">
                  <span className="text-slate-400">Last Retraining:</span>
                  <span className="text-slate-200">{new Date(intel.last_retraining).toLocaleString()}</span>
                </div>
                <div className="flex justify-between items-center bg-slate-800/50 px-2 py-1.5 rounded mt-1">
                  <span className="text-slate-400">Critical Queue:</span>
                  <span className="text-red-400 font-bold">{criticalCount}</span>
                </div>
              </div>
            ) : (
              <span className="text-xs font-mono text-cyan-500 animate-pulse">Syncing logic core...</span>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
