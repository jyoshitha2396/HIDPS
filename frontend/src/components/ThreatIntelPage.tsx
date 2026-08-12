import { useEffect, useState } from 'react';
import { Globe2, Radar, ShieldAlert, Sparkles } from 'lucide-react';
import { Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import { apiFetch } from '../lib/api';
import {
  formatRelativeTime,
  getSeverityTone,
  getSourceCountries,
  getThreatFamilies,
  sortAlertsNewest,
} from '../lib/insights';
import type { AlertData, CorrelationCase, ThreatCoverageSummary } from '../types';

interface ThreatIntelPageProps {
  alerts: AlertData[];
}

const colors = ['#ef4444', '#f97316', '#06b6d4', '#a855f7', '#eab308', '#10b981'];

export function ThreatIntelPage({ alerts }: ThreatIntelPageProps) {
  const [coverage, setCoverage] = useState<ThreatCoverageSummary | null>(null);
  const [cases, setCases] = useState<CorrelationCase[]>([]);
  const threatFamilies = getThreatFamilies(alerts);
  const sourceCountries = getSourceCountries(alerts);
  const adversarialAlerts = alerts.filter(
    (alert) =>
      alert.attack_type.includes('Zero-day') || alert.attack_type.includes('Adversarial'),
  );
  const priorityQueue = sortAlertsNewest(
    alerts.filter((alert) => alert.severity === 'Critical' || alert.severity === 'High'),
  ).slice(0, 6);

  useEffect(() => {
    let ignore = false;

    const loadIntel = async () => {
      try {
        const [coverageResponse, caseResponse] = await Promise.all([
          apiFetch('/api/mitre/coverage'),
          apiFetch('/api/correlation/cases'),
        ]);
        if (!coverageResponse.ok || !caseResponse.ok) {
          throw new Error('Threat intelligence services unavailable.');
        }

        const [coverageData, caseData] = (await Promise.all([
          coverageResponse.json(),
          caseResponse.json(),
        ])) as [ThreatCoverageSummary, CorrelationCase[]];

        if (!ignore) {
          setCoverage(coverageData);
          setCases(caseData);
        }
      } catch {
        if (!ignore) {
          setCoverage(null);
          setCases([]);
        }
      }
    };

    void loadIntel();

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
              <p className="text-xs uppercase tracking-wider text-slate-500">Active Campaigns</p>
              <p className="mt-2 text-3xl font-bold text-white">{cases.length || threatFamilies.length}</p>
            </div>
            <Radar className="h-6 w-6 text-cyan-400" />
          </div>
          <p className="mt-3 text-xs text-slate-400">
            Correlated campaigns assembled from live ATT&CK-mapped detections.
          </p>
        </div>

        <div className="glass-panel rounded-xl border border-slate-800 bg-slate-900 p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-xs uppercase tracking-wider text-slate-500">Risk Regions</p>
              <p className="mt-2 text-3xl font-bold text-white">{sourceCountries.length}</p>
            </div>
            <Globe2 className="h-6 w-6 text-orange-400" />
          </div>
          <p className="mt-3 text-xs text-slate-400">
            Top geographies contributing hostile traffic into the edge mesh.
          </p>
        </div>

        <div className="glass-panel rounded-xl border border-slate-800 bg-slate-900 p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-xs uppercase tracking-wider text-slate-500">AI-Driven Threats</p>
              <p className="mt-2 text-3xl font-bold text-white">{adversarialAlerts.length}</p>
            </div>
            <Sparkles className="h-6 w-6 text-fuchsia-400" />
          </div>
          <p className="mt-3 text-xs text-slate-400">
            Zero-day and adversarial events requiring elevated analyst scrutiny.
          </p>
        </div>

        <div className="glass-panel rounded-xl border border-slate-800 bg-slate-900 p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-xs uppercase tracking-wider text-slate-500">ATT&CK Coverage</p>
              <p className="mt-2 text-3xl font-bold text-white">
                {coverage ? `${(coverage.coverage_ratio * 100).toFixed(0)}%` : '--'}
              </p>
            </div>
            <ShieldAlert className="h-6 w-6 text-red-400" />
          </div>
          <p className="mt-3 text-xs text-slate-400">
            Technique coverage across the modeled threat surface.
          </p>
        </div>
      </section>

      <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <div className="glass-panel rounded-xl border border-slate-800 bg-slate-900 p-4 xl:col-span-7">
          <div className="mb-4">
            <h2 className="text-lg font-bold tracking-wide text-white">Threat Family Dominance</h2>
            <p className="text-xs uppercase tracking-wider text-slate-400">
              Classifier detections by attack pattern
            </p>
          </div>
          <div className="h-80">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={threatFamilies} margin={{ top: 0, right: 12, left: 0, bottom: 8 }}>
                <CartesianGrid stroke="#1e293b" vertical={false} />
                <XAxis dataKey="label" stroke="#64748b" fontSize={10} tickLine={false} />
                <YAxis stroke="#64748b" fontSize={10} tickLine={false} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#0f172a', borderColor: '#1e293b' }}
                  labelStyle={{ color: '#94a3b8' }}
                />
                <Bar dataKey="value" radius={[8, 8, 0, 0]}>
                  {threatFamilies.map((entry, index) => (
                    <Cell key={entry.label} fill={colors[index % colors.length]} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="glass-panel rounded-xl border border-slate-800 bg-slate-900 p-4 xl:col-span-5">
          <div className="mb-4">
            <h2 className="text-lg font-bold tracking-wide text-white">MITRE Coverage</h2>
            <p className="text-xs uppercase tracking-wider text-slate-400">
              Tactics and techniques currently exercised
            </p>
          </div>
          <div className="space-y-3">
            {coverage?.items.slice(0, 6).map((item) => (
              <div key={item.technique_id} className="rounded-lg border border-slate-800 bg-slate-950 p-3">
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <p className="text-sm font-semibold text-white">
                      {item.technique_id} {item.technique_name}
                    </p>
                    <p className="text-xs text-slate-500">{item.tactic}</p>
                  </div>
                  <span className="rounded-full bg-cyan-500/10 px-2 py-1 text-xs font-semibold text-cyan-200">
                    {item.detections} detections
                  </span>
                </div>
                <p className="mt-2 text-xs text-slate-400">
                  Avg confidence {(item.avg_confidence * 100).toFixed(1)}%
                </p>
              </div>
            ))}
            {!coverage && (
              <div className="rounded-lg border border-slate-800 bg-slate-950 p-4 text-sm text-slate-400">
                Coverage data will appear when the backend telemetry service is reachable.
              </div>
            )}
          </div>
        </div>
      </section>

      <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <div className="glass-panel rounded-xl border border-slate-800 bg-slate-900 p-4 xl:col-span-5">
          <div className="mb-4">
            <h2 className="text-lg font-bold tracking-wide text-white">Regional Hotspots</h2>
            <p className="text-xs uppercase tracking-wider text-slate-400">
              Top hostile source countries
            </p>
          </div>
          <div className="space-y-3">
            {sourceCountries.map((country) => (
              <div key={country.label} className="rounded-lg border border-slate-800 bg-slate-950 p-3">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-semibold text-white">{country.label}</p>
                    <p className="text-xs text-slate-500">{country.value} total detections</p>
                  </div>
                  <span className="rounded-full bg-red-500/10 px-2 py-1 text-xs font-semibold text-red-300">
                    {country.critical} critical
                  </span>
                </div>
                <div className="mt-3 h-2 rounded-full bg-slate-800">
                  <div
                    className="h-2 rounded-full bg-gradient-to-r from-red-500 to-orange-400"
                    style={{ width: `${Math.min(country.value * 12, 100)}%` }}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="glass-panel rounded-xl border border-slate-800 bg-slate-900 p-4 xl:col-span-7">
          <div className="mb-4">
            <h2 className="text-lg font-bold tracking-wide text-white">Correlated Campaigns</h2>
            <p className="text-xs uppercase tracking-wider text-slate-400">
              Multi-source evidence chains assembled by the correlator
            </p>
          </div>
          <div className="space-y-3">
            {cases.slice(0, 5).map((item) => (
              <div key={item.case_id} className="rounded-lg border border-slate-800 bg-slate-950 p-3">
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <div>
                    <p className="text-sm font-semibold text-white">{item.title}</p>
                    <p className="text-xs text-slate-500">{item.summary}</p>
                  </div>
                  <span className="rounded-full bg-fuchsia-500/10 px-2 py-1 text-xs font-semibold text-fuchsia-200">
                    Risk {(item.risk_score * 100).toFixed(0)}%
                  </span>
                </div>
                <div className="mt-3 flex flex-wrap gap-2 text-xs">
                  {item.tactic_chain.map((tactic) => (
                    <span key={tactic} className="rounded-full border border-slate-700 px-2 py-1 text-slate-300">
                      {tactic}
                    </span>
                  ))}
                </div>
                <p className="mt-3 text-xs text-slate-400">
                  Playbook: {item.recommended_playbook}
                </p>
              </div>
            ))}
            {cases.length === 0 && (
              <div className="rounded-lg border border-slate-800 bg-slate-950 p-4 text-sm text-slate-400">
                Correlated cases will appear as repeated hostile behaviors are observed.
              </div>
            )}
          </div>
        </div>
      </section>

      <section className="glass-panel rounded-xl border border-slate-800 bg-slate-900 p-4">
        <div className="mb-4">
          <h2 className="text-lg font-bold tracking-wide text-white">Priority Investigation Queue</h2>
          <p className="text-xs uppercase tracking-wider text-slate-400">
            Highest-risk incidents requiring immediate triage
          </p>
        </div>
        <div className="space-y-3">
          {priorityQueue.map((alert) => (
            <div key={alert.id} className="rounded-lg border border-slate-800 bg-slate-950 p-3">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div>
                  <p className="text-sm font-semibold text-white">{alert.attack_type}</p>
                  <p className="text-xs text-slate-500">
                    {alert.source_ip} | {alert.source_geo.country} | {alert.telemetry_source}
                  </p>
                </div>
                <span className={`rounded-full border px-2 py-1 text-xs font-semibold ${getSeverityTone(alert.severity)}`}>
                  {alert.severity}
                </span>
              </div>
              <div className="mt-3 flex flex-wrap items-center gap-4 text-xs text-slate-400">
                <span>Confidence {(alert.confidence * 100).toFixed(1)}%</span>
                <span>Destination {alert.dest_ip}</span>
                <span>{formatRelativeTime(alert.timestamp)}</span>
              </div>
            </div>
          ))}
        </div>
      </section>
    </main>
  );
}
