import { useEffect, useState } from 'react';
import { SearchCode, ShieldAlert, Workflow } from 'lucide-react';
import { apiFetch } from '../lib/api';
import { formatRelativeTime, getSeverityTone, sortAlertsNewest } from '../lib/insights';
import type { AlertData, ForensicsRecord } from '../types';

interface LogsForensicsPageProps {
  alerts: AlertData[];
  selectedAlert: AlertData | null;
  searchQuery: string;
  onInvestigateAlert: (alert: AlertData) => void;
}

export function LogsForensicsPage({
  alerts,
  selectedAlert,
  searchQuery,
  onInvestigateAlert,
}: LogsForensicsPageProps) {
  const [record, setRecord] = useState<ForensicsRecord | null>(null);
  const rows = sortAlertsNewest(alerts).slice(0, 20);

  useEffect(() => {
    if (!selectedAlert) {
      setRecord(null);
      return;
    }

    let ignore = false;

    const loadForensics = async () => {
      try {
        const response = await apiFetch(`/api/forensics/${encodeURIComponent(selectedAlert.id)}`);
        if (!response.ok) {
          throw new Error('Forensics record unavailable.');
        }
        const data = (await response.json()) as ForensicsRecord;
        if (!ignore) {
          setRecord(data);
        }
      } catch {
        if (!ignore) {
          setRecord(null);
        }
      }
    };

    void loadForensics();

    return () => {
      ignore = true;
    };
  }, [selectedAlert]);

  return (
    <main className="flex-1 space-y-4 overflow-auto p-4">
      <section className="grid grid-cols-1 gap-4 md:grid-cols-3">
        <div className="glass-panel rounded-xl border border-slate-800 bg-slate-900 p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-xs uppercase tracking-wider text-slate-500">Search Hits</p>
              <p className="mt-2 text-3xl font-bold text-white">{alerts.length}</p>
            </div>
            <SearchCode className="h-6 w-6 text-cyan-400" />
          </div>
          <p className="mt-3 text-xs text-slate-400">
            {searchQuery ? `Filtered by "${searchQuery}".` : 'Showing the most recent telemetry records.'}
          </p>
        </div>

        <div className="glass-panel rounded-xl border border-slate-800 bg-slate-900 p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-xs uppercase tracking-wider text-slate-500">Critical Evidence</p>
              <p className="mt-2 text-3xl font-bold text-white">
                {alerts.filter((alert) => alert.severity === 'Critical').length}
              </p>
            </div>
            <ShieldAlert className="h-6 w-6 text-red-400" />
          </div>
          <p className="mt-3 text-xs text-slate-400">
            Critical records should be escalated to active case handling immediately.
          </p>
        </div>

        <div className="glass-panel rounded-xl border border-slate-800 bg-slate-900 p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-xs uppercase tracking-wider text-slate-500">Flow Records</p>
              <p className="mt-2 text-3xl font-bold text-white">
                {alerts.filter((alert) => alert.flow_features && Object.keys(alert.flow_features).length > 0).length}
              </p>
            </div>
            <Workflow className="h-6 w-6 text-fuchsia-400" />
          </div>
          <p className="mt-3 text-xs text-slate-400">
            Structured features are preserved for explainability and replay workflows.
          </p>
        </div>
      </section>

      <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <div className="glass-panel rounded-xl border border-slate-800 bg-slate-900 p-4 xl:col-span-7">
          <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
            <div>
              <h2 className="text-lg font-bold tracking-wide text-white">Forensics Logbook</h2>
              <p className="text-xs uppercase tracking-wider text-slate-400">
                Recent events available for analyst pivoting
              </p>
            </div>
            <div className="rounded-lg border border-slate-800 bg-slate-950 px-3 py-2 text-xs text-slate-400">
              {searchQuery ? `Scoped search: ${searchQuery}` : 'No active search filter'}
            </div>
          </div>

          <div className="overflow-x-auto">
            <table className="min-w-full text-left text-sm">
              <thead className="text-xs uppercase tracking-wider text-slate-500">
                <tr className="border-b border-slate-800">
                  <th className="pb-3 pr-4 font-medium">Timestamp</th>
                  <th className="pb-3 pr-4 font-medium">Threat</th>
                  <th className="pb-3 pr-4 font-medium">Source</th>
                <th className="pb-3 pr-4 font-medium">Destination</th>
                <th className="pb-3 pr-4 font-medium">Node</th>
                <th className="pb-3 pr-4 font-medium">Queue</th>
                <th className="pb-3 pr-4 font-medium">Severity</th>
                <th className="pb-3 font-medium">Action</th>
              </tr>
              </thead>
              <tbody>
                {rows.map((alert) => (
                  <tr key={alert.id} className="border-b border-slate-900/80 text-slate-300">
                    <td className="whitespace-nowrap py-3 pr-4 text-xs text-slate-400">
                      {formatRelativeTime(alert.timestamp)}
                    </td>
                    <td className="py-3 pr-4">
                      <div>
                        <p className="font-semibold text-white">{alert.attack_type}</p>
                        <p className="text-xs text-slate-500">{alert.id}</p>
                      </div>
                    </td>
                    <td className="py-3 pr-4 text-xs">
                      {alert.source_ip}
                      <div className="text-slate-500">{alert.source_geo.country}</div>
                    </td>
                    <td className="py-3 pr-4 text-xs">{alert.dest_ip}</td>
                    <td className="py-3 pr-4 text-xs">{alert.edge_node_id}</td>
                    <td className="py-3 pr-4 text-xs">
                      <div className="text-white">{alert.queue_level}</div>
                      <div className="text-slate-500">{alert.status}</div>
                    </td>
                    <td className="py-3 pr-4">
                      <span className={`rounded-full border px-2 py-1 text-xs font-semibold ${getSeverityTone(alert.severity)}`}>
                        {alert.severity}
                      </span>
                    </td>
                    <td className="py-3">
                      <button
                        onClick={() => onInvestigateAlert(alert)}
                        className="rounded-lg bg-cyan-500/10 px-3 py-2 text-xs font-semibold text-cyan-300 hover:bg-cyan-500/20"
                      >
                        Investigate
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>

            {rows.length === 0 && (
              <div className="rounded-lg border border-slate-800 bg-slate-950 p-6 text-sm text-slate-400">
                No records match the current search filter.
              </div>
            )}
          </div>
        </div>

        <div className="glass-panel rounded-xl border border-slate-800 bg-slate-900 p-4 xl:col-span-5">
          <div className="mb-4">
            <h2 className="text-lg font-bold tracking-wide text-white">Forensics Workspace</h2>
            <p className="text-xs uppercase tracking-wider text-slate-400">
              Packet fingerprints, artifacts, and related activity
            </p>
          </div>
          {selectedAlert && record ? (
            <div className="space-y-3">
              <div className="rounded-lg border border-slate-800 bg-slate-950 p-3">
                <p className="text-xs uppercase tracking-wider text-slate-500">Selected alert</p>
                <p className="mt-2 text-sm font-semibold text-white">{selectedAlert.attack_type}</p>
                <p className="mt-1 text-xs text-slate-400">{selectedAlert.id}</p>
                <p className="mt-2 text-xs text-cyan-300">Fingerprint {record.packet_fingerprint}</p>
                {selectedAlert.report_excerpt && (
                  <p className="mt-2 text-xs text-slate-400">{selectedAlert.report_excerpt}</p>
                )}
              </div>

              <div className="rounded-lg border border-slate-800 bg-slate-950 p-3">
                <p className="text-xs uppercase tracking-wider text-slate-500">Raw features</p>
                <div className="mt-3 grid grid-cols-2 gap-2 text-xs text-slate-300">
                  {Object.entries(record.raw_features).map(([key, value]) => (
                    <div key={key} className="rounded-lg border border-slate-800 bg-slate-900/60 p-2">
                      <p className="text-slate-500">{key}</p>
                      <p className="mt-1 font-semibold text-white">{String(value)}</p>
                    </div>
                  ))}
                </div>
              </div>

              <div className="rounded-lg border border-slate-800 bg-slate-950 p-3">
                <p className="text-xs uppercase tracking-wider text-slate-500">Timeline</p>
                <div className="mt-3 space-y-3">
                  {record.timeline.map((item, index) => (
                    <div key={`${item.artifact_ref}-${index}`} className="rounded-lg border border-slate-800 bg-slate-900/60 p-3">
                      <p className="text-xs font-semibold uppercase tracking-wider text-cyan-300">
                        {item.artifact_type}
                      </p>
                      <p className="mt-2 text-sm text-slate-200">{item.summary}</p>
                      <p className="mt-2 text-xs text-slate-500">
                        {formatRelativeTime(item.timestamp)} | {item.artifact_ref}
                      </p>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          ) : (
            <div className="rounded-lg border border-slate-800 bg-slate-950 p-6 text-sm text-slate-400">
              Select an alert from the logbook to open a forensics record.
            </div>
          )}
        </div>
      </section>
    </main>
  );
}
