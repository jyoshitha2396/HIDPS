import { Fragment, useMemo, useState } from 'react';
import { ChevronDown, RotateCcw, Search, UserPlus } from 'lucide-react';
import type { AlertData } from '../types';
import { formatRelativeTime, getSeverityTone, sortAlertsNewest } from '../lib/insights';

interface AlertStreamProps {
  alerts: AlertData[];
  selectedAlertId?: string | null;
  onSelectAlert: (alert: AlertData) => void;
  onAssignAlert?: (alert: AlertData) => void;
}

export function AlertStream({
  alerts,
  selectedAlertId,
  onSelectAlert,
  onAssignAlert,
}: AlertStreamProps) {
  const [localQuery, setLocalQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [statusFilter, setStatusFilter] = useState('all');
  const [typeFilter, setTypeFilter] = useState('all');
  const [showCount, setShowCount] = useState('15');

  const alertTypes = useMemo(() => {
    return Array.from(new Set(alerts.map((alert) => alert.attack_type))).sort();
  }, [alerts]);

  const filteredQueue = useMemo(() => {
    const query = localQuery.trim().toLowerCase();

    return sortAlertsNewest(alerts)
      .filter((alert) => severityFilter === 'all' || alert.severity === severityFilter)
      .filter((alert) => statusFilter === 'all' || alert.status === statusFilter)
      .filter((alert) => typeFilter === 'all' || alert.attack_type === typeFilter)
      .filter((alert) => {
        if (!query) {
          return true;
        }

        return [
          alert.id,
          alert.attack_type,
          alert.source_ip,
          alert.dest_ip,
          alert.asset_name,
          alert.telemetry_source,
        ]
          .join(' ')
          .toLowerCase()
          .includes(query);
      })
      .slice(0, Number(showCount));
  }, [alerts, localQuery, severityFilter, statusFilter, typeFilter, showCount]);

  const resetFilters = () => {
    setLocalQuery('');
    setSeverityFilter('all');
    setStatusFilter('all');
    setTypeFilter('all');
    setShowCount('15');
  };

  return (
    <section className="rounded-[20px] border border-white/6 bg-[#1c2943] p-5">
      <div className="mb-4 flex flex-wrap items-center gap-3">
        <div className="relative min-w-[260px] flex-1">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500" />
          <input
            value={localQuery}
            onChange={(event) => setLocalQuery(event.target.value)}
            placeholder="Search for an alert"
            className="w-full rounded-lg border border-white/8 bg-[#121d33] py-2.5 pl-10 pr-4 text-sm text-slate-200 placeholder:text-slate-600 focus:border-[#8fd11f]/20 focus:outline-none focus:ring-1 focus:ring-[#8fd11f]/20"
          />
        </div>

        <button
          onClick={resetFilters}
          className="inline-flex items-center gap-2 rounded-lg border border-white/8 bg-[#121d33] px-3 py-2.5 text-sm text-slate-300 transition hover:text-white"
        >
          <RotateCcw className="h-4 w-4" />
          Reset Filters
        </button>

        <select
          value={severityFilter}
          onChange={(event) => setSeverityFilter(event.target.value)}
          className="rounded-lg border border-white/8 bg-[#121d33] px-3 py-2.5 text-sm text-slate-200 outline-none"
        >
          <option value="all">Severity</option>
          <option value="Critical">Critical</option>
          <option value="High">High</option>
          <option value="Medium">Medium</option>
          <option value="Low">Low</option>
        </select>

        <select
          value={statusFilter}
          onChange={(event) => setStatusFilter(event.target.value)}
          className="rounded-lg border border-white/8 bg-[#121d33] px-3 py-2.5 text-sm text-slate-200 outline-none"
        >
          <option value="all">Status</option>
          <option value="open">Open</option>
          <option value="investigating">Investigating</option>
          <option value="escalated">Escalated</option>
          <option value="closed">Closed</option>
        </select>

        <select
          value={typeFilter}
          onChange={(event) => setTypeFilter(event.target.value)}
          className="rounded-lg border border-white/8 bg-[#121d33] px-3 py-2.5 text-sm text-slate-200 outline-none"
        >
          <option value="all">Alert type</option>
          {alertTypes.map((type) => (
            <option key={type} value={type}>
              {type}
            </option>
          ))}
        </select>

        <label className="inline-flex items-center gap-2 text-sm text-slate-300">
          <span>Show</span>
          <select
            value={showCount}
            onChange={(event) => setShowCount(event.target.value)}
            className="rounded-lg border border-white/8 bg-[#121d33] px-3 py-2.5 text-sm text-slate-200 outline-none"
          >
            <option value="10">10</option>
            <option value="15">15</option>
            <option value="20">20</option>
            <option value="30">30</option>
          </select>
          <span>alerts</span>
        </label>
      </div>

      <div className="overflow-x-auto">
        <table className="min-w-full border-separate border-spacing-0 text-left">
          <thead>
            <tr className="text-xs uppercase tracking-[0.18em] text-slate-500">
              <th className="border-b border-white/6 px-4 py-3 font-medium">ID</th>
              <th className="border-b border-white/6 px-4 py-3 font-medium">Alert rule</th>
              <th className="border-b border-white/6 px-4 py-3 font-medium">Severity</th>
              <th className="border-b border-white/6 px-4 py-3 font-medium">Type</th>
              <th className="border-b border-white/6 px-4 py-3 font-medium">Date</th>
              <th className="border-b border-white/6 px-4 py-3 font-medium">Status</th>
              <th className="border-b border-white/6 px-4 py-3 font-medium text-right">Action</th>
            </tr>
          </thead>
          <tbody>
            {filteredQueue.map((alert) => {
              const isSelected = selectedAlertId === alert.id;

              return (
                <Fragment key={alert.id}>
                  <tr
                    onClick={() => onSelectAlert(alert)}
                    className={`cursor-pointer text-sm text-slate-300 transition ${
                      isSelected ? 'bg-[#18243c]' : 'hover:bg-[#17233b]'
                    }`}
                  >
                    <td className="border-b border-white/6 px-4 py-4 font-semibold">{alert.id}</td>
                    <td className="border-b border-white/6 px-4 py-4">
                      <div className="flex items-center gap-3">
                        <ChevronDown
                          className={`h-4 w-4 text-slate-500 transition ${isSelected ? 'rotate-180' : ''}`}
                        />
                        <div>
                          <p className="font-semibold text-white">{alert.attack_type}</p>
                          <p className="mt-1 text-xs text-slate-500">{alert.asset_name}</p>
                        </div>
                      </div>
                    </td>
                    <td className="border-b border-white/6 px-4 py-4">
                      <span className={`rounded-full border px-2.5 py-1 text-xs font-semibold ${getSeverityTone(alert.severity)}`}>
                        {alert.severity}
                      </span>
                    </td>
                    <td className="border-b border-white/6 px-4 py-4 text-sm">{alert.source_type}</td>
                    <td className="border-b border-white/6 px-4 py-4 text-sm">
                      {formatRelativeTime(alert.timestamp)}
                    </td>
                    <td className="border-b border-white/6 px-4 py-4">
                      <span className="rounded-full bg-white/8 px-3 py-1 text-xs font-medium text-slate-200">
                        {alert.status}
                      </span>
                    </td>
                    <td className="border-b border-white/6 px-4 py-4">
                      <div className="flex items-center justify-end gap-2">
                        <button
                          onClick={(event) => {
                            event.stopPropagation();
                            onSelectAlert(alert);
                          }}
                          className="rounded-lg border border-white/8 bg-[#121d33] px-3 py-2 text-xs font-semibold text-slate-200"
                        >
                          Open
                        </button>
                        {onAssignAlert && (
                          <button
                            onClick={(event) => {
                              event.stopPropagation();
                              onAssignAlert(alert);
                            }}
                            className="inline-flex items-center gap-1 rounded-lg border border-[#8fd11f]/20 bg-[#8fd11f]/10 px-3 py-2 text-xs font-semibold text-[#c6f36d]"
                          >
                            <UserPlus className="h-3 w-3" />
                            Assign
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>

                  {isSelected && (
                    <tr className="bg-[#18243c]">
                      <td colSpan={7} className="border-b border-white/6 px-6 py-5">
                        <div className="grid gap-4 lg:grid-cols-2">
                          <div className="space-y-2 text-sm text-slate-300">
                            <p>
                              <span className="text-slate-500">Description:</span>{' '}
                              {alert.report_excerpt ||
                                `${alert.attack_type} was detected and routed into the analyst queue.`}
                            </p>
                            <p>
                              <span className="text-slate-500">Telemetry source:</span>{' '}
                              {alert.telemetry_source}
                            </p>
                            <p>
                              <span className="text-slate-500">Source IP:</span> {alert.source_ip}
                            </p>
                            <p>
                              <span className="text-slate-500">Destination IP:</span> {alert.dest_ip}
                            </p>
                            <p>
                              <span className="text-slate-500">Node:</span> {alert.edge_node_id}
                            </p>
                            <p>
                              <span className="text-slate-500">Owner:</span>{' '}
                              {alert.assigned_analyst || 'Unassigned'}
                            </p>
                          </div>

                          <div className="space-y-3">
                            <div>
                              <p className="text-xs uppercase tracking-[0.18em] text-slate-500">
                                MITRE techniques
                              </p>
                              <div className="mt-2 flex flex-wrap gap-2">
                                {alert.mitre.map((technique) => (
                                  <span
                                    key={`${technique.technique_id}-${technique.tactic}`}
                                    className="rounded-full border border-white/8 px-3 py-1 text-xs text-slate-200"
                                  >
                                    {technique.technique_id} {technique.technique_name}
                                  </span>
                                ))}
                              </div>
                            </div>

                            {alert.flow_features && Object.keys(alert.flow_features).length > 0 && (
                              <div>
                                <p className="text-xs uppercase tracking-[0.18em] text-slate-500">
                                  Flow features
                                </p>
                                <div className="mt-2 grid gap-2 sm:grid-cols-2">
                                  {Object.entries(alert.flow_features)
                                    .slice(0, 6)
                                    .map(([key, value]) => (
                                      <div
                                        key={key}
                                        className="rounded-lg border border-white/8 bg-[#121d33] px-3 py-2 text-xs text-slate-300"
                                      >
                                        <span className="text-slate-500">{key}:</span> {String(value)}
                                      </div>
                                    ))}
                                </div>
                              </div>
                            )}
                          </div>
                        </div>
                      </td>
                    </tr>
                  )}
                </Fragment>
              );
            })}
          </tbody>
        </table>
      </div>

      {filteredQueue.length === 0 && (
        <div className="rounded-xl border border-dashed border-white/8 bg-[#121d33] px-4 py-10 text-center text-sm text-slate-400">
          No alerts match the current filter set.
        </div>
      )}
    </section>
  );
}
