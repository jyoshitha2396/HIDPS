import { CheckCircle2, FileWarning, ShieldAlert, UserRoundCheck } from 'lucide-react';
import { ActionPanel } from './ActionPanel';
import { AlertStream } from './AlertStream';
import { ThreatPanel } from './ThreatPanel';
import { apiFetch } from '../lib/api';
import { formatRelativeTime } from '../lib/insights';
import type { AlertData, AuthUser } from '../types';

interface AlertsPageProps {
  alerts: AlertData[];
  selectedAlert: AlertData | null;
  onSelectAlert: (alert: AlertData) => void;
  onAlertUpdate: (alert: AlertData) => void;
  currentUser: AuthUser;
}

export function AlertsPage({
  alerts,
  selectedAlert,
  onSelectAlert,
  onAlertUpdate,
  currentUser,
}: AlertsPageProps) {
  const escalatedCount = alerts.filter((alert) => alert.status === 'escalated').length;
  const closedCount = alerts.filter((alert) => alert.status === 'closed').length;
  const reviewedCount = alerts.filter((alert) => alert.disposition !== 'unreviewed').length;
  const openCount = alerts.filter((alert) => alert.status !== 'closed').length;
  const progressPercent = alerts.length === 0 ? 0 : Math.min(100, (openCount / alerts.length) * 100);

  const assignToMe = async (alert: AlertData) => {
    try {
      const response = await apiFetch('/api/alerts/workflow', {
        method: 'POST',
        body: JSON.stringify({
          alert_id: alert.id,
          analyst: currentUser.name,
          assigned_analyst: currentUser.name,
          status: 'investigating',
          report_summary:
            alert.report_excerpt || `Alert assigned to ${currentUser.name} for investigation.`,
        }),
      });
      if (!response.ok) {
        throw new Error('Assignment failed.');
      }
      const updatedAlert = (await response.json()) as AlertData;
      onAlertUpdate(updatedAlert);
      onSelectAlert(updatedAlert);
    } catch {
      // Quiet failure keeps the queue usable during a live demo.
    }
  };

  const jumpToWorkbench = () => {
    document
      .getElementById('alert-workbench')
      ?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  };

  return (
    <main className="flex-1 overflow-auto px-4 py-5 md:px-6 lg:px-8">
      <div className="mx-auto flex w-full max-w-[1480px] flex-col gap-4">
        <section className="rounded-[24px] border border-white/6 bg-[#1c2943] p-6">
          <div className="flex flex-wrap items-center gap-4">
            <h1 className="text-[22px] font-semibold text-white">Alert queue</h1>
            <div className="h-2 w-20 overflow-hidden rounded-full bg-[#24314e]">
              <div className="h-full rounded-full bg-[#3b82f6]" style={{ width: `${progressPercent}%` }} />
            </div>
            <p className="text-sm text-slate-400">{openCount} alerts incoming</p>
          </div>
        </section>

        <section className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
          <div className="rounded-[20px] border border-white/6 bg-[#1c2943] p-5">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Open alerts</p>
                <p className="mt-3 text-3xl font-semibold text-white">{openCount}</p>
              </div>
              <ShieldAlert className="h-6 w-6 text-red-300" />
            </div>
          </div>

          <div className="rounded-[20px] border border-white/6 bg-[#1c2943] p-5">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Escalated</p>
                <p className="mt-3 text-3xl font-semibold text-white">{escalatedCount}</p>
              </div>
              <FileWarning className="h-6 w-6 text-fuchsia-300" />
            </div>
          </div>

          <div className="rounded-[20px] border border-white/6 bg-[#1c2943] p-5">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Reviewed</p>
                <p className="mt-3 text-3xl font-semibold text-white">{reviewedCount}</p>
              </div>
              <UserRoundCheck className="h-6 w-6 text-[#a8eb37]" />
            </div>
          </div>

          <div className="rounded-[20px] border border-white/6 bg-[#1c2943] p-5">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Closed</p>
                <p className="mt-3 text-3xl font-semibold text-white">{closedCount}</p>
              </div>
              <CheckCircle2 className="h-6 w-6 text-emerald-300" />
            </div>
          </div>
        </section>

        <section className="rounded-[20px] border border-white/6 bg-[#1c2943]">
          <div className="flex flex-wrap items-start justify-between gap-4 border-b border-white/6 px-5 py-4">
            <div>
              <p className="text-sm font-semibold text-white">Assigned alert(s)</p>
              <p className="mt-2 text-sm text-slate-400">
                {selectedAlert
                  ? 'The selected incident is pinned here so you can brief, report, and close it without losing context.'
                  : "You haven't picked up an alert yet. Assign yourself to one to begin investigating and finding the true positives."}
              </p>
            </div>
            {selectedAlert && (
              <button
                onClick={jumpToWorkbench}
                className="rounded-lg bg-[#9ddb24] px-4 py-2 text-sm font-semibold text-[#152033] transition hover:bg-[#b5ef4d]"
              >
                Write case report
              </button>
            )}
          </div>

          <div className="px-5 py-4">
            {selectedAlert ? (
              <div className="rounded-xl bg-[#18243c]">
                <div className="grid grid-cols-[80px_minmax(0,1fr)_90px_110px_160px_44px] items-center gap-4 px-4 py-4 text-sm">
                  <p className="font-semibold text-slate-300">{selectedAlert.id}</p>
                  <div className="min-w-0">
                    <p className="truncate font-semibold text-white">{selectedAlert.attack_type}</p>
                    <p className="mt-1 truncate text-xs text-slate-500">{selectedAlert.asset_name}</p>
                  </div>
                  <p className="font-medium text-[#a8eb37]">{selectedAlert.severity}</p>
                  <p className="text-slate-300">{selectedAlert.source_type}</p>
                  <p className="text-sm text-slate-300">
                    {formatRelativeTime(selectedAlert.timestamp)}
                  </p>
                  <p className="text-right text-slate-500">-</p>
                </div>
                <div className="border-t border-white/6 px-6 py-5">
                  <div className="grid gap-4 md:grid-cols-2">
                    <div className="space-y-2 text-sm text-slate-300">
                      <p>
                        <span className="text-slate-500">Description:</span>{' '}
                        {selectedAlert.report_excerpt ||
                          'Analyst workspace open for this detection.'}
                      </p>
                      <p>
                        <span className="text-slate-500">Telemetry source:</span>{' '}
                        {selectedAlert.telemetry_source}
                      </p>
                      <p>
                        <span className="text-slate-500">Queue:</span> {selectedAlert.queue_level}
                      </p>
                      <p>
                        <span className="text-slate-500">Owner:</span>{' '}
                        {selectedAlert.assigned_analyst || 'Unassigned'}
                      </p>
                      <p>
                        <span className="text-slate-500">Edge node:</span> {selectedAlert.edge_node_id}
                      </p>
                    </div>
                    <div className="space-y-2 text-sm text-slate-300">
                      <p>
                        <span className="text-slate-500">Source:</span> {selectedAlert.source_ip}
                      </p>
                      <p>
                        <span className="text-slate-500">Destination:</span>{' '}
                        {selectedAlert.dest_ip}
                      </p>
                      <p>
                        <span className="text-slate-500">Status:</span> {selectedAlert.status}
                      </p>
                      <p>
                        <span className="text-slate-500">Disposition:</span>{' '}
                        {selectedAlert.disposition}
                      </p>
                      <p>
                        <span className="text-slate-500">Confidence:</span>{' '}
                        {(selectedAlert.confidence * 100).toFixed(1)}%
                      </p>
                    </div>
                  </div>
                </div>
              </div>
            ) : (
              <div className="rounded-xl border border-dashed border-[#3a4865] bg-[#18243c] px-4 py-5 text-sm text-slate-400">
                No alert is assigned to the current workbench yet.
              </div>
            )}
          </div>
        </section>

        <AlertStream
          alerts={alerts}
          selectedAlertId={selectedAlert?.id}
          onSelectAlert={onSelectAlert}
          onAssignAlert={(alert) => void assignToMe(alert)}
        />

        <section id="alert-workbench" className="grid grid-cols-1 gap-4 xl:grid-cols-12">
          <div className="xl:col-span-8">
            <ThreatPanel
              selectedAlert={selectedAlert}
              onAlertUpdate={onAlertUpdate}
              currentUser={currentUser}
            />
          </div>
          <div className="xl:col-span-4">
            <ActionPanel selectedAlert={selectedAlert} currentUser={currentUser} />
          </div>
        </section>
      </div>
    </main>
  );
}
