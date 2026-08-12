import { useEffect, useRef, useState } from 'react';
import { AlertTriangle, ShieldBan, TerminalSquare, Zap } from 'lucide-react';
import { apiFetch } from '../lib/api';
import type { ActionResponse, AlertData, AuthUser } from '../types';

interface ActionPanelProps {
  selectedAlert: AlertData | null;
  currentUser: AuthUser;
}

const actions = [
  {
    id: 'IP BLOCK',
    title: 'BLOCK SOURCE IP',
    description: 'Reject traffic at edge firewall with approval gates for crown-jewel assets',
    icon: ShieldBan,
    accent: 'hover:border-red-500/50 hover:bg-red-500/10 group-hover:bg-red-500/20 group-hover:text-red-500',
  },
  {
    id: 'QUARANTINE',
    title: 'QUARANTINE DEVICE',
    description: 'Isolate node or identity path after human approval',
    icon: AlertTriangle,
    accent:
      'hover:border-orange-500/50 hover:bg-orange-500/10 group-hover:bg-orange-500/20 group-hover:text-orange-500',
  },
  {
    id: 'THROTTLE',
    title: 'THROTTLE BANDWIDTH',
    description: 'Limit the target flow while preserving forensic visibility',
    icon: Zap,
    accent:
      'hover:border-yellow-500/50 hover:bg-yellow-500/10 group-hover:bg-yellow-500/20 group-hover:text-yellow-500',
  },
];

export function ActionPanel({ selectedAlert, currentUser }: ActionPanelProps) {
  const canExecuteActions =
    currentUser.role === 'SOC Manager' || currentUser.permissions.includes('actions.execute');
  const [logs, setLogs] = useState<string[]>([
    '[SYSTEM] Response automation interface initialized.',
    '[SYSTEM] Approval gates active for high-impact playbooks.',
  ]);
  const [pendingAction, setPendingAction] = useState<string | null>(null);
  const [lastResponse, setLastResponse] = useState<ActionResponse | null>(null);
  const logEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    logEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs]);

  const handleAction = async (action: string) => {
    if (!selectedAlert) {
      return;
    }

    setPendingAction(action);
    setLastResponse(null);
    setLogs((prev) => [...prev, `[CMD] Requesting ${action} for ${selectedAlert.source_ip}...`]);

    try {
      const response = await apiFetch('/api/action/execute', {
        method: 'POST',
        body: JSON.stringify({
          action_type: action,
          target_ip: selectedAlert.source_ip,
          alert_id: selectedAlert.id,
          requested_by: currentUser.name,
        }),
      });

      if (!response.ok) {
        throw new Error('Mitigation request failed.');
      }

      const data = (await response.json()) as ActionResponse;
      setLastResponse(data);
      setLogs((prev) => [
        ...prev,
        data.requires_approval
          ? `[WAIT] ${data.msg}. Approval ticket ${data.action_id} created.`
          : `[OK] ${data.msg}. Executed with playbook guardrails.`,
      ]);
      if (data.recommended_playbook) {
        setLogs((prev) => [...prev, `[PLAYBOOK] ${data.recommended_playbook}`]);
      }
    } catch {
      setLogs((prev) => [...prev, '[ERR] Action failed: could not reach mitigation gateway.']);
    } finally {
      setPendingAction(null);
    }
  };

  return (
    <div className="glass-panel flex h-full flex-col rounded-xl border border-slate-800 bg-slate-900 p-6 shadow-[0_0_15px_rgba(0,0,0,0.5)] animate-in fade-in zoom-in duration-300">
      <div className="mb-6 flex items-center justify-between">
        <h3 className="flex items-center gap-2 text-sm font-semibold uppercase tracking-wider text-slate-400">
          <TerminalSquare className="h-4 w-4 text-cyan-400" /> Response Center
        </h3>
        <span className="rounded border border-green-500/30 bg-green-500/10 px-2 py-1 text-[10px] font-bold tracking-wider text-green-500">
          {pendingAction ? 'PROCESSING' : 'SOAR READY'}
        </span>
      </div>

      <div className="mb-5 rounded-lg border border-slate-800 bg-slate-950 p-3">
        <p className="mb-2 text-[10px] uppercase tracking-widest text-slate-500">Selected Target</p>
        {selectedAlert ? (
          <div className="space-y-1 text-xs font-mono">
            <div className="flex justify-between gap-3">
              <span className="text-slate-400">Source IP</span>
              <span className="text-white">{selectedAlert.source_ip}</span>
            </div>
            <div className="flex justify-between gap-3">
              <span className="text-slate-400">Threat Type</span>
              <span className="text-red-400">{selectedAlert.attack_type}</span>
            </div>
            <div className="flex justify-between gap-3">
              <span className="text-slate-400">Asset</span>
              <span className="text-white">{selectedAlert.asset_name}</span>
            </div>
            <div className="flex justify-between gap-3">
              <span className="text-slate-400">Confidence</span>
              <span className="text-cyan-400">{(selectedAlert.confidence * 100).toFixed(1)}%</span>
            </div>
          </div>
        ) : (
          <p className="text-xs text-slate-500">Select an alert to unlock containment actions.</p>
        )}
      </div>

      <div className="mb-4 grid grid-cols-1 gap-3">
        {actions.map((action) => (
          <button
            key={action.id}
            onClick={() => void handleAction(action.id)}
            disabled={!selectedAlert || pendingAction !== null || !canExecuteActions}
            className={`group flex items-center gap-3 rounded-lg border border-slate-800 bg-slate-950 p-3 text-left transition-colors disabled:cursor-not-allowed disabled:opacity-50 ${action.accent}`}
          >
            <div className="rounded border border-slate-800 bg-slate-900 p-2 transition-colors">
              <action.icon className="h-4 w-4" />
            </div>
            <div>
              <h4 className="text-xs font-bold tracking-wider text-slate-200">{action.title}</h4>
              <p className="font-mono text-[10px] text-slate-500">{action.description}</p>
            </div>
          </button>
        ))}
      </div>

      {!canExecuteActions && (
        <div className="mb-4 rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 text-xs text-amber-200">
          Your role can investigate alerts, but containment actions require IR Engineer or SOC Manager access.
        </div>
      )}

      {lastResponse && (
        <div className="mb-4 rounded-lg border border-slate-800 bg-slate-950 p-3 text-xs text-slate-300">
          <p className="font-semibold text-white">
            {lastResponse.requires_approval ? 'Approval Required' : 'Action Executed'}
          </p>
          <p className="mt-1">{lastResponse.msg}</p>
          {lastResponse.action_id && (
            <p className="mt-1 text-slate-500">Action ID: {lastResponse.action_id}</p>
          )}
        </div>
      )}

      <div className="max-h-48 flex-1 space-y-2 overflow-y-auto rounded-lg border border-slate-800 bg-black/50 p-3 font-mono text-[10px]">
        {logs.map((log, index) => (
          <div
            key={`${log}-${index}`}
            className={`flex items-start gap-2 ${
              log.includes('[CMD]')
                ? 'text-yellow-400'
                : log.includes('[OK]')
                  ? 'text-green-400'
                  : log.includes('[WAIT]')
                    ? 'text-orange-400'
                    : log.includes('[ERR]')
                      ? 'text-red-400'
                      : log.includes('[PLAYBOOK]')
                        ? 'text-cyan-400'
                        : 'text-slate-500'
            }`}
          >
            <span>&gt;</span>
            <span className="leading-tight">{log}</span>
          </div>
        ))}
        <div ref={logEndRef} />
      </div>
    </div>
  );
}
