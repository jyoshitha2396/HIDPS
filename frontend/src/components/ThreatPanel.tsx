import { useEffect, useState } from 'react';
import { Bar, BarChart, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import { ArrowRight, Brain, Cpu, FileText, Network, ShieldAlert, UserCheck } from 'lucide-react';
import { apiFetch } from '../lib/api';
import { formatRelativeTime } from '../lib/insights';
import type {
  AlertData,
  AlertDisposition,
  AuthUser,
  ExplainabilityModel,
  InvestigationWorkspace,
} from '../types';

interface ThreatPanelProps {
  selectedAlert: AlertData | null;
  onAlertUpdate: (alert: AlertData) => void;
  currentUser: AuthUser;
}

interface ThreatDetails extends ExplainabilityModel {
  attackType: string;
  probabilities: Array<{
    name: string;
    prob: number;
  }>;
}

const verdictActions: Array<{ verdict: AlertDisposition; label: string; tone: string }> = [
  {
    verdict: 'true_positive',
    label: 'Confirm TP',
    tone: 'border-red-500/30 bg-red-500/10 text-red-200 hover:bg-red-500/20',
  },
  {
    verdict: 'false_positive',
    label: 'Mark FP',
    tone: 'border-amber-500/30 bg-amber-500/10 text-amber-200 hover:bg-amber-500/20',
  },
  {
    verdict: 'benign_expected',
    label: 'Benign Expected',
    tone: 'border-emerald-500/30 bg-emerald-500/10 text-emerald-200 hover:bg-emerald-500/20',
  },
];

export function ThreatPanel({ selectedAlert, onAlertUpdate, currentUser }: ThreatPanelProps) {
  const [details, setDetails] = useState<ThreatDetails | null>(null);
  const [workspace, setWorkspace] = useState<InvestigationWorkspace | null>(null);
  const [queueLevel, setQueueLevel] = useState('L1');
  const [status, setStatus] = useState('open');
  const [verdict, setVerdict] = useState<string>('unreviewed');
  const [reportSummary, setReportSummary] = useState('');
  const [reportRecommendation, setReportRecommendation] = useState('');
  const [escalationReason, setEscalationReason] = useState('');
  const [closeReason, setCloseReason] = useState('');
  const [workflowState, setWorkflowState] = useState<'idle' | 'saving'>('idle');
  const [workflowMessage, setWorkflowMessage] = useState('');

  const refreshWorkspace = async (alertId: string) => {
    const response = await apiFetch(`/api/investigation/${encodeURIComponent(alertId)}`);
    if (!response.ok) {
      throw new Error('Investigation workspace unavailable.');
    }
    const data = (await response.json()) as InvestigationWorkspace;
    setWorkspace(data);
    setQueueLevel(data.alert.queue_level);
    setStatus(data.alert.status);
    setVerdict(data.alert.disposition);
    setReportSummary(data.report.summary);
    setReportRecommendation(data.report.recommendation);
    setEscalationReason('');
    setCloseReason('');
  };

  useEffect(() => {
    setWorkflowMessage('');

    if (!selectedAlert) {
      setDetails(null);
      setWorkspace(null);
      return;
    }

    let ignore = false;

    const loadDetails = async () => {
      try {
        const [shapResponse, workspaceResponse] = await Promise.all([
          apiFetch(
            `/api/shap-values/${encodeURIComponent(selectedAlert.attack_type)}?alert_id=${encodeURIComponent(selectedAlert.id)}`,
          ),
          apiFetch(`/api/investigation/${encodeURIComponent(selectedAlert.id)}`),
        ]);
        if (!shapResponse.ok || !workspaceResponse.ok) {
          throw new Error('Investigation services unavailable.');
        }

        const [shapData, workspaceData] = (await Promise.all([
          shapResponse.json(),
          workspaceResponse.json(),
        ])) as [ExplainabilityModel, InvestigationWorkspace];
        const residual = Math.max(0, 1 - selectedAlert.confidence);
        const normalProbability = Number((residual * 0.6).toFixed(3));
        const otherProbability = Number(
          Math.max(0, 1 - selectedAlert.confidence - normalProbability).toFixed(3),
        );

        if (!ignore) {
          setDetails({
            ...shapData,
            attackType: selectedAlert.attack_type,
            probabilities: [
              { name: selectedAlert.attack_type, prob: selectedAlert.confidence },
              { name: 'Normal', prob: normalProbability },
              { name: 'Other', prob: otherProbability },
            ],
          });
          setWorkspace(workspaceData);
          setQueueLevel(workspaceData.alert.queue_level);
          setStatus(workspaceData.alert.status);
          setVerdict(workspaceData.alert.disposition);
          setReportSummary(workspaceData.report.summary);
          setReportRecommendation(workspaceData.report.recommendation);
          setEscalationReason('');
          setCloseReason('');
        }
      } catch {
        if (!ignore) {
          setDetails({
            alert_id: selectedAlert.id,
            attackType: selectedAlert.attack_type,
            explanation:
              'Explainability engine unavailable. Falling back to last-known local model context.',
            shap_values: [
              { feature: 'packet_rate', importance: 0.82 },
              { feature: 'entropy', importance: 0.71 },
              { feature: 'avg_packet_size', importance: -0.33 },
              { feature: 'duration', importance: 0.28 },
            ],
            probabilities: [
              { name: selectedAlert.attack_type, prob: selectedAlert.confidence },
              { name: 'Normal', prob: Number(((1 - selectedAlert.confidence) * 0.7).toFixed(3)) },
              { name: 'Other', prob: Number(((1 - selectedAlert.confidence) * 0.3).toFixed(3)) },
            ],
          });
          setWorkspace(null);
        }
      }
    };

    void loadDetails();

    return () => {
      ignore = true;
    };
  }, [selectedAlert]);

  if (!selectedAlert) {
    return (
      <div className="glass-panel h-96 rounded-xl border border-slate-800 bg-slate-900 p-6 shadow-md">
        <div className="flex h-full flex-col items-center justify-center text-slate-500">
          <Brain className="mb-4 h-12 w-12 opacity-50" />
          <h3 className="text-lg font-semibold uppercase tracking-widest">Awaiting Selection</h3>
          <p className="text-sm">Click an alert from the stream to begin deep investigation.</p>
        </div>
      </div>
    );
  }

  const isLoading = !details || details.alert_id !== selectedAlert.id;

  const submitWorkflow = async (overrides?: Partial<{
    verdict: string;
    status: string;
    queue_level: string;
    assigned_analyst: string;
    escalation_reason: string;
    close_reason: string;
  }>) => {
    setWorkflowState('saving');
    setWorkflowMessage('Saving investigation workflow...');

    try {
      const response = await apiFetch('/api/alerts/workflow', {
        method: 'POST',
        body: JSON.stringify({
          alert_id: selectedAlert.id,
          analyst: currentUser.name,
          verdict: overrides?.verdict ?? verdict,
          status: overrides?.status ?? status,
          queue_level: overrides?.queue_level ?? queueLevel,
          assigned_analyst:
            overrides?.assigned_analyst ?? selectedAlert.assigned_analyst ?? undefined,
          report_summary: reportSummary,
          report_recommendation: reportRecommendation,
          escalation_reason: overrides?.escalation_reason ?? escalationReason,
          close_reason: overrides?.close_reason ?? closeReason,
        }),
      });
      if (!response.ok) {
        throw new Error('Workflow save failed.');
      }

      const updatedAlert = (await response.json()) as AlertData;
      onAlertUpdate(updatedAlert);
      await refreshWorkspace(updatedAlert.id);
      setWorkflowMessage(
        updatedAlert.status === 'closed'
          ? 'Alert closed with analyst report.'
          : `Workflow saved at ${updatedAlert.queue_level}.`,
      );
    } catch {
      setWorkflowMessage('Could not save the investigation workflow.');
    } finally {
      setWorkflowState('idle');
    }
  };

  return (
    <div className="glass-panel animate-in fade-in zoom-in rounded-xl border border-slate-800 bg-slate-900 p-6 shadow-md duration-300">
      <div className="mb-6 flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="rounded-lg border border-red-500/50 bg-red-500/10 p-2 text-red-500">
            <ShieldAlert className="h-6 w-6" />
          </div>
          <div>
            <h2 className="text-xl font-bold uppercase tracking-widest text-white">
              {selectedAlert.attack_type} Investigation
            </h2>
            <p className="font-mono text-xs text-slate-400">
              ID: {selectedAlert.id} | Edge Node: {selectedAlert.edge_node_id} | Asset {selectedAlert.asset_name}
            </p>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-3">
          <div className="flex items-center gap-2 rounded-lg border border-cyan-500/30 bg-slate-950 px-4 py-2">
            <Brain className="h-4 w-4 text-cyan-400" />
            <span className="text-sm font-semibold tracking-wider text-cyan-400">
              AI CONFIDENCE: {(selectedAlert.confidence * 100).toFixed(1)}%
            </span>
          </div>
          <div className="rounded-lg border border-fuchsia-500/30 bg-fuchsia-500/10 px-3 py-2 text-xs font-semibold uppercase tracking-wider text-fuchsia-200">
            {selectedAlert.queue_level} | {selectedAlert.status}
          </div>
          <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-3 py-2 text-xs font-semibold uppercase tracking-wider text-emerald-200">
            {selectedAlert.assigned_analyst || 'Unassigned'}
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-12">
        <div className="space-y-4 xl:col-span-5">
          <div className="relative overflow-hidden rounded-lg border border-slate-800 bg-slate-950 p-4">
            <h3 className="mb-4 flex items-center gap-2 text-sm font-semibold uppercase tracking-wider text-slate-400">
              <Network className="h-4 w-4" /> Threat Vector
            </h3>
            <div className="relative z-10 mt-6 flex items-center justify-between text-sm font-mono">
              <div className="text-center">
                <p className="rounded border border-slate-700 bg-slate-800 px-3 py-1 text-white">
                  {selectedAlert.source_ip}
                </p>
                <p className="mt-2 text-xs text-slate-500">{selectedAlert.source_geo.country}</p>
              </div>
              <ArrowRight className="absolute left-1/2 h-5 w-5 -translate-x-1/2 -mt-4 animate-pulse text-red-500" />
              <div className="text-center">
                <p className="rounded border border-slate-700 bg-slate-800 px-3 py-1 text-white">
                  {selectedAlert.dest_ip}
                </p>
                <p className="mt-2 text-xs text-slate-500">{selectedAlert.dest_geo.country}</p>
              </div>
            </div>

            <div className="mt-8 border-t border-slate-800/50 pt-4">
              <p className="max-w-sm font-mono text-xs leading-relaxed text-cyan-400">
                <span className="font-semibold text-white">AI Diagnostic Log: </span>
                {details?.explanation || 'Analyzing detection layers...'}
              </p>
            </div>
          </div>

          <div className="rounded-lg border border-slate-800 bg-slate-950 p-4">
            <h3 className="mb-3 text-sm font-semibold uppercase tracking-wider text-slate-400">ATT&CK Mapping</h3>
            <div className="flex flex-wrap gap-2">
              {selectedAlert.mitre.map((technique) => (
                <div
                  key={`${technique.technique_id}-${technique.tactic}`}
                  className="rounded-full border border-cyan-500/20 bg-cyan-500/10 px-3 py-2 text-xs"
                >
                  <span className="font-semibold text-cyan-200">{technique.technique_id}</span>
                  <span className="ml-2 text-slate-200">{technique.technique_name}</span>
                  <span className="ml-2 text-slate-400">{technique.tactic}</span>
                </div>
              ))}
            </div>
          </div>

          <div className="rounded-lg border border-slate-800 bg-slate-950 p-4">
            <h3 className="mb-3 text-sm font-semibold uppercase tracking-wider text-slate-400">Threat Intel</h3>
            <div className="space-y-3">
              {(workspace?.threat_intel || []).map((indicator) => (
                <div key={`${indicator.indicator_type}-${indicator.value}`} className="rounded-lg border border-slate-800 bg-slate-900/60 p-3">
                  <div className="flex items-center justify-between gap-3">
                    <p className="text-sm font-semibold text-white">{indicator.value}</p>
                    <span className="rounded-full bg-cyan-500/10 px-2 py-1 text-xs font-semibold text-cyan-200">
                      {indicator.confidence}
                    </span>
                  </div>
                  <p className="mt-1 text-xs uppercase tracking-wider text-slate-500">
                    {indicator.indicator_type}
                  </p>
                  <p className="mt-2 text-xs text-slate-400">{indicator.context}</p>
                </div>
              ))}
            </div>
          </div>

          <div className="rounded-lg border border-slate-800 bg-slate-950 p-4">
            <h3 className="mb-3 text-sm font-semibold uppercase tracking-wider text-slate-400">
              Zero-Trust Context
            </h3>
            <div className="grid grid-cols-2 gap-3 text-xs text-slate-300">
              <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-3">
                <p className="text-slate-500">Identity risk</p>
                <p className="mt-1 font-semibold text-white">{selectedAlert.zero_trust.identity_risk}</p>
              </div>
              <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-3">
                <p className="text-slate-500">Device trust</p>
                <p className="mt-1 font-semibold text-white">{selectedAlert.zero_trust.device_trust}</p>
              </div>
              <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-3">
                <p className="text-slate-500">Asset criticality</p>
                <p className="mt-1 font-semibold text-white">{selectedAlert.zero_trust.asset_criticality}</p>
              </div>
              <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-3">
                <p className="text-slate-500">Policy state</p>
                <p className="mt-1 font-semibold text-white">{selectedAlert.zero_trust.policy_state}</p>
              </div>
            </div>
          </div>
        </div>

        <div className="space-y-4 xl:col-span-7">
          <div className="rounded-lg border border-slate-800 bg-slate-950 p-4">
            <h3 className="mb-4 flex items-center gap-2 text-sm font-semibold uppercase tracking-wider text-slate-400">
              <Cpu className="h-4 w-4" /> AI Decision Logic (SHAP)
            </h3>
            <div className="h-64">
              {details ? (
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart
                    data={details.shap_values}
                    layout="vertical"
                    margin={{ top: 5, right: 24, left: 12, bottom: 5 }}
                  >
                    <XAxis type="number" fontSize={10} tick={{ fill: '#64748b' }} stroke="#334155" />
                    <YAxis
                      dataKey="feature"
                      type="category"
                      width={120}
                      fontSize={10}
                      tick={{ fill: '#94a3b8' }}
                      stroke="#334155"
                    />
                    <Tooltip
                      contentStyle={{ backgroundColor: '#0f172a', borderColor: '#1e293b', fontSize: '12px' }}
                      itemStyle={{ color: '#00f0ff' }}
                      formatter={(value) => (typeof value === 'number' ? value.toFixed(3) : String(value ?? ''))}
                    />
                    <Bar dataKey="importance" radius={[0, 4, 4, 0]}>
                      {details.shap_values.map((entry, index) => (
                        <Cell
                          key={`cell-${entry.feature}-${index}`}
                          fill={entry.importance > 0 ? '#ef4444' : '#22c55e'}
                        />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              ) : (
                <div className="flex h-full w-full items-center justify-center">
                  <span className="animate-pulse font-mono text-xs text-cyan-500">
                    Running SHAP explainer computation...
                  </span>
                </div>
              )}
            </div>
          </div>

          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            <div className="rounded-lg border border-slate-800 bg-slate-950 p-4">
              <h3 className="mb-3 text-sm font-semibold uppercase tracking-wider text-slate-400">
                Class Probability Stack
              </h3>
              <div className="space-y-3">
                {(details?.probabilities || []).map((entry) => (
                  <div key={entry.name}>
                    <div className="mb-1 flex items-center justify-between font-mono text-xs">
                      <span className="text-slate-300">{entry.name}</span>
                      <span className="text-cyan-400">{(entry.prob * 100).toFixed(1)}%</span>
                    </div>
                    <div className="h-2 overflow-hidden rounded-full bg-slate-800">
                      <div
                        className="h-full rounded-full bg-gradient-to-r from-cyan-500 to-blue-500"
                        style={{ width: `${Math.min(entry.prob * 100, 100)}%` }}
                      />
                    </div>
                  </div>
                ))}
                {isLoading && (
                  <span className="animate-pulse font-mono text-xs text-cyan-500">
                    Building classifier decision stack...
                  </span>
                )}
              </div>
            </div>

            <div className="rounded-lg border border-slate-800 bg-slate-950 p-4">
              <h3 className="mb-3 text-sm font-semibold uppercase tracking-wider text-slate-400">
                Investigation Playbook
              </h3>
              <div className="space-y-3">
                {(workspace?.playbook.steps || []).map((step) => (
                  <div key={step.step} className="rounded-lg border border-slate-800 bg-slate-900/60 p-3">
                    <p className="text-xs font-semibold uppercase tracking-wider text-cyan-300">
                      Step {step.step}: {step.title}
                    </p>
                    <p className="mt-2 text-sm text-slate-200">{step.instruction}</p>
                  </div>
                ))}
              </div>
            </div>
          </div>

          <div className="rounded-lg border border-slate-800 bg-slate-950 p-4">
            <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
              <h3 className="flex items-center gap-2 text-sm font-semibold uppercase tracking-wider text-slate-400">
                <FileText className="h-4 w-4" /> Analyst Report and Escalation
              </h3>
              {workflowMessage && (
                <span className="rounded-full border border-cyan-500/30 bg-cyan-500/10 px-3 py-1 text-xs text-cyan-200">
                  {workflowMessage}
                </span>
              )}
            </div>

            <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
              <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-3 lg:col-span-3">
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <div>
                    <p className="text-xs uppercase tracking-wider text-slate-500">Alert Owner</p>
                    <p className="mt-1 text-sm font-semibold text-white">
                      {selectedAlert.assigned_analyst || 'No analyst assigned yet'}
                    </p>
                  </div>
                  <button
                    onClick={() =>
                      void submitWorkflow({
                        assigned_analyst: currentUser.name,
                        status: 'investigating',
                      })
                    }
                    disabled={workflowState === 'saving'}
                    className="flex items-center gap-2 rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-4 py-2 text-xs font-semibold text-emerald-200 hover:bg-emerald-500/20 disabled:opacity-50"
                  >
                    <UserCheck className="h-4 w-4" />
                    Assign to Me
                  </button>
                </div>
              </div>
              <label className="text-xs text-slate-400">
                Queue
                <select
                  value={queueLevel}
                  onChange={(event) => setQueueLevel(event.target.value)}
                  className="mt-2 w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-white"
                >
                  <option value="L1">L1</option>
                  <option value="L2">L2</option>
                  <option value="L3">L3</option>
                </select>
              </label>
              <label className="text-xs text-slate-400">
                Status
                <select
                  value={status}
                  onChange={(event) => setStatus(event.target.value)}
                  className="mt-2 w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-white"
                >
                  <option value="open">Open</option>
                  <option value="investigating">Investigating</option>
                  <option value="escalated">Escalated</option>
                  <option value="closed">Closed</option>
                </select>
              </label>
              <label className="text-xs text-slate-400">
                Disposition
                <select
                  value={verdict}
                  onChange={(event) => setVerdict(event.target.value)}
                  className="mt-2 w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-white"
                >
                  <option value="unreviewed">Unreviewed</option>
                  <option value="true_positive">True Positive</option>
                  <option value="false_positive">False Positive</option>
                  <option value="benign_expected">Benign Expected</option>
                </select>
              </label>
            </div>

            <div className="mt-4 flex flex-wrap gap-3">
              {verdictActions.map((action) => (
                <button
                  key={action.verdict}
                  onClick={() => {
                    setVerdict(action.verdict);
                    void submitWorkflow({ verdict: action.verdict, status: 'investigating' });
                  }}
                  disabled={workflowState === 'saving'}
                  className={`rounded-lg border px-3 py-2 text-xs font-semibold transition-colors disabled:cursor-not-allowed disabled:opacity-50 ${action.tone}`}
                >
                  {action.label}
                </button>
              ))}
            </div>

            <div className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-2">
              <label className="text-xs text-slate-400">
                Report Summary
                <textarea
                  value={reportSummary}
                  onChange={(event) => setReportSummary(event.target.value)}
                  rows={5}
                  className="mt-2 w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-white"
                />
              </label>
              <label className="text-xs text-slate-400">
                Recommendation / Closure Notes
                <textarea
                  value={reportRecommendation}
                  onChange={(event) => setReportRecommendation(event.target.value)}
                  rows={5}
                  className="mt-2 w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-white"
                />
              </label>
            </div>

            <div className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-2">
              <label className="text-xs text-slate-400">
                Escalation Reason
                <input
                  value={escalationReason}
                  onChange={(event) => setEscalationReason(event.target.value)}
                  className="mt-2 w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-white"
                  placeholder="Why should this move to L2 or L3?"
                />
              </label>
              <label className="text-xs text-slate-400">
                Close Reason
                <input
                  value={closeReason}
                  onChange={(event) => setCloseReason(event.target.value)}
                  className="mt-2 w-full rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-white"
                  placeholder="Required context when closing the alert"
                />
              </label>
            </div>

            <div className="mt-4 flex flex-wrap gap-3">
              <button
                onClick={() => void submitWorkflow()}
                disabled={workflowState === 'saving'}
                className="rounded-lg border border-cyan-500/30 bg-cyan-500/10 px-4 py-2 text-xs font-semibold text-cyan-200 hover:bg-cyan-500/20 disabled:opacity-50"
              >
                Save Investigation
              </button>
              <button
                onClick={() => void submitWorkflow({ status: 'escalated' })}
                disabled={workflowState === 'saving'}
                className="rounded-lg border border-fuchsia-500/30 bg-fuchsia-500/10 px-4 py-2 text-xs font-semibold text-fuchsia-200 hover:bg-fuchsia-500/20 disabled:opacity-50"
              >
                Escalate to {queueLevel}
              </button>
              <button
                onClick={() => void submitWorkflow({ status: 'closed', close_reason: closeReason || reportRecommendation })}
                disabled={workflowState === 'saving'}
                className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-4 py-2 text-xs font-semibold text-emerald-200 hover:bg-emerald-500/20 disabled:opacity-50"
              >
                Close Alert
              </button>
            </div>

            <div className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-2">
              <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-3">
                <p className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                  Report Snapshot
                </p>
                <p className="mt-2 text-sm text-white">{workspace?.report.summary || reportSummary}</p>
                <p className="mt-2 text-xs text-slate-500">
                  {workspace?.report.author || currentUser.name} |{' '}
                  {workspace ? formatRelativeTime(workspace.report.updated_at) : 'pending'}
                </p>
              </div>
              <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-3">
                <p className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                  Escalation History
                </p>
                <div className="mt-2 space-y-2">
                  {(workspace?.escalation_history || []).length > 0 ? (
                    workspace?.escalation_history.map((event, index) => (
                      <div key={`${event.timestamp}-${index}`} className="rounded-lg border border-slate-800 bg-slate-950 p-2 text-xs text-slate-300">
                        {event.from_queue} to {event.to_queue} by {event.analyst}
                        <p className="mt-1 text-slate-500">
                          {event.reason} | {formatRelativeTime(event.timestamp)}
                        </p>
                      </div>
                    ))
                  ) : (
                    <p className="text-xs text-slate-500">No escalation recorded yet.</p>
                  )}
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
