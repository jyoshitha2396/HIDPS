import { useEffect, useState } from 'react';
import {
  Activity,
  Clock3,
  Gauge,
  ShieldCheck,
  Sparkles,
  TimerReset,
  UserPlus,
  UsersRound,
} from 'lucide-react';
import { apiFetch } from '../lib/api';
import { formatRelativeTime } from '../lib/insights';
import type {
  BenchmarkMetrics,
  CreateUserRequest,
  PendingAction,
  SocManagerOverview,
  UserAccount,
} from '../types';

const defaultForm: CreateUserRequest = {
  name: '',
  email: '',
  role: 'SOC Analyst',
  team: 'Detection',
  shift: 'Day',
  queue_level: 'L1',
};

const roleOptions = ['SOC Analyst', 'Threat Hunter', 'IR Engineer', 'SOC Manager', 'Compliance Lead'];
const teamOptions = ['Detection', 'Response', 'Governance', 'Threat Intel', 'Leadership'];
const shiftOptions = ['Day', 'Swing', 'Night'];
const queueOptions = ['L1', 'L2', 'L3'];

function formatSeconds(value: number) {
  if (!Number.isFinite(value) || value <= 0) {
    return '--';
  }

  if (value < 60) {
    return `${Math.round(value)}s`;
  }

  const minutes = value / 60;
  if (minutes < 60) {
    return `${minutes.toFixed(1)}m`;
  }

  return `${(minutes / 60).toFixed(1)}h`;
}

function formatPercent(value: number) {
  return `${(value * 100).toFixed(0)}%`;
}

function getWorkloadTone(score: number) {
  if (score >= 75) {
    return 'text-red-300 border-red-500/30 bg-red-500/10';
  }
  if (score >= 45) {
    return 'text-amber-300 border-amber-500/30 bg-amber-500/10';
  }
  return 'text-emerald-300 border-emerald-500/30 bg-emerald-500/10';
}

function getStatusTone(status: string) {
  const normalized = status.toLowerCase();
  if (normalized.includes('active') || normalized.includes('duty') || normalized.includes('monitor')) {
    return 'text-emerald-300 border-emerald-500/30 bg-emerald-500/10';
  }
  if (normalized.includes('review')) {
    return 'text-amber-300 border-amber-500/30 bg-amber-500/10';
  }
  return 'text-slate-300 border-slate-700 bg-slate-800/70';
}

export function AccessControlPage() {
  const [overview, setOverview] = useState<SocManagerOverview | null>(null);
  const [benchmark, setBenchmark] = useState<BenchmarkMetrics | null>(null);
  const [pendingActions, setPendingActions] = useState<PendingAction[]>([]);
  const [form, setForm] = useState<CreateUserRequest>(defaultForm);
  const [savingUser, setSavingUser] = useState(false);
  const [message, setMessage] = useState('');

  useEffect(() => {
    let ignore = false;

    const loadManagerData = async () => {
      try {
        const [overviewResponse, benchmarkResponse, pendingResponse] = await Promise.all([
          apiFetch('/api/manager/overview'),
          apiFetch('/api/metrics/benchmark'),
          apiFetch('/api/action/pending'),
        ]);
        if (!overviewResponse.ok || !benchmarkResponse.ok || !pendingResponse.ok) {
          throw new Error('Manager services unavailable.');
        }

        const [overviewData, benchmarkData, pendingData] = (await Promise.all([
          overviewResponse.json(),
          benchmarkResponse.json(),
          pendingResponse.json(),
        ])) as [SocManagerOverview, BenchmarkMetrics, PendingAction[]];

        if (!ignore) {
          setOverview(overviewData);
          setBenchmark(benchmarkData);
          setPendingActions(pendingData);
        }
      } catch {
        if (!ignore) {
          setOverview(null);
          setBenchmark(null);
          setPendingActions([]);
        }
      }
    };

    void loadManagerData();

    return () => {
      ignore = true;
    };
  }, []);

  const createUser = async () => {
    if (!form.name.trim() || !form.email.trim()) {
      setMessage('Name and email are required before creating a user.');
      return;
    }

    setSavingUser(true);
    setMessage('Creating new SOC user...');

    try {
      const response = await apiFetch('/api/manager/users', {
        method: 'POST',
        body: JSON.stringify({
          ...form,
          name: form.name.trim(),
          email: form.email.trim(),
        }),
      });

      if (!response.ok) {
        throw new Error('User creation failed.');
      }

      const createdUser = (await response.json()) as UserAccount;
      setOverview((current) => {
        if (!current) {
          return current;
        }

        return {
          ...current,
          total_users: current.total_users + 1,
          active_users: current.active_users + (createdUser.status === 'Active' ? 1 : 0),
          users: [createdUser, ...current.users],
          performance: [
            ...current.performance,
            {
              analyst: createdUser.name,
              role: createdUser.role,
              queue_level: createdUser.queue_level,
              assigned_alerts: 0,
              investigating_alerts: 0,
              escalated_alerts: 0,
              closed_alerts: 0,
              true_positive_rate: 0,
              false_positive_rate: 0,
              mtta_seconds: createdUser.queue_level === 'L1' ? 210 : createdUser.queue_level === 'L2' ? 248 : 277,
              mttd_seconds: createdUser.queue_level === 'L1' ? 320 : createdUser.queue_level === 'L2' ? 378 : 422,
              mttr_seconds: createdUser.queue_level === 'L1' ? 540 : createdUser.queue_level === 'L2' ? 637 : 713,
              workload_score: 0,
            },
          ],
        };
      });
      setForm(defaultForm);
      setMessage(
        createdUser.temporary_password
          ? `${createdUser.name} was added. Temporary password: ${createdUser.temporary_password}`
          : `${createdUser.name} was added to the SOC roster.`,
      );
    } catch {
      setMessage('Could not create the SOC user right now.');
    } finally {
      setSavingUser(false);
    }
  };

  const performance = overview?.performance ?? [];
  const users = overview?.users ?? [];
  const overloadedAnalysts = performance.filter((person) => person.workload_score >= 75);
  const fastestResponder = [...performance].sort((left, right) => left.mttr_seconds - right.mttr_seconds)[0];
  const strongestDetector = [...performance].sort((left, right) => left.mttd_seconds - right.mttd_seconds)[0];

  return (
    <main className="flex-1 space-y-4 overflow-auto p-4">
      <section className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
        <div className="glass-panel rounded-xl border border-slate-800 bg-slate-900 p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-xs uppercase tracking-wider text-slate-500">SOC Users</p>
              <p className="mt-2 text-3xl font-bold text-white">{overview?.total_users ?? '--'}</p>
            </div>
            <UsersRound className="h-6 w-6 text-cyan-400" />
          </div>
          <p className="mt-3 text-xs text-slate-400">
            {overview
              ? `${overview.active_users} active across analyst, response, and manager queues.`
              : 'User roster will populate when the backend is reachable.'}
          </p>
        </div>

        <div className="glass-panel rounded-xl border border-slate-800 bg-slate-900 p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-xs uppercase tracking-wider text-slate-500">Average MTTA</p>
              <p className="mt-2 text-3xl font-bold text-white">
                {overview ? formatSeconds(overview.average_mtta_seconds) : '--'}
              </p>
            </div>
            <Clock3 className="h-6 w-6 text-amber-400" />
          </div>
          <p className="mt-3 text-xs text-slate-400">Analyst acknowledgement speed across all queues.</p>
        </div>

        <div className="glass-panel rounded-xl border border-slate-800 bg-slate-900 p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-xs uppercase tracking-wider text-slate-500">Average MTTD</p>
              <p className="mt-2 text-3xl font-bold text-white">
                {overview ? formatSeconds(overview.average_mttd_seconds) : '--'}
              </p>
            </div>
            <Activity className="h-6 w-6 text-fuchsia-400" />
          </div>
          <p className="mt-3 text-xs text-slate-400">
            Detection quality and evidence recognition across the team.
          </p>
        </div>

        <div className="glass-panel rounded-xl border border-slate-800 bg-slate-900 p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-xs uppercase tracking-wider text-slate-500">Average MTTR</p>
              <p className="mt-2 text-3xl font-bold text-white">
                {overview ? formatSeconds(overview.average_mttr_seconds) : '--'}
              </p>
            </div>
            <TimerReset className="h-6 w-6 text-emerald-400" />
          </div>
          <p className="mt-3 text-xs text-slate-400">
            Mean closure and response time across current operations.
          </p>
        </div>
      </section>

      <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <div className="glass-panel rounded-xl border border-slate-800 bg-slate-900 p-4 xl:col-span-8">
          <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
            <div>
              <h2 className="text-lg font-bold tracking-wide text-white">SOC Manager Command View</h2>
              <p className="text-xs uppercase tracking-wider text-slate-400">
                Team health, incident pressure, and analyst performance baselines
              </p>
            </div>
            {message && (
              <span className="rounded-full border border-cyan-500/30 bg-cyan-500/10 px-3 py-2 text-xs text-cyan-200">
                {message}
              </span>
            )}
          </div>

          <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
            <div className="rounded-xl border border-slate-800 bg-slate-950 p-4">
              <p className="text-xs uppercase tracking-wider text-slate-500">Open alerts</p>
              <p className="mt-2 text-3xl font-bold text-white">{overview?.open_alerts ?? '--'}</p>
              <p className="mt-2 text-xs text-slate-400">Current queue volume needing coverage.</p>
            </div>
            <div className="rounded-xl border border-slate-800 bg-slate-950 p-4">
              <p className="text-xs uppercase tracking-wider text-slate-500">Escalated alerts</p>
              <p className="mt-2 text-3xl font-bold text-white">{overview?.escalated_alerts ?? '--'}</p>
              <p className="mt-2 text-xs text-slate-400">Cases already requiring L2 or L3 attention.</p>
            </div>
            <div className="rounded-xl border border-slate-800 bg-slate-950 p-4">
              <p className="text-xs uppercase tracking-wider text-slate-500">Pending approvals</p>
              <p className="mt-2 text-3xl font-bold text-white">{overview?.pending_approvals ?? '--'}</p>
              <p className="mt-2 text-xs text-slate-400">High-impact response actions awaiting sign-off.</p>
            </div>
            <div className="rounded-xl border border-slate-800 bg-slate-950 p-4">
              <p className="text-xs uppercase tracking-wider text-slate-500">Detection F1</p>
              <p className="mt-2 text-3xl font-bold text-white">
                {benchmark ? formatPercent(benchmark.f1_score) : '--'}
              </p>
              <p className="mt-2 text-xs text-slate-400">Overall detection quality from reviewed alerts.</p>
            </div>
          </div>

          <div className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-3">
            <div className="rounded-xl border border-slate-800 bg-slate-950 p-4">
              <div className="flex items-center gap-2">
                <ShieldCheck className="h-4 w-4 text-emerald-400" />
                <p className="text-sm font-semibold text-white">Best Responder</p>
              </div>
              {fastestResponder ? (
                <>
                  <p className="mt-3 text-xl font-bold text-white">{fastestResponder.analyst}</p>
                  <p className="mt-1 text-xs text-slate-400">
                    MTTR {formatSeconds(fastestResponder.mttr_seconds)} | {fastestResponder.role}
                  </p>
                </>
              ) : (
                <p className="mt-3 text-sm text-slate-400">
                  Performance data will appear once analysts start working alerts.
                </p>
              )}
            </div>

            <div className="rounded-xl border border-slate-800 bg-slate-950 p-4">
              <div className="flex items-center gap-2">
                <Sparkles className="h-4 w-4 text-fuchsia-400" />
                <p className="text-sm font-semibold text-white">Fastest Detector</p>
              </div>
              {strongestDetector ? (
                <>
                  <p className="mt-3 text-xl font-bold text-white">{strongestDetector.analyst}</p>
                  <p className="mt-1 text-xs text-slate-400">
                    MTTD {formatSeconds(strongestDetector.mttd_seconds)} | {strongestDetector.role}
                  </p>
                </>
              ) : (
                <p className="mt-3 text-sm text-slate-400">
                  Detection KPIs will appear when reviewed alerts exist.
                </p>
              )}
            </div>

            <div className="rounded-xl border border-slate-800 bg-slate-950 p-4">
              <div className="flex items-center gap-2">
                <Gauge className="h-4 w-4 text-amber-400" />
                <p className="text-sm font-semibold text-white">Capacity Risk</p>
              </div>
              <p className="mt-3 text-xl font-bold text-white">{overloadedAnalysts.length}</p>
              <p className="mt-1 text-xs text-slate-400">
                Analysts above safe workload threshold and needing redistribution.
              </p>
            </div>
          </div>
        </div>

        <div className="glass-panel rounded-xl border border-slate-800 bg-slate-900 p-4 xl:col-span-4">
          <div className="mb-4 flex items-center gap-2">
            <UserPlus className="h-4 w-4 text-cyan-400" />
            <div>
              <h2 className="text-lg font-bold tracking-wide text-white">Add SOC User</h2>
              <p className="text-xs uppercase tracking-wider text-slate-400">
                Provision new manager, analyst, or response coverage
              </p>
            </div>
          </div>

          <div className="space-y-3">
            <label className="block">
              <span className="text-xs uppercase tracking-wider text-slate-500">Name</span>
              <input
                type="text"
                value={form.name}
                onChange={(event) => setForm((current) => ({ ...current, name: event.target.value }))}
                placeholder="Analyst-21"
                className="mt-2 w-full rounded-lg border border-slate-800 bg-slate-950 px-3 py-2 text-sm text-slate-200 outline-none transition focus:border-cyan-500/50"
              />
            </label>

            <label className="block">
              <span className="text-xs uppercase tracking-wider text-slate-500">Email</span>
              <input
                type="email"
                value={form.email}
                onChange={(event) => setForm((current) => ({ ...current, email: event.target.value }))}
                placeholder="analyst-21@nexussoc.local"
                className="mt-2 w-full rounded-lg border border-slate-800 bg-slate-950 px-3 py-2 text-sm text-slate-200 outline-none transition focus:border-cyan-500/50"
              />
            </label>

            <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
              <label className="block">
                <span className="text-xs uppercase tracking-wider text-slate-500">Role</span>
                <select
                  value={form.role}
                  onChange={(event) => setForm((current) => ({ ...current, role: event.target.value }))}
                  className="mt-2 w-full rounded-lg border border-slate-800 bg-slate-950 px-3 py-2 text-sm text-slate-200 outline-none transition focus:border-cyan-500/50"
                >
                  {roleOptions.map((option) => (
                    <option key={option} value={option}>
                      {option}
                    </option>
                  ))}
                </select>
              </label>

              <label className="block">
                <span className="text-xs uppercase tracking-wider text-slate-500">Team</span>
                <select
                  value={form.team}
                  onChange={(event) => setForm((current) => ({ ...current, team: event.target.value }))}
                  className="mt-2 w-full rounded-lg border border-slate-800 bg-slate-950 px-3 py-2 text-sm text-slate-200 outline-none transition focus:border-cyan-500/50"
                >
                  {teamOptions.map((option) => (
                    <option key={option} value={option}>
                      {option}
                    </option>
                  ))}
                </select>
              </label>
            </div>

            <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
              <label className="block">
                <span className="text-xs uppercase tracking-wider text-slate-500">Shift</span>
                <select
                  value={form.shift}
                  onChange={(event) => setForm((current) => ({ ...current, shift: event.target.value }))}
                  className="mt-2 w-full rounded-lg border border-slate-800 bg-slate-950 px-3 py-2 text-sm text-slate-200 outline-none transition focus:border-cyan-500/50"
                >
                  {shiftOptions.map((option) => (
                    <option key={option} value={option}>
                      {option}
                    </option>
                  ))}
                </select>
              </label>

              <label className="block">
                <span className="text-xs uppercase tracking-wider text-slate-500">Queue Level</span>
                <select
                  value={form.queue_level}
                  onChange={(event) => setForm((current) => ({ ...current, queue_level: event.target.value }))}
                  className="mt-2 w-full rounded-lg border border-slate-800 bg-slate-950 px-3 py-2 text-sm text-slate-200 outline-none transition focus:border-cyan-500/50"
                >
                  {queueOptions.map((option) => (
                    <option key={option} value={option}>
                      {option}
                    </option>
                  ))}
                </select>
              </label>
            </div>

            <button
              onClick={() => void createUser()}
              disabled={savingUser}
              className="w-full rounded-lg border border-cyan-500/30 bg-cyan-500/10 px-3 py-3 text-sm font-semibold text-cyan-200 transition hover:bg-cyan-500/20 disabled:cursor-not-allowed disabled:opacity-60"
            >
              {savingUser ? 'Provisioning User...' : 'Create User'}
            </button>
          </div>
        </div>
      </section>

      <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <div className="glass-panel rounded-xl border border-slate-800 bg-slate-900 p-4 xl:col-span-5">
          <div className="mb-4">
            <h2 className="text-lg font-bold tracking-wide text-white">Team Roster</h2>
            <p className="text-xs uppercase tracking-wider text-slate-400">
              Current ownership, shifts, and queue placement
            </p>
          </div>
          <div className="space-y-3">
            {users.map((user) => (
              <div key={user.user_id} className="rounded-xl border border-slate-800 bg-slate-950 p-4">
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div>
                    <p className="text-sm font-semibold text-white">{user.name}</p>
                    <p className="text-xs text-cyan-300">{user.role}</p>
                  </div>
                  <span
                    className={`rounded-full border px-2 py-1 text-xs font-semibold ${getStatusTone(user.status)}`}
                  >
                    {user.status}
                  </span>
                </div>
                <div className="mt-3 grid grid-cols-2 gap-3 text-xs text-slate-400">
                  <div>
                    <p className="uppercase tracking-wider text-slate-500">Team</p>
                    <p className="mt-1 text-sm text-slate-200">{user.team}</p>
                  </div>
                  <div>
                    <p className="uppercase tracking-wider text-slate-500">Shift</p>
                    <p className="mt-1 text-sm text-slate-200">{user.shift}</p>
                  </div>
                  <div>
                    <p className="uppercase tracking-wider text-slate-500">Queue</p>
                    <p className="mt-1 text-sm text-slate-200">{user.queue_level}</p>
                  </div>
                  <div>
                    <p className="uppercase tracking-wider text-slate-500">Email</p>
                    <p className="mt-1 truncate text-sm text-slate-200">{user.email}</p>
                  </div>
                </div>
                <div className="mt-3 flex flex-wrap gap-2">
                  {user.permissions.slice(0, 4).map((permission) => (
                    <span
                      key={permission}
                      className="rounded-full border border-slate-700 px-2 py-1 text-[11px] text-slate-300"
                    >
                      {permission}
                    </span>
                  ))}
                </div>
              </div>
            ))}
            {users.length === 0 && (
              <div className="rounded-lg border border-slate-800 bg-slate-950 p-4 text-sm text-slate-400">
                Team members will appear here when the backend manager service is reachable.
              </div>
            )}
          </div>
        </div>

        <div className="glass-panel rounded-xl border border-slate-800 bg-slate-900 p-4 xl:col-span-7">
          <div className="mb-4">
            <h2 className="text-lg font-bold tracking-wide text-white">Analyst Performance Board</h2>
            <p className="text-xs uppercase tracking-wider text-slate-400">
              Individual MTTA, MTTD, MTTR, accuracy, and queue pressure
            </p>
          </div>
          <div className="space-y-3">
            {performance.map((person) => (
              <div
                key={`${person.analyst}-${person.queue_level}`}
                className="rounded-xl border border-slate-800 bg-slate-950 p-4"
              >
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div>
                    <p className="text-sm font-semibold text-white">{person.analyst}</p>
                    <p className="text-xs text-cyan-300">
                      {person.role} | {person.queue_level}
                    </p>
                  </div>
                  <span
                    className={`rounded-full border px-2 py-1 text-xs font-semibold ${getWorkloadTone(person.workload_score)}`}
                  >
                    Load {person.workload_score.toFixed(0)}
                  </span>
                </div>

                <div className="mt-4 grid grid-cols-2 gap-3 xl:grid-cols-4">
                  <div className="rounded-lg border border-slate-800 bg-slate-900/70 p-3">
                    <p className="text-[11px] uppercase tracking-wider text-slate-500">Assigned</p>
                    <p className="mt-2 text-xl font-bold text-white">{person.assigned_alerts}</p>
                  </div>
                  <div className="rounded-lg border border-slate-800 bg-slate-900/70 p-3">
                    <p className="text-[11px] uppercase tracking-wider text-slate-500">Investigating</p>
                    <p className="mt-2 text-xl font-bold text-white">{person.investigating_alerts}</p>
                  </div>
                  <div className="rounded-lg border border-slate-800 bg-slate-900/70 p-3">
                    <p className="text-[11px] uppercase tracking-wider text-slate-500">Escalated</p>
                    <p className="mt-2 text-xl font-bold text-white">{person.escalated_alerts}</p>
                  </div>
                  <div className="rounded-lg border border-slate-800 bg-slate-900/70 p-3">
                    <p className="text-[11px] uppercase tracking-wider text-slate-500">Closed</p>
                    <p className="mt-2 text-xl font-bold text-white">{person.closed_alerts}</p>
                  </div>
                </div>

                <div className="mt-4 grid grid-cols-2 gap-3 xl:grid-cols-5">
                  <div className="rounded-lg border border-slate-800 bg-slate-900/70 p-3">
                    <p className="text-[11px] uppercase tracking-wider text-slate-500">TP Rate</p>
                    <p className="mt-2 text-lg font-bold text-white">
                      {formatPercent(person.true_positive_rate)}
                    </p>
                  </div>
                  <div className="rounded-lg border border-slate-800 bg-slate-900/70 p-3">
                    <p className="text-[11px] uppercase tracking-wider text-slate-500">FP Rate</p>
                    <p className="mt-2 text-lg font-bold text-white">
                      {formatPercent(person.false_positive_rate)}
                    </p>
                  </div>
                  <div className="rounded-lg border border-slate-800 bg-slate-900/70 p-3">
                    <p className="text-[11px] uppercase tracking-wider text-slate-500">MTTA</p>
                    <p className="mt-2 text-lg font-bold text-white">{formatSeconds(person.mtta_seconds)}</p>
                  </div>
                  <div className="rounded-lg border border-slate-800 bg-slate-900/70 p-3">
                    <p className="text-[11px] uppercase tracking-wider text-slate-500">MTTD</p>
                    <p className="mt-2 text-lg font-bold text-white">{formatSeconds(person.mttd_seconds)}</p>
                  </div>
                  <div className="rounded-lg border border-slate-800 bg-slate-900/70 p-3">
                    <p className="text-[11px] uppercase tracking-wider text-slate-500">MTTR</p>
                    <p className="mt-2 text-lg font-bold text-white">{formatSeconds(person.mttr_seconds)}</p>
                  </div>
                </div>
              </div>
            ))}
            {performance.length === 0 && (
              <div className="rounded-lg border border-slate-800 bg-slate-950 p-4 text-sm text-slate-400">
                Analyst performance metrics will appear once manager telemetry is available.
              </div>
            )}
          </div>
        </div>
      </section>

      <section className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <div className="glass-panel rounded-xl border border-slate-800 bg-slate-900 p-4 xl:col-span-5">
          <div className="mb-4">
            <h2 className="text-lg font-bold tracking-wide text-white">Response Benchmark</h2>
            <p className="text-xs uppercase tracking-wider text-slate-400">
              Detection model quality and operational efficiency
            </p>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div className="rounded-lg border border-slate-800 bg-slate-950 p-3">
              <p className="text-xs uppercase tracking-wider text-slate-500">Precision</p>
              <p className="mt-2 text-2xl font-bold text-white">
                {benchmark ? formatPercent(benchmark.precision) : '--'}
              </p>
            </div>
            <div className="rounded-lg border border-slate-800 bg-slate-950 p-3">
              <p className="text-xs uppercase tracking-wider text-slate-500">Recall</p>
              <p className="mt-2 text-2xl font-bold text-white">
                {benchmark ? formatPercent(benchmark.recall) : '--'}
              </p>
            </div>
            <div className="rounded-lg border border-slate-800 bg-slate-950 p-3">
              <p className="text-xs uppercase tracking-wider text-slate-500">False-positive rate</p>
              <p className="mt-2 text-2xl font-bold text-white">
                {benchmark ? formatPercent(benchmark.false_positive_rate) : '--'}
              </p>
            </div>
            <div className="rounded-lg border border-slate-800 bg-slate-950 p-3">
              <p className="text-xs uppercase tracking-wider text-slate-500">Model latency</p>
              <p className="mt-2 text-2xl font-bold text-white">
                {benchmark ? `${benchmark.model_latency_ms.toFixed(1)}ms` : '--'}
              </p>
            </div>
          </div>
          <div className="mt-4 rounded-xl border border-slate-800 bg-slate-950 p-4">
            <p className="text-xs uppercase tracking-wider text-slate-500">ATT&CK coverage ratio</p>
            <p className="mt-2 text-3xl font-bold text-white">
              {benchmark ? formatPercent(benchmark.attack_coverage_ratio) : '--'}
            </p>
            <p className="mt-2 text-xs text-slate-400">
              Technique coverage blended into the manager scorecard for quarterly review.
            </p>
          </div>
        </div>

        <div className="glass-panel rounded-xl border border-slate-800 bg-slate-900 p-4 xl:col-span-7">
          <div className="mb-4">
            <h2 className="text-lg font-bold tracking-wide text-white">Approvals and Leadership Notes</h2>
            <p className="text-xs uppercase tracking-wider text-slate-400">
              Actions needing sign-off and current operational watchpoints
            </p>
          </div>
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            <div className="space-y-3">
              {pendingActions.slice(0, 4).map((action) => (
                <div key={action.action_id} className="rounded-xl border border-slate-800 bg-slate-950 p-4">
                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <div>
                      <p className="text-sm font-semibold text-white">{action.action_type}</p>
                      <p className="text-xs text-slate-500">
                        Target {action.target_ip} | Requested by {action.requested_by}
                      </p>
                    </div>
                    <span className="rounded-full border border-orange-500/30 bg-orange-500/10 px-2 py-1 text-xs font-semibold text-orange-300">
                      {action.risk_level}
                    </span>
                  </div>
                  <p className="mt-3 text-xs text-slate-400">{action.recommended_playbook}</p>
                  <p className="mt-3 text-xs text-slate-500">Created {formatRelativeTime(action.created_at)}</p>
                </div>
              ))}
              {pendingActions.length === 0 && (
                <div className="rounded-lg border border-slate-800 bg-slate-950 p-4 text-sm text-slate-400">
                  No approval backlog right now.
                </div>
              )}
            </div>

            <div className="space-y-3">
              <div className="rounded-xl border border-slate-800 bg-slate-950 p-4">
                <p className="text-sm font-semibold text-white">Leadership Focus</p>
                <p className="mt-3 text-sm text-slate-300">
                  Use this dashboard to balance queue load, provision new analysts during surge windows, and spot which people need coaching on acknowledgement, detection quality, or closure speed.
                </p>
              </div>
              <div className="rounded-xl border border-slate-800 bg-slate-950 p-4">
                <p className="text-sm font-semibold text-white">Current Recommendations</p>
                <div className="mt-3 space-y-2 text-sm text-slate-300">
                  <p>Redistribute work if workload exceeds 75 for any analyst.</p>
                  <p>Track MTTA drift when open-alert volume rises faster than active staffing.</p>
                  <p>Use FP rate and MTTR together before deciding training or escalation changes.</p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>
    </main>
  );
}
