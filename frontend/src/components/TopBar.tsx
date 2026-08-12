import { useEffect, useState } from 'react';
import {
  Bell,
  Clock3,
  LogOut,
  PauseCircle,
  PlayCircle,
  Search,
  Shield,
  Wifi,
} from 'lucide-react';
import type { AuthUser, ConnectionState } from '../types';

interface TopBarProps {
  simulationActive: boolean;
  toggleSimulation: () => void;
  connectionState: ConnectionState;
  activeThreatCount: number;
  activeViewLabel: string;
  activeViewDescription: string;
  searchQuery: string;
  onSearchChange: (value: string) => void;
  currentUser: AuthUser;
  onLogout: () => void;
}

function formatElapsed(totalSeconds: number) {
  const hours = Math.floor(totalSeconds / 3600)
    .toString()
    .padStart(2, '0');
  const minutes = Math.floor((totalSeconds % 3600) / 60)
    .toString()
    .padStart(2, '0');
  const seconds = Math.floor(totalSeconds % 60)
    .toString()
    .padStart(2, '0');

  return `${hours}:${minutes}:${seconds}`;
}

export function TopBar({
  simulationActive,
  toggleSimulation,
  connectionState,
  activeThreatCount,
  activeViewLabel,
  activeViewDescription,
  searchQuery,
  onSearchChange,
  currentUser,
  onLogout,
}: TopBarProps) {
  const [elapsedSeconds, setElapsedSeconds] = useState(0);
  const [timeLabel, setTimeLabel] = useState(() =>
    new Date().toLocaleString([], {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    }),
  );

  useEffect(() => {
    const timerId = window.setInterval(() => {
      setTimeLabel(
        new Date().toLocaleString([], {
          month: 'short',
          day: 'numeric',
          hour: '2-digit',
          minute: '2-digit',
        }),
      );
      setElapsedSeconds((current) => (simulationActive ? current + 1 : current));
    }, 1000);

    return () => {
      window.clearInterval(timerId);
    };
  }, [simulationActive]);

  const userInitials = currentUser.name
    .split(/[\s-]+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((part) => part[0]?.toUpperCase() || '')
    .join('');

  const connectionTone =
    connectionState === 'online'
      ? 'border-emerald-500/25 bg-emerald-500/10 text-emerald-200'
      : connectionState === 'connecting'
        ? 'border-amber-500/25 bg-amber-500/10 text-amber-200'
        : 'border-red-500/25 bg-red-500/10 text-red-200';

  return (
    <header className="shrink-0 border-b border-white/6 bg-[#121d33]/95 px-4 py-4 backdrop-blur md:px-8">
      <div className="flex flex-col gap-4 xl:flex-row xl:items-center xl:justify-between">
        <div className="flex min-w-0 flex-1 items-start gap-4">
          <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-2xl border border-[#8fd11f]/18 bg-[#8fd11f]/10 text-[#a8eb37] xl:hidden">
            <Shield className="h-5 w-5" />
          </div>

          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-3">
              <h2 className="truncate text-2xl font-semibold text-white">{activeViewLabel}</h2>
              <span className="rounded-full border border-white/8 bg-white/4 px-3 py-1 text-[11px] font-semibold uppercase tracking-[0.18em] text-slate-400">
                {timeLabel}
              </span>
            </div>
            <p className="mt-1 max-w-3xl text-sm text-slate-400">{activeViewDescription}</p>
          </div>
        </div>

        <div className="flex flex-1 flex-col gap-3 xl:max-w-4xl">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500" />
            <input
              type="text"
              value={searchQuery}
              onChange={(event) => onSearchChange(event.target.value)}
              placeholder="Search alerts, indicators, IPs, playbooks, or nodes"
              className="w-full rounded-xl border border-white/6 bg-[#0f1728] py-2.5 pl-10 pr-4 text-sm text-slate-200 placeholder:text-slate-600 focus:border-[#8fd11f]/25 focus:outline-none focus:ring-1 focus:ring-[#8fd11f]/20"
            />
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <div className={`rounded-xl border px-3 py-2 text-xs font-semibold uppercase tracking-[0.18em] ${connectionTone}`}>
              <span className="flex items-center gap-2">
                <Wifi className="h-3.5 w-3.5" />
                {connectionState}
              </span>
            </div>

            <div className="rounded-xl border border-white/6 bg-[#0f1728] px-3 py-2 text-xs text-slate-300">
              <span className="font-semibold text-white">{activeThreatCount}</span> active threats
            </div>

            <div className="rounded-xl border border-[#8fd11f]/20 bg-[#8fd11f]/10 px-3 py-2 text-xs font-semibold text-[#c6f36d]">
              Scenario {formatElapsed(elapsedSeconds)}
            </div>

            <button
              onClick={toggleSimulation}
              disabled={connectionState !== 'online'}
              className={`flex items-center gap-2 rounded-xl border px-3 py-2 text-sm font-medium transition disabled:cursor-not-allowed disabled:opacity-50 ${
                simulationActive
                  ? 'border-amber-500/25 bg-amber-500/10 text-amber-200 hover:bg-amber-500/16'
                  : 'border-emerald-500/25 bg-emerald-500/10 text-emerald-200 hover:bg-emerald-500/16'
              }`}
            >
              {simulationActive ? (
                <PauseCircle className="h-4 w-4" />
              ) : (
                <PlayCircle className="h-4 w-4" />
              )}
              {simulationActive ? 'Pause simulation' : 'Resume simulation'}
            </button>

            <button className="relative rounded-xl border border-white/6 bg-[#0f1728] p-2.5 text-slate-400 transition hover:text-white">
              <Bell className="h-4 w-4" />
              <span className="absolute right-2 top-2 h-2 w-2 rounded-full bg-[#8fd11f]" />
            </button>

            <div className="ml-auto hidden items-center gap-3 rounded-xl border border-white/6 bg-[#0f1728] px-3 py-2 md:flex">
              <div className="flex h-8 w-8 items-center justify-center rounded-full bg-[#1a2741] text-xs font-bold text-[#c6f36d]">
                {userInitials || 'NA'}
              </div>
              <div className="leading-tight">
                <p className="text-sm font-semibold text-white">{currentUser.name}</p>
                <p className="text-xs text-slate-500">{currentUser.role}</p>
              </div>
            </div>

            <button
              onClick={onLogout}
              className="hidden items-center gap-2 rounded-xl border border-white/6 bg-[#0f1728] px-3 py-2 text-sm text-slate-300 transition hover:border-white/12 hover:text-white md:flex"
            >
              <LogOut className="h-4 w-4" />
              Sign out
            </button>

            <div className="flex items-center gap-2 rounded-xl border border-white/6 bg-[#0f1728] px-3 py-2 text-xs text-slate-400 md:hidden">
              <Clock3 className="h-3.5 w-3.5" />
              {timeLabel}
            </div>
          </div>
        </div>
      </div>
    </header>
  );
}
