import { useState } from 'react';
import { LockKeyhole, Radar, ShieldCheck, TriangleAlert } from 'lucide-react';
import { API_BASE_URL, WS_BASE_URL } from '../lib/api';
import type { LoginRequest } from '../types';

interface LoginPageProps {
  onLogin: (credentials: LoginRequest) => Promise<void>;
  isSubmitting: boolean;
  errorMessage: string;
}

const demoAccounts = [
  { label: 'SOC Manager', identifier: 'admin-01@nexussoc.local', password: 'NexusAdmin!2026' },
  { label: 'Threat Hunter', identifier: 'analyst-07@nexussoc.local', password: 'NexusHunter!2026' },
  { label: 'IR Engineer', identifier: 'responder-03@nexussoc.local', password: 'NexusRespond!2026' },
  { label: 'Compliance Lead', identifier: 'auditor-02@nexussoc.local', password: 'NexusAudit!2026' },
];

export function LoginPage({ onLogin, isSubmitting, errorMessage }: LoginPageProps) {
  const [identifier, setIdentifier] = useState(demoAccounts[1].identifier);
  const [password, setPassword] = useState(demoAccounts[1].password);

  return (
    <main className="min-h-screen overflow-auto bg-[radial-gradient(circle_at_top,_rgba(34,211,238,0.16),_transparent_32%),linear-gradient(180deg,_#020617_0%,_#0f172a_55%,_#020617_100%)] px-4 py-10 text-slate-100">
      <div className="mx-auto grid max-w-6xl gap-6 lg:grid-cols-[1.15fr_0.85fr]">
        <section className="rounded-[28px] border border-slate-800 bg-slate-950/80 p-8 shadow-[0_30px_120px_rgba(2,6,23,0.65)] backdrop-blur">
          <div className="inline-flex items-center gap-2 rounded-full border border-cyan-500/20 bg-cyan-500/10 px-4 py-2 text-xs font-semibold uppercase tracking-[0.2em] text-cyan-200">
            <Radar className="h-4 w-4" />
            Analyst Access Portal
          </div>
          <h1 className="mt-6 max-w-2xl font-serif text-4xl font-semibold leading-tight text-white">
            Secure analyst login for the NEXUS SOC operations console.
          </h1>
          <p className="mt-4 max-w-2xl text-sm leading-7 text-slate-300">
            Sessions are token-based, passwords are hashed, repeated failures trigger lockout,
            and manager actions remain role-gated after login.
          </p>

          <div className="mt-8 grid gap-4 md:grid-cols-3">
            <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-4">
              <ShieldCheck className="h-5 w-5 text-emerald-400" />
              <p className="mt-3 text-sm font-semibold text-white">Role-aware access</p>
              <p className="mt-2 text-xs leading-6 text-slate-400">
                Manager-only areas stay hidden and protected after authentication.
              </p>
            </div>
            <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-4">
              <LockKeyhole className="h-5 w-5 text-cyan-400" />
              <p className="mt-3 text-sm font-semibold text-white">Hardened sessions</p>
              <p className="mt-2 text-xs leading-6 text-slate-400">
                Access tokens expire automatically and the app returns to login on session loss.
              </p>
            </div>
            <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-4">
              <TriangleAlert className="h-5 w-5 text-amber-400" />
              <p className="mt-3 text-sm font-semibold text-white">Abuse controls</p>
              <p className="mt-2 text-xs leading-6 text-slate-400">
                Failed login bursts trigger account lockout to slow brute-force attempts.
              </p>
            </div>
          </div>
        </section>

        <section className="rounded-[28px] border border-slate-800 bg-slate-950/85 p-8 shadow-[0_30px_120px_rgba(15,23,42,0.7)] backdrop-blur">
          <h2 className="text-lg font-bold uppercase tracking-[0.2em] text-slate-300">Sign In</h2>
          <p className="mt-2 text-sm text-slate-400">
            Use email or analyst ID and your assigned password.
          </p>
          <button
            type="button"
            onClick={() => {
              globalThis.location.hash = '#/demo-lab';
            }}
            className="mt-4 rounded-2xl border border-emerald-500/20 bg-emerald-500/10 px-4 py-3 text-sm font-semibold text-emerald-100 transition hover:bg-emerald-500/18"
          >
            Open Live Demo Webpage
          </button>

          <div className="mt-6 rounded-2xl border border-slate-800 bg-slate-900/70 p-4">
            <p className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-400">
              Runtime Endpoints
            </p>
            <p className="mt-3 text-xs text-slate-500">REST API</p>
            <p className="mt-1 break-all font-mono text-xs text-slate-300">{API_BASE_URL}</p>
            <p className="mt-3 text-xs text-slate-500">WebSocket</p>
            <p className="mt-1 break-all font-mono text-xs text-slate-300">{WS_BASE_URL}</p>
          </div>

          <form
            className="mt-8 space-y-4"
            onSubmit={(event) => {
              event.preventDefault();
              void onLogin({ identifier, password });
            }}
          >
            <label className="block">
              <span className="text-xs uppercase tracking-[0.18em] text-slate-500">Identifier</span>
              <input
                type="text"
                value={identifier}
                onChange={(event) => setIdentifier(event.target.value)}
                className="mt-2 w-full rounded-2xl border border-slate-800 bg-slate-900 px-4 py-3 text-sm text-white outline-none transition focus:border-cyan-500/50"
                placeholder="analyst-07@nexussoc.local"
                autoComplete="username"
              />
            </label>
            <label className="block">
              <span className="text-xs uppercase tracking-[0.18em] text-slate-500">Password</span>
              <input
                type="password"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                className="mt-2 w-full rounded-2xl border border-slate-800 bg-slate-900 px-4 py-3 text-sm text-white outline-none transition focus:border-cyan-500/50"
                placeholder="Enter your password"
                autoComplete="current-password"
              />
            </label>

            {errorMessage && (
              <div className="rounded-2xl border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-200">
                {errorMessage}
              </div>
            )}

            <button
              type="submit"
              disabled={isSubmitting}
              className="w-full rounded-2xl border border-cyan-500/30 bg-cyan-500/10 px-4 py-3 text-sm font-semibold text-cyan-100 transition hover:bg-cyan-500/20 disabled:cursor-not-allowed disabled:opacity-60"
            >
              {isSubmitting ? 'Authenticating...' : 'Enter SOC Console'}
            </button>
          </form>

          <div className="mt-8 rounded-2xl border border-slate-800 bg-slate-900/70 p-4">
            <p className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-400">
              Demo Accounts
            </p>
            <div className="mt-4 space-y-3">
              {demoAccounts.map((account) => (
                <button
                  key={account.identifier}
                  type="button"
                  onClick={() => {
                    setIdentifier(account.identifier);
                    setPassword(account.password);
                  }}
                  className="w-full rounded-2xl border border-slate-800 bg-slate-950 px-4 py-3 text-left transition hover:border-cyan-500/30 hover:bg-slate-900"
                >
                  <p className="text-sm font-semibold text-white">{account.label}</p>
                  <p className="mt-1 text-xs text-slate-400">{account.identifier}</p>
                  <p className="mt-1 text-xs text-cyan-300">{account.password}</p>
                </button>
              ))}
            </div>
          </div>
        </section>
      </div>
    </main>
  );
}
