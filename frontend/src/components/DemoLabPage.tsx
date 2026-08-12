import { useEffect, useRef, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  ArrowRight,
  Bot,
  DatabaseZap,
  Globe,
  Play,
  Search,
  Shield,
  ShieldAlert,
  Sparkles,
  Waves,
} from 'lucide-react';
import { API_BASE_URL, apiUrl } from '../lib/api';
import type { MonitoredEventResponse } from '../types';

interface DemoLabPageProps {
  authenticated: boolean;
}

interface DemoScenario {
  id: string;
  label: string;
  tone: string;
  description: string;
  payload: Record<string, unknown>;
}

interface DemoLogEntry {
  id: string;
  title: string;
  detail: string;
  tone: 'info' | 'success' | 'warning' | 'danger';
  createdAt: number;
}

const SUCCESS_PASSWORD = 'Correct!2026';
const DEMO_SCENARIOS: DemoScenario[] = [
  {
    id: 'browse',
    label: 'Normal browse',
    tone: 'border-emerald-500/20 bg-emerald-500/10 text-emerald-200',
    description: 'Generates low-risk browsing telemetry with no alert.',
    payload: {
      attack_type: 'AUTO',
      page_url: 'https://soc-dashboards.netlify.app/#/demo-lab',
      request_path: '/products?q=security+monitor',
      http_method: 'GET',
      asset_name: 'demo-commerce-portal',
      source_type: 'web-access',
      telemetry_source: 'web-monitor',
      features: {
        flow_duration: 1.4,
        packet_rate: 45,
        connection_rate: 1.8,
        payload_kb: 0.3,
        destination_port: 443,
        total_backward_packets: 12,
        total_length_bwd_packets: 18000,
        avg_packet_size: 340,
        packet_length_mean: 330,
        flow_bytes_per_s: 2300,
        flow_packets_per_s: 42,
        subflow_fwd_packets: 18,
      },
    },
  },
  {
    id: 'sqli',
    label: 'SQL injection probe',
    tone: 'border-amber-500/20 bg-amber-500/10 text-amber-200',
    description: 'Suspicious path tokens push the engine into Web Attack classification.',
    payload: {
      attack_type: 'AUTO',
      page_url: 'https://soc-dashboards.netlify.app/#/demo-lab',
      request_path: "/login?username=admin' OR 1=1 --",
      http_method: 'POST',
      asset_name: 'demo-commerce-portal',
      source_type: 'web-access',
      telemetry_source: 'web-monitor',
      features: {
        uri_entropy: 6.9,
        payload_kb: 3.2,
        packet_rate: 560,
        connection_rate: 11.2,
        destination_port: 443,
        total_backward_packets: 3,
        total_length_bwd_packets: 42000,
        avg_packet_size: 500,
        packet_length_mean: 480,
        flow_bytes_per_s: 12000,
        flow_packets_per_s: 480,
        subflow_fwd_packets: 20,
      },
    },
  },
  {
    id: 'dos',
    label: 'Traffic flood',
    tone: 'border-red-500/20 bg-red-500/10 text-red-200',
    description: 'High packet rate drives a DoS alert and containment recommendation.',
    payload: {
      attack_type: 'AUTO',
      page_url: 'https://soc-dashboards.netlify.app/#/demo-lab',
      request_path: '/checkout',
      http_method: 'POST',
      asset_name: 'checkout-api',
      source_type: 'web-access',
      telemetry_source: 'web-monitor',
      features: {
        packet_rate: 6200,
        connection_rate: 94,
        payload_kb: 0.8,
        destination_port: 443,
        total_backward_packets: 0,
        total_length_bwd_packets: 0,
        avg_packet_size: 270,
        packet_length_mean: 260,
        flow_bytes_per_s: 850000,
        flow_packets_per_s: 6100,
        subflow_fwd_packets: 300,
      },
    },
  },
  {
    id: 'infiltration',
    label: 'Data exfiltration',
    tone: 'border-fuchsia-500/20 bg-fuchsia-500/10 text-fuchsia-200',
    description: 'Large payload transfer simulates data theft or staged extraction.',
    payload: {
      attack_type: 'AUTO',
      page_url: 'https://soc-dashboards.netlify.app/#/demo-lab',
      request_path: '/api/export/customers',
      http_method: 'POST',
      asset_name: 'analytics-lake',
      source_type: 'web-access',
      telemetry_source: 'web-monitor',
      features: {
        payload_kb: 42,
        connection_rate: 8.8,
        destination_port: 443,
        total_backward_packets: 24,
        total_length_bwd_packets: 760000,
        avg_packet_size: 880,
        packet_length_mean: 860,
        flow_bytes_per_s: 250000,
        flow_packets_per_s: 340,
        subflow_fwd_packets: 52,
      },
    },
  },
  {
    id: 'zero-day',
    label: 'Zero-day dropper',
    tone: 'border-orange-500/20 bg-orange-500/10 text-orange-200',
    description: 'Explicit high-confidence exploit pattern for dramatic demo moments.',
    payload: {
      attack_type: 'Zero-day (GAN-generated)',
      page_url: 'https://soc-dashboards.netlify.app/#/demo-lab',
      request_path: '/wp-admin/upload.php',
      http_method: 'POST',
      asset_name: 'edge-mesh-controller',
      source_type: 'web-access',
      telemetry_source: 'web-monitor',
      auto_prevent: true,
      features: {
        confidence: 0.95,
        uri_entropy: 7.2,
        payload_kb: 12.8,
        connection_rate: 16.4,
        destination_port: 443,
        avg_packet_size: 920,
        packet_length_mean: 890,
        flow_bytes_per_s: 140000,
        flow_packets_per_s: 1200,
        subflow_fwd_packets: 42,
      },
    },
  },
  {
    id: 'evasion',
    label: 'Model evasion callback',
    tone: 'border-cyan-500/20 bg-cyan-500/10 text-cyan-200',
    description: 'Explicit adversarial activity with beacons and evasion score.',
    payload: {
      attack_type: 'Adversarial (FGSM/PGD)',
      page_url: 'https://soc-dashboards.netlify.app/#/demo-lab',
      request_path: '/api/metrics',
      http_method: 'GET',
      asset_name: 'edge-mesh-controller',
      source_type: 'dns',
      telemetry_source: 'web-monitor',
      auto_prevent: true,
      features: {
        confidence: 0.94,
        model_evasion_score: 0.96,
        dns_beacon_frequency: 18.3,
        entropy: 4.7,
        packet_rate: 920,
        destination_port: 53,
        total_backward_packets: 1,
        avg_packet_size: 240,
        packet_length_mean: 230,
        flow_bytes_per_s: 98000,
        flow_packets_per_s: 910,
        subflow_fwd_packets: 31,
      },
    },
  },
];

function randomSourceIp() {
  return `203.0.113.${Math.floor(Math.random() * 180) + 20}`;
}

function toneClass(tone: DemoLogEntry['tone']) {
  switch (tone) {
    case 'success':
      return 'text-emerald-200 border-emerald-500/20 bg-emerald-500/10';
    case 'warning':
      return 'text-amber-200 border-amber-500/20 bg-amber-500/10';
    case 'danger':
      return 'text-red-200 border-red-500/20 bg-red-500/10';
    default:
      return 'text-slate-200 border-white/8 bg-white/4';
  }
}

export function DemoLabPage({ authenticated }: DemoLabPageProps) {
  const [operatorName, setOperatorName] = useState('alex.hunter@busybrains.ai');
  const [password, setPassword] = useState('');
  const [searchTerm, setSearchTerm] = useState('telemetry gateway');
  const [autoPrevent, setAutoPrevent] = useState(true);
  const [loginFailures, setLoginFailures] = useState(0);
  const [runningSequence, setRunningSequence] = useState(false);
  const [lastDecision, setLastDecision] = useState<MonitoredEventResponse | null>(null);
  const [logs, setLogs] = useState<DemoLogEntry[]>([
    {
      id: 'boot',
      title: 'Demo page loaded',
      detail: 'This page is ready to post monitored browser activity into /api/model/evaluate.',
      tone: 'info',
      createdAt: Date.now(),
    },
  ]);
  const sequenceTimer = useRef<number | null>(null);

  const appendLog = (entry: Omit<DemoLogEntry, 'id' | 'createdAt'>) => {
    setLogs((current) => [
      {
        id: crypto.randomUUID(),
        createdAt: Date.now(),
        ...entry,
      },
      ...current,
    ].slice(0, 18));
  };

  const sendScenario = async (scenario: DemoScenario, overrides?: Record<string, unknown>) => {
    const payload = structuredClone(scenario.payload) as Record<string, unknown>;
    payload.source_ip = randomSourceIp();
    payload.auto_prevent = autoPrevent || Boolean(payload.auto_prevent);
    payload.requested_by = 'demo-lab';
    payload.timestamp = Math.floor(Date.now() / 1000);
    if (payload.features && typeof payload.features === 'object') {
      payload.features = {
        ...(payload.features as Record<string, unknown>),
        page_operator: operatorName,
        search_term: searchTerm,
      };
    }
    Object.assign(payload, overrides || {});

    appendLog({
      title: scenario.label,
      detail: `Submitting ${String(payload.request_path || '/') } to the backend model endpoint.`,
      tone: 'info',
    });

    try {
      const response = await fetch(apiUrl('/api/model/evaluate'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });

      if (!response.ok) {
        throw new Error(`Model endpoint returned ${response.status}.`);
      }

      const decision = (await response.json()) as MonitoredEventResponse;
      setLastDecision(decision);
      appendLog({
        title: decision.should_alert ? 'Alert created' : 'Telemetry observed',
        detail: `${decision.attack_type} | score ${decision.threat_score.toFixed(2)} | ${decision.severity}${decision.alert_id ? ` | ${decision.alert_id}` : ''}`,
        tone: decision.should_alert
          ? decision.severity === 'Critical' || decision.severity === 'High'
            ? 'danger'
            : 'warning'
          : 'success',
      });
    } catch (error) {
      appendLog({
        title: 'Demo request failed',
        detail: error instanceof Error ? error.message : 'Could not reach the monitored-event endpoint.',
        tone: 'danger',
      });
    }
  };

  const attemptLogin = async () => {
    const nextFailures = password === SUCCESS_PASSWORD ? 0 : loginFailures + 1;
    setLoginFailures(nextFailures);
    await sendScenario(
      nextFailures >= 5
        ? DEMO_SCENARIOS.find((item) => item.id === 'sqli')!
        : DEMO_SCENARIOS.find((item) => item.id === 'browse')!,
      {
        request_path: '/login',
        http_method: 'POST',
        features: {
          failed_logins: nextFailures,
          packet_rate: nextFailures >= 5 ? 420 : 80,
          connection_rate: nextFailures >= 5 ? 24 : 2.4,
          payload_kb: 0.8,
          destination_port: 443,
          total_backward_packets: 4,
          total_length_bwd_packets: 26000,
          avg_packet_size: 320,
          packet_length_mean: 310,
          flow_bytes_per_s: nextFailures >= 5 ? 14000 : 2600,
          flow_packets_per_s: nextFailures >= 5 ? 380 : 65,
          subflow_fwd_packets: nextFailures >= 5 ? 16 : 4,
        },
      },
    );
  };

  const startAttackChain = () => {
    if (runningSequence) {
      return;
    }
    setRunningSequence(true);
    const scenarioIds = ['browse', 'sqli', 'dos', 'infiltration', 'evasion'];
    let index = 0;

    appendLog({
      title: 'Auto scenario started',
      detail: 'Running a chained series of demo interactions for the live dashboard.',
      tone: 'warning',
    });

    const runNext = async () => {
      const scenario = DEMO_SCENARIOS.find((item) => item.id === scenarioIds[index]);
      if (scenario) {
        await sendScenario(scenario);
      }
      index += 1;
      if (index >= scenarioIds.length) {
        setRunningSequence(false);
        sequenceTimer.current = null;
        appendLog({
          title: 'Auto scenario complete',
          detail: 'The demo chain finished. Review the dashboard queue and analytics now.',
          tone: 'success',
        });
        return;
      }
      sequenceTimer.current = window.setTimeout(() => {
        void runNext();
      }, 2400);
    };

    void runNext();
  };

  useEffect(() => {
    return () => {
      if (sequenceTimer.current !== null) {
        window.clearTimeout(sequenceTimer.current);
      }
    };
  }, []);

  return (
    <main className="min-h-screen bg-[radial-gradient(circle_at_top_left,rgba(91,196,255,0.12),transparent_26%),linear-gradient(180deg,#08101d_0%,#0f1829_45%,#0a1220_100%)] px-4 py-8 text-slate-100">
      <div className="mx-auto flex w-full max-w-[1480px] flex-col gap-5">
        <section className="overflow-hidden rounded-[28px] border border-white/8 bg-[linear-gradient(135deg,#11203a_0%,#1b2742_52%,#101a2e_100%)]">
          <div className="flex flex-col gap-6 px-6 py-6 lg:flex-row lg:items-center lg:justify-between">
            <div className="max-w-3xl">
              <div className="inline-flex items-center gap-2 rounded-full border border-[#8fd11f]/20 bg-[#8fd11f]/10 px-4 py-2 text-[11px] font-semibold uppercase tracking-[0.22em] text-[#c6f36d]">
                <Shield className="h-4 w-4" />
                Monitored webpage
              </div>
              <h1 className="mt-5 text-4xl font-semibold leading-tight text-white">
                BusyBrains customer access portal demo
              </h1>
              <p className="mt-4 text-sm leading-7 text-slate-300">
                Every action on this page can generate browser telemetry, send it into your
                deployed model endpoint, and create live alerts inside the SOC dashboard.
              </p>
            </div>

            <div className="grid gap-3 sm:grid-cols-2">
              <div className="rounded-2xl border border-white/8 bg-[#0f182c]/80 px-4 py-4">
                <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Monitored API</p>
                <p className="mt-2 break-all font-mono text-sm text-slate-200">{API_BASE_URL}</p>
              </div>
              <div className="rounded-2xl border border-white/8 bg-[#0f182c]/80 px-4 py-4">
                <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Open next</p>
                <div className="mt-3 flex flex-wrap gap-2">
                  <button
                    onClick={() => {
                      globalThis.location.hash = authenticated ? '#/dashboard' : '#/dashboard';
                    }}
                    className="rounded-xl border border-white/8 bg-white/4 px-3 py-2 text-sm text-white"
                  >
                    {authenticated ? 'Return to dashboard' : 'Analyst sign in'}
                  </button>
                  <button
                    onClick={startAttackChain}
                    disabled={runningSequence}
                    className="inline-flex items-center gap-2 rounded-xl border border-[#8fd11f]/20 bg-[#8fd11f]/10 px-3 py-2 text-sm font-semibold text-[#c6f36d] disabled:opacity-60"
                  >
                    <Play className="h-4 w-4" />
                    {runningSequence ? 'Scenario running' : 'Run attack chain'}
                  </button>
                </div>
              </div>
            </div>
          </div>
        </section>

        <section className="grid grid-cols-1 gap-5 xl:grid-cols-[1.1fr_0.9fr]">
          <div className="space-y-5">
            <div className="rounded-[24px] border border-white/8 bg-[#f7fafc] p-6 text-slate-900 shadow-[0_24px_80px_rgba(2,12,27,0.25)]">
              <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-200 pb-4">
                <div>
                  <p className="text-sm font-semibold uppercase tracking-[0.18em] text-slate-500">
                    BusyBrains Workspace
                  </p>
                  <h2 className="mt-2 text-3xl font-semibold text-slate-950">
                    Account and operations portal
                  </h2>
                </div>
                <div className="rounded-full border border-emerald-200 bg-emerald-50 px-3 py-1 text-xs font-semibold uppercase tracking-[0.18em] text-emerald-700">
                  Monitored live
                </div>
              </div>

              <div className="mt-6 grid gap-6 lg:grid-cols-[1fr_0.92fr]">
                <div className="space-y-5">
                  <div className="rounded-2xl border border-slate-200 bg-white p-5">
                    <div className="flex items-center gap-2 text-sm font-semibold text-slate-700">
                      <Search className="h-4 w-4 text-slate-500" />
                      Product search
                    </div>
                    <div className="mt-4 flex gap-3">
                      <input
                        value={searchTerm}
                        onChange={(event) => setSearchTerm(event.target.value)}
                        className="flex-1 rounded-xl border border-slate-200 px-4 py-3 text-sm text-slate-900 outline-none focus:border-sky-400"
                        placeholder="Search telemetry gateway"
                      />
                      <button
                        onClick={() => void sendScenario(DEMO_SCENARIOS[0])}
                        className="rounded-xl bg-slate-950 px-4 py-3 text-sm font-semibold text-white"
                      >
                        Browse
                      </button>
                    </div>
                    <p className="mt-3 text-sm text-slate-500">
                      Use this for a safe baseline before you trigger threat scenarios.
                    </p>
                  </div>

                  <div className="rounded-2xl border border-slate-200 bg-white p-5">
                    <div className="flex items-center gap-2 text-sm font-semibold text-slate-700">
                      <ShieldAlert className="h-4 w-4 text-rose-500" />
                      Sign in panel
                    </div>
                    <div className="mt-4 space-y-3">
                      <input
                        value={operatorName}
                        onChange={(event) => setOperatorName(event.target.value)}
                        className="w-full rounded-xl border border-slate-200 px-4 py-3 text-sm text-slate-900 outline-none focus:border-sky-400"
                        placeholder="alex.hunter@busybrains.ai"
                      />
                      <input
                        value={password}
                        onChange={(event) => setPassword(event.target.value)}
                        type="password"
                        className="w-full rounded-xl border border-slate-200 px-4 py-3 text-sm text-slate-900 outline-none focus:border-sky-400"
                        placeholder="Password"
                      />
                    </div>
                    <div className="mt-4 flex flex-wrap gap-3">
                      <button
                        onClick={() => void attemptLogin()}
                        className="rounded-xl bg-slate-950 px-4 py-3 text-sm font-semibold text-white"
                      >
                        Attempt login
                      </button>
                      <button
                        onClick={() => {
                          setPassword(SUCCESS_PASSWORD);
                          setLoginFailures(0);
                          void sendScenario(DEMO_SCENARIOS[0], {
                            request_path: '/login/success',
                            http_method: 'POST',
                          });
                        }}
                        className="rounded-xl border border-slate-300 px-4 py-3 text-sm font-semibold text-slate-700"
                      >
                        Valid login
                      </button>
                    </div>
                    <p className="mt-3 text-sm text-slate-500">
                      Failed attempts tracked on this page: <span className="font-semibold">{loginFailures}</span>
                    </p>
                  </div>

                  <div className="rounded-2xl border border-slate-200 bg-white p-5">
                    <p className="text-sm font-semibold text-slate-700">High-risk scenario triggers</p>
                    <div className="mt-4 grid gap-3 sm:grid-cols-2">
                      {DEMO_SCENARIOS.slice(1).map((scenario) => (
                        <button
                          key={scenario.id}
                          onClick={() => void sendScenario(scenario)}
                          className={`rounded-2xl border px-4 py-4 text-left text-sm font-medium transition ${scenario.tone}`}
                        >
                          <span className="block text-base font-semibold">{scenario.label}</span>
                          <span className="mt-2 block text-xs leading-5 opacity-90">
                            {scenario.description}
                          </span>
                        </button>
                      ))}
                    </div>
                  </div>
                </div>

                <div className="space-y-5">
                  <div className="rounded-2xl border border-slate-200 bg-slate-950 p-5 text-white">
                    <div className="flex items-center gap-2 text-sm font-semibold text-slate-300">
                      <Globe className="h-4 w-4 text-sky-400" />
                      Network posture
                    </div>
                    <div className="mt-4 grid grid-cols-2 gap-3">
                      <div className="rounded-xl border border-white/8 bg-white/4 p-4">
                        <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Auto prevent</p>
                        <button
                          onClick={() => setAutoPrevent((current) => !current)}
                          className={`mt-3 rounded-xl px-3 py-2 text-sm font-semibold ${
                            autoPrevent ? 'bg-[#8fd11f] text-[#152033]' : 'bg-white/8 text-white'
                          }`}
                        >
                          {autoPrevent ? 'Enabled' : 'Recommended only'}
                        </button>
                      </div>
                      <div className="rounded-xl border border-white/8 bg-white/4 p-4">
                        <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Alert flow</p>
                        <p className="mt-3 text-sm text-slate-200">
                          Demo page <ArrowRight className="inline h-4 w-4 text-sky-400" /> model
                          endpoint <ArrowRight className="inline h-4 w-4 text-sky-400" /> dashboard
                        </p>
                      </div>
                    </div>
                  </div>

                  <div className="rounded-2xl border border-slate-200 bg-white p-5">
                    <div className="flex items-center gap-2 text-sm font-semibold text-slate-700">
                      <Bot className="h-4 w-4 text-sky-500" />
                      Last model decision
                    </div>

                    {lastDecision ? (
                      <div className="mt-4 space-y-3">
                        <div className="rounded-xl border border-slate-200 bg-slate-50 p-4">
                          <div className="flex items-center justify-between gap-3">
                            <div>
                              <p className="text-lg font-semibold text-slate-950">{lastDecision.attack_type}</p>
                              <p className="mt-1 text-sm text-slate-500">
                                {lastDecision.request_path || '/'} | {lastDecision.status}
                              </p>
                            </div>
                            <span className="rounded-full border border-slate-200 bg-white px-3 py-1 text-xs font-semibold text-slate-700">
                              {lastDecision.severity}
                            </span>
                          </div>
                        </div>

                        <div className="grid grid-cols-2 gap-3">
                          <div className="rounded-xl border border-slate-200 p-4">
                            <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Threat score</p>
                            <p className="mt-2 text-3xl font-semibold text-slate-950">
                              {(lastDecision.threat_score * 100).toFixed(0)}%
                            </p>
                          </div>
                          <div className="rounded-xl border border-slate-200 p-4">
                            <p className="text-xs uppercase tracking-[0.18em] text-slate-500">Confidence</p>
                            <p className="mt-2 text-3xl font-semibold text-slate-950">
                              {(lastDecision.confidence * 100).toFixed(0)}%
                            </p>
                          </div>
                        </div>

                        <div className="rounded-xl border border-slate-200 p-4 text-sm text-slate-700">
                          <p>
                            Alert generated:{' '}
                            <span className="font-semibold">{lastDecision.should_alert ? 'Yes' : 'No'}</span>
                          </p>
                          <p className="mt-2">
                            Recommended action:{' '}
                            <span className="font-semibold">
                              {lastDecision.recommended_action || 'None'}
                            </span>
                          </p>
                          <p className="mt-2">
                            Prevention:{' '}
                            <span className="font-semibold">{lastDecision.prevention_status}</span>
                          </p>
                          {lastDecision.alert_id && (
                            <p className="mt-2">
                              Alert ID: <span className="font-semibold">{lastDecision.alert_id}</span>
                            </p>
                          )}
                        </div>
                      </div>
                    ) : (
                      <div className="mt-4 rounded-xl border border-dashed border-slate-200 bg-slate-50 p-5 text-sm text-slate-500">
                        Trigger a scenario on the left to watch the backend score the event.
                      </div>
                    )}
                  </div>
                </div>
              </div>
            </div>
          </div>

          <div className="space-y-5">
            <div className="rounded-[24px] border border-white/8 bg-[#1a2741] p-5">
              <div className="flex items-center gap-2 text-sm font-semibold text-white">
                <DatabaseZap className="h-4 w-4 text-[#c6f36d]" />
                Live telemetry log
              </div>
              <div className="mt-4 space-y-3">
                {logs.map((entry) => (
                  <div key={entry.id} className={`rounded-xl border p-4 ${toneClass(entry.tone)}`}>
                    <div className="flex items-center justify-between gap-3">
                      <p className="text-sm font-semibold">{entry.title}</p>
                      <span className="text-[11px] uppercase tracking-[0.18em] opacity-80">
                        {new Date(entry.createdAt).toLocaleTimeString()}
                      </span>
                    </div>
                    <p className="mt-2 text-sm opacity-90">{entry.detail}</p>
                  </div>
                ))}
              </div>
            </div>

            <div className="rounded-[24px] border border-white/8 bg-[#1a2741] p-5">
              <div className="flex items-center gap-2 text-sm font-semibold text-white">
                <Sparkles className="h-4 w-4 text-[#c6f36d]" />
                Demo instructions
              </div>
              <div className="mt-4 space-y-3 text-sm text-slate-300">
                <p>1. Open this page in one tab.</p>
                <p>2. Open the SOC dashboard in another tab and log in.</p>
                <p>3. Trigger `SQL injection probe`, `Traffic flood`, or `Model evasion callback`.</p>
                <p>4. Watch the alert queue, dashboard cards, and forensics pages update live.</p>
              </div>
            </div>

            <div className="grid gap-4 sm:grid-cols-2">
              <div className="rounded-[24px] border border-white/8 bg-[#1a2741] p-5">
                <div className="flex items-center gap-2 text-sm font-semibold text-white">
                  <Waves className="h-4 w-4 text-sky-300" />
                  Safe flow
                </div>
                <p className="mt-3 text-sm text-slate-300">
                  Normal browsing keeps the score low and helps you explain the baseline state.
                </p>
              </div>
              <div className="rounded-[24px] border border-white/8 bg-[#1a2741] p-5">
                <div className="flex items-center gap-2 text-sm font-semibold text-white">
                  <AlertTriangle className="h-4 w-4 text-amber-300" />
                  High-risk flow
                </div>
                <p className="mt-3 text-sm text-slate-300">
                  Use attack-chain mode when you want several alert types to appear within one minute.
                </p>
              </div>
            </div>

            <div className="rounded-[24px] border border-white/8 bg-[#1a2741] p-5">
              <div className="flex items-center gap-2 text-sm font-semibold text-white">
                <Activity className="h-4 w-4 text-[#c6f36d]" />
                Hosted demo URL
              </div>
              <p className="mt-3 break-all font-mono text-sm text-slate-200">
                {globalThis.location.origin}/#/demo-lab
              </p>
            </div>
          </div>
        </section>
      </div>
    </main>
  );
}
