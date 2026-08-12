import { useEffect, useRef, useState } from 'react';
import { AccessControlPage } from './components/AccessControlPage';
import { AlertsPage } from './components/AlertsPage';
import { DashboardPage } from './components/DashboardPage';
import { DemoLabPage } from './components/DemoLabPage';
import { EdgeNodesPage } from './components/EdgeNodesPage';
import { FullAnalyticsPage } from './components/FullAnalyticsPage';
import { LoginPage } from './components/LoginPage';
import { LogsForensicsPage } from './components/LogsForensicsPage';
import { SettingsPage } from './components/SettingsPage';
import { Sidebar } from './components/Sidebar';
import { ThreatIntelPage } from './components/ThreatIntelPage';
import { TopBar } from './components/TopBar';
import { ViewSwitcher } from './components/ViewSwitcher';
import {
  apiFetch,
  apiUrl,
  AUTH_EXPIRED_EVENT,
  clearStoredAuthSession,
  getEndpointConfigurationIssue,
  getStoredAuthSession,
  setStoredAuthSession,
  wsUrl,
} from './lib/api';
import { matchesAlertSearch } from './lib/insights';
import {
  canAccessView,
  getNavigationItemsForUser,
  getViewMeta,
  parseViewHash,
  toViewHash,
} from './lib/navigation';
import type {
  AlertData,
  AlertSocketMessage,
  AuthSession,
  AuthUser,
  AppView,
  ConnectionState,
  LoginRequest,
  LoginResponse,
  SimulationCommand,
} from './types';

export default function App() {
  const endpointConfigurationIssue = getEndpointConfigurationIssue();
  const [alerts, setAlerts] = useState<AlertData[]>([]);
  const [selectedAlert, setSelectedAlert] = useState<AlertData | null>(null);
  const [simulationActive, setSimulationActive] = useState(true);
  const [connectionState, setConnectionState] = useState<ConnectionState>('offline');
  const [searchQuery, setSearchQuery] = useState('');
  const [activeView, setActiveView] = useState<AppView>(() =>
    parseViewHash(globalThis.location?.hash || ''),
  );
  const [authSession, setAuthSession] = useState<AuthSession | null>(null);
  const [authReady, setAuthReady] = useState(false);
  const [loginPending, setLoginPending] = useState(false);
  const [loginError, setLoginError] = useState('');
  const socketRef = useRef<WebSocket | null>(null);
  const reconnectTimerRef = useRef<number | null>(null);
  const reconnectAttemptsRef = useRef(0);
  const simulationActiveRef = useRef(simulationActive);

  const mergeAlerts = (existing: AlertData[], incoming: AlertData[]) => {
    const byId = new Map(existing.map((alert) => [alert.id, alert]));
    incoming.forEach((alert) => {
      byId.set(alert.id, alert);
    });
    return Array.from(byId.values())
      .sort((left, right) => right.timestamp - left.timestamp)
      .slice(0, 120);
  };

  useEffect(() => {
    simulationActiveRef.current = simulationActive;
  }, [simulationActive]);

  useEffect(() => {
    const hydrateAuth = async () => {
      const storedSession = getStoredAuthSession();
      if (!storedSession || storedSession.expires_at <= Date.now() / 1000) {
        clearStoredAuthSession();
        setAuthSession(null);
        setAuthReady(true);
        return;
      }

      try {
        const response = await apiFetch('/api/auth/me');
        if (!response.ok) {
          throw new Error('Session validation failed.');
        }
        const user = (await response.json()) as AuthUser;
        const nextSession = { ...storedSession, user };
        setStoredAuthSession(nextSession);
        setAuthSession(nextSession);
      } catch {
        clearStoredAuthSession();
        setAuthSession(null);
      } finally {
        setAuthReady(true);
      }
    };

    const handleExpiredSession = () => {
      clearStoredAuthSession();
      setAuthSession(null);
      setAlerts([]);
      setSelectedAlert(null);
      setConnectionState('offline');
      setLoginError('Your session expired. Please sign in again.');
      setAuthReady(true);
    };

    void hydrateAuth();
    window.addEventListener(AUTH_EXPIRED_EVENT, handleExpiredSession);

    return () => {
      window.removeEventListener(AUTH_EXPIRED_EVENT, handleExpiredSession);
    };
  }, []);

  useEffect(() => {
    const syncFromHash = () => {
      setActiveView(parseViewHash(window.location.hash));
    };

    window.addEventListener('hashchange', syncFromHash);
    if (!window.location.hash) {
      window.history.replaceState(null, '', toViewHash(activeView));
    }

    return () => {
      window.removeEventListener('hashchange', syncFromHash);
    };
  }, [activeView]);

  useEffect(() => {
    const nextHash = toViewHash(activeView);
    if (window.location.hash !== nextHash) {
      window.history.replaceState(null, '', nextHash);
    }
  }, [activeView]);

  useEffect(() => {
    if (activeView === 'demo-lab' || !authSession || canAccessView(activeView, authSession.user)) {
      return;
    }
    setActiveView('dashboard');
  }, [activeView, authSession]);

  useEffect(() => {
    if (!authSession) {
      return;
    }

    let ignore = false;

    const loadRecentAlerts = async () => {
      try {
        const response = await apiFetch('/api/alerts?limit=80');
        if (!response.ok) {
          throw new Error('Recent alerts unavailable.');
        }
        const recentAlerts = (await response.json()) as AlertData[];
        if (ignore) {
          return;
        }
        setAlerts((prev) => mergeAlerts(prev, recentAlerts));
        setSelectedAlert((prev) => {
          if (prev) {
            return recentAlerts.find((alert) => alert.id === prev.id) ?? prev;
          }
          return recentAlerts[0] ?? null;
        });
      } catch {
        // WebSocket bootstrap still provides a recent queue for live usage.
      }
    };

    void loadRecentAlerts();

    return () => {
      ignore = true;
    };
  }, [authSession]);

  useEffect(() => {
    if (!authSession) {
      socketRef.current?.close();
      socketRef.current = null;
      if (reconnectTimerRef.current !== null) {
        window.clearTimeout(reconnectTimerRef.current);
        reconnectTimerRef.current = null;
      }
      return;
    }

    let isMounted = true;

    const upsertIncomingAlert = (newAlert: AlertData) => {
      setAlerts((prev) => mergeAlerts(prev, [newAlert]));
      setSelectedAlert((prev) => (prev?.id === newAlert.id ? newAlert : prev ?? newAlert));
    };

    const clearReconnectTimer = () => {
      if (reconnectTimerRef.current !== null) {
        window.clearTimeout(reconnectTimerRef.current);
        reconnectTimerRef.current = null;
      }
    };

    const scheduleReconnect = () => {
      clearReconnectTimer();
      if (!isMounted) {
        return;
      }

      const delay = Math.min(1000 * 2 ** reconnectAttemptsRef.current, 10_000);
      reconnectAttemptsRef.current += 1;
      reconnectTimerRef.current = window.setTimeout(connect, delay);
    };

    const connect = () => {
      clearReconnectTimer();
      setConnectionState('connecting');

      const socket = new WebSocket(wsUrl('/ws/alerts', authSession.token));
      socketRef.current = socket;

      socket.onopen = () => {
        if (!isMounted) {
          return;
        }

        reconnectAttemptsRef.current = 0;
        setConnectionState('online');
        const bootstrapCommand: SimulationCommand = simulationActiveRef.current
          ? 'NORMAL_TRAFFIC'
          : 'STOP_SIMULATION';
        socket.send(bootstrapCommand);
      };

      socket.onmessage = (event) => {
        const message = JSON.parse(event.data) as AlertSocketMessage;
        if (message.type !== 'NEW_ALERT') {
          return;
        }

        upsertIncomingAlert(message.data);
      };

      socket.onerror = () => {
        if (isMounted) {
          setConnectionState('offline');
        }
      };

      socket.onclose = (event) => {
        if (socketRef.current === socket) {
          socketRef.current = null;
        }

        if (!isMounted) {
          return;
        }

        if (event.code === 4401) {
          clearStoredAuthSession();
          setAuthSession(null);
          setLoginError('Your session is no longer valid. Please sign in again.');
          setConnectionState('offline');
          return;
        }

        setConnectionState('offline');
        scheduleReconnect();
      };
    };

    connect();

    return () => {
      isMounted = false;
      clearReconnectTimer();
      socketRef.current?.close();
      socketRef.current = null;
    };
  }, [authSession]);

  const handleLogin = async (credentials: LoginRequest) => {
    setLoginPending(true);
    setLoginError('');

    try {
      const response = await fetch(apiUrl('/api/auth/login'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(credentials),
      });
      const payload = (await response.json()) as LoginResponse | { detail?: string };
      if (!response.ok) {
        const errorPayload = payload as { detail?: string };
        setLoginError(errorPayload.detail || 'Could not sign in.');
        return;
      }

      const loginPayload = payload as LoginResponse;
      const nextSession: AuthSession = {
        token: loginPayload.token,
        expires_at: loginPayload.expires_at,
        user: loginPayload.user,
      };
      setStoredAuthSession(nextSession);
      setAuthSession(nextSession);
      setActiveView('dashboard');
      setAlerts([]);
      setSelectedAlert(null);
      setConnectionState('connecting');
    } catch {
      setLoginError(
        endpointConfigurationIssue ||
          `Could not reach the authentication service at ${apiUrl('/api/auth/login')}.`,
      );
    } finally {
      setLoginPending(false);
      setAuthReady(true);
    }
  };

  const handleLogout = async () => {
    try {
      await apiFetch('/api/auth/logout', { method: 'POST' });
    } catch {
      // Allow local logout even if the backend session is already gone.
    }
    clearStoredAuthSession();
    setAuthSession(null);
    setAlerts([]);
    setSelectedAlert(null);
    setConnectionState('offline');
    setSearchQuery('');
  };

  const toggleSimulation = () => {
    const socket = socketRef.current;
    if (!socket || socket.readyState !== WebSocket.OPEN) {
      return;
    }

    const nextCommand: SimulationCommand = simulationActive
      ? 'STOP_SIMULATION'
      : 'START_SIMULATION';
    socket.send(nextCommand);
    setSimulationActive((current) => !current);
  };

  const filteredAlerts = alerts.filter((alert) => matchesAlertSearch(alert, searchQuery));
  const activeThreatCount = filteredAlerts.filter(
    (alert) => alert.severity === 'Critical' || alert.severity === 'High',
  ).length;
  const activeViewMeta = getViewMeta(activeView);
  const investigateFromLogs = (alert: AlertData) => {
    setSelectedAlert(alert);
  };

  const syncAlertUpdate = (nextAlert: AlertData) => {
    setAlerts((prev) => mergeAlerts(prev, [nextAlert]));
    setSelectedAlert((prev) => (prev?.id === nextAlert.id ? nextAlert : prev));
  };

  if (!authReady) {
    if (activeView === 'demo-lab') {
      return <DemoLabPage authenticated={Boolean(authSession)} />;
    }
    return (
      <div className="flex min-h-screen items-center justify-center bg-[linear-gradient(180deg,#07101b_0%,#0a1220_48%,#09111d_100%)] text-slate-300">
        Validating secure session...
      </div>
    );
  }

  if (activeView === 'demo-lab') {
    return <DemoLabPage authenticated={Boolean(authSession)} />;
  }

  if (!authSession) {
    return (
      <LoginPage
        onLogin={handleLogin}
        isSubmitting={loginPending}
        errorMessage={loginError || endpointConfigurationIssue}
      />
    );
  }

  const navigationItems = getNavigationItemsForUser(authSession.user);

  const renderMainView = () => {
    switch (activeView) {
      case 'dashboard':
        return <DashboardPage alerts={filteredAlerts} />;
      case 'threat-intelligence':
        return <ThreatIntelPage alerts={filteredAlerts} />;
      case 'alerts':
        return (
          <AlertsPage
            alerts={filteredAlerts}
            selectedAlert={selectedAlert}
            onSelectAlert={setSelectedAlert}
            onAlertUpdate={syncAlertUpdate}
            currentUser={authSession.user}
          />
        );
      case 'edge-nodes':
        return <EdgeNodesPage alerts={filteredAlerts} connectionState={connectionState} />;
      case 'analytics':
        return <FullAnalyticsPage alerts={filteredAlerts} />;
      case 'logs-forensics':
        return (
          <LogsForensicsPage
            alerts={filteredAlerts}
            selectedAlert={selectedAlert}
            searchQuery={searchQuery}
            onInvestigateAlert={investigateFromLogs}
          />
        );
      case 'access-control':
        return <AccessControlPage />;
      case 'settings':
        return (
          <SettingsPage
            connectionState={connectionState}
            simulationActive={simulationActive}
          />
        );
      default:
        return null;
    }
  };

  return (
    <div className="flex h-screen overflow-hidden bg-[linear-gradient(180deg,#07101b_0%,#0a1220_48%,#09111d_100%)] font-sans text-slate-200">
      <Sidebar activeView={activeView} onSelectView={setActiveView} items={navigationItems} />
      <div className="flex min-w-0 flex-1 flex-col">
        <TopBar
          simulationActive={simulationActive}
          toggleSimulation={toggleSimulation}
          connectionState={connectionState}
          activeThreatCount={activeThreatCount}
          activeViewLabel={activeViewMeta.label}
          activeViewDescription={activeViewMeta.description}
          searchQuery={searchQuery}
          onSearchChange={setSearchQuery}
          currentUser={authSession.user}
          onLogout={handleLogout}
        />
        <ViewSwitcher
          activeView={activeView}
          onSelectView={setActiveView}
          items={navigationItems}
        />
        {renderMainView()}
      </div>
    </div>
  );
}
