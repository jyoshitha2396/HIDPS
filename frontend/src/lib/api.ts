import type { AuthSession } from '../types';

const locationHost = globalThis.location?.hostname || 'localhost';
const pageProtocol = globalThis.location?.protocol || 'http:';
const socketProtocol = pageProtocol === 'https:' ? 'wss:' : 'ws:';
const isLocalHostname =
  locationHost === 'localhost' ||
  locationHost === '127.0.0.1' ||
  locationHost === '0.0.0.0' ||
  locationHost.endsWith('.local');
export const AUTH_STORAGE_KEY = 'nexus-soc-auth-session';
export const AUTH_EXPIRED_EVENT = 'nexus-soc-auth-expired';
export const HAS_EXPLICIT_API_BASE_URL = Boolean(import.meta.env.VITE_API_BASE_URL);
export const HAS_EXPLICIT_WS_BASE_URL = Boolean(import.meta.env.VITE_WS_BASE_URL);

export const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL || `${pageProtocol}//${locationHost}:8000`;

export const WS_BASE_URL =
  import.meta.env.VITE_WS_BASE_URL || `${socketProtocol}//${locationHost}:8000`;

export function apiUrl(path: string) {
  return `${API_BASE_URL}${path}`;
}

export function getEndpointConfigurationIssue() {
  if (isLocalHostname || (HAS_EXPLICIT_API_BASE_URL && HAS_EXPLICIT_WS_BASE_URL)) {
    return '';
  }

  return 'Production endpoint variables are missing. Deploy the FastAPI backend separately, then set VITE_API_BASE_URL and VITE_WS_BASE_URL in Netlify.';
}

export function getStoredAuthSession(): AuthSession | null {
  const rawValue = globalThis.localStorage?.getItem(AUTH_STORAGE_KEY);
  if (!rawValue) {
    return null;
  }

  try {
    return JSON.parse(rawValue) as AuthSession;
  } catch {
    clearStoredAuthSession();
    return null;
  }
}

export function setStoredAuthSession(session: AuthSession) {
  globalThis.localStorage?.setItem(AUTH_STORAGE_KEY, JSON.stringify(session));
}

export function clearStoredAuthSession() {
  globalThis.localStorage?.removeItem(AUTH_STORAGE_KEY);
}

export function getCurrentAnalystName() {
  return getStoredAuthSession()?.user.name || 'Analyst';
}

export async function apiFetch(path: string, init: RequestInit = {}) {
  const headers = new Headers(init.headers);
  const authSession = getStoredAuthSession();

  if (authSession?.token) {
    headers.set('Authorization', `Bearer ${authSession.token}`);
  }

  if (init.body && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json');
  }

  const response = await fetch(apiUrl(path), {
    ...init,
    headers,
  });

  if (response.status === 401) {
    clearStoredAuthSession();
    globalThis.dispatchEvent(new CustomEvent(AUTH_EXPIRED_EVENT));
  }

  return response;
}

export function wsUrl(path: string, token?: string) {
  const targetUrl = new URL(`${WS_BASE_URL}${path}`);
  if (token) {
    targetUrl.searchParams.set('token', token);
  }
  return targetUrl.toString();
}
