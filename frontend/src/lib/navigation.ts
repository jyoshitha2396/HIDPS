import {
  Activity,
  BellRing,
  BookOpenText,
  ChartColumnBig,
  ClipboardList,
  Cpu,
  Radar,
  Users,
  type LucideIcon,
} from 'lucide-react';
import type { AppView, AuthUser } from '../types';

export interface NavigationItem {
  icon: LucideIcon;
  label: string;
  shortLabel: string;
  view: AppView;
  description: string;
  section: string;
  allowedRoles?: string[];
}

export const NAV_ITEMS: NavigationItem[] = [
  {
    icon: Activity,
    label: 'Dashboard',
    shortLabel: 'Overview',
    view: 'dashboard',
    section: 'Operations',
    description:
      'Live command view for queue pressure, model runtime, telemetry health, and response readiness.',
  },
  {
    icon: BellRing,
    label: 'Alert queue',
    shortLabel: 'Queue',
    view: 'alerts',
    section: 'Operations',
    description: 'Triage detections, assign ownership, write reports, escalate, and close alerts.',
  },
  {
    icon: ChartColumnBig,
    label: 'SIEM',
    shortLabel: 'SIEM',
    view: 'analytics',
    section: 'Operations',
    description: 'Detection analytics, severity trends, source concentration, and benchmark scorecards.',
  },
  {
    icon: ClipboardList,
    label: 'Forensics',
    shortLabel: 'Forensics',
    view: 'logs-forensics',
    section: 'Operations',
    description: 'Searchable investigation records, packet fingerprints, raw features, and evidence pivots.',
  },
  {
    icon: Radar,
    label: 'Threat intel',
    shortLabel: 'Intel',
    view: 'threat-intelligence',
    section: 'Knowledge',
    description: 'Campaign context, MITRE coverage, risk regions, and priority investigation playbooks.',
  },
  {
    icon: Cpu,
    label: 'Sensor mesh',
    shortLabel: 'Nodes',
    view: 'edge-nodes',
    section: 'Knowledge',
    description: 'Edge node posture, telemetry collectors, latency, throughput, and rollout readiness.',
  },
  {
    icon: Users,
    label: 'SOC manager',
    shortLabel: 'Manager',
    view: 'access-control',
    section: 'Leadership',
    description: 'Staffing, performance, approvals, queue balance, and leadership oversight.',
    allowedRoles: ['SOC Manager', 'Compliance Lead'],
  },
  {
    icon: BookOpenText,
    label: 'Guide',
    shortLabel: 'Guide',
    view: 'settings',
    section: 'Leadership',
    description: 'Deployment wiring, model status, endpoint configuration, and demo integration guidance.',
  },
];

const VIEW_SET = new Set<AppView>(NAV_ITEMS.map((item) => item.view));

export function isAppView(value: string): value is AppView {
  return VIEW_SET.has(value as AppView) || value === 'demo-lab';
}

export function parseViewHash(hash: string): AppView {
  const normalized = hash.replace(/^#\/?/, '').trim();
  return isAppView(normalized) ? normalized : 'dashboard';
}

export function toViewHash(view: AppView) {
  return `#/${view}`;
}

export function getViewMeta(view: AppView) {
  return NAV_ITEMS.find((item) => item.view === view) || NAV_ITEMS[0];
}

export function getNavigationItemsForUser(user: AuthUser | null) {
  if (!user) {
    return [];
  }
  return NAV_ITEMS.filter((item) => !item.allowedRoles || item.allowedRoles.includes(user.role));
}

export function canAccessView(view: AppView, user: AuthUser | null) {
  if (view === 'demo-lab') {
    return true;
  }
  const item = getViewMeta(view);
  if (!user) {
    return false;
  }
  return !item.allowedRoles || item.allowedRoles.includes(user.role);
}
