import type { AlertData, AlertSeverity } from '../types';

interface ChartPoint {
  label: string;
  value: number;
}

interface TimeSeriesPoint {
  time: string;
  total: number;
  critical: number;
  medium: number;
}

export interface EdgeNodeSnapshot {
  nodeId: string;
  totalAlerts: number;
  criticalAlerts: number;
  highRiskAlerts: number;
  averageConfidence: number;
  lastSeen: number;
  status: 'Healthy' | 'Monitoring' | 'Critical';
  latencyMs: number;
  throughputMbps: number;
  syncState: 'Synced' | 'Lagging';
}

const severityScore: Record<AlertSeverity, number> = {
  Critical: 4,
  High: 3,
  Medium: 2,
  Low: 1,
};

export function formatRelativeTime(timestamp: number) {
  const deltaSeconds = Math.max(0, Math.floor(Date.now() / 1000 - timestamp));
  if (deltaSeconds < 60) {
    return `${deltaSeconds}s ago`;
  }
  if (deltaSeconds < 3600) {
    return `${Math.floor(deltaSeconds / 60)}m ago`;
  }
  return `${Math.floor(deltaSeconds / 3600)}h ago`;
}

export function matchesAlertSearch(alert: AlertData, searchQuery: string) {
  if (!searchQuery.trim()) {
    return true;
  }

  const query = searchQuery.toLowerCase();
  const haystack = [
    alert.id,
    alert.source_ip,
    alert.dest_ip,
    alert.attack_type,
    alert.severity,
    alert.edge_node_id,
    alert.source_geo.country,
    alert.dest_geo.country,
  ]
    .join(' ')
    .toLowerCase();

  return haystack.includes(query);
}

export function getSeverityTone(severity: AlertSeverity) {
  switch (severity) {
    case 'Critical':
      return 'text-red-300 bg-red-500/10 border-red-500/30';
    case 'High':
      return 'text-orange-300 bg-orange-500/10 border-orange-500/30';
    case 'Medium':
      return 'text-amber-300 bg-amber-500/10 border-amber-500/30';
    default:
      return 'text-emerald-300 bg-emerald-500/10 border-emerald-500/30';
  }
}

export function getThreatFamilies(alerts: AlertData[]): ChartPoint[] {
  const counts = new Map<string, number>();
  alerts.forEach((alert) => {
    if (alert.attack_type === 'Normal') {
      return;
    }
    counts.set(alert.attack_type, (counts.get(alert.attack_type) || 0) + 1);
  });

  return Array.from(counts.entries())
    .sort((left, right) => right[1] - left[1])
    .slice(0, 6)
    .map(([label, value]) => ({ label, value }));
}

export function getSourceCountries(alerts: AlertData[]): Array<ChartPoint & { critical: number }> {
  const countries = new Map<string, { value: number; critical: number }>();
  alerts.forEach((alert) => {
    const current = countries.get(alert.source_geo.country) || { value: 0, critical: 0 };
    current.value += 1;
    if (alert.severity === 'Critical') {
      current.critical += 1;
    }
    countries.set(alert.source_geo.country, current);
  });

  return Array.from(countries.entries())
    .sort((left, right) => right[1].value - left[1].value)
    .slice(0, 8)
    .map(([label, value]) => ({ label, value: value.value, critical: value.critical }));
}

export function getSeverityMix(alerts: AlertData[]): ChartPoint[] {
  const counts: Record<AlertSeverity, number> = {
    Critical: 0,
    High: 0,
    Medium: 0,
    Low: 0,
  };

  alerts.forEach((alert) => {
    counts[alert.severity] += 1;
  });

  return Object.entries(counts).map(([label, value]) => ({ label, value }));
}

export function getHourlySeries(alerts: AlertData[]): TimeSeriesPoint[] {
  if (alerts.length === 0) {
    return [
      { time: '10:00', total: 8, critical: 2, medium: 3 },
      { time: '10:05', total: 10, critical: 3, medium: 3 },
      { time: '10:10', total: 11, critical: 4, medium: 4 },
      { time: '10:15', total: 14, critical: 5, medium: 4 },
      { time: '10:20', total: 13, critical: 4, medium: 5 },
      { time: '10:25', total: 12, critical: 3, medium: 5 },
    ];
  }

  const buckets = new Map<string, TimeSeriesPoint>();

  [...alerts].reverse().forEach((alert) => {
    const time = new Date(alert.timestamp * 1000).toLocaleTimeString([], {
      hour: '2-digit',
      minute: '2-digit',
    });
    const current = buckets.get(time) || { time, total: 0, critical: 0, medium: 0 };
    current.total += 1;
    if (alert.severity === 'Critical' || alert.severity === 'High') {
      current.critical += 1;
    }
    if (alert.severity === 'Medium' || alert.severity === 'Low') {
      current.medium += 1;
    }
    buckets.set(time, current);
  });

  return Array.from(buckets.values()).slice(-8);
}

export function getEdgeNodeSnapshots(alerts: AlertData[]): EdgeNodeSnapshot[] {
  const grouped = new Map<string, AlertData[]>();
  alerts.forEach((alert) => {
    const current = grouped.get(alert.edge_node_id) || [];
    current.push(alert);
    grouped.set(alert.edge_node_id, current);
  });

  if (grouped.size === 0) {
    return ['Node-Alpha', 'Node-Beta', 'Node-Gamma', 'Node-Delta'].map((nodeId, index) => ({
      nodeId,
      totalAlerts: 0,
      criticalAlerts: 0,
      highRiskAlerts: 0,
      averageConfidence: 0.92,
      lastSeen: Date.now() / 1000 - index * 45,
      status: 'Healthy',
      latencyMs: 12 + index * 4,
      throughputMbps: 1.4 + index * 0.5,
      syncState: 'Synced',
    }));
  }

  return Array.from(grouped.entries())
    .map(([nodeId, nodeAlerts], index) => {
      const totalAlerts = nodeAlerts.length;
      const criticalAlerts = nodeAlerts.filter((alert) => alert.severity === 'Critical').length;
      const highRiskAlerts = nodeAlerts.filter(
        (alert) => alert.severity === 'Critical' || alert.severity === 'High',
      ).length;
      const averageConfidence =
        nodeAlerts.reduce((sum, alert) => sum + alert.confidence, 0) / totalAlerts;
      const lastSeen = Math.max(...nodeAlerts.map((alert) => alert.timestamp));
      const threatIndex =
        nodeAlerts.reduce((sum, alert) => sum + severityScore[alert.severity], 0) / totalAlerts;

      return {
        nodeId,
        totalAlerts,
        criticalAlerts,
        highRiskAlerts,
        averageConfidence,
        lastSeen,
        status:
          threatIndex >= 3.2 ? 'Critical' : threatIndex >= 2.2 ? 'Monitoring' : 'Healthy',
        latencyMs: 9 + highRiskAlerts * 2 + index * 3,
        throughputMbps: Number((0.8 + totalAlerts * 0.16).toFixed(1)),
        syncState: highRiskAlerts >= Math.max(4, totalAlerts / 2) ? 'Lagging' : 'Synced',
      } satisfies EdgeNodeSnapshot;
    })
    .sort((left, right) => right.totalAlerts - left.totalAlerts);
}

export function getTopSourceIps(alerts: AlertData[]): ChartPoint[] {
  const counts = new Map<string, number>();
  alerts.forEach((alert) => {
    counts.set(alert.source_ip, (counts.get(alert.source_ip) || 0) + 1);
  });
  return Array.from(counts.entries())
    .sort((left, right) => right[1] - left[1])
    .slice(0, 6)
    .map(([label, value]) => ({ label, value }));
}

export function getAverageConfidence(alerts: AlertData[]) {
  if (alerts.length === 0) {
    return 0;
  }
  return alerts.reduce((sum, alert) => sum + alert.confidence, 0) / alerts.length;
}

export function getUniqueSourceCount(alerts: AlertData[]) {
  return new Set(alerts.map((alert) => alert.source_ip)).size;
}

export function sortAlertsNewest(alerts: AlertData[]) {
  return [...alerts].sort((left, right) => right.timestamp - left.timestamp);
}
