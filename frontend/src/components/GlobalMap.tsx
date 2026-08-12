import { memo } from 'react';
import {
  ComposableMap,
  Geographies,
  Geography,
  Line,
  Marker,
  type GeographyFeature,
} from 'react-simple-maps';
import type { AlertData } from '../types';

const geoUrl = 'https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json';

interface GlobalMapProps {
  alerts: AlertData[];
}

interface AttackLine {
  id: string;
  from: [number, number];
  to: [number, number];
  severity: AlertData['severity'];
}

export const GlobalMap = memo(({ alerts }: GlobalMapProps) => {
  const lines: AttackLine[] = alerts
    .filter((alert) => alert.severity === 'Critical' || alert.severity === 'High')
    .map((alert) => ({
      id: alert.id,
      from: [alert.source_geo.lon, alert.source_geo.lat],
      to: [alert.dest_geo.lon, alert.dest_geo.lat],
      severity: alert.severity,
    }));

  return (
    <div className="glass-panel p-4 rounded-xl relative overflow-hidden bg-slate-900 border border-slate-800 shadow-md">
      <div className="flex justify-between items-center mb-4 relative z-10 px-2 pt-2">
        <div>
          <h2 className="text-xl font-bold text-white tracking-widest text-shadow-sm">GLOBAL ATTACK ORIGINS</h2>
          <p className="text-xs text-slate-400 uppercase tracking-wider">Live Threat Vector Tracing</p>
        </div>
        <div className="flex gap-4">
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 rounded-full bg-red-500 shadow-[0_0_8px_rgba(239,68,68,0.8)] animate-pulse" />
            <span className="text-xs font-semibold text-slate-300 uppercase">Critical</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 rounded-full bg-orange-500 shadow-[0_0_8px_rgba(249,115,22,0.8)]" />
            <span className="text-xs font-semibold text-slate-300 uppercase">High</span>
          </div>
        </div>
      </div>

      <div className="w-full h-[400px] relative pointer-events-none">
        <ComposableMap projection="geoMercator" projectionConfig={{ scale: 120, center: [0, 40] }}>
          <Geographies geography={geoUrl}>
            {({ geographies }: { geographies: GeographyFeature[] }) =>
              geographies.map((geo: GeographyFeature) => (
                <Geography
                  key={geo.rsmKey}
                  geography={geo}
                  fill="#1e293b"
                  stroke="#334155"
                  strokeWidth={0.5}
                  className="transition-all duration-300"
                  style={{
                    default: { outline: 'none' },
                    hover: { fill: '#334155', outline: 'none' },
                    pressed: { outline: 'none' },
                  }}
                />
              ))
            }
          </Geographies>

          {lines.map((line) => (
            <Line
              key={line.id}
              from={line.from}
              to={line.to}
              stroke={line.severity === 'Critical' ? '#ef4444' : '#f97316'}
              strokeWidth={2}
              strokeLinecap="round"
              className="animate-pulse"
              style={{
                strokeDasharray: '4 2',
              }}
            />
          ))}

          {lines.map((line) => (
            <Marker key={`marker-${line.id}`} coordinates={line.to}>
              <circle
                r={4}
                fill={line.severity === 'Critical' ? '#ef4444' : '#f97316'}
                className="animate-ping"
                fillOpacity={0.5}
              />
              <circle r={2} fill={line.severity === 'Critical' ? '#ef4444' : '#f97316'} />
            </Marker>
          ))}
        </ComposableMap>
      </div>

      <div className="absolute inset-0 pointer-events-none bg-[radial-gradient(circle_at_center,transparent_50%,rgba(15,23,42,0.7)_100%)] z-0" />
    </div>
  );
});
