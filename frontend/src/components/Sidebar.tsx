import { Shield, Sparkles } from 'lucide-react';
import type { NavigationItem } from '../lib/navigation';
import type { AppView } from '../types';

interface SidebarProps {
  activeView: AppView;
  onSelectView: (view: AppView) => void;
  items: NavigationItem[];
}

export function Sidebar({ activeView, onSelectView, items }: SidebarProps) {
  const sections = items.reduce<Record<string, NavigationItem[]>>((groups, item) => {
    groups[item.section] = [...(groups[item.section] || []), item];
    return groups;
  }, {});

  return (
    <aside className="hidden xl:flex w-[248px] shrink-0 border-r border-white/6 bg-[#19243b] flex-col">
      <div className="flex-1 overflow-y-auto px-7 py-8">
        <div className="flex items-center gap-4">
          <div className="flex h-14 w-14 items-center justify-center rounded-2xl border border-[#8fd11f]/20 bg-[#8fd11f]/10 text-[#a8eb37]">
            <Shield className="h-7 w-7" />
          </div>
          <div>
            <h1 className="text-lg font-semibold text-white">HIDPS SOC</h1>
            <p className="text-[11px] uppercase tracking-[0.24em] text-slate-500">
              AI defense console
            </p>
          </div>
        </div>

        <div className="mt-10 space-y-8">
          {Object.entries(sections).map(([section, sectionItems]) => (
            <div key={section}>
              <p className="px-1 text-[11px] font-semibold uppercase tracking-[0.22em] text-slate-500">
                {section}
              </p>
              <nav className="mt-3 space-y-1">
                {sectionItems.map((item) => {
                  const isActive = item.view === activeView;

                  return (
                    <button
                      key={item.view}
                      onClick={() => onSelectView(item.view)}
                      className={`group flex w-full items-center gap-3 rounded-xl px-3 py-3 text-left transition ${
                        isActive
                          ? 'bg-[#121d33] text-[#9ddb24] shadow-[inset_0_0_0_1px_rgba(143,209,31,0.18)]'
                          : 'text-slate-300 hover:bg-white/4 hover:text-white'
                      }`}
                    >
                      <span
                        className={`flex h-8 w-8 items-center justify-center rounded-lg border transition ${
                          isActive
                            ? 'border-[#8fd11f]/20 bg-[#8fd11f]/10 text-[#a8eb37]'
                            : 'border-white/6 bg-[#152033] text-slate-400'
                        }`}
                      >
                        <item.icon className="h-4 w-4" />
                      </span>
                      <span className="min-w-0">
                        <span className="block truncate text-sm font-medium">{item.label}</span>
                        <span className="block truncate text-[11px] text-slate-500">
                          {item.shortLabel}
                        </span>
                      </span>
                    </button>
                  );
                })}
              </nav>
            </div>
          ))}
        </div>
      </div>

      <div className="border-t border-white/6 px-7 py-6">
        <div className="rounded-2xl border border-white/6 bg-[#121d33] p-4">
          <div className="flex items-center gap-2 text-sm font-semibold text-white">
            <Sparkles className="h-4 w-4 text-[#a8eb37]" />
            Demo ready
          </div>
          <p className="mt-3 text-xs leading-6 text-slate-400">
            Use Dashboard for the live story, Alert queue for analyst actions, and Guide to verify
            the deployed model, API, and monitored webpage flow before you present.
          </p>
        </div>
      </div>
    </aside>
  );
}
