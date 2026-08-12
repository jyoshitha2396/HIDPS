import type { NavigationItem } from '../lib/navigation';
import type { AppView } from '../types';

interface ViewSwitcherProps {
  activeView: AppView;
  onSelectView: (view: AppView) => void;
  items: NavigationItem[];
}

export function ViewSwitcher({ activeView, onSelectView, items }: ViewSwitcherProps) {
  return (
    <div className="xl:hidden border-b border-white/6 bg-[#19243b] px-4 py-3">
      <div className="flex gap-2 overflow-x-auto pb-1">
        {items.map((item) => {
          const isActive = item.view === activeView;
          return (
            <button
              key={item.view}
              onClick={() => onSelectView(item.view)}
              className={`shrink-0 rounded-full border px-3 py-2 text-xs font-semibold transition ${
                isActive
                  ? 'border-[#8fd11f]/20 bg-[#8fd11f]/10 text-[#c6f36d]'
                  : 'border-white/6 bg-[#121d33] text-slate-400'
              }`}
            >
              {item.label}
            </button>
          );
        })}
      </div>
    </div>
  );
}
