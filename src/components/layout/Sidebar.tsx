import React from 'react';
import {
  LayoutDashboard,
  ShieldAlert,
  Search,
  Crosshair,
  FileCheck,
  FileText,
  Settings,
  LogOut,
  ChevronRight,
  Shield,
  Radio,
} from 'lucide-react';
import { useForensics } from '../../context/ForensicContext';

interface SidebarProps {
  mobileOpen: boolean;
  setMobileOpen: (open: boolean) => void;
}

export const Sidebar: React.FC<SidebarProps> = ({ mobileOpen, setMobileOpen }) => {
  const { currentView, setCurrentView, cases, evidenceList, reports, currentUser, logout } = useForensics();

  const navItems = [
    { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard, count: undefined },
    { id: 'investigations', label: 'Investigations', icon: ShieldAlert, count: cases.length },
    { id: 'analyze', label: 'Analyze Email', icon: Search, count: undefined, highlight: true },
    { id: 'threat-intel', label: 'Threat Intelligence', icon: Crosshair, count: undefined },
    { id: 'evidence', label: 'Evidence', icon: FileCheck, count: evidenceList.length },
    { id: 'reports', label: 'Reports', icon: FileText, count: reports.length },
    { id: 'settings', label: 'Settings', icon: Settings, count: undefined },
  ];

  const handleNavClick = (id: string) => {
    setCurrentView(id);
    if (mobileOpen) setMobileOpen(false);
  };

  return (
    <>
      {/* Mobile Backdrop */}
      {mobileOpen && (
        <div
          className="fixed inset-0 z-40 bg-black/70 backdrop-blur-xs lg:hidden"
          onClick={() => setMobileOpen(false)}
        />
      )}

      <aside
        className={`fixed top-0 bottom-0 left-0 z-50 w-64 bg-[#090d16] border-r border-slate-800 flex flex-col transition-transform duration-200 ease-in-out lg:translate-x-0 ${
          mobileOpen ? 'translate-x-0' : '-translate-x-full'
        }`}
      >
        {/* Brand Header */}
        <div className="p-4 border-b border-slate-800/80">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded bg-cyan-950/80 border border-cyan-500/40 flex items-center justify-center text-cyan-400 shadow-xs">
              <Shield className="w-4 h-4" />
            </div>
            <div>
              <div className="flex items-center gap-1.5">
                <span className="text-sm font-bold tracking-wider text-slate-100 uppercase">
                  MAILSENTINEL
                </span>
                <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse" />
              </div>
              <p className="text-[10px] text-slate-400 font-mono tracking-tight leading-none mt-0.5">
                Forensic Intelligence
              </p>
            </div>
          </div>

          <div className="mt-3 px-2 py-1.5 rounded bg-slate-900/60 border border-slate-800/60">
            <div className="flex items-center justify-between text-[9px] font-mono text-cyan-400/90 tracking-wider">
              <span>DETECT</span>
              <span>→</span>
              <span>INVESTIGATE</span>
              <span>→</span>
              <span>TRACE</span>
              <span>→</span>
              <span>VERIFY</span>
            </div>
          </div>
        </div>

        {/* Navigation */}
        <div className="flex-1 px-3 py-4 space-y-1 overflow-y-auto">
          <div className="px-2 pb-1.5">
            <span className="text-[10px] font-semibold uppercase tracking-wider text-slate-500 font-mono">
              Forensic Operations
            </span>
          </div>

          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = currentView === item.id;

            return (
              <button
                key={item.id}
                onClick={() => handleNavClick(item.id)}
                className={`w-full flex items-center justify-between px-3 py-2 rounded text-xs font-medium transition-colors ${
                  isActive
                    ? 'bg-cyan-950/40 text-cyan-300 border border-cyan-500/30'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/60'
                }`}
              >
                <div className="flex items-center gap-2.5">
                  <Icon className={`w-4 h-4 ${isActive ? 'text-cyan-400' : 'text-slate-400'}`} />
                  <span className="truncate">{item.label}</span>
                </div>

                {item.count !== undefined && (
                  <span className={`font-mono text-[11px] tabular-nums px-1.5 py-0.2 rounded ${
                    isActive ? 'bg-cyan-900/40 text-cyan-200' : 'bg-slate-900 text-slate-400'
                  }`}>
                    {item.count}
                  </span>
                )}
              </button>
            );
          })}
        </div>

        {/* Investigator Profile & Logout Footer */}
        <div className="p-3 border-t border-slate-800 bg-[#070b13]">
          <div className="flex items-center justify-between p-2 rounded bg-slate-900/50 border border-slate-800/80 mb-2">
            <div className="min-w-0 flex-1 mr-2">
              <div className="flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
                <span className="text-xs font-semibold text-slate-200 truncate">
                  {currentUser.name}
                </span>
              </div>
              <p className="text-[10px] text-slate-400 font-mono truncate">
                {currentUser.badgeId} · {currentUser.clearance}
              </p>
            </div>
            <button
              onClick={logout}
              title="Logout Session"
              className="p-1.5 rounded text-slate-400 hover:text-rose-400 hover:bg-slate-800 transition-colors focus:outline-none"
            >
              <LogOut className="w-3.5 h-3.5" />
            </button>
          </div>

          <div className="flex items-center justify-between px-2 text-[10px] text-slate-500 font-mono">
            <span className="flex items-center gap-1">
              <Radio className="w-3 h-3 text-cyan-400" /> SOC NODE 01
            </span>
            <span>SEC-LEVEL 4</span>
          </div>
        </div>
      </aside>
    </>
  );
};
