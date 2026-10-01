import React, { useState, useEffect } from 'react';
import {
  Menu,
  Plus,
  RefreshCw,
  Search,
  Server,
  Shield,
  Clock,
} from 'lucide-react';
import { useForensics } from '../../context/ForensicContext';

interface TopBarProps {
  onToggleMobileMenu: () => void;
}

export const TopBar: React.FC<TopBarProps> = ({ onToggleMobileMenu }) => {
  const { currentView, setCurrentView, activeCase, backendStatus, refreshBackendStatus } = useForensics();
  const [utcTime, setUtcTime] = useState<string>('');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [isRefreshing, setIsRefreshing] = useState<boolean>(false);

  useEffect(() => {
    const updateClock = () => {
      const now = new Date();
      setUtcTime(now.toUTCString().replace('GMT', 'UTC'));
    };
    updateClock();
    const timer = setInterval(updateClock, 1000);
    return () => clearInterval(timer);
  }, []);

  const handleRefresh = async () => {
    setIsRefreshing(true);
    await refreshBackendStatus();
    setTimeout(() => setIsRefreshing(false), 500);
  };

  const getViewTitle = () => {
    switch (currentView) {
      case 'dashboard':
        return 'Forensic SOC Dashboard';
      case 'investigations':
        return 'Investigation Repository';
      case 'analyze':
        return 'Email Threat Ingestion';
      case 'workspace':
        return activeCase ? `Case ${activeCase.caseNumber}` : 'Investigation Workspace';
      case 'threat-intel':
        return 'Threat Intelligence (IOC Lookup)';
      case 'evidence':
        return 'Chain of Custody & Evidence';
      case 'reports':
        return 'Forensic Reports';
      case 'settings':
        return 'System & API Configuration';
      default:
        return 'MAILSENTINEL';
    }
  };

  return (
    <header className="h-14 bg-[#090d16]/90 backdrop-blur-xs border-b border-slate-800 px-4 flex items-center justify-between sticky top-0 z-30">
      {/* Zone 1: Mobile toggle & Breadcrumb Trail */}
      <div className="flex items-center gap-3">
        <button
          onClick={onToggleMobileMenu}
          className="p-1.5 rounded text-slate-400 hover:text-slate-200 hover:bg-slate-800 lg:hidden focus:outline-none"
        >
          <Menu className="w-5 h-5" />
        </button>

        <div className="flex items-center gap-2">
          <span className="text-xs font-mono text-slate-500 hidden sm:inline">MAILSENTINEL /</span>
          <h1 className="text-sm font-semibold text-slate-100 whitespace-nowrap">
            {getViewTitle()}
          </h1>
          {currentView === 'workspace' && activeCase && (
            <span className="font-mono text-xs text-cyan-400 bg-cyan-950/40 px-2 py-0.5 rounded border border-cyan-500/30">
              {activeCase.status.toUpperCase()}
            </span>
          )}
        </div>
      </div>

      {/* Zone 2: UTC Monospace Clock & Search Bar */}
      <div className="hidden md:flex items-center gap-4">
        <div className="flex items-center gap-2 text-xs font-mono text-slate-400 bg-slate-900/80 px-2.5 py-1 rounded border border-slate-800/80">
          <Clock className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
          <span className="tabular-nums">{utcTime || 'UTC 00:00:00'}</span>
        </div>

        <div className="relative w-56 lg:w-72">
          <Search className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-500" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search Case ID, IP, or IOC..."
            className="w-full pl-8 pr-3 py-1 bg-slate-900/90 border border-slate-800 rounded text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-cyan-500/50 font-mono"
          />
        </div>
      </div>

      {/* Zone 3: Actions + Backend Connectivity */}
      <div className="flex items-center gap-3">
        {/* Backend status indicator */}
        <div
          title={backendStatus.message}
          className="flex items-center gap-1.5 text-[11px] font-mono px-2 py-1 rounded bg-slate-900/60 border border-slate-800"
        >
          <Server className="w-3 h-3 text-slate-400" />
          <span
            className={`w-1.5 h-1.5 rounded-full ${
              backendStatus.online ? 'bg-emerald-400 animate-pulse' : 'bg-amber-400'
            }`}
          />
          <span className="text-slate-400 hidden xl:inline">
            {backendStatus.online ? 'FastAPI Online' : 'FastAPI Standby'}
          </span>
          <button
            onClick={handleRefresh}
            title="Refresh backend status"
            className="text-slate-500 hover:text-slate-300 ml-1"
          >
            <RefreshCw className={`w-3 h-3 ${isRefreshing ? 'animate-spin' : ''}`} />
          </button>
        </div>

        <button
          onClick={() => setCurrentView('analyze')}
          className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold text-white bg-cyan-600 hover:bg-cyan-500 rounded transition-colors shadow-xs whitespace-nowrap"
        >
          <Plus className="w-3.5 h-3.5" />
          <span>Analyze Email</span>
        </button>
      </div>
    </header>
  );
};
