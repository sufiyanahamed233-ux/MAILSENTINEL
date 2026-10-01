import React, { useState } from 'react';
import {
  Crosshair,
  Search,
  Globe,
  Server,
  Link2,
  FileCode,
  ShieldAlert,
  ShieldCheck,
  AlertCircle,
  Database,
  Radio,
} from 'lucide-react';
import { ApiClient } from '../services/api';
import { EmptyState } from '../components/common/EmptyState';
import { HashDisplay } from '../components/common/HashDisplay';

export const ThreatIntelPage: React.FC = () => {
  const [iocType, setIocType] = useState<'ip' | 'domain' | 'url' | 'hash'>('ip');
  const [iocQuery, setIocQuery] = useState('');
  const [isSearching, setIsSearching] = useState(false);
  const [searched, setSearched] = useState(false);
  const [searchResult, setSearchResult] = useState<any | null>(null);

  const handleSearch = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!iocQuery.trim()) return;

    setIsSearching(true);
    setSearched(true);
    setSearchResult(null);

    // Live query against future FastAPI endpoint
    const result = await ApiClient.getThreatIntelligence({
      ioc: iocQuery.trim(),
      type: iocType,
    });

    setIsSearching(false);
    setSearchResult(result);
  };

  const getPlaceholder = () => {
    switch (iocType) {
      case 'ip':
        return 'e.g., 198.51.100.42';
      case 'domain':
        return 'e.g., malicious-phish-portal.example';
      case 'url':
        return 'e.g., https://secure-account-verification.example/login';
      case 'hash':
        return 'e.g., e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
    }
  };

  return (
    <div className="space-y-5 max-w-5xl mx-auto">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-4">
        <div>
          <h2 className="text-base font-bold text-slate-100 font-mono uppercase tracking-wider">
            Threat Intelligence & IOC Correlation
          </h2>
          <p className="text-xs text-slate-400 font-mono mt-0.5">
            Query global adversary telemetry, autonomous systems, and reputation databases
          </p>
        </div>

        <div className="flex items-center gap-1.5 text-xs font-mono text-cyan-400 bg-cyan-950/20 px-2.5 py-1 rounded border border-cyan-500/30">
          <Database className="w-3.5 h-3.5" />
          <span>Active Telemetry Feeds</span>
        </div>
      </div>

      {/* Search Console */}
      <div className="border border-slate-800 bg-[#0d1322] rounded-lg p-5 space-y-4">
        {/* Type Selector */}
        <div className="flex items-center gap-2">
          {[
            { id: 'ip', label: 'IP Address', icon: Server },
            { id: 'domain', label: 'Domain', icon: Globe },
            { id: 'url', label: 'URL Target', icon: Link2 },
            { id: 'hash', label: 'File Hash (SHA-256)', icon: FileCode },
          ].map((type) => {
            const Icon = type.icon;
            const isSelected = iocType === type.id;
            return (
              <button
                key={type.id}
                type="button"
                onClick={() => setIocType(type.id as any)}
                className={`flex items-center gap-2 px-3 py-1.5 rounded text-xs font-mono transition-colors ${
                  isSelected
                    ? 'bg-cyan-950/60 text-cyan-300 border border-cyan-500/40 font-semibold'
                    : 'text-slate-400 hover:text-slate-200 bg-slate-900/60 border border-slate-800'
                }`}
              >
                <Icon className="w-3.5 h-3.5" />
                <span>{type.label}</span>
              </button>
            );
          })}
        </div>

        {/* Search Bar */}
        <form onSubmit={handleSearch} className="flex gap-2">
          <div className="relative flex-1">
            <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
            <input
              type="text"
              value={iocQuery}
              onChange={(e) => setIocQuery(e.target.value)}
              placeholder={getPlaceholder()}
              className="w-full pl-9 pr-3 py-2 bg-slate-950 border border-slate-800 rounded font-mono text-xs text-slate-100 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500"
            />
          </div>

          <button
            type="submit"
            disabled={isSearching || !iocQuery.trim()}
            className="px-5 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded text-xs font-mono font-bold transition-colors shadow-xs disabled:opacity-40 disabled:cursor-not-allowed cursor-pointer flex items-center gap-1.5"
          >
            {isSearching ? (
              <>
                <span className="w-3.5 h-3.5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                <span>Querying...</span>
              </>
            ) : (
              <>
                <Crosshair className="w-3.5 h-3.5" />
                <span>Lookup IOC</span>
              </>
            )}
          </button>
        </form>
      </div>

      {/* Results View: NO fake telemetry */}
      {isSearching ? (
        <div className="p-12 text-center border border-slate-800 rounded-lg bg-[#0d1322] font-mono text-xs text-cyan-400">
          <div className="w-8 h-8 mx-auto border-2 border-cyan-500/20 border-t-cyan-400 rounded-full animate-spin mb-3" />
          <span>Interrogating external threat telemetry engines...</span>
        </div>
      ) : searched && !searchResult ? (
        <div className="border border-slate-800 bg-[#0d1322] rounded-lg p-8">
          <EmptyState
            icon={Crosshair}
            title="No threat intelligence available"
            description={`No historical threat signatures or malicious campaigns are recorded for indicator "${iocQuery}" in connected feeds.`}
            secondaryText="Status: Clean or Unindexed Indicator"
          />
        </div>
      ) : searchResult ? (
        /* Real API Result structure when FastAPI backend responds */
        <div className="border border-slate-800 bg-[#0d1322] rounded-lg p-5 space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-slate-800">
            <span className="text-xs font-mono uppercase text-slate-400">
              Intelligence Dossier: {iocQuery}
            </span>
            <span className="text-xs font-mono text-cyan-400">Verified Feed Match</span>
          </div>
          <pre className="text-xs font-mono text-slate-300 bg-slate-950 p-4 rounded border border-slate-800 whitespace-pre-wrap">
            {JSON.stringify(searchResult, null, 2)}
          </pre>
        </div>
      ) : (
        /* Initial Empty State */
        <div className="border border-slate-800 bg-[#0d1322] rounded-lg p-6">
          <EmptyState
            icon={Crosshair}
            title="No threat intelligence available"
            description="Enter an IP address, domain name, URL path, or SHA-256 hash above to evaluate against threat intelligence databases, reputation feeds, and ASN records."
          />
        </div>
      )}
    </div>
  );
};
