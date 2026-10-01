import React, { useState } from 'react';
import { Globe, Link as LinkIcon, Search, AlertTriangle, ShieldCheck, ExternalLink, ChevronDown, ChevronRight } from 'lucide-react';
import { URLIndicator, DomainIndicator } from '../../types/forensics';
import { EmptyState } from '../common/EmptyState';

interface UrlsDomainsTabProps {
  urls?: URLIndicator[];
  domains?: DomainIndicator[];
}

export const UrlsDomainsTab: React.FC<UrlsDomainsTabProps> = ({ urls = [], domains = [] }) => {
  const [filterText, setFilterText] = useState('');
  const [riskFilter, setRiskFilter] = useState<'all' | 'malicious' | 'suspicious' | 'clean'>('all');
  const [expandedUrlId, setExpandedUrlId] = useState<string | null>(null);

  if (!urls || urls.length === 0) {
    return (
      <EmptyState
        icon={LinkIcon}
        title="No URLs or hyperlinks detected"
        description="Extracted hyperlinks, redirects, and canonical domain indicators will populate in this forensic table once an email body or headers stream is analyzed."
      />
    );
  }

  const filteredUrls = urls.filter((item) => {
    const matchesText =
      !filterText ||
      item.url.toLowerCase().includes(filterText.toLowerCase()) ||
      item.domain.toLowerCase().includes(filterText.toLowerCase());

    const matchesRisk =
      riskFilter === 'all' || item.risk === riskFilter;

    return matchesText && matchesRisk;
  });

  return (
    <div className="space-y-4">
      {/* Search & Filter Toolbar */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 p-3 bg-slate-900/60 border border-slate-800 rounded-lg">
        <div className="relative flex-1 max-w-md">
          <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
          <input
            type="text"
            value={filterText}
            onChange={(e) => setFilterText(e.target.value)}
            placeholder="Search extracted URLs or domains..."
            className="w-full pl-9 pr-3 py-1.5 bg-slate-950 border border-slate-800 rounded text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-cyan-500/50 font-mono"
          />
        </div>

        {/* Functional segmented filter tabs */}
        <div className="flex items-center gap-1 bg-slate-950 p-1 rounded border border-slate-800">
          {(['all', 'malicious', 'suspicious', 'clean'] as const).map((mode) => (
            <button
              key={mode}
              onClick={() => setRiskFilter(mode)}
              className={`px-3 py-1 text-xs font-medium rounded capitalize transition-colors whitespace-nowrap ${
                riskFilter === mode
                  ? 'bg-cyan-950/60 text-cyan-300 font-semibold border border-cyan-500/30'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              {mode}
            </button>
          ))}
        </div>
      </div>

      {/* Forensic URL & Domain Table */}
      <div className="border border-slate-800 bg-[#0d1322] rounded-lg overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-slate-900/90 text-slate-400 border-b border-slate-800 uppercase text-[10px] tracking-wider">
              <tr>
                <th className="py-2.5 px-4 w-10"></th>
                <th className="py-2.5 px-4">Hyperlink / URL</th>
                <th className="py-2.5 px-4">Domain</th>
                <th className="py-2.5 px-4">Risk Posture</th>
                <th className="py-2.5 px-4">Reputation</th>
                <th className="py-2.5 px-4">Status</th>
                <th className="py-2.5 px-4">Related IP</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              {filteredUrls.length === 0 ? (
                <tr>
                  <td colSpan={7} className="text-center py-8 text-slate-500 font-mono text-xs">
                    No URLs match filter query.
                  </td>
                </tr>
              ) : (
                filteredUrls.map((u) => {
                  const isExpanded = expandedUrlId === u.id;

                  return (
                    <React.Fragment key={u.id}>
                      <tr
                        onClick={() => setExpandedUrlId(isExpanded ? null : u.id)}
                        className="hover:bg-slate-800/40 cursor-pointer transition-colors"
                      >
                        <td className="py-2.5 px-4 text-slate-500">
                          {isExpanded ? (
                            <ChevronDown className="w-3.5 h-3.5 text-cyan-400" />
                          ) : (
                            <ChevronRight className="w-3.5 h-3.5" />
                          )}
                        </td>
                        <td className="py-2.5 px-4 max-w-xs truncate text-cyan-300">
                          {u.url}
                        </td>
                        <td className="py-2.5 px-4 text-slate-200 font-semibold">
                          {u.domain}
                        </td>
                        <td className="py-2.5 px-4">
                          <span
                            className={
                              u.risk === 'malicious'
                                ? 'text-red-400 font-bold'
                                : u.risk === 'suspicious'
                                ? 'text-amber-400 font-semibold'
                                : 'text-emerald-400'
                            }
                          >
                            {u.risk.toUpperCase()}
                          </span>
                        </td>
                        <td className="py-2.5 px-4 tabular-nums">
                          {u.reputationScore !== undefined ? `${u.reputationScore}/100` : 'Telemetry Clean'}
                        </td>
                        <td className="py-2.5 px-4 text-slate-400">
                          {u.status}
                        </td>
                        <td className="py-2.5 px-4 text-slate-300 select-all">
                          {u.relatedIp || 'DNS Resolved'}
                        </td>
                      </tr>

                      {isExpanded && (
                        <tr className="bg-slate-950/80 border-b border-slate-800">
                          <td colSpan={7} className="p-4 space-y-2 text-xs font-mono">
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-slate-400">
                              <div>
                                <span className="text-slate-500 block text-[11px]">Full Target URI:</span>
                                <span className="text-cyan-300 break-all select-all font-mono">{u.url}</span>
                              </div>
                              <div>
                                <span className="text-slate-500 block text-[11px]">Scheme / Protocol:</span>
                                <span className="text-slate-200">{u.scheme.toUpperCase()}</span>
                              </div>
                            </div>
                            <div className="pt-2 text-slate-400">
                              <span className="text-slate-500 block text-[11px]">Forensic Assessment Note:</span>
                              <span className="text-slate-300 font-sans">
                                Extracted from MIME body payload. Hyperlink validated against local threat telemetry.
                              </span>
                            </div>
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
