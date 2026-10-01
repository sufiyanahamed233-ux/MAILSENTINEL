import React, { useState } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  CheckCircle,
  XCircle,
  AlertTriangle,
  ChevronDown,
  ChevronRight,
  Copy,
  Check,
  Search,
  Server,
  Layers,
} from 'lucide-react';
import { EmailAuthentication, EmailHeaderHop } from '../../types/forensics';

interface ForensicHeadersViewerProps {
  auth: EmailAuthentication;
  hops: EmailHeaderHop[];
  rawHeaders: string;
}

export const ForensicHeadersViewer: React.FC<ForensicHeadersViewerProps> = ({
  auth,
  hops,
  rawHeaders,
}) => {
  const [activeTab, setActiveTab] = useState<'auth' | 'hops' | 'raw'>('auth');
  const [expandedHop, setExpandedHop] = useState<number | null>(hops.length > 0 ? 1 : null);
  const [copiedRaw, setCopiedRaw] = useState(false);
  const [searchFilter, setSearchFilter] = useState('');

  const handleCopyRaw = () => {
    navigator.clipboard.writeText(rawHeaders);
    setCopiedRaw(true);
    setTimeout(() => setCopiedRaw(false), 2000);
  };

  const getStatusBadge = (status: string) => {
    const s = status.toLowerCase();
    if (s === 'pass') {
      return (
        <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-emerald-400">
          <CheckCircle className="w-3.5 h-3.5" />
          <span>PASS</span>
        </span>
      );
    }
    if (s === 'fail' || s === 'reject' || s === 'quarantine' || s === 'permerror') {
      return (
        <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-red-400">
          <XCircle className="w-3.5 h-3.5" />
          <span>{s.toUpperCase()}</span>
        </span>
      );
    }
    if (s === 'softfail' || s === 'neutral' || s === 'temperror') {
      return (
        <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-amber-400">
          <AlertTriangle className="w-3.5 h-3.5" />
          <span>{s.toUpperCase()}</span>
        </span>
      );
    }
    return (
      <span className="inline-flex items-center gap-1.5 text-xs font-medium text-slate-400">
        <span>NONE / UNSET</span>
      </span>
    );
  };

  const filteredRawLines = rawHeaders
    .split(/\r?\n/)
    .filter(line => !searchFilter || line.toLowerCase().includes(searchFilter.toLowerCase()));

  return (
    <div className="border border-slate-800 bg-[#0d1322] rounded-lg overflow-hidden flex flex-col">
      {/* Sub-navigation tabs */}
      <div className="px-4 py-2 bg-slate-900/80 border-b border-slate-800 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <button
            onClick={() => setActiveTab('auth')}
            className={`px-3 py-1.5 text-xs font-medium rounded transition-colors ${
              activeTab === 'auth'
                ? 'bg-cyan-950/60 text-cyan-300 border border-cyan-500/30'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Authentication (SPF / DKIM / DMARC)
          </button>
          <button
            onClick={() => setActiveTab('hops')}
            className={`px-3 py-1.5 text-xs font-medium rounded transition-colors ${
              activeTab === 'hops'
                ? 'bg-cyan-950/60 text-cyan-300 border border-cyan-500/30'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Received Hops Chain ({hops.length})
          </button>
          <button
            onClick={() => setActiveTab('raw')}
            className={`px-3 py-1.5 text-xs font-medium rounded transition-colors ${
              activeTab === 'raw'
                ? 'bg-cyan-950/60 text-cyan-300 border border-cyan-500/30'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Raw Headers Stream
          </button>
        </div>

        {activeTab === 'raw' && (
          <button
            onClick={handleCopyRaw}
            className="flex items-center gap-1.5 px-2.5 py-1 text-xs text-slate-300 bg-slate-800 hover:bg-slate-700 rounded transition-colors border border-slate-700"
          >
            {copiedRaw ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            <span>{copiedRaw ? 'Copied' : 'Copy All'}</span>
          </button>
        )}
      </div>

      <div className="p-5 flex-1">
        {/* Authentication Summary */}
        {activeTab === 'auth' && (
          <div className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {/* SPF */}
              <div className="p-4 rounded-md border border-slate-800 bg-slate-900/50">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xs font-mono uppercase tracking-wider text-slate-400">
                    SPF (Sender Policy Framework)
                  </span>
                  {getStatusBadge(auth.spf.status)}
                </div>
                <p className="text-xs text-slate-300 font-mono mt-2 break-all bg-slate-950 p-2 rounded border border-slate-800/80">
                  {auth.spf.details || 'No SPF evaluation recorded'}
                </p>
                {auth.spf.domain && (
                  <div className="mt-2 text-[11px] text-slate-400 font-mono">
                    Validated Domain: <span className="text-slate-200">{auth.spf.domain}</span>
                  </div>
                )}
              </div>

              {/* DKIM */}
              <div className="p-4 rounded-md border border-slate-800 bg-slate-900/50">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xs font-mono uppercase tracking-wider text-slate-400">
                    DKIM (DomainKeys Identified Mail)
                  </span>
                  {getStatusBadge(auth.dkim.status)}
                </div>
                <p className="text-xs text-slate-300 font-mono mt-2 break-all bg-slate-950 p-2 rounded border border-slate-800/80">
                  {auth.dkim.details || 'No DKIM signature detected'}
                </p>
                {auth.dkim.selector && (
                  <div className="mt-2 text-[11px] text-slate-400 font-mono">
                    Selector: <span className="text-slate-200">{auth.dkim.selector}</span>
                  </div>
                )}
              </div>

              {/* DMARC */}
              <div className="p-4 rounded-md border border-slate-800 bg-slate-900/50">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xs font-mono uppercase tracking-wider text-slate-400">
                    DMARC Policy
                  </span>
                  {getStatusBadge(auth.dmarc.status)}
                </div>
                <p className="text-xs text-slate-300 font-mono mt-2 break-all bg-slate-950 p-2 rounded border border-slate-800/80">
                  {auth.dmarc.details || 'No DMARC evaluation found'}
                </p>
                {auth.dmarc.policy && (
                  <div className="mt-2 text-[11px] text-slate-400 font-mono">
                    Enforced Policy: <span className="text-slate-200">{auth.dmarc.policy}</span>
                  </div>
                )}
              </div>
            </div>

            {/* Raw Authentication Results Header */}
            <div className="mt-4 p-4 rounded-md border border-slate-800 bg-slate-900/30">
              <span className="text-xs font-mono uppercase text-slate-400 block mb-1">
                Authentication-Results Header
              </span>
              <pre className="text-xs font-mono text-cyan-300/80 bg-slate-950 p-3 rounded border border-slate-800/80 whitespace-pre-wrap select-all">
                {auth.authResultsRaw || 'None extracted'}
              </pre>
            </div>
          </div>
        )}

        {/* Received Chain Hops */}
        {activeTab === 'hops' && (
          <div className="space-y-3">
            {hops.length === 0 ? (
              <div className="text-center py-10 text-slate-500 font-mono text-xs">
                No Received header hops found in message envelope.
              </div>
            ) : (
              hops.map((hop) => {
                const isExpanded = expandedHop === hop.hopNumber;

                return (
                  <div
                    key={hop.hopNumber}
                    className="border border-slate-800 rounded-md bg-slate-900/40 overflow-hidden"
                  >
                    <div
                      onClick={() => setExpandedHop(isExpanded ? null : hop.hopNumber)}
                      className="px-4 py-2.5 flex items-center justify-between cursor-pointer hover:bg-slate-800/40 transition-colors"
                    >
                      <div className="flex items-center gap-3">
                        <span className="w-5 h-5 rounded-full bg-cyan-950 text-cyan-400 border border-cyan-500/30 text-xs font-mono flex items-center justify-center font-bold">
                          {hop.hopNumber}
                        </span>
                        <div>
                          <div className="flex items-center gap-2 text-xs font-mono">
                            <span className="text-slate-400">From:</span>
                            <span className="text-slate-200 font-semibold">{hop.fromHost}</span>
                            <span className="text-slate-500">→</span>
                            <span className="text-slate-400">By:</span>
                            <span className="text-slate-200">{hop.byHost}</span>
                          </div>
                          {hop.ipAddress && (
                            <span className="text-[11px] font-mono text-cyan-400">
                              Relay IP: {hop.ipAddress}
                            </span>
                          )}
                        </div>
                      </div>

                      <div className="flex items-center gap-3">
                        <span className="text-xs font-mono text-slate-400 hidden sm:inline">
                          {hop.timestamp}
                        </span>
                        {isExpanded ? (
                          <ChevronDown className="w-4 h-4 text-slate-400" />
                        ) : (
                          <ChevronRight className="w-4 h-4 text-slate-400" />
                        )}
                      </div>
                    </div>

                    {isExpanded && (
                      <div className="p-4 bg-slate-950/70 border-t border-slate-800/80 space-y-2 text-xs font-mono">
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-slate-400">
                          <div>
                            <span className="text-slate-500">Protocol: </span>
                            <span className="text-slate-300">{hop.withProtocol || 'Standard SMTP'}</span>
                          </div>
                          <div>
                            <span className="text-slate-500">Recipient envelope: </span>
                            <span className="text-slate-300">{hop.forRecipient || 'None specified'}</span>
                          </div>
                        </div>
                        <div>
                          <span className="text-slate-500">Raw Hop String:</span>
                          <pre className="mt-1 p-2 bg-slate-900 rounded border border-slate-800 text-[11px] text-slate-300 whitespace-pre-wrap break-all select-all">
                            {hop.rawHeader}
                          </pre>
                        </div>
                      </div>
                    )}
                  </div>
                );
              })
            )}
          </div>
        )}

        {/* Raw Stream Tab */}
        {activeTab === 'raw' && (
          <div className="space-y-3">
            <div className="relative">
              <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
              <input
                type="text"
                value={searchFilter}
                onChange={(e) => setSearchFilter(e.target.value)}
                placeholder="Filter raw header keys or values..."
                className="w-full pl-9 pr-3 py-1.5 bg-slate-950 border border-slate-800 rounded text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-cyan-500/50 font-mono"
              />
            </div>

            <div className="max-h-[500px] overflow-y-auto bg-slate-950 p-4 rounded border border-slate-800 font-mono text-xs text-slate-300 leading-relaxed space-y-0.5 select-all">
              {filteredRawLines.map((line, idx) => {
                const isHeaderName = /^[A-Za-z0-9_-]+:/.test(line);
                return (
                  <div key={idx} className="hover:bg-slate-900/60 px-1 rounded">
                    {isHeaderName ? (
                      <span className="text-cyan-400 font-semibold">{line}</span>
                    ) : (
                      <span className="text-slate-400 pl-4">{line}</span>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
