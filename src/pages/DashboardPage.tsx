import React from 'react';
import {
  ShieldAlert,
  Search,
  Crosshair,
  FileCheck,
  Plus,
  ArrowUpRight,
  Clock,
  Activity,
  Layers,
  FileText,
  AlertTriangle,
} from 'lucide-react';
import { useForensics } from '../context/ForensicContext';
import { RiskBadge } from '../components/common/RiskBadge';
import { StatusBadge } from '../components/common/StatusBadge';
import { EmptyState } from '../components/common/EmptyState';

export const DashboardPage: React.FC = () => {
  const { cases, setCurrentView, selectCase } = useForensics();

  // Metrics strictly computed from real state; defaults to 0 when no cases exist
  const totalCases = cases.length;
  const highRiskCases = cases.filter(c => c.riskLevel === 'malicious' || c.riskLevel === 'critical').length;
  const underReviewCases = cases.filter(c => c.status === 'under_review').length;
  const verifiedCases = cases.filter(c => c.status === 'verified').length;

  return (
    <div className="space-y-6">
      {/* 1. Overview Cards (Real values; 0 when empty) */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Total Cases */}
        <div className="p-4 rounded-lg bg-[#0d1322] border border-slate-800">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-mono uppercase tracking-wider">Total Cases</span>
            <Layers className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-2xl font-bold font-mono text-slate-100 tabular-nums">
              {totalCases}
            </span>
            <span className="text-[11px] font-mono text-slate-500">
              {totalCases === 0 ? 'No records' : 'Cases registered'}
            </span>
          </div>
        </div>

        {/* High Risk */}
        <div className="p-4 rounded-lg bg-[#0d1322] border border-slate-800">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-mono uppercase tracking-wider">High Risk / Malicious</span>
            <AlertTriangle className="w-4 h-4 text-rose-400" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-2xl font-bold font-mono text-rose-400 tabular-nums">
              {highRiskCases}
            </span>
            <span className="text-[11px] font-mono text-slate-500">
              Critical posture
            </span>
          </div>
        </div>

        {/* Under Review */}
        <div className="p-4 rounded-lg bg-[#0d1322] border border-slate-800">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-mono uppercase tracking-wider">Under Review</span>
            <Clock className="w-4 h-4 text-amber-400" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-2xl font-bold font-mono text-amber-400 tabular-nums">
              {underReviewCases}
            </span>
            <span className="text-[11px] font-mono text-slate-500">
              Active triage
            </span>
          </div>
        </div>

        {/* Verified */}
        <div className="p-4 rounded-lg bg-[#0d1322] border border-slate-800">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-mono uppercase tracking-wider">Verified Clean</span>
            <FileCheck className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-2xl font-bold font-mono text-emerald-400 tabular-nums">
              {verifiedCases}
            </span>
            <span className="text-[11px] font-mono text-slate-500">
              Passed verification
            </span>
          </div>
        </div>
      </div>

      {/* Quick Actions Panel */}
      <div className="border border-slate-800 bg-[#0d1322] rounded-lg p-4">
        <div className="flex items-center justify-between mb-3 pb-2 border-b border-slate-800">
          <span className="text-xs font-semibold uppercase tracking-wider text-slate-400 font-mono">
            Forensic Quick Actions
          </span>
          <span className="text-[10px] text-slate-500 font-mono">
            Fast Execution
          </span>
        </div>

        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          <button
            onClick={() => setCurrentView('analyze')}
            className="flex items-center justify-between p-3 rounded bg-cyan-950/40 hover:bg-cyan-900/50 border border-cyan-500/30 text-cyan-200 transition-colors group text-left"
          >
            <div className="flex items-center gap-2.5">
              <Search className="w-4 h-4 text-cyan-400" />
              <div>
                <span className="text-xs font-semibold block">Analyze Email</span>
                <span className="text-[10px] text-slate-400 font-mono">Ingest .eml or headers</span>
              </div>
            </div>
            <ArrowUpRight className="w-3.5 h-3.5 opacity-60 group-hover:opacity-100" />
          </button>

          <button
            onClick={() => setCurrentView('investigations')}
            className="flex items-center justify-between p-3 rounded bg-slate-900/60 hover:bg-slate-800/80 border border-slate-800 text-slate-200 transition-colors group text-left"
          >
            <div className="flex items-center gap-2.5">
              <ShieldAlert className="w-4 h-4 text-slate-400" />
              <div>
                <span className="text-xs font-semibold block">Investigations</span>
                <span className="text-[10px] text-slate-400 font-mono">View case dossiers</span>
              </div>
            </div>
            <ArrowUpRight className="w-3.5 h-3.5 opacity-60 group-hover:opacity-100" />
          </button>

          <button
            onClick={() => setCurrentView('threat-intel')}
            className="flex items-center justify-between p-3 rounded bg-slate-900/60 hover:bg-slate-800/80 border border-slate-800 text-slate-200 transition-colors group text-left"
          >
            <div className="flex items-center gap-2.5">
              <Crosshair className="w-4 h-4 text-slate-400" />
              <div>
                <span className="text-xs font-semibold block">Threat Intel</span>
                <span className="text-[10px] text-slate-400 font-mono">Lookup IOC telemetry</span>
              </div>
            </div>
            <ArrowUpRight className="w-3.5 h-3.5 opacity-60 group-hover:opacity-100" />
          </button>

          <button
            onClick={() => setCurrentView('evidence')}
            className="flex items-center justify-between p-3 rounded bg-slate-900/60 hover:bg-slate-800/80 border border-slate-800 text-slate-200 transition-colors group text-left"
          >
            <div className="flex items-center gap-2.5">
              <FileCheck className="w-4 h-4 text-slate-400" />
              <div>
                <span className="text-xs font-semibold block">Evidence Vault</span>
                <span className="text-[10px] text-slate-400 font-mono">SHA-256 & Custody</span>
              </div>
            </div>
            <ArrowUpRight className="w-3.5 h-3.5 opacity-60 group-hover:opacity-100" />
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* 2. Recent Investigations Table */}
        <div className="lg:col-span-2 border border-slate-800 bg-[#0d1322] rounded-lg overflow-hidden flex flex-col">
          <div className="px-5 py-3 bg-slate-900/80 border-b border-slate-800 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-cyan-400" />
              <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-200 font-mono">
                Recent Investigations
              </h3>
            </div>
            <button
              onClick={() => setCurrentView('investigations')}
              className="text-xs font-mono text-cyan-400 hover:text-cyan-300"
            >
              View Repository
            </button>
          </div>

          <div className="p-4 flex-1">
            {cases.length === 0 ? (
              <EmptyState
                icon={ShieldAlert}
                title="No investigations yet"
                description="Upload an email or paste raw RFC headers to begin automated forensic extraction and triage."
                actionText="Upload Email to Begin"
                onAction={() => setCurrentView('analyze')}
              />
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs font-mono">
                  <thead className="text-[10px] text-slate-400 uppercase tracking-wider border-b border-slate-800">
                    <tr>
                      <th className="pb-2">Case ID</th>
                      <th className="pb-2">Subject</th>
                      <th className="pb-2">Sender</th>
                      <th className="pb-2">Risk</th>
                      <th className="pb-2">Status</th>
                      <th className="pb-2">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60">
                    {cases.slice(0, 5).map((c) => (
                      <tr key={c.id} className="hover:bg-slate-900/40">
                        <td className="py-2.5 text-cyan-400 font-bold">{c.caseNumber}</td>
                        <td className="py-2.5 max-w-[140px] truncate text-slate-200 font-sans">
                          {c.subject}
                        </td>
                        <td className="py-2.5 max-w-[120px] truncate text-slate-400">
                          {c.sender}
                        </td>
                        <td className="py-2.5">
                          <RiskBadge level={c.riskLevel} classification={c.classification} />
                        </td>
                        <td className="py-2.5">
                          <StatusBadge status={c.status} />
                        </td>
                        <td className="py-2.5">
                          <button
                            onClick={() => selectCase(c.id)}
                            className="text-cyan-400 hover:text-cyan-300 font-semibold"
                          >
                            Open →
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>

        {/* 3. Investigation Activity Section */}
        <div className="border border-slate-800 bg-[#0d1322] rounded-lg overflow-hidden flex flex-col">
          <div className="px-5 py-3 bg-slate-900/80 border-b border-slate-800 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Activity className="w-4 h-4 text-cyan-400" />
              <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-200 font-mono">
                Investigation Activity
              </h3>
            </div>
          </div>

          <div className="p-4 flex-1">
            {cases.length === 0 ? (
              <EmptyState
                icon={Activity}
                title="No forensic activity recorded"
                description="Live audit events, ingestions, and blockchain notarizations will stream here as investigations proceed."
              />
            ) : (
              <div className="space-y-3">
                {cases.flatMap(c => c.timeline || []).slice(0, 5).map((evt) => (
                  <div key={evt.id} className="p-2.5 rounded bg-slate-900/50 border border-slate-800/80 text-xs font-mono">
                    <div className="flex items-center justify-between text-slate-400 mb-1">
                      <span className="text-cyan-400 font-semibold">{evt.action}</span>
                      <span className="text-[10px]">{evt.timestamp.slice(11, 19)} UTC</span>
                    </div>
                    <p className="text-[11px] text-slate-300">{evt.details}</p>
                    <span className="text-[10px] text-slate-500 mt-1 block">Actor: {evt.actor}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
