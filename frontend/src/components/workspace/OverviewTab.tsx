import React from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  FileCheck,
  ArrowRight,
  ExternalLink,
  CheckCircle,
  XCircle,
  Brain,
  Layers,
} from 'lucide-react';
import { Case } from '../../types/forensics';
import { RiskBadge } from '../common/RiskBadge';

interface OverviewTabProps {
  forensicCase: Case;
  onNavigateTab: (tab: string) => void;
}

export const OverviewTab: React.FC<OverviewTabProps> = ({ forensicCase, onNavigateTab }) => {
  const { emailData, indicators, aiAnalysis, riskLevel, classification, riskScore } = forensicCase;
  const auth = emailData.authentication;

  return (
    <div className="space-y-6">
      {/* 1. Threat Assessment Header Card */}
      <div className="border border-slate-800 bg-[#0d1322] rounded-lg p-5">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-800">
          <div>
            <span className="text-[11px] font-mono uppercase tracking-wider text-slate-400">
              Forensic Assessment & Posture
            </span>
            <div className="flex items-center gap-3 mt-1">
              <h2 className="text-xl font-bold text-slate-100">
                {classification}
              </h2>
              <RiskBadge level={riskLevel} classification={classification} showScore score={riskScore} />
            </div>
          </div>

          <div className="flex items-center gap-4 text-xs font-mono">
            {aiAnalysis && (
              <div className="bg-slate-900/80 px-3 py-1.5 rounded border border-slate-800 text-right">
                <span className="text-slate-400 block text-[10px]">Confidence Index</span>
                <span className="text-cyan-400 font-bold tabular-nums">
                  {(aiAnalysis.confidence * 100).toFixed(0)}%
                </span>
              </div>
            )}
            <div className="bg-slate-900/80 px-3 py-1.5 rounded border border-slate-800 text-right">
              <span className="text-slate-400 block text-[10px]">Indicators Flagged</span>
              <span className="text-slate-200 font-bold tabular-nums">
                {indicators.length}
              </span>
            </div>
          </div>
        </div>

        {/* Key Indicators Snippet */}
        <div className="mt-4">
          <span className="text-xs font-semibold uppercase tracking-wider text-slate-400 font-mono block mb-2">
            Forensic Findings Summary:
          </span>
          {indicators.length === 0 ? (
            <div className="text-xs text-slate-500 font-mono py-2">
              No anomalous indicators detected. Email envelope aligns with RFC parameters.
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
              {indicators.map((ind) => (
                <div
                  key={ind.id}
                  className="flex items-start gap-2 p-2.5 rounded bg-slate-900/50 border border-slate-800/80 text-xs"
                >
                  <AlertTriangle className="w-3.5 h-3.5 text-amber-400 shrink-0 mt-0.5" />
                  <div>
                    <span className="font-semibold text-slate-200">{ind.title}:</span>{' '}
                    <span className="text-slate-400">{ind.description}</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* 2. Email Authentication Panel */}
        <div className="border border-slate-800 bg-[#0d1322] rounded-lg p-5">
          <div className="flex items-center justify-between pb-3 border-b border-slate-800 mb-4">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-300 font-mono">
              Email Authentication Validation
            </h3>
            <button
              onClick={() => onNavigateTab('headers')}
              className="text-xs text-cyan-400 hover:text-cyan-300 flex items-center gap-1 font-mono"
            >
              <span>Examine Headers</span>
              <ArrowRight className="w-3 h-3" />
            </button>
          </div>

          <div className="space-y-3">
            {/* SPF */}
            <div className="flex items-center justify-between p-3 rounded bg-slate-900/60 border border-slate-800">
              <div className="min-w-0 pr-2">
                <span className="text-xs font-mono font-bold text-slate-200 block">
                  SPF (Sender Policy Framework)
                </span>
                <span className="text-[11px] text-slate-400 truncate block">
                  {auth.spf.details || 'No SPF record found'}
                </span>
              </div>
              <span className={`text-xs font-mono font-bold px-2 py-0.5 rounded ${
                auth.spf.status === 'pass'
                  ? 'bg-emerald-950/60 text-emerald-400 border border-emerald-500/30'
                  : 'bg-rose-950/60 text-rose-400 border border-rose-500/30'
              }`}>
                {auth.spf.status.toUpperCase()}
              </span>
            </div>

            {/* DKIM */}
            <div className="flex items-center justify-between p-3 rounded bg-slate-900/60 border border-slate-800">
              <div className="min-w-0 pr-2">
                <span className="text-xs font-mono font-bold text-slate-200 block">
                  DKIM (Cryptographic Signature)
                </span>
                <span className="text-[11px] text-slate-400 truncate block">
                  {auth.dkim.details || 'No DKIM signature detected'}
                </span>
              </div>
              <span className={`text-xs font-mono font-bold px-2 py-0.5 rounded ${
                auth.dkim.status === 'pass'
                  ? 'bg-emerald-950/60 text-emerald-400 border border-emerald-500/30'
                  : 'bg-slate-800 text-slate-400'
              }`}>
                {auth.dkim.status.toUpperCase()}
              </span>
            </div>

            {/* DMARC */}
            <div className="flex items-center justify-between p-3 rounded bg-slate-900/60 border border-slate-800">
              <div className="min-w-0 pr-2">
                <span className="text-xs font-mono font-bold text-slate-200 block">
                  DMARC Policy Enforcement
                </span>
                <span className="text-[11px] text-slate-400 truncate block">
                  {auth.dmarc.details || 'No DMARC policy reported'}
                </span>
              </div>
              <span className={`text-xs font-mono font-bold px-2 py-0.5 rounded ${
                auth.dmarc.status === 'pass'
                  ? 'bg-emerald-950/60 text-emerald-400 border border-emerald-500/30'
                  : 'bg-rose-950/60 text-rose-400 border border-rose-500/30'
              }`}>
                {auth.dmarc.status.toUpperCase()}
              </span>
            </div>
          </div>
        </div>

        {/* 3. Suspicious Indicators Breakdown */}
        <div className="border border-slate-800 bg-[#0d1322] rounded-lg p-5">
          <div className="flex items-center justify-between pb-3 border-b border-slate-800 mb-4">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-300 font-mono">
              Suspicious Indicators Matrix
            </h3>
            <span className="text-[11px] font-mono text-slate-400">
              RFC 5322 Invariants
            </span>
          </div>

          <div className="space-y-2 text-xs font-mono">
            <div className="flex items-center justify-between p-2 rounded bg-slate-900/40 border border-slate-800/80">
              <span className="text-slate-300">Sender Envelope Mismatch:</span>
              <span className={emailData.returnPath && emailData.returnPath !== emailData.from ? 'text-amber-400 font-bold' : 'text-emerald-400'}>
                {emailData.returnPath && emailData.returnPath !== emailData.from ? 'ANOMALY DETECTED' : 'ALIGNED'}
              </span>
            </div>

            <div className="flex items-center justify-between p-2 rounded bg-slate-900/40 border border-slate-800/80">
              <span className="text-slate-300">Reply-To Divergence:</span>
              <span className={emailData.replyTo && emailData.replyTo !== emailData.from ? 'text-rose-400 font-bold' : 'text-emerald-400'}>
                {emailData.replyTo && emailData.replyTo !== emailData.from ? 'MISMATCH FLAGGED' : 'ALIGNED'}
              </span>
            </div>

            <div className="flex items-center justify-between p-2 rounded bg-slate-900/40 border border-slate-800/80">
              <span className="text-slate-300">Extracted URLs:</span>
              <span className="text-cyan-400 tabular-nums">
                {forensicCase.urls.length} URLs Detected
              </span>
            </div>

            <div className="flex items-center justify-between p-2 rounded bg-slate-900/40 border border-slate-800/80">
              <span className="text-slate-300">Relay IP Hops:</span>
              <span className="text-slate-200 tabular-nums">
                {emailData.hops.length} Network Hops
              </span>
            </div>

            <div className="flex items-center justify-between p-2 rounded bg-slate-900/40 border border-slate-800/80">
              <span className="text-slate-300">Attachment Payloads:</span>
              <span className="text-slate-200 tabular-nums">
                {emailData.attachments.length} Files Attached
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* 4. AI Forensic Summary Panel */}
      {aiAnalysis && (
        <div className="border border-slate-800 bg-[#0d1322] rounded-lg p-5">
          <div className="flex items-center justify-between pb-3 border-b border-slate-800 mb-3">
            <div className="flex items-center gap-2">
              <Brain className="w-4 h-4 text-cyan-400" />
              <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-300 font-mono">
                AI Forensic Analysis & Synthesis
              </h3>
            </div>
            <button
              onClick={() => onNavigateTab('ai')}
              className="text-xs text-cyan-400 hover:text-cyan-300 flex items-center gap-1 font-mono"
            >
              <span>View Full Reasoning</span>
              <ArrowRight className="w-3 h-3" />
            </button>
          </div>

          <p className="text-xs text-slate-300 leading-relaxed bg-slate-950 p-3.5 rounded border border-slate-800/80 mb-3">
            {aiAnalysis.explanation}
          </p>

          <div className="flex items-center justify-between pt-2 text-xs font-mono">
            <span className="text-slate-400">
              Recommended Protocol:{' '}
              <span className="text-slate-200">
                {aiAnalysis.recommendedActions[0] || 'Observe chain of custody.'}
              </span>
            </span>
            <button
              onClick={() => onNavigateTab('evidence')}
              className="px-3 py-1 bg-slate-800 hover:bg-slate-700 text-cyan-300 rounded border border-slate-700 transition-colors"
            >
              View Supporting Evidence
            </button>
          </div>
        </div>
      )}
    </div>
  );
};
