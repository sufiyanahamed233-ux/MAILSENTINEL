import React, { useState } from 'react';
import {
  Brain,
  ShieldAlert,
  CheckCircle2,
  FileSearch,
  ArrowRight,
  ListChecks,
  ExternalLink,
} from 'lucide-react';
import { AIAnalysis } from '../../types/forensics';
import { RiskBadge } from '../common/RiskBadge';
import { EmptyState } from '../common/EmptyState';

interface AIAssessmentPanelProps {
  analysis?: AIAnalysis;
  onViewEvidence?: () => void;
}

export const AIAssessmentPanel: React.FC<AIAssessmentPanelProps> = ({
  analysis,
  onViewEvidence,
}) => {
  const [showEvidenceModal, setShowEvidenceModal] = useState<boolean>(false);

  if (!analysis) {
    return (
      <EmptyState
        icon={Brain}
        title="No AI assessment generated"
        description="Forensic intelligence reasoning will appear here once the envelope indicators, authentication headers, and URL signals are ingested and evaluated by the forensic engine."
      />
    );
  }

  return (
    <div className="space-y-5">
      {/* Classification & Risk Evaluation Bar */}
      <div className="border border-slate-800 bg-[#0d1322] rounded-lg p-5">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-800">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded bg-cyan-950/80 border border-cyan-500/40 flex items-center justify-center text-cyan-400">
              <Brain className="w-5 h-5" />
            </div>
            <div>
              <span className="text-[11px] font-mono uppercase tracking-wider text-slate-400">
                Forensic Classification
              </span>
              <div className="flex items-center gap-2 mt-0.5">
                <h3 className="text-base font-bold text-slate-100">
                  {analysis.classification}
                </h3>
                <RiskBadge level={analysis.riskLevel} />
              </div>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <div className="text-right">
              <span className="text-[11px] font-mono text-slate-400 block">
                Evidence Confidence Index
              </span>
              <span className="font-mono text-sm font-bold text-cyan-400">
                {(analysis.confidence * 100).toFixed(0)}% Certainty
              </span>
            </div>
            {onViewEvidence && (
              <button
                onClick={onViewEvidence}
                className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold text-cyan-300 bg-cyan-950/50 hover:bg-cyan-900/60 border border-cyan-500/40 rounded transition-colors"
              >
                <FileSearch className="w-3.5 h-3.5" />
                <span>View Supporting Evidence</span>
              </button>
            )}
          </div>
        </div>

        {/* Structured Forensic Explanation */}
        <div className="mt-4">
          <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-300 font-mono mb-2">
            Evidence-Backed Forensic Reasoning
          </h4>
          <p className="text-sm text-slate-200 leading-relaxed bg-slate-950/60 p-4 rounded-md border border-slate-800">
            {analysis.explanation}
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
        {/* Key Indicators */}
        <div className="border border-slate-800 bg-[#0d1322] rounded-lg p-5">
          <div className="flex items-center gap-2 pb-3 border-b border-slate-800 mb-3">
            <ShieldAlert className="w-4 h-4 text-amber-400" />
            <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-300 font-mono">
              Key Substantiated Indicators ({analysis.keyIndicators.length})
            </h4>
          </div>

          {analysis.keyIndicators.length === 0 ? (
            <p className="text-xs text-slate-500 font-mono py-4">
              No anomalies or malicious indicators detected in envelope.
            </p>
          ) : (
            <ul className="space-y-2">
              {analysis.keyIndicators.map((ind, i) => (
                <li
                  key={i}
                  className="flex items-start gap-2.5 p-2.5 rounded bg-slate-900/60 border border-slate-800/80 text-xs text-slate-200"
                >
                  <span className="w-1.5 h-1.5 rounded-full bg-amber-400 shrink-0 mt-1.5" />
                  <span className="leading-snug">{ind}</span>
                </li>
              ))}
            </ul>
          )}
        </div>

        {/* Recommended Investigation Guidance */}
        <div className="border border-slate-800 bg-[#0d1322] rounded-lg p-5">
          <div className="flex items-center gap-2 pb-3 border-b border-slate-800 mb-3">
            <ListChecks className="w-4 h-4 text-cyan-400" />
            <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-300 font-mono">
              Recommended Investigation Actions
            </h4>
          </div>

          <div className="space-y-2">
            {analysis.recommendedActions.map((action, i) => (
              <div
                key={i}
                className="flex items-start gap-2.5 p-2.5 rounded bg-slate-900/60 border border-slate-800/80 text-xs text-slate-200"
              >
                <CheckCircle2 className="w-3.5 h-3.5 text-cyan-400 shrink-0 mt-0.5" />
                <span className="leading-snug">{action}</span>
              </div>
            ))}
          </div>

          {/* Evidence Sources Citation */}
          <div className="mt-4 pt-3 border-t border-slate-800">
            <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wider block mb-1.5">
              Forensic Source Ingestion:
            </span>
            <div className="flex flex-wrap gap-1.5">
              {analysis.evidenceSources.map((source, idx) => (
                <span
                  key={idx}
                  className="text-[11px] font-mono text-slate-400 bg-slate-950 px-2 py-0.5 rounded border border-slate-800"
                >
                  {source}
                </span>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
