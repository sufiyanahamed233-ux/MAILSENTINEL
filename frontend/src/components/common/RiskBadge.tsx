import React from 'react';
import { RiskLevel, ThreatClassification } from '../../types/forensics';

interface RiskBadgeProps {
  level?: RiskLevel;
  classification?: ThreatClassification;
  showScore?: boolean;
  score?: number;
}

export const RiskBadge: React.FC<RiskBadgeProps> = ({ level = 'unassessed', classification, showScore, score }) => {
  // Observes zero-pill discipline: unboxed typographic presentation with semantic accent dots
  switch (level) {
    case 'critical':
      return (
        <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-rose-400">
          <span className="w-1.5 h-1.5 rounded-full bg-rose-500 animate-pulse" />
          <span>{classification || 'Critical Risk'}</span>
          {showScore && score !== undefined && (
            <span className="font-mono text-rose-500/80">({score}/100)</span>
          )}
        </span>
      );
    case 'malicious':
      return (
        <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-red-400">
          <span className="w-1.5 h-1.5 rounded-full bg-red-500" />
          <span>{classification || 'Malicious'}</span>
          {showScore && score !== undefined && (
            <span className="font-mono text-red-500/80">({score}/100)</span>
          )}
        </span>
      );
    case 'suspicious':
      return (
        <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-amber-400">
          <span className="w-1.5 h-1.5 rounded-full bg-amber-500" />
          <span>{classification || 'Suspicious'}</span>
          {showScore && score !== undefined && (
            <span className="font-mono text-amber-500/80">({score}/100)</span>
          )}
        </span>
      );
    case 'benign':
      return (
        <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-emerald-400">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
          <span>{classification || 'Verified Clean'}</span>
          {showScore && score !== undefined && (
            <span className="font-mono text-emerald-500/80">({score}/100)</span>
          )}
        </span>
      );
    default:
      return (
        <span className="inline-flex items-center gap-1.5 text-xs font-medium text-slate-400">
          <span className="w-1.5 h-1.5 rounded-full bg-slate-600" />
          <span>{classification || 'Unassessed'}</span>
        </span>
      );
  }
};
