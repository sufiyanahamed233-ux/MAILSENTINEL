import React from 'react';
import { CaseStatus } from '../../types/forensics';

interface StatusBadgeProps {
  status: CaseStatus | string;
}

export const StatusBadge: React.FC<StatusBadgeProps> = ({ status }) => {
  switch (status) {
    case 'open':
      return (
        <span className="inline-flex items-center gap-1.5 text-xs font-medium text-cyan-400">
          <span className="w-1.5 h-1.5 rounded-full bg-cyan-400" />
          <span>Open</span>
        </span>
      );
    case 'under_review':
      return (
        <span className="inline-flex items-center gap-1.5 text-xs font-medium text-amber-300">
          <span className="w-1.5 h-1.5 rounded-full bg-amber-400" />
          <span>Under Review</span>
        </span>
      );
    case 'verified':
      return (
        <span className="inline-flex items-center gap-1.5 text-xs font-medium text-emerald-400">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
          <span>Verified</span>
        </span>
      );
    case 'closed':
      return (
        <span className="inline-flex items-center gap-1.5 text-xs font-medium text-slate-400">
          <span className="w-1.5 h-1.5 rounded-full bg-slate-500" />
          <span>Closed</span>
        </span>
      );
    default:
      return (
        <span className="inline-flex items-center gap-1.5 text-xs font-medium text-slate-400">
          <span className="w-1.5 h-1.5 rounded-full bg-slate-600" />
          <span>{status}</span>
        </span>
      );
  }
};
