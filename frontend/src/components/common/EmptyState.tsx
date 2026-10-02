import React from 'react';
import { LucideIcon, ShieldAlert } from 'lucide-react';

interface EmptyStateProps {
  icon?: LucideIcon;
  title: string;
  description: string;
  actionText?: string;
  onAction?: () => void;
  secondaryText?: string;
}

export const EmptyState: React.FC<EmptyStateProps> = ({
  icon: Icon = ShieldAlert,
  title,
  description,
  actionText,
  onAction,
  secondaryText,
}) => {
  return (
    <div className="flex flex-col items-center justify-center p-12 text-center border border-slate-800/80 rounded-lg bg-[#0b101c]/50">
      <div className="w-12 h-12 rounded-lg bg-slate-900/90 border border-slate-800 flex items-center justify-center text-cyan-400 mb-4 shadow-inner">
        <Icon className="w-6 h-6 stroke-[1.5]" />
      </div>
      <h3 className="text-base font-semibold text-slate-200 mb-1.5">{title}</h3>
      <p className="text-sm text-slate-400 max-w-md mb-6 leading-relaxed">{description}</p>
      
      {actionText && onAction && (
        <button
          onClick={onAction}
          className="inline-flex items-center gap-2 px-4 py-2 text-xs font-semibold text-white bg-cyan-600 hover:bg-cyan-500 rounded-md transition-colors shadow-sm focus:outline-none focus:ring-2 focus:ring-cyan-500/50"
        >
          {actionText}
        </button>
      )}

      {secondaryText && (
        <span className="text-xs text-slate-500 mt-4 font-mono">{secondaryText}</span>
      )}
    </div>
  );
};
