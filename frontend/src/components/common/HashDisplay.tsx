import React, { useState } from 'react';
import { Copy, Check } from 'lucide-react';

interface HashDisplayProps {
  hash: string;
  label?: string;
  truncate?: boolean;
  length?: number;
  className?: string;
}

export const HashDisplay: React.FC<HashDisplayProps> = ({
  hash,
  label,
  truncate = false,
  length = 16,
  className = '',
}) => {
  const [copied, setCopied] = useState(false);

  const handleCopy = (e: React.MouseEvent) => {
    e.stopPropagation();
    if (!hash) return;
    navigator.clipboard.writeText(hash);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const displayText = truncate && hash.length > length * 2
    ? `${hash.slice(0, length)}...${hash.slice(-length)}`
    : hash;

  return (
    <div className={`inline-flex items-center gap-2 group ${className}`}>
      {label && <span className="text-xs text-slate-400 font-mono">{label}:</span>}
      <code className="text-xs font-mono text-cyan-300/90 bg-slate-900/80 px-2 py-0.5 rounded border border-slate-800 select-all tracking-tight">
        {displayText || 'None'}
      </code>
      {hash && (
        <button
          onClick={handleCopy}
          title="Copy SHA-256 Hash"
          className="text-slate-400 hover:text-cyan-300 transition-colors p-1 rounded hover:bg-slate-800 focus:outline-none"
        >
          {copied ? (
            <Check className="w-3.5 h-3.5 text-emerald-400" />
          ) : (
            <Copy className="w-3.5 h-3.5" />
          )}
        </button>
      )}
    </div>
  );
};
