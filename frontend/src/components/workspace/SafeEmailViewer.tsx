import React, { useState } from 'react';
import { ShieldCheck, AlertTriangle, Eye, Code, FileText, Lock } from 'lucide-react';
import { EmailData } from '../../types/forensics';

interface SafeEmailViewerProps {
  email: EmailData;
}

export const SafeEmailViewer: React.FC<SafeEmailViewerProps> = ({ email }) => {
  const [viewMode, setViewMode] = useState<'text' | 'raw'>('text');

  return (
    <div className="border border-slate-800 bg-[#0d1322] rounded-lg overflow-hidden flex flex-col">
      {/* Security Banner */}
      <div className="px-4 py-2 bg-slate-900/90 border-b border-slate-800 flex items-center justify-between text-xs">
        <div className="flex items-center gap-2 text-emerald-400">
          <ShieldCheck className="w-4 h-4 shrink-0" />
          <span className="font-mono text-[11px]">
            ACTIVE FORENSIC SANDBOX — Active scripting, external image beacons, and telemetry disabled
          </span>
        </div>
        <div className="flex items-center gap-1 bg-slate-950 p-0.5 rounded border border-slate-800">
          <button
            onClick={() => setViewMode('text')}
            className={`px-2.5 py-1 text-xs rounded transition-colors ${
              viewMode === 'text' ? 'bg-cyan-900/40 text-cyan-300 font-medium' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Safe Text Body
          </button>
          <button
            onClick={() => setViewMode('raw')}
            className={`px-2.5 py-1 text-xs rounded transition-colors ${
              viewMode === 'raw' ? 'bg-cyan-900/40 text-cyan-300 font-medium' : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Raw RFC Stream
          </button>
        </div>
      </div>

      {/* RFC Envelope Metadata Headers */}
      <div className="p-4 border-b border-slate-800 bg-slate-900/40 space-y-2 text-xs font-mono">
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
          <div>
            <span className="text-slate-400 inline-block w-24">From:</span>
            <span className="text-slate-200 font-semibold select-all">{email.from}</span>
          </div>
          <div>
            <span className="text-slate-400 inline-block w-24">To:</span>
            <span className="text-slate-200 select-all">{email.to}</span>
          </div>
        </div>

        {email.replyTo && (
          <div>
            <span className="text-amber-400/90 inline-block w-24">Reply-To:</span>
            <span className="text-amber-300 select-all bg-amber-950/20 px-1.5 py-0.5 rounded border border-amber-900/40">
              {email.replyTo}
            </span>
          </div>
        )}

        {email.returnPath && (
          <div>
            <span className="text-slate-400 inline-block w-24">Return-Path:</span>
            <span className="text-slate-300 select-all">{email.returnPath}</span>
          </div>
        )}

        <div>
          <span className="text-slate-400 inline-block w-24">Subject:</span>
          <span className="text-slate-100 font-sans font-semibold text-sm select-all">
            {email.subject}
          </span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-slate-400">
          <div>
            <span className="text-slate-400 inline-block w-24">Date:</span>
            <span className="text-slate-300">{email.date}</span>
          </div>
          <div>
            <span className="text-slate-400 inline-block w-24">Message-ID:</span>
            <span className="text-slate-300 truncate select-all">{email.messageId}</span>
          </div>
        </div>
      </div>

      {/* Email Body Content (Strictly sanitized, no executable scripts) */}
      <div className="p-5 flex-1 overflow-y-auto max-h-[500px]">
        {viewMode === 'text' ? (
          email.bodyText ? (
            <div className="space-y-4">
              <pre className="text-xs text-slate-300 whitespace-pre-wrap font-mono leading-relaxed bg-slate-950/60 p-4 rounded border border-slate-800/80">
                {email.bodyText}
              </pre>
            </div>
          ) : (
            <div className="text-center py-12 text-slate-500 font-mono text-xs">
              No textual email payload present in RFC stream.
            </div>
          )
        ) : (
          <pre className="text-xs text-cyan-300/80 font-mono whitespace-pre-wrap bg-slate-950 p-4 rounded border border-slate-800/80 leading-relaxed select-all">
            {email.headersRaw}
          </pre>
        )}
      </div>

      {/* Attachments Footer */}
      {email.attachments && email.attachments.length > 0 && (
        <div className="px-4 py-3 bg-slate-900/60 border-t border-slate-800 flex items-center justify-between">
          <div className="flex items-center gap-2 text-xs">
            <span className="text-slate-400 font-mono">Attachments ({email.attachments.length}):</span>
            {email.attachments.map((att) => (
              <span
                key={att.id}
                className="inline-flex items-center gap-1.5 px-2 py-1 rounded bg-slate-800/80 border border-slate-700 text-slate-200 font-mono text-xs"
              >
                <FileText className="w-3 h-3 text-cyan-400" />
                <span>{att.filename}</span>
                <span className="text-slate-400">({(att.sizeBytes / 1024).toFixed(1)} KB)</span>
              </span>
            ))}
          </div>
          <span className="text-[11px] text-slate-500 font-mono">
            Cryptographic SHA-256 fingerprints generated
          </span>
        </div>
      )}
    </div>
  );
};
