import React, { useState, useRef } from 'react';
import {
  UploadCloud,
  FileCode,
  FileText,
  AlertCircle,
  CheckCircle2,
  ArrowRight,
  ShieldCheck,
  X,
  Play,
  RotateCcw,
} from 'lucide-react';
import { useForensics } from '../context/ForensicContext';
import { AnalysisPipeline } from '../components/analysis/AnalysisPipeline';

export const AnalyzeEmailPage: React.FC = () => {
  const { startEmailAnalysis, pipelineStages, isAnalyzing, analysisError, selectCase } = useForensics();

  const [activeInputTab, setActiveInputTab] = useState<'upload' | 'paste'>('upload');
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [pastedHeaders, setPastedHeaders] = useState<string>('');
  const [isDragOver, setIsDragOver] = useState(false);
  const [completedCaseId, setCompletedCaseId] = useState<string | null>(null);

  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleFileDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragOver(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      const file = e.dataTransfer.files[0];
      setSelectedFile(file);
      setCompletedCaseId(null);
    }
  };

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      setSelectedFile(e.target.files[0]);
      setCompletedCaseId(null);
    }
  };

  const handleClear = () => {
    setSelectedFile(null);
    setPastedHeaders('');
    setCompletedCaseId(null);
  };

  const handleStartAnalysis = async () => {
    setCompletedCaseId(null);
    const caseId = await startEmailAnalysis(
      activeInputTab === 'upload' ? selectedFile || undefined : undefined,
      activeInputTab === 'paste' ? pastedHeaders : undefined
    );

    if (caseId) {
      setCompletedCaseId(caseId);
    }
  };

  return (
    <div className="space-y-6 max-w-5xl mx-auto">
      {/* Title & Forensic Ingestion Directives */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-4">
        <div>
          <h2 className="text-base font-bold text-slate-100 font-mono uppercase tracking-wider">
            Email Threat Ingestion & Parsing
          </h2>
          <p className="text-xs text-slate-400 font-mono mt-0.5">
            Accepts RFC 5322 raw streams, standard .eml, and Outlook .msg envelopes
          </p>
        </div>

        <div className="flex items-center gap-1.5 text-xs font-mono text-emerald-400 bg-emerald-950/20 px-2.5 py-1 rounded border border-emerald-500/30">
          <ShieldCheck className="w-3.5 h-3.5" />
          <span>Active Forensic Sandbox Enabled</span>
        </div>
      </div>

      {/* Input Selection Segmented Tabs */}
      <div className="flex items-center gap-2">
        <button
          onClick={() => setActiveInputTab('upload')}
          disabled={isAnalyzing}
          className={`flex items-center gap-2 px-4 py-2 text-xs font-mono font-medium rounded transition-colors ${
            activeInputTab === 'upload'
              ? 'bg-cyan-950/60 text-cyan-300 border border-cyan-500/40 shadow-xs'
              : 'text-slate-400 hover:text-slate-200 bg-slate-900/40 border border-slate-800'
          }`}
        >
          <UploadCloud className="w-4 h-4" />
          <span>Upload .eml / .msg File</span>
        </button>

        <button
          onClick={() => setActiveInputTab('paste')}
          disabled={isAnalyzing}
          className={`flex items-center gap-2 px-4 py-2 text-xs font-mono font-medium rounded transition-colors ${
            activeInputTab === 'paste'
              ? 'bg-cyan-950/60 text-cyan-300 border border-cyan-500/40 shadow-xs'
              : 'text-slate-400 hover:text-slate-200 bg-slate-900/40 border border-slate-800'
          }`}
        >
          <FileCode className="w-4 h-4" />
          <span>Paste Raw Email Headers</span>
        </button>
      </div>

      {/* Upload Interface */}
      {activeInputTab === 'upload' && (
        <div
          onDragOver={(e) => {
            e.preventDefault();
            setIsDragOver(true);
          }}
          onDragLeave={() => setIsDragOver(false)}
          onDrop={handleFileDrop}
          className={`border-2 border-dashed rounded-lg p-10 text-center transition-colors ${
            isDragOver
              ? 'border-cyan-400 bg-cyan-950/20'
              : 'border-slate-800 bg-[#0d1322]/80 hover:border-slate-700'
          }`}
        >
          <input
            ref={fileInputRef}
            type="file"
            accept=".eml,.msg,message/rfc822,text/plain"
            onChange={handleFileSelect}
            className="hidden"
          />

          {selectedFile ? (
            <div className="max-w-md mx-auto p-4 rounded bg-slate-900 border border-slate-800 text-left font-mono">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2.5 truncate">
                  <FileText className="w-5 h-5 text-cyan-400 shrink-0" />
                  <div className="truncate">
                    <span className="text-xs font-bold text-slate-100 block truncate">
                      {selectedFile.name}
                    </span>
                    <span className="text-[11px] text-slate-400">
                      {(selectedFile.size / 1024).toFixed(1)} KB · Ready for hash verification
                    </span>
                  </div>
                </div>

                {!isAnalyzing && (
                  <button
                    onClick={handleClear}
                    className="p-1 rounded text-slate-400 hover:text-rose-400 transition-colors ml-2"
                  >
                    <X className="w-4 h-4" />
                  </button>
                )}
              </div>
            </div>
          ) : (
            <div className="space-y-3">
              <div className="w-12 h-12 mx-auto rounded-lg bg-slate-900 border border-slate-800 flex items-center justify-center text-cyan-400 shadow-inner">
                <UploadCloud className="w-6 h-6 stroke-[1.5]" />
              </div>
              <div>
                <p className="text-sm font-semibold text-slate-200">
                  Drag & Drop email file here, or{' '}
                  <button
                    type="button"
                    onClick={() => fileInputRef.current?.click()}
                    className="text-cyan-400 hover:underline font-semibold focus:outline-none"
                  >
                    browse local file system
                  </button>
                </p>
                <p className="text-xs text-slate-500 font-mono mt-1">
                  Supported formats: Standard RFC 5322 (.eml) and Microsoft Outlook (.msg)
                </p>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Paste Headers Interface */}
      {activeInputTab === 'paste' && (
        <div className="border border-slate-800 bg-[#0d1322] rounded-lg p-4 space-y-2">
          <div className="flex items-center justify-between text-xs font-mono text-slate-400">
            <span>RFC 5322 Envelope & Header Input Stream</span>
            <span className="tabular-nums">{pastedHeaders.length} characters</span>
          </div>

          <textarea
            value={pastedHeaders}
            onChange={(e) => setPastedHeaders(e.target.value)}
            disabled={isAnalyzing}
            placeholder={`Received: from mail.attacker-domain.example (mail.attacker-domain.example [198.51.100.24])\nFrom: Executive Security <spoofed@company.com>\nReply-To: phish@suspicious-host.net\nSubject: Urgent: Verify Account Credentials\nAuthentication-Results: spf=fail; dkim=none; dmarc=fail\n...`}
            rows={10}
            className="w-full p-4 bg-slate-950 border border-slate-800 rounded font-mono text-xs text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500/60 leading-relaxed"
          />

          <div className="flex items-center justify-between pt-1">
            <span className="text-[11px] text-slate-500 font-mono">
              Include Received, Authentication-Results, From, and Subject headers for full fidelity.
            </span>
            {pastedHeaders && !isAnalyzing && (
              <button
                onClick={() => setPastedHeaders('')}
                className="text-xs font-mono text-slate-400 hover:text-slate-200"
              >
                Clear Input
              </button>
            )}
          </div>
        </div>
      )}

      {/* Action Trigger Button */}
      <div className="flex items-center justify-between pt-2">
        <div className="text-xs font-mono text-slate-400">
          <span>Target Destination: </span>
          <span className="text-cyan-400 font-semibold">Forensic Investigation Vault</span>
        </div>

        <button
          onClick={handleStartAnalysis}
          disabled={isAnalyzing || (activeInputTab === 'upload' && !selectedFile) || (activeInputTab === 'paste' && !pastedHeaders.trim())}
          className="flex items-center gap-2 px-6 py-2.5 bg-cyan-600 hover:bg-cyan-500 text-white rounded font-mono text-xs font-bold transition-colors shadow-sm disabled:opacity-40 disabled:cursor-not-allowed cursor-pointer"
        >
          {isAnalyzing ? (
            <>
              <span className="w-3.5 h-3.5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
              <span>Analyzing Envelope...</span>
            </>
          ) : (
            <>
              <Play className="w-3.5 h-3.5 fill-current" />
              <span>Start Analysis</span>
            </>
          )}
        </button>
      </div>

      {/* Error State */}
      {analysisError && (
        <div className="p-3.5 rounded bg-rose-950/30 border border-rose-500/40 text-rose-300 text-xs font-mono flex items-center gap-2">
          <AlertCircle className="w-4 h-4 text-rose-400 shrink-0" />
          <span>{analysisError}</span>
        </div>
      )}

      {/* Success Banner when analysis finishes */}
      {completedCaseId && (
        <div className="p-4 rounded-lg bg-emerald-950/30 border border-emerald-500/40 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0" />
            <div>
              <h4 className="text-xs font-bold text-emerald-200 font-mono uppercase tracking-wider">
                Forensic Pipeline Execution Completed
              </h4>
              <p className="text-xs text-slate-300 font-mono mt-0.5">
                All 9 inspection stages finished. Case fingerprint registered in evidence vault.
              </p>
            </div>
          </div>

          <button
            onClick={() => selectCase(completedCaseId)}
            className="flex items-center gap-1.5 px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded text-xs font-mono font-bold transition-colors shadow-xs"
          >
            <span>Open Investigation Workspace</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>
      )}

      {/* 9-Stage Analysis Pipeline Reusable Progress Component */}
      <AnalysisPipeline stages={pipelineStages} isAnalyzing={isAnalyzing} />
    </div>
  );
};
