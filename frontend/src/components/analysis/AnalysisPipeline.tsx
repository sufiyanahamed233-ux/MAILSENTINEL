import React from 'react';
import { CheckCircle2, Loader2, Circle, AlertCircle } from 'lucide-react';
import { PipelineStage } from '../../types/forensics';

interface AnalysisPipelineProps {
  stages: PipelineStage[];
  isAnalyzing: boolean;
}

export const AnalysisPipeline: React.FC<AnalysisPipelineProps> = ({ stages, isAnalyzing }) => {
  return (
    <div className="border border-slate-800 bg-[#0d1322] rounded-lg p-5">
      <div className="flex items-center justify-between border-b border-slate-800 pb-3 mb-4">
        <div>
          <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400">
            Forensic Inspection Pipeline
          </h4>
          <span className="text-xs text-slate-500 font-mono">
            RFC 5322 & Telemetry Correlator (9 Steps)
          </span>
        </div>
        <div className="flex items-center gap-2">
          {isAnalyzing ? (
            <span className="inline-flex items-center gap-1.5 text-xs text-cyan-400 font-mono">
              <Loader2 className="w-3.5 h-3.5 animate-spin" />
              <span>PROCESSING PIPELINE</span>
            </span>
          ) : (
            <span className="text-xs text-slate-500 font-mono">STANDBY / READY</span>
          )}
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
        {stages.map((stage) => {
          let statusIcon = <Circle className="w-4 h-4 text-slate-600" />;
          let cardBorder = 'border-slate-800/60 bg-slate-900/40 text-slate-400';

          if (stage.status === 'completed') {
            statusIcon = <CheckCircle2 className="w-4 h-4 text-emerald-400" />;
            cardBorder = 'border-emerald-950/60 bg-emerald-950/10 text-slate-200';
          } else if (stage.status === 'running') {
            statusIcon = <Loader2 className="w-4 h-4 text-cyan-400 animate-spin" />;
            cardBorder = 'border-cyan-500/40 bg-cyan-950/20 text-cyan-200 shadow-sm shadow-cyan-950';
          } else if (stage.status === 'failed') {
            statusIcon = <AlertCircle className="w-4 h-4 text-rose-400" />;
            cardBorder = 'border-rose-950/60 bg-rose-950/10 text-rose-300';
          }

          return (
            <div
              key={stage.id}
              className={`flex items-start gap-3 p-3 rounded-md border text-xs transition-colors ${cardBorder}`}
            >
              <div className="mt-0.5 shrink-0">{statusIcon}</div>
              <div className="min-w-0 flex-1">
                <div className="flex items-center justify-between">
                  <span className="font-semibold truncate">
                    {stage.id}. {stage.name}
                  </span>
                  <span className="font-mono text-[10px] text-slate-500 ml-2">
                    {stage.status.toUpperCase()}
                  </span>
                </div>
                {stage.detail ? (
                  <p className="mt-1 text-[11px] text-slate-400 font-mono truncate">
                    {stage.detail}
                  </p>
                ) : (
                  <p className="mt-1 text-[11px] text-slate-600">
                    Awaiting execution
                  </p>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
