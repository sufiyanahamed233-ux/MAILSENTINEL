import React, { useState } from 'react';
import { X, FileText, Check, ShieldCheck, Download } from 'lucide-react';
import { useForensics } from '../../context/ForensicContext';

interface GenerateReportModalProps {
  caseId: string;
  isOpen: boolean;
  onClose: () => void;
  onSuccess?: () => void;
}

const REPORT_SECTIONS = [
  { id: '1', name: '1. Executive Summary' },
  { id: '2', name: '2. Email Information' },
  { id: '3', name: '3. Header Analysis' },
  { id: '4', name: '4. SPF/DKIM/DMARC' },
  { id: '5', name: '5. URL Analysis' },
  { id: '6', name: '6. Domain Analysis' },
  { id: '7', name: '7. IP/Infrastructure Analysis' },
  { id: '8', name: '8. Geolocation' },
  { id: '9', name: '9. AI Assessment' },
  { id: '10', name: '10. Evidence' },
  { id: '11', name: '11. Blockchain Verification' },
  { id: '12', name: '12. Investigation Timeline' },
];

export const GenerateReportModal: React.FC<GenerateReportModalProps> = ({
  caseId,
  isOpen,
  onClose,
  onSuccess,
}) => {
  const { cases, generateReport } = useForensics();
  const currentCase = cases.find(c => c.id === caseId);

  const [title, setTitle] = useState(`Forensic Intelligence Report - ${currentCase?.caseNumber || 'CASE'}`);
  const [selectedSections, setSelectedSections] = useState<string[]>(REPORT_SECTIONS.map(s => s.id));
  const [isCompiling, setIsCompiling] = useState(false);

  if (!isOpen) return null;

  const toggleSection = (id: string) => {
    setSelectedSections(prev =>
      prev.includes(id) ? prev.filter(x => x !== id) : [...prev, id]
    );
  };

  const handleSelectAll = () => {
    setSelectedSections(REPORT_SECTIONS.map(s => s.id));
  };

  const handleDeselectAll = () => {
    setSelectedSections(['1', '2', '10']); // Keep essential
  };

  const handleGenerate = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsCompiling(true);
    await new Promise(r => setTimeout(r, 600)); // compiling effect
    await generateReport(caseId, title, selectedSections);
    setIsCompiling(false);
    onClose();
    if (onSuccess) onSuccess();
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-xs">
      <div className="bg-[#0b101c] border border-slate-800 rounded-lg max-w-xl w-full p-6 shadow-2xl overflow-hidden flex flex-col max-h-[90vh]">
        <div className="flex items-center justify-between pb-3 border-b border-slate-800">
          <div className="flex items-center gap-2">
            <FileText className="w-5 h-5 text-cyan-400" />
            <h3 className="text-sm font-bold text-slate-100 uppercase tracking-wider font-mono">
              Compile Forensic Dossier
            </h3>
          </div>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-slate-200 p-1 rounded hover:bg-slate-800"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <form onSubmit={handleGenerate} className="mt-4 space-y-4 flex-1 overflow-y-auto pr-1">
          <div>
            <label className="text-xs font-mono uppercase text-slate-400 block mb-1.5">
              Report Title
            </label>
            <input
              type="text"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded text-xs text-slate-200 font-mono focus:outline-none focus:border-cyan-500"
              required
            />
          </div>

          <div>
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-mono uppercase text-slate-400">
                Include Forensic Modules ({selectedSections.length}/12)
              </span>
              <div className="flex items-center gap-2 text-[11px] font-mono">
                <button
                  type="button"
                  onClick={handleSelectAll}
                  className="text-cyan-400 hover:underline"
                >
                  Select All
                </button>
                <span className="text-slate-600">·</span>
                <button
                  type="button"
                  onClick={handleDeselectAll}
                  className="text-slate-400 hover:underline"
                >
                  Essential Only
                </button>
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 max-h-56 overflow-y-auto p-2 bg-slate-950/60 rounded border border-slate-800/80">
              {REPORT_SECTIONS.map((sec) => {
                const isChecked = selectedSections.includes(sec.id);
                return (
                  <label
                    key={sec.id}
                    className={`flex items-center gap-2 p-2 rounded text-xs font-mono cursor-pointer transition-colors ${
                      isChecked
                        ? 'bg-slate-900 text-slate-200 border border-slate-800'
                        : 'text-slate-500 hover:text-slate-400'
                    }`}
                  >
                    <input
                      type="checkbox"
                      checked={isChecked}
                      onChange={() => toggleSection(sec.id)}
                      className="rounded border-slate-700 text-cyan-500 focus:ring-0 bg-slate-900"
                    />
                    <span className="truncate">{sec.name}</span>
                  </label>
                );
              })}
            </div>
          </div>

          <div className="p-3 rounded bg-cyan-950/20 border border-cyan-500/20 text-xs text-cyan-200 font-mono flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-cyan-400 shrink-0" />
            <span>Cryptographic SHA-256 signatures & integrity stamps are appended automatically.</span>
          </div>

          <div className="pt-3 border-t border-slate-800 flex items-center justify-end gap-3">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 text-xs font-mono text-slate-400 hover:text-slate-200"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={isCompiling || selectedSections.length === 0}
              className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded text-xs font-semibold font-mono flex items-center gap-2 transition-colors disabled:opacity-50"
            >
              {isCompiling ? (
                <>
                  <span className="w-3.5 h-3.5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                  <span>Compiling...</span>
                </>
              ) : (
                <>
                  <Download className="w-3.5 h-3.5" />
                  <span>Generate Report</span>
                </>
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
