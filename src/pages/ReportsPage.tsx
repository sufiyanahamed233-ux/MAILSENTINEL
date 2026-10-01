import React, { useState } from 'react';
import {
  FileText,
  Search,
  Download,
  Eye,
  Plus,
  ShieldCheck,
  Calendar,
  Layers,
  CheckCircle,
  X,
  Printer,
} from 'lucide-react';
import { useForensics } from '../context/ForensicContext';
import { ForensicReport } from '../types/forensics';
import { EmptyState } from '../components/common/EmptyState';
import { GenerateReportModal } from '../components/reports/GenerateReportModal';

export const ReportsPage: React.FC = () => {
  const { reports, cases, selectCase } = useForensics();
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedReport, setSelectedReport] = useState<ForensicReport | null>(null);
  const [isModalOpen, setIsModalOpen] = useState(false);

  const filteredReports = reports.filter(r =>
    !searchTerm ||
    r.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
    r.caseNumber.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const handleDownload = (rep: ForensicReport) => {
    const jsonStr = JSON.stringify(rep, null, 2);
    const blob = new Blob([jsonStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `MAILSENTINEL-${rep.caseNumber}-REPORT.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-4">
        <div>
          <h2 className="text-base font-bold text-slate-100 font-mono uppercase tracking-wider">
            Forensic Intelligence Reports
          </h2>
          <p className="text-xs text-slate-400 font-mono mt-0.5">
            Compiled digital forensics dossiers with cryptographic evidence attachments
          </p>
        </div>

        {cases.length > 0 && (
          <button
            onClick={() => setIsModalOpen(true)}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold text-white bg-cyan-600 hover:bg-cyan-500 rounded transition-colors shadow-xs font-mono self-start sm:self-auto"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>Generate New Report</span>
          </button>
        )}
      </div>

      {/* Search Toolbar */}
      <div className="p-3 bg-[#0d1322] border border-slate-800 rounded-lg flex items-center justify-between">
        <div className="relative flex-1 max-w-md">
          <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Search reports by title or case number..."
            className="w-full pl-9 pr-3 py-1.5 bg-slate-950 border border-slate-800 rounded text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-cyan-500/50 font-mono"
          />
        </div>
        <span className="text-xs font-mono text-slate-400">
          Total Dossiers: {reports.length}
        </span>
      </div>

      {/* Reports List */}
      <div className="border border-slate-800 bg-[#0d1322] rounded-lg overflow-hidden flex flex-col">
        {reports.length === 0 ? (
          <div className="p-8">
            <EmptyState
              icon={FileText}
              title="No reports generated"
              description="Formal forensic investigation dossiers will be archived here once compiled from an active case."
              actionText={cases.length > 0 ? "Generate Report from Case" : "Upload Email to Begin"}
              onAction={() => {
                if (cases.length > 0) setIsModalOpen(true);
                else selectCase('analyze');
              }}
            />
          </div>
        ) : filteredReports.length === 0 ? (
          <div className="p-8 text-center text-xs font-mono text-slate-500">
            No forensic reports match search query.
          </div>
        ) : (
          <div className="divide-y divide-slate-800">
            {filteredReports.map((rep) => (
              <div
                key={rep.id}
                className="p-4 hover:bg-slate-900/40 transition-colors flex flex-col sm:flex-row sm:items-center justify-between gap-3"
              >
                <div className="space-y-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-mono font-bold text-cyan-400">
                      {rep.caseNumber}
                    </span>
                    <span className="text-slate-500">·</span>
                    <span className="text-xs font-bold text-slate-100 font-sans truncate">
                      {rep.title}
                    </span>
                  </div>

                  <div className="flex items-center gap-4 text-xs font-mono text-slate-400">
                    <span>Generated: {rep.generatedAt.slice(0, 10)}</span>
                    <span>·</span>
                    <span>By: {rep.generatedBy}</span>
                    <span>·</span>
                    <span className="text-emerald-400">
                      {rep.sections.filter(s => s.isIncluded).length}/12 Modules Included
                    </span>
                  </div>
                </div>

                <div className="flex items-center gap-2 shrink-0">
                  <button
                    onClick={() => setSelectedReport(rep)}
                    className="flex items-center gap-1.5 px-3 py-1.5 text-xs text-slate-200 bg-slate-900 hover:bg-slate-800 border border-slate-700 rounded transition-colors font-mono"
                  >
                    <Eye className="w-3.5 h-3.5 text-cyan-400" />
                    <span>View Dossier</span>
                  </button>

                  <button
                    onClick={() => handleDownload(rep)}
                    className="flex items-center gap-1.5 px-3 py-1.5 text-xs text-slate-200 bg-slate-900 hover:bg-slate-800 border border-slate-700 rounded transition-colors font-mono"
                  >
                    <Download className="w-3.5 h-3.5 text-emerald-400" />
                    <span>JSON</span>
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Detailed Dossier Viewer Modal */}
      {selectedReport && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-xs">
          <div className="bg-[#0b101c] border border-slate-800 rounded-lg max-w-2xl w-full p-6 shadow-2xl flex flex-col max-h-[90vh]">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div className="flex items-center gap-2">
                <FileText className="w-5 h-5 text-cyan-400" />
                <h3 className="text-sm font-bold text-slate-100 uppercase tracking-wider font-mono">
                  {selectedReport.caseNumber} Dossier Overview
                </h3>
              </div>
              <button
                onClick={() => setSelectedReport(null)}
                className="text-slate-400 hover:text-slate-200 p-1"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="mt-4 space-y-4 flex-1 overflow-y-auto pr-1">
              <div className="p-3 bg-slate-950 rounded border border-slate-800 space-y-1 font-mono text-xs">
                <div className="text-slate-100 font-bold">{selectedReport.title}</div>
                <div className="text-slate-400">Docket: {selectedReport.caseNumber} · Investigator: {selectedReport.generatedBy}</div>
                <div className="text-slate-400">Timestamp: {selectedReport.generatedAt}</div>
              </div>

              <div>
                <h4 className="text-xs font-mono uppercase text-slate-400 tracking-wider mb-2">
                  Included Forensic Analysis Modules:
                </h4>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                  {selectedReport.sections.map((sec) => (
                    <div
                      key={sec.id}
                      className={`p-2.5 rounded text-xs font-mono flex items-center justify-between ${
                        sec.isIncluded
                          ? 'bg-slate-900 border border-slate-800 text-slate-200'
                          : 'bg-slate-950/40 border border-slate-900 text-slate-600 line-through'
                      }`}
                    >
                      <span>{sec.title}</span>
                      {sec.isIncluded && <CheckCircle className="w-3.5 h-3.5 text-cyan-400" />}
                    </div>
                  ))}
                </div>
              </div>
            </div>

            <div className="pt-4 border-t border-slate-800 flex items-center justify-between">
              <button
                onClick={() => window.print()}
                className="flex items-center gap-1.5 px-3 py-1.5 text-xs text-slate-300 bg-slate-900 hover:bg-slate-800 rounded font-mono border border-slate-700"
              >
                <Printer className="w-3.5 h-3.5 text-cyan-400" />
                <span>Print Dossier</span>
              </button>

              <button
                onClick={() => setSelectedReport(null)}
                className="px-4 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-white rounded text-xs font-mono font-bold"
              >
                Close View
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Generation Modal */}
      {cases.length > 0 && (
        <GenerateReportModal
          caseId={cases[0].id}
          isOpen={isModalOpen}
          onClose={() => setIsModalOpen(false)}
        />
      )}
    </div>
  );
};
