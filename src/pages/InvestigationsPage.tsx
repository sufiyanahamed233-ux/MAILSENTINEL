import React, { useState } from 'react';
import {
  ShieldAlert,
  Search,
  Filter,
  Calendar,
  ChevronLeft,
  ChevronRight,
  ExternalLink,
  Plus,
} from 'lucide-react';
import { useForensics } from '../context/ForensicContext';
import { RiskBadge } from '../components/common/RiskBadge';
import { StatusBadge } from '../components/common/StatusBadge';
import { EmptyState } from '../components/common/EmptyState';

export const InvestigationsPage: React.FC = () => {
  const { cases, selectCase, setCurrentView } = useForensics();

  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [riskFilter, setRiskFilter] = useState('all');
  const [currentPage, setCurrentPage] = useState(1);
  const itemsPerPage = 8;

  // Filter logic
  const filteredCases = cases.filter((c) => {
    const matchesSearch =
      !searchTerm ||
      c.caseNumber.toLowerCase().includes(searchTerm.toLowerCase()) ||
      c.subject.toLowerCase().includes(searchTerm.toLowerCase()) ||
      c.sender.toLowerCase().includes(searchTerm.toLowerCase());

    const matchesStatus = statusFilter === 'all' || c.status === statusFilter;
    const matchesRisk = riskFilter === 'all' || c.riskLevel === riskFilter;

    return matchesSearch && matchesStatus && matchesRisk;
  });

  const totalPages = Math.max(1, Math.ceil(filteredCases.length / itemsPerPage));
  const paginatedCases = filteredCases.slice(
    (currentPage - 1) * itemsPerPage,
    currentPage * itemsPerPage
  );

  return (
    <div className="space-y-5">
      {/* Header & Controls */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3">
        <div>
          <h2 className="text-base font-bold text-slate-100 font-mono uppercase tracking-wider">
            Investigation Case Files
          </h2>
          <p className="text-xs text-slate-400 font-mono mt-0.5">
            Active Forensic Repositories & Cryptographic Dockets
          </p>
        </div>

        <button
          onClick={() => setCurrentView('analyze')}
          className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold text-white bg-cyan-600 hover:bg-cyan-500 rounded transition-colors shadow-xs whitespace-nowrap self-start sm:self-auto"
        >
          <Plus className="w-3.5 h-3.5" />
          <span>New Investigation</span>
        </button>
      </div>

      {/* Filter Bar */}
      <div className="p-3 bg-[#0d1322] border border-slate-800 rounded-lg flex flex-col md:flex-row items-stretch md:items-center justify-between gap-3">
        <div className="relative flex-1 max-w-md">
          <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Search by Case ID, subject, or sender address..."
            className="w-full pl-9 pr-3 py-1.5 bg-slate-950 border border-slate-800 rounded text-xs text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-cyan-500/50 font-mono"
          />
        </div>

        <div className="flex flex-wrap items-center gap-2 text-xs font-mono">
          {/* Status Filter */}
          <div className="flex items-center gap-1 bg-slate-950 px-2 py-1 rounded border border-slate-800">
            <span className="text-slate-500">Status:</span>
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="bg-transparent text-slate-300 focus:outline-none cursor-pointer"
            >
              <option value="all" className="bg-slate-900">All Statuses</option>
              <option value="open" className="bg-slate-900">Open</option>
              <option value="under_review" className="bg-slate-900">Under Review</option>
              <option value="verified" className="bg-slate-900">Verified</option>
              <option value="closed" className="bg-slate-900">Closed</option>
            </select>
          </div>

          {/* Risk Filter */}
          <div className="flex items-center gap-1 bg-slate-950 px-2 py-1 rounded border border-slate-800">
            <span className="text-slate-500">Risk:</span>
            <select
              value={riskFilter}
              onChange={(e) => setRiskFilter(e.target.value)}
              className="bg-transparent text-slate-300 focus:outline-none cursor-pointer"
            >
              <option value="all" className="bg-slate-900">All Risk Levels</option>
              <option value="critical" className="bg-slate-900">Critical</option>
              <option value="malicious" className="bg-slate-900">Malicious</option>
              <option value="suspicious" className="bg-slate-900">Suspicious</option>
              <option value="benign" className="bg-slate-900">Benign Clean</option>
            </select>
          </div>
        </div>
      </div>

      {/* Investigations Table */}
      <div className="border border-slate-800 bg-[#0d1322] rounded-lg overflow-hidden flex flex-col">
        {cases.length === 0 ? (
          <div className="p-8">
            <EmptyState
              icon={ShieldAlert}
              title="No investigations yet"
              description="No digital forensics cases have been registered in the database. Ingest an email file or raw headers to begin the investigation pipeline."
              actionText="Analyze Email"
              onAction={() => setCurrentView('analyze')}
            />
          </div>
        ) : filteredCases.length === 0 ? (
          <div className="p-8 text-center text-xs font-mono text-slate-500">
            No investigations match the applied filter criteria.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className="bg-slate-900/90 text-slate-400 border-b border-slate-800 uppercase text-[10px] tracking-wider">
                <tr>
                  <th className="py-3 px-4">Case ID</th>
                  <th className="py-3 px-4">Email Subject</th>
                  <th className="py-3 px-4">Sender Address</th>
                  <th className="py-3 px-4">Risk Posture</th>
                  <th className="py-3 px-4">Classification</th>
                  <th className="py-3 px-4">Status</th>
                  <th className="py-3 px-4">Created</th>
                  <th className="py-3 px-4 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-slate-300">
                {paginatedCases.map((c) => (
                  <tr
                    key={c.id}
                    onClick={() => selectCase(c.id)}
                    className="hover:bg-slate-800/40 cursor-pointer transition-colors"
                  >
                    <td className="py-3 px-4 text-cyan-400 font-bold select-all">
                      {c.caseNumber}
                    </td>
                    <td className="py-3 px-4 font-sans text-slate-100 max-w-xs truncate font-medium">
                      {c.subject}
                    </td>
                    <td className="py-3 px-4 text-slate-400 max-w-[160px] truncate select-all">
                      {c.sender}
                    </td>
                    <td className="py-3 px-4">
                      <RiskBadge level={c.riskLevel} />
                    </td>
                    <td className="py-3 px-4 text-slate-200">
                      {c.classification}
                    </td>
                    <td className="py-3 px-4">
                      <StatusBadge status={c.status} />
                    </td>
                    <td className="py-3 px-4 text-slate-400 text-[11px]">
                      {c.createdAt.slice(0, 10)}
                    </td>
                    <td className="py-3 px-4 text-right">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          selectCase(c.id);
                        }}
                        className="text-cyan-400 hover:text-cyan-300 font-semibold inline-flex items-center gap-1"
                      >
                        <span>Open</span>
                        <ExternalLink className="w-3 h-3" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Pagination UI */}
        {filteredCases.length > 0 && (
          <div className="p-3 bg-slate-900/60 border-t border-slate-800 flex items-center justify-between text-xs font-mono">
            <span className="text-slate-400">
              Showing {(currentPage - 1) * itemsPerPage + 1} to{' '}
              {Math.min(currentPage * itemsPerPage, filteredCases.length)} of{' '}
              {filteredCases.length} case records
            </span>

            <div className="flex items-center gap-1">
              <button
                disabled={currentPage === 1}
                onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
                className="p-1 rounded text-slate-400 hover:text-slate-200 hover:bg-slate-800 disabled:opacity-30 disabled:cursor-not-allowed"
              >
                <ChevronLeft className="w-4 h-4" />
              </button>
              <span className="px-2 text-slate-300">
                Page {currentPage} of {totalPages}
              </span>
              <button
                disabled={currentPage === totalPages}
                onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))}
                className="p-1 rounded text-slate-400 hover:text-slate-200 hover:bg-slate-800 disabled:opacity-30 disabled:cursor-not-allowed"
              >
                <ChevronRight className="w-4 h-4" />
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
