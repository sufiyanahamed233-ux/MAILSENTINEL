import React, { useState } from 'react';
import {
  ShieldAlert,
  Mail,
  Code2,
  Link2,
  Network,
  Globe,
  Brain,
  FileCheck,
  FileDown,
  ArrowLeft,
  Clock,
  User,
  Hash,
} from 'lucide-react';
import { useForensics } from '../context/ForensicContext';
import { OverviewTab } from '../components/workspace/OverviewTab';
import { SafeEmailViewer } from '../components/workspace/SafeEmailViewer';
import { ForensicHeadersViewer } from '../components/workspace/ForensicHeadersViewer';
import { UrlsDomainsTab } from '../components/workspace/UrlsDomainsTab';
import { InfrastructureGraph } from '../components/workspace/InfrastructureGraph';
import { GeoLocationMap } from '../components/workspace/GeoLocationMap';
import { AIAssessmentPanel } from '../components/workspace/AIAssessmentPanel';
import { EvidenceVerificationTab } from '../components/workspace/EvidenceVerificationTab';
import { GenerateReportModal } from '../components/reports/GenerateReportModal';
import { StatusBadge } from '../components/common/StatusBadge';
import { RiskBadge } from '../components/common/RiskBadge';
import { EmptyState } from '../components/common/EmptyState';

export const WorkspacePage: React.FC = () => {
  const { activeCase, setCurrentView } = useForensics();
  const [activeTab, setActiveTab] = useState<string>('overview');
  const [isReportModalOpen, setIsReportModalOpen] = useState<boolean>(false);

  if (!activeCase) {
    return (
      <div className="max-w-4xl mx-auto py-12">
        <EmptyState
          icon={ShieldAlert}
          title="No active case selected"
          description="Select an existing case from the investigation repository or upload an email to open a forensic workspace."
          actionText="Ingest Email to Investigate"
          onAction={() => setCurrentView('analyze')}
        />
      </div>
    );
  }

  const tabs = [
    { id: 'overview', label: 'Overview', icon: ShieldAlert },
    { id: 'email', label: 'Email', icon: Mail },
    { id: 'headers', label: 'Headers', icon: Code2 },
    { id: 'urls', label: 'URLs & Domains', icon: Link2, badge: activeCase.urls.length },
    { id: 'infrastructure', label: 'Infrastructure', icon: Network },
    { id: 'geolocation', label: 'GeoLocation', icon: Globe },
    { id: 'ai', label: 'AI Analysis', icon: Brain },
    { id: 'evidence', label: 'Evidence', icon: FileCheck },
  ];

  return (
    <div className="space-y-4">
      {/* Workspace Header & Docket Info */}
      <div className="p-4 bg-[#0d1322] border border-slate-800 rounded-lg">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div className="flex items-start gap-3">
            <button
              onClick={() => setCurrentView('investigations')}
              title="Return to Case Files"
              className="p-1.5 rounded text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors mt-0.5"
            >
              <ArrowLeft className="w-4 h-4" />
            </button>

            <div>
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-xs font-mono font-bold text-cyan-400 bg-cyan-950/40 px-2 py-0.5 rounded border border-cyan-500/30">
                  {activeCase.caseNumber}
                </span>
                <StatusBadge status={activeCase.status} />
                <RiskBadge level={activeCase.riskLevel} classification={activeCase.classification} />
              </div>

              <h2 className="text-base font-bold text-slate-100 mt-1 font-sans">
                {activeCase.subject}
              </h2>

              <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs font-mono text-slate-400 mt-1">
                <span className="truncate max-w-sm">From: {activeCase.sender}</span>
                <span>·</span>
                <span className="flex items-center gap-1">
                  <Clock className="w-3 h-3" />
                  {activeCase.createdAt.slice(0, 19).replace('T', ' ')} UTC
                </span>
                <span>·</span>
                <span className="flex items-center gap-1">
                  <User className="w-3 h-3" />
                  {activeCase.investigator || 'SOC Lead'}
                </span>
              </div>
            </div>
          </div>

          <div className="flex items-center gap-2 self-start lg:self-center">
            <button
              onClick={() => setIsReportModalOpen(true)}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold text-slate-200 bg-slate-900 hover:bg-slate-800 border border-slate-700 rounded transition-colors font-mono"
            >
              <FileDown className="w-3.5 h-3.5 text-cyan-400" />
              <span>Compile Report</span>
            </button>
          </div>
        </div>

        {/* Tab Navigation */}
        <div className="flex items-center gap-1 mt-4 pt-3 border-t border-slate-800 overflow-x-auto">
          {tabs.map((tab) => {
            const Icon = tab.icon;
            const isActive = activeTab === tab.id;

            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center gap-2 px-3 py-1.5 rounded text-xs font-mono font-medium transition-colors whitespace-nowrap ${
                  isActive
                    ? 'bg-cyan-950/60 text-cyan-300 border border-cyan-500/40 shadow-xs'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/60'
                }`}
              >
                <Icon className={`w-3.5 h-3.5 ${isActive ? 'text-cyan-400' : 'text-slate-500'}`} />
                <span>{tab.label}</span>
                {tab.badge !== undefined && tab.badge > 0 && (
                  <span className="text-[10px] bg-slate-800 text-slate-300 px-1.5 rounded tabular-nums">
                    {tab.badge}
                  </span>
                )}
              </button>
            );
          })}
        </div>
      </div>

      {/* Tab Panels */}
      <div className="transition-opacity">
        {activeTab === 'overview' && (
          <OverviewTab forensicCase={activeCase} onNavigateTab={setActiveTab} />
        )}

        {activeTab === 'email' && (
          <SafeEmailViewer email={activeCase.emailData} />
        )}

        {activeTab === 'headers' && (
          <ForensicHeadersViewer
            auth={activeCase.emailData.authentication}
            hops={activeCase.emailData.hops}
            rawHeaders={activeCase.emailData.headersRaw}
          />
        )}

        {activeTab === 'urls' && (
          <UrlsDomainsTab urls={activeCase.urls} domains={activeCase.domains} />
        )}

        {activeTab === 'infrastructure' && (
          <InfrastructureGraph graph={activeCase.infrastructure} />
        )}

        {activeTab === 'geolocation' && (
          <GeoLocationMap ips={activeCase.ips} />
        )}

        {activeTab === 'ai' && (
          <AIAssessmentPanel
            analysis={activeCase.aiAnalysis}
            onViewEvidence={() => setActiveTab('evidence')}
          />
        )}

        {activeTab === 'evidence' && (
          <EvidenceVerificationTab evidence={activeCase.evidence} />
        )}
      </div>

      {/* Report Modal */}
      <GenerateReportModal
        caseId={activeCase.id}
        isOpen={isReportModalOpen}
        onClose={() => setIsReportModalOpen(false)}
        onSuccess={() => setCurrentView('reports')}
      />
    </div>
  );
};
