import React from 'react';
import {
  FileCheck,
  ShieldCheck,
  Hash,
  Database,
  Search,
  ExternalLink,
  Clock,
  Layers,
  AlertCircle,
} from 'lucide-react';
import { useForensics } from '../context/ForensicContext';
import { HashDisplay } from '../components/common/HashDisplay';
import { EmptyState } from '../components/common/EmptyState';

export const EvidencePage: React.FC = () => {
  const { evidenceList, selectCase, setCurrentView } = useForensics();

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-4">
        <div>
          <h2 className="text-base font-bold text-slate-100 font-mono uppercase tracking-wider">
            Evidence Vault & Chain of Custody
          </h2>
          <p className="text-xs text-slate-400 font-mono mt-0.5">
            Cryptographic SHA-256 fingerprints, hash notarizations, and audit logs
          </p>
        </div>

        <div className="flex items-center gap-2 text-xs font-mono text-cyan-400 bg-cyan-950/20 px-3 py-1.5 rounded border border-cyan-500/30">
          <Database className="w-3.5 h-3.5" />
          <span>Chain of Custody Compliant</span>
        </div>
      </div>

      {/* Advisory Banner */}
      <div className="flex items-start gap-2.5 p-3 rounded-md bg-slate-900/80 border border-slate-800 text-xs text-slate-300">
        <AlertCircle className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
        <p className="leading-relaxed">
          <span className="font-semibold text-cyan-300 font-mono">EVIDENCE INTEGRITY RULE: </span>
          Hashes recorded here represent immutable mathematical signatures of submitted byte streams. Blockchain timestamps attest to verification sequencing and tamper-evident custody; they do not attest to email trustworthiness.
        </p>
      </div>

      {/* Evidence Table */}
      <div className="border border-slate-800 bg-[#0d1322] rounded-lg overflow-hidden flex flex-col">
        {evidenceList.length === 0 ? (
          <div className="p-8">
            <EmptyState
              icon={FileCheck}
              title="No evidence collected"
              description="No cryptographic evidence records or envelope hashes have been fingerprinted yet. Upload an email file to ingest and notarize forensic artifacts."
              actionText="Ingest Email Artifact"
              onAction={() => setCurrentView('analyze')}
            />
          </div>
        ) : (
          <div className="divide-y divide-slate-800">
            {evidenceList.map((ev) => (
              <div key={ev.id} className="p-5 hover:bg-slate-900/30 transition-colors space-y-4">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800/60 pb-3">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-mono font-bold text-cyan-400">
                      {ev.caseId}
                    </span>
                    <span className="text-slate-500">·</span>
                    <span className="text-xs font-mono text-slate-300">
                      Investigator: {ev.investigator}
                    </span>
                  </div>

                  <div className="flex items-center gap-3">
                    <span className="text-xs font-mono text-slate-400">
                      {ev.timestamp.slice(0, 19).replace('T', ' ')} UTC
                    </span>
                    <button
                      onClick={() => selectCase(ev.caseId)}
                      className="text-xs font-mono text-cyan-400 hover:text-cyan-300 inline-flex items-center gap-1"
                    >
                      <span>View Case Dossier</span>
                      <ExternalLink className="w-3 h-3" />
                    </button>
                  </div>
                </div>

                <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                  {/* Hashes Column */}
                  <div className="space-y-2">
                    <div className="p-3 rounded bg-slate-950/80 border border-slate-800/80">
                      <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wider block mb-1">
                        Original Email Stream SHA-256
                      </span>
                      <HashDisplay hash={ev.originalEmailSha256} className="w-full justify-between" />
                    </div>

                    <div className="p-3 rounded bg-slate-950/80 border border-slate-800/80">
                      <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wider block mb-1">
                        Header Evidence SHA-256
                      </span>
                      <HashDisplay hash={ev.headerEvidenceSha256} className="w-full justify-between" />
                    </div>
                  </div>

                  {/* Blockchain & Verification Column */}
                  <div className="p-3 rounded bg-slate-950/80 border border-slate-800/80 flex flex-col justify-between">
                    <div className="space-y-2">
                      <div className="flex items-center justify-between pb-1 border-b border-slate-800">
                        <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wider">
                          Blockchain Notarization
                        </span>
                        <span className="inline-flex items-center gap-1 text-xs font-mono font-bold text-emerald-400">
                          <ShieldCheck className="w-3.5 h-3.5" />
                          <span>SEALED</span>
                        </span>
                      </div>

                      <div className="text-xs font-mono text-slate-400">
                        <span>Transaction Hash:</span>
                        <HashDisplay
                          hash={ev.blockchainVerification.transactionId || 'Pending'}
                          truncate
                          length={12}
                          className="mt-1 w-full justify-between"
                        />
                      </div>

                      {ev.blockchainVerification.merkleRoot && (
                        <div className="text-xs font-mono text-slate-400">
                          <span>Merkle Tree Root:</span>
                          <HashDisplay
                            hash={ev.blockchainVerification.merkleRoot}
                            truncate
                            length={12}
                            className="mt-1 w-full justify-between"
                          />
                        </div>
                      )}
                    </div>

                    <div className="pt-2 border-t border-slate-800 text-[10px] text-slate-500 font-mono flex items-center justify-between">
                      <span>Ledger: {ev.blockchainVerification.network || 'Distributed Ledger'}</span>
                      <span>Height #{ev.blockchainVerification.blockNumber || 100}</span>
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};
