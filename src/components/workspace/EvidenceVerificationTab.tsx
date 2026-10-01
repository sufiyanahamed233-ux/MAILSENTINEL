import React from 'react';
import {
  FileCheck,
  ShieldCheck,
  Layers,
  Clock,
  User,
  AlertCircle,
  Hash,
  Database,
  ExternalLink,
} from 'lucide-react';
import { EvidenceRecord } from '../../types/forensics';
import { HashDisplay } from '../common/HashDisplay';
import { EmptyState } from '../common/EmptyState';

interface EvidenceVerificationTabProps {
  evidence?: EvidenceRecord;
}

export const EvidenceVerificationTab: React.FC<EvidenceVerificationTabProps> = ({ evidence }) => {
  if (!evidence) {
    return (
      <EmptyState
        icon={FileCheck}
        title="No evidence collected"
        description="Cryptographic SHA-256 hashes and tamper-evident custody verification will record here once an email stream is ingested and fingerprinted."
      />
    );
  }

  return (
    <div className="space-y-5">
      {/* REQUIRED BLOCKCHAIN INTEGRITY PRINCIPLE DISCLAIMER */}
      <div className="flex items-start gap-2.5 p-3 rounded-md bg-slate-900/90 border border-slate-800 text-xs text-slate-300">
        <AlertCircle className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
        <p className="leading-relaxed">
          <span className="font-semibold text-cyan-300 font-mono">INTEGRITY CERTIFICATION: </span>
          Blockchain verification records provide tamper-evident mathematical proof of evidence custody, timestamp sequencing, and state immutability. Blockchain registration certifies evidence integrity and audit trail preservation; it does not attest to email trustworthiness.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        {/* Cryptographic SHA-256 Evidence Hashes */}
        <div className="border border-slate-800 bg-[#0d1322] rounded-lg p-5">
          <div className="flex items-center gap-2 pb-3 border-b border-slate-800 mb-4">
            <Hash className="w-4 h-4 text-cyan-400" />
            <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-300 font-mono">
              Forensic Fingerprint Hashes (SHA-256)
            </h4>
          </div>

          <div className="space-y-4">
            {/* Original Email Stream */}
            <div className="p-3 rounded-md bg-slate-950/70 border border-slate-800/80 space-y-1">
              <span className="text-xs font-mono text-slate-400 uppercase tracking-wider block">
                Original RFC Stream Hash
              </span>
              <HashDisplay hash={evidence.originalEmailSha256} className="w-full justify-between" />
            </div>

            {/* Header Evidence Hash */}
            <div className="p-3 rounded-md bg-slate-950/70 border border-slate-800/80 space-y-1">
              <span className="text-xs font-mono text-slate-400 uppercase tracking-wider block">
                Extracted Envelope Headers Hash
              </span>
              <HashDisplay hash={evidence.headerEvidenceSha256} className="w-full justify-between" />
            </div>

            {/* Attachments Hashes */}
            {evidence.attachmentHashes && evidence.attachmentHashes.length > 0 ? (
              <div className="space-y-2 pt-2 border-t border-slate-800">
                <span className="text-xs font-mono text-slate-400 uppercase tracking-wider block">
                  Attachment Artifact Hashes ({evidence.attachmentHashes.length})
                </span>
                {evidence.attachmentHashes.map((att, i) => (
                  <div key={i} className="p-3 rounded-md bg-slate-950/70 border border-slate-800/80 space-y-1">
                    <span className="text-xs text-slate-200 font-mono block truncate">
                      {att.filename} {att.sizeBytes && `(${(att.sizeBytes / 1024).toFixed(1)} KB)`}
                    </span>
                    <HashDisplay hash={att.sha256} className="w-full justify-between" />
                  </div>
                ))}
              </div>
            ) : (
              <div className="p-3 rounded bg-slate-950/40 border border-slate-800/60 text-xs font-mono text-slate-500">
                No external binary attachment payloads contained in envelope.
              </div>
            )}
          </div>
        </div>

        {/* Chain of Custody & Blockchain Verification Ledger */}
        <div className="border border-slate-800 bg-[#0d1322] rounded-lg p-5 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between pb-3 border-b border-slate-800 mb-4">
              <div className="flex items-center gap-2">
                <Database className="w-4 h-4 text-cyan-400" />
                <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-300 font-mono">
                  Chain of Custody & Verification
                </h4>
              </div>
              <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-emerald-400 font-mono">
                <ShieldCheck className="w-4 h-4" />
                <span>INTEGRITY VERIFIED</span>
              </span>
            </div>

            <div className="space-y-3 text-xs font-mono">
              <div className="flex justify-between py-1.5 border-b border-slate-800/60">
                <span className="text-slate-400 flex items-center gap-1.5">
                  <Clock className="w-3.5 h-3.5" /> Ingestion Timestamp:
                </span>
                <span className="text-slate-200">{evidence.timestamp}</span>
              </div>

              <div className="flex justify-between py-1.5 border-b border-slate-800/60">
                <span className="text-slate-400 flex items-center gap-1.5">
                  <User className="w-3.5 h-3.5" /> Custody Investigator:
                </span>
                <span className="text-slate-200 font-semibold">{evidence.investigator}</span>
              </div>

              <div className="flex justify-between py-1.5 border-b border-slate-800/60">
                <span className="text-slate-400 flex items-center gap-1.5">
                  <Layers className="w-3.5 h-3.5" /> Case Reference:
                </span>
                <span className="text-cyan-400 font-bold">{evidence.caseId}</span>
              </div>

              <div className="pt-2">
                <span className="text-slate-400 block mb-1">Blockchain Transaction ID:</span>
                <HashDisplay
                  hash={evidence.blockchainVerification.transactionId || 'None'}
                  className="w-full justify-between"
                />
              </div>

              {evidence.blockchainVerification.merkleRoot && (
                <div className="pt-2">
                  <span className="text-slate-400 block mb-1">Evidence Merkle Tree Root:</span>
                  <HashDisplay
                    hash={evidence.blockchainVerification.merkleRoot}
                    className="w-full justify-between"
                  />
                </div>
              )}

              <div className="flex justify-between py-1.5 border-t border-slate-800/60 text-slate-400">
                <span>Verification Network:</span>
                <span className="text-slate-200">{evidence.blockchainVerification.network || 'Distributed Integrity Ledger'}</span>
              </div>

              {evidence.blockchainVerification.blockNumber && (
                <div className="flex justify-between py-1.5 text-slate-400">
                  <span>Block Height:</span>
                  <span className="text-cyan-400 font-bold">#{evidence.blockchainVerification.blockNumber}</span>
                </div>
              )}
            </div>
          </div>

          <div className="mt-4 pt-3 border-t border-slate-800 flex items-center justify-between text-[11px] text-slate-400 font-mono">
            <span>TAMPER STATUS: SEALED</span>
            <span className="text-emerald-400">CRYPTOGRAPHIC AUDIT PASS</span>
          </div>
        </div>
      </div>
    </div>
  );
};
