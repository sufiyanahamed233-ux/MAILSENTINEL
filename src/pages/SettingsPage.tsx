import React, { useState } from 'react';
import {
  User,
  Shield,
  Key,
  Server,
  Sliders,
  Check,
  AlertCircle,
  RefreshCw,
  Lock,
} from 'lucide-react';
import { useForensics } from '../context/ForensicContext';
import { API_BASE_URL, ApiClient } from '../services/api';

export const SettingsPage: React.FC = () => {
  const { currentUser, backendStatus, refreshBackendStatus } = useForensics();
  const [activeTab, setActiveTab] = useState<'profile' | 'account' | 'security' | 'api' | 'preferences'>('api');

  // API Config State
  const [apiUrl, setApiUrl] = useState(API_BASE_URL);
  const [isTestingApi, setIsTestingApi] = useState(false);
  const [testResult, setTestResult] = useState<string | null>(null);

  // Preference state
  const [timezone, setTimezone] = useState('UTC');
  const [themeMode, setThemeMode] = useState('dark');
  const [sandboxActive, setSandboxActive] = useState(true);

  const handleTestBackend = async () => {
    setIsTestingApi(true);
    setTestResult(null);
    const result = await ApiClient.checkBackendHealth();
    setIsTestingApi(false);
    if (result.online) {
      setTestResult('Successfully established socket with FastAPI backend service.');
    } else {
      setTestResult(`Backend unreachable (${result.message}). Operating in offline client forensics mode.`);
    }
  };

  return (
    <div className="space-y-5 max-w-4xl mx-auto">
      {/* Header */}
      <div className="border-b border-slate-800 pb-4">
        <h2 className="text-base font-bold text-slate-100 font-mono uppercase tracking-wider">
          System & Forensic Settings
        </h2>
        <p className="text-xs text-slate-400 font-mono mt-0.5">
          Operator clearance, API gateways, security credentials, and application parameters
        </p>
      </div>

      {/* Tabs */}
      <div className="flex items-center gap-2 border-b border-slate-800 pb-2 overflow-x-auto">
        {[
          { id: 'api', label: 'API Configuration', icon: Server },
          { id: 'profile', label: 'Analyst Profile', icon: User },
          { id: 'account', label: 'SOC Account', icon: Lock },
          { id: 'security', label: 'Security & PGP', icon: Key },
          { id: 'preferences', label: 'Preferences', icon: Sliders },
        ].map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as any)}
              className={`flex items-center gap-2 px-3 py-1.5 rounded text-xs font-mono transition-colors whitespace-nowrap ${
                isActive
                  ? 'bg-cyan-950/60 text-cyan-300 border border-cyan-500/30 font-semibold'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <Icon className="w-3.5 h-3.5" />
              <span>{tab.label}</span>
            </button>
          );
        })}
      </div>

      {/* API Configuration */}
      {activeTab === 'api' && (
        <div className="border border-slate-800 bg-[#0d1322] rounded-lg p-6 space-y-5">
          <div className="border-b border-slate-800 pb-3">
            <h3 className="text-sm font-bold text-slate-100 font-mono uppercase">
              FastAPI Forensic Backend Gateway
            </h3>
            <p className="text-xs text-slate-400 font-mono mt-1">
              Configure connection parameters for the future FastAPI intelligence microservice.
            </p>
          </div>

          <div className="space-y-4">
            <div>
              <label className="text-xs font-mono uppercase text-slate-400 block mb-1.5">
                FastAPI Server Endpoint (REST / JSON)
              </label>
              <div className="flex gap-2">
                <input
                  type="text"
                  value={apiUrl}
                  onChange={(e) => setApiUrl(e.target.value)}
                  placeholder="http://localhost:8000/api"
                  className="flex-1 px-3 py-2 bg-slate-950 border border-slate-800 rounded font-mono text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
                />
                <button
                  type="button"
                  onClick={handleTestBackend}
                  disabled={isTestingApi}
                  className="px-4 py-2 bg-slate-900 hover:bg-slate-800 text-cyan-300 border border-slate-700 rounded text-xs font-mono flex items-center gap-1.5 transition-colors"
                >
                  <RefreshCw className={`w-3.5 h-3.5 ${isTestingApi ? 'animate-spin' : ''}`} />
                  <span>Test Socket</span>
                </button>
              </div>
              <p className="text-[11px] text-slate-500 font-mono mt-1.5">
                Configured via environment variable <code className="text-slate-400">VITE_API_URL</code>.
              </p>
            </div>

            {testResult && (
              <div className="p-3 rounded bg-slate-950 border border-slate-800 text-xs font-mono flex items-start gap-2 text-slate-300">
                <AlertCircle className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
                <span>{testResult}</span>
              </div>
            )}

            <div className="p-4 rounded bg-slate-950/60 border border-slate-800 text-xs font-mono space-y-2">
              <span className="text-slate-400 uppercase tracking-wider block">
                Target Backend Route Endpoints:
              </span>
              <ul className="text-slate-300 space-y-1">
                <li><code className="text-cyan-400">GET  /api/cases</code> — Case repository index</li>
                <li><code className="text-cyan-400">GET  /api/cases/{'{id}'}</code> — Forensic case docket</li>
                <li><code className="text-cyan-400">POST /api/analyze-email</code> — MIME ingest & pipeline stream</li>
                <li><code className="text-cyan-400">GET  /api/evidence</code> — SHA-256 chain of custody</li>
                <li><code className="text-cyan-400">GET  /api/infrastructure</code> — Relational infrastructure nodes</li>
                <li><code className="text-cyan-400">GET  /api/threat-intelligence</code> — IOC query feed</li>
                <li><code className="text-cyan-400">POST /api/reports</code> — PDF/JSON dossier compilation</li>
              </ul>
            </div>
          </div>
        </div>
      )}

      {/* Analyst Profile */}
      {activeTab === 'profile' && (
        <div className="border border-slate-800 bg-[#0d1322] rounded-lg p-6 space-y-4 font-mono text-xs">
          <div className="border-b border-slate-800 pb-3">
            <h3 className="text-sm font-bold text-slate-100 uppercase">Analyst Credentials</h3>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <span className="text-slate-400 block mb-1">Analyst Full Name:</span>
              <div className="p-2 bg-slate-950 rounded border border-slate-800 text-slate-200">
                {currentUser.name}
              </div>
            </div>
            <div>
              <span className="text-slate-400 block mb-1">Badge Identifier:</span>
              <div className="p-2 bg-slate-950 rounded border border-slate-800 text-cyan-400">
                {currentUser.badgeId}
              </div>
            </div>
            <div>
              <span className="text-slate-400 block mb-1">Email Address:</span>
              <div className="p-2 bg-slate-950 rounded border border-slate-800 text-slate-200">
                {currentUser.email}
              </div>
            </div>
            <div>
              <span className="text-slate-400 block mb-1">Forensic Security Clearance:</span>
              <div className="p-2 bg-slate-950 rounded border border-slate-800 text-emerald-400">
                {currentUser.clearance}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* SOC Account */}
      {activeTab === 'account' && (
        <div className="border border-slate-800 bg-[#0d1322] rounded-lg p-6 space-y-4 font-mono text-xs">
          <div className="border-b border-slate-800 pb-3">
            <h3 className="text-sm font-bold text-slate-100 uppercase">SOC Account Parameters</h3>
          </div>
          <div className="space-y-3">
            <div className="flex items-center justify-between p-3 bg-slate-950 rounded border border-slate-800">
              <div>
                <span className="text-slate-200 font-bold block">Two-Factor Authentication (2FA)</span>
                <span className="text-slate-500 text-[11px]">Hardware security key (FIDO2/WebAuthn)</span>
              </div>
              <span className="text-emerald-400 font-bold">ENFORCED</span>
            </div>

            <div className="flex items-center justify-between p-3 bg-slate-950 rounded border border-slate-800">
              <div>
                <span className="text-slate-200 font-bold block">Forensic Session Inactivity Timeout</span>
                <span className="text-slate-500 text-[11px]">Auto-locks sandbox after inactivity</span>
              </div>
              <span className="text-slate-300">30 MINUTES</span>
            </div>
          </div>
        </div>
      )}

      {/* Security & PGP */}
      {activeTab === 'security' && (
        <div className="border border-slate-800 bg-[#0d1322] rounded-lg p-6 space-y-4 font-mono text-xs">
          <div className="border-b border-slate-800 pb-3">
            <h3 className="text-sm font-bold text-slate-100 uppercase">Cryptographic Keyring</h3>
          </div>
          <p className="text-slate-400">
            Digital signatures and Merkle root sealing use investigator local keyring and HSM modules.
          </p>
          <div className="p-3 bg-slate-950 rounded border border-slate-800">
            <span className="text-slate-400 block mb-1">Public Signature Fingerprint:</span>
            <code className="text-cyan-300 select-all block break-all">
              4A89 FC01 2B34 91D0 E45F 8892 00B1 4239 C0A1 7891
            </code>
          </div>
        </div>
      )}

      {/* Preferences */}
      {activeTab === 'preferences' && (
        <div className="border border-slate-800 bg-[#0d1322] rounded-lg p-6 space-y-4 font-mono text-xs">
          <div className="border-b border-slate-800 pb-3">
            <h3 className="text-sm font-bold text-slate-100 uppercase">Forensic UI Preferences</h3>
          </div>

          <div className="space-y-3">
            <div className="flex items-center justify-between p-3 bg-slate-950 rounded border border-slate-800">
              <div>
                <span className="text-slate-200 font-bold block">Timestamp Telemetry Reference</span>
                <span className="text-slate-500 text-[11px]">Forensic standard UTC timeline</span>
              </div>
              <span className="text-cyan-400 font-bold">UTC (ISO 8601)</span>
            </div>

            <div className="flex items-center justify-between p-3 bg-slate-950 rounded border border-slate-800">
              <div>
                <span className="text-slate-200 font-bold block">Sandbox Script Execution Blocker</span>
                <span className="text-slate-500 text-[11px]">Never allow active email JS execution</span>
              </div>
              <span className="text-emerald-400 font-bold">ALWAYS ACTIVE</span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
