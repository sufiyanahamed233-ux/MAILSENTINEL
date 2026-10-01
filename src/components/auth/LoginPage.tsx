import React, { useState } from 'react';
import { Shield, Lock, Mail, ArrowRight, AlertCircle, Radio } from 'lucide-react';
import { useForensics } from '../../context/ForensicContext';

export const LoginPage: React.FC = () => {
  const { login } = useForensics();

  const [email, setEmail] = useState('a.rivera@sentinel-soc.internal');
  const [password, setPassword] = useState('forensics-clearance-pass');
  const [isLoading, setIsLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMessage(null);

    if (!email || !password) {
      setErrorMessage('Please provide both investigator email and security credential.');
      return;
    }

    if (password.length < 6) {
      setErrorMessage('Security credential must contain at least 6 characters.');
      return;
    }

    setIsLoading(true);
    await new Promise(r => setTimeout(r, 500)); // simulated auth handshake
    const success = await login(email, password);
    setIsLoading(false);

    if (!success) {
      setErrorMessage('Authentication rejected. Invalid investigator credential or inactive session.');
    }
  };

  return (
    <div className="min-h-screen bg-[#070b13] flex flex-col justify-center items-center p-4 relative overflow-hidden">
      {/* Background Matrix Grid */}
      <div className="absolute inset-0 bg-[linear-gradient(to_right,#0c1322_1px,transparent_1px),linear-gradient(to_bottom,#0c1322_1px,transparent_1px)] bg-[size:4rem_4rem] [mask-image:radial-gradient(ellipse_60%_50%_at_50%_50%,#000_70%,transparent_100%)] opacity-40 pointer-events-none" />

      <div className="w-full max-w-md relative z-10">
        {/* Brand Header */}
        <div className="text-center mb-8">
          <div className="w-14 h-14 mx-auto rounded-xl bg-cyan-950/80 border border-cyan-500/40 flex items-center justify-center text-cyan-400 shadow-lg shadow-cyan-950/50 mb-3">
            <Shield className="w-8 h-8 stroke-[1.5]" />
          </div>

          <h1 className="text-xl font-bold tracking-wider text-slate-100 uppercase font-mono">
            MAILSENTINEL
          </h1>
          <p className="text-xs text-slate-400 font-mono mt-1">
            Email Threat Detection & Forensic Intelligence
          </p>

          <div className="mt-3 inline-flex items-center justify-center px-3 py-1 rounded bg-slate-900/80 border border-slate-800 text-[10px] font-mono text-cyan-400/90 tracking-wider">
            <span>DETECT</span>
            <span className="mx-1.5 text-slate-600">→</span>
            <span>INVESTIGATE</span>
            <span className="mx-1.5 text-slate-600">→</span>
            <span>TRACE</span>
            <span className="mx-1.5 text-slate-600">→</span>
            <span>VERIFY</span>
          </div>
        </div>

        {/* Card Panel */}
        <div className="border border-slate-800 bg-[#0d1322]/90 backdrop-blur-md rounded-lg p-6 shadow-2xl">
          <div className="flex items-center justify-between pb-3 border-b border-slate-800 mb-5">
            <span className="text-xs font-mono font-semibold uppercase text-slate-300">
              Analyst Access Authentication
            </span>
            <span className="text-[10px] font-mono text-slate-500 flex items-center gap-1">
              <Radio className="w-2.5 h-2.5 text-emerald-400" /> SECURE GATEWAY
            </span>
          </div>

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="text-xs font-mono uppercase text-slate-400 block mb-1">
                Investigator Email
              </label>
              <div className="relative">
                <Mail className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="analyst@sentinel-soc.internal"
                  className="w-full pl-9 pr-3 py-2 bg-slate-950 border border-slate-800 rounded font-mono text-xs text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500"
                  required
                />
              </div>
            </div>

            <div>
              <label className="text-xs font-mono uppercase text-slate-400 block mb-1">
                Security Credential
              </label>
              <div className="relative">
                <Lock className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••••••"
                  className="w-full pl-9 pr-3 py-2 bg-slate-950 border border-slate-800 rounded font-mono text-xs text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500"
                  required
                />
              </div>
            </div>

            {errorMessage && (
              <div className="p-3 rounded bg-rose-950/40 border border-rose-500/40 text-rose-300 text-xs font-mono flex items-start gap-2">
                <AlertCircle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
                <span>{errorMessage}</span>
              </div>
            )}

            <button
              type="submit"
              disabled={isLoading}
              className="w-full py-2.5 bg-cyan-600 hover:bg-cyan-500 text-white rounded font-mono text-xs font-bold transition-colors shadow-sm flex items-center justify-center gap-2 cursor-pointer disabled:opacity-50 mt-2"
            >
              {isLoading ? (
                <>
                  <span className="w-3.5 h-3.5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                  <span>Validating Clearance...</span>
                </>
              ) : (
                <>
                  <span>Sign In to Forensic Console</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </>
              )}
            </button>
          </form>

          <div className="mt-5 pt-4 border-t border-slate-800/80 text-center">
            <span className="text-[11px] font-mono text-slate-500 block">
              Direct API authentication will bind with FastAPI endpoint <code className="text-slate-400">/api/auth/token</code>
            </span>
          </div>
        </div>

        <div className="mt-6 text-center text-[10px] text-slate-600 font-mono">
          MAILSENTINEL FORENSIC INTELLIGENCE PLATFORM · RESTRICTED ACCESS
        </div>
      </div>
    </div>
  );
};
