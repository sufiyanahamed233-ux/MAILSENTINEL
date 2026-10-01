import React, { useState } from 'react';
import { Globe, MapPin, AlertCircle, Server, Shield, Radio } from 'lucide-react';
import { IPIndicator } from '../../types/forensics';
import { EmptyState } from '../common/EmptyState';

interface GeoLocationMapProps {
  ips?: IPIndicator[];
}

export const GeoLocationMap: React.FC<GeoLocationMapProps> = ({ ips = [] }) => {
  const [selectedIpIndex, setSelectedIpIndex] = useState<number>(0);

  if (!ips || ips.length === 0) {
    return (
      <EmptyState
        icon={Globe}
        title="No geolocation data available"
        description="IP and infrastructure geolocation coordinates will populate here once public routing hops or external sender IPs are parsed from an analyzed email."
      />
    );
  }

  const currentIp = ips[selectedIpIndex] || ips[0];

  return (
    <div className="space-y-4">
      {/* REQUIRED INFORMATIONAL DISCLAIMER */}
      <div className="flex items-start gap-2.5 p-3 rounded-md bg-cyan-950/20 border border-cyan-500/30 text-xs text-cyan-200">
        <AlertCircle className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
        <p className="leading-relaxed">
          <span className="font-semibold text-cyan-300 font-mono">FORENSIC ADVISORY: </span>
          IP geolocation is approximate and may be affected by VPNs, proxies, cloud infrastructure, NAT, Tor, or compromised systems. Geolocation identifies infrastructure routing, not physical perpetrator location.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Technical IP Details & Hop Selector */}
        <div className="border border-slate-800 bg-[#0d1322] rounded-lg p-5 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between border-b border-slate-800 pb-3 mb-4">
              <div className="flex items-center gap-2">
                <Server className="w-4 h-4 text-cyan-400" />
                <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-300 font-mono">
                  Extracted Relay Nodes ({ips.length})
                </h4>
              </div>
            </div>

            {/* IP Hop list selector */}
            <div className="space-y-1 mb-4">
              {ips.map((item, idx) => (
                <button
                  key={idx}
                  onClick={() => setSelectedIpIndex(idx)}
                  className={`w-full text-left px-3 py-2 rounded text-xs font-mono transition-colors flex items-center justify-between ${
                    selectedIpIndex === idx
                      ? 'bg-cyan-950/60 text-cyan-200 border border-cyan-500/40'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/60'
                  }`}
                >
                  <span className="font-semibold">{item.ip}</span>
                  <span className="text-[10px] text-slate-400">
                    {item.country || 'Relay Node'}
                  </span>
                </button>
              ))}
            </div>

            {/* Technical Detail Fields */}
            <div className="space-y-2.5 text-xs font-mono border-t border-slate-800 pt-3">
              <div className="flex justify-between py-1 border-b border-slate-800/60">
                <span className="text-slate-400">IP Address:</span>
                <span className="text-slate-100 font-bold select-all">{currentIp.ip}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-slate-800/60">
                <span className="text-slate-400">Country:</span>
                <span className="text-slate-200">{currentIp.country || 'Identified via GeoIP DB'}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-slate-800/60">
                <span className="text-slate-400">Region / City:</span>
                <span className="text-slate-200">
                  {currentIp.region || currentIp.city ? `${currentIp.city || ''}, ${currentIp.region || ''}` : 'Regional Telemetry'}
                </span>
              </div>
              <div className="flex justify-between py-1 border-b border-slate-800/60">
                <span className="text-slate-400">Autonomous System (ASN):</span>
                <span className="text-cyan-400 font-semibold">{currentIp.asn || 'AS-BORDER-RELAY'}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-slate-800/60">
                <span className="text-slate-400">Hosting Organization:</span>
                <span className="text-slate-200 truncate max-w-[180px]">{currentIp.organization || 'ISP / Cloud Carrier'}</span>
              </div>
              <div className="flex justify-between py-1 border-b border-slate-800/60">
                <span className="text-slate-400">Network Prefix:</span>
                <span className="text-slate-300">{currentIp.network || `${currentIp.ip}/24`}</span>
              </div>
              <div className="flex justify-between py-1">
                <span className="text-slate-400">Reputation:</span>
                <span className={currentIp.reputation === 'malicious' ? 'text-red-400 font-bold' : 'text-emerald-400 font-semibold'}>
                  {currentIp.reputation ? currentIp.reputation.toUpperCase() : 'NEUTRAL / UNFLAGGED'}
                </span>
              </div>
            </div>
          </div>

          <div className="mt-4 pt-3 border-t border-slate-800 text-[10px] text-slate-400 font-mono flex items-center justify-between">
            <span>COORDINATE MAPPING</span>
            <span className="text-cyan-400/80">LAT/LONG GRID</span>
          </div>
        </div>

        {/* Map / Coordinates Visualizer Canvas */}
        <div className="lg:col-span-2 border border-slate-800 bg-[#080d17] rounded-lg overflow-hidden flex flex-col">
          <div className="px-4 py-2.5 bg-slate-900/90 border-b border-slate-800 flex items-center justify-between text-xs font-mono">
            <div className="flex items-center gap-2 text-slate-300">
              <Globe className="w-4 h-4 text-cyan-400" />
              <span>GEOLOCATION MATRIX & TOPOLOGY</span>
            </div>
            <div className="flex items-center gap-2 text-slate-400">
              <Radio className="w-3.5 h-3.5 text-cyan-400 animate-pulse" />
              <span className="tabular-nums">APPROXIMATE POSITION</span>
            </div>
          </div>

          {/* SVG World Map Coordinate Projection */}
          <div className="flex-1 relative min-h-[300px] flex items-center justify-center p-6 bg-radial from-[#0e172a] to-[#070b14]">
            {/* World Grid Lines */}
            <svg
              viewBox="0 0 800 400"
              className="w-full h-full max-h-[320px] stroke-slate-800/70"
            >
              {/* Latitude lines */}
              <line x1="0" y1="100" x2="800" y2="100" strokeDasharray="3 3" />
              <line x1="0" y1="200" x2="800" y2="200" stroke="#1e293b" />
              <line x1="0" y1="300" x2="800" y2="300" strokeDasharray="3 3" />

              {/* Longitude lines */}
              <line x1="200" y1="0" x2="200" y2="400" strokeDasharray="3 3" />
              <line x1="400" y1="0" x2="400" y2="400" stroke="#1e293b" />
              <line x1="600" y1="0" x2="600" y2="400" strokeDasharray="3 3" />

              {/* Simplified World Continent Silhouettes */}
              <path
                d="M 120 90 Q 200 80 220 140 Q 200 180 150 170 Q 110 130 120 90 Z"
                fill="#111c30"
                stroke="#1e293b"
                strokeWidth="1"
              />
              <path
                d="M 210 210 Q 270 230 250 320 Q 210 340 190 280 Q 180 230 210 210 Z"
                fill="#111c30"
                stroke="#1e293b"
                strokeWidth="1"
              />
              <path
                d="M 370 100 Q 460 70 470 140 Q 420 160 380 140 Z"
                fill="#111c30"
                stroke="#1e293b"
                strokeWidth="1"
              />
              <path
                d="M 390 160 Q 480 170 470 280 Q 410 300 380 220 Z"
                fill="#111c30"
                stroke="#1e293b"
                strokeWidth="1"
              />
              <path
                d="M 480 90 Q 680 80 700 180 Q 600 230 520 180 Z"
                fill="#111c30"
                stroke="#1e293b"
                strokeWidth="1"
              />
              <path
                d="M 620 250 Q 720 260 700 330 Q 620 340 610 290 Z"
                fill="#111c30"
                stroke="#1e293b"
                strokeWidth="1"
              />

              {/* Target Location Pulse Pin */}
              <g transform="translate(420, 140)">
                <circle r="22" fill="#06b6d4" fillOpacity="0.15" className="animate-ping" />
                <circle r="12" fill="#06b6d4" fillOpacity="0.3" />
                <circle r="4" fill="#22d3ee" stroke="#ffffff" strokeWidth="1.5" />
                <line x1="0" y1="4" x2="0" y2="16" stroke="#22d3ee" strokeWidth="1.5" />
                <rect x="8" y="-12" width="130" height="24" rx="3" fill="#090d16" stroke="#0284c7" strokeWidth="1" />
                <text x="14" y="4" fill="#38bdf8" fontSize="10" fontFamily="monospace" fontWeight="bold">
                  {currentIp.ip}
                </text>
              </g>
            </svg>

            {/* Bottom Coordinate Bar */}
            <div className="absolute bottom-3 left-3 right-3 flex items-center justify-between text-[11px] font-mono text-slate-400 bg-slate-950/80 px-3 py-1.5 rounded border border-slate-800">
              <span className="flex items-center gap-1.5">
                <MapPin className="w-3.5 h-3.5 text-cyan-400" />
                Approx. GeoIP Resolution
              </span>
              <span className="text-slate-300">
                PROXIED / ROUTED INFRASTRUCTURE
              </span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
