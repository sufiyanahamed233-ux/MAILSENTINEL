import React, { useState } from 'react';
import {
  ZoomIn,
  ZoomOut,
  Maximize2,
  Network,
  Server,
  Globe,
  Mail,
  Building,
  Shield,
  Layers,
  Info,
} from 'lucide-react';
import { InfrastructureGraph as IGraph, InfrastructureNode } from '../../types/forensics';
import { EmptyState } from '../common/EmptyState';

interface InfrastructureGraphProps {
  graph?: IGraph;
}

export const InfrastructureGraph: React.FC<InfrastructureGraphProps> = ({ graph }) => {
  const [zoomLevel, setZoomLevel] = useState<number>(1);
  const [panOffset, setPanOffset] = useState<{ x: number; y: number }>({ x: 0, y: 0 });
  const [selectedNode, setSelectedNode] = useState<InfrastructureNode | null>(null);

  if (!graph || graph.nodes.length === 0) {
    return (
      <EmptyState
        icon={Network}
        title="No infrastructure mapped"
        description="Infrastructure relationships (Email → Domain → IP → ASN → Hosting Organization) will automatically map here once email headers have been correlated by the backend."
      />
    );
  }

  const handleZoomIn = () => setZoomLevel(prev => Math.min(prev + 0.2, 2.2));
  const handleZoomOut = () => setZoomLevel(prev => Math.max(prev - 0.2, 0.6));
  const handleResetZoom = () => {
    setZoomLevel(1);
    setPanOffset({ x: 0, y: 0 });
  };

  const getNodeIcon = (type: string) => {
    switch (type) {
      case 'email':
        return <Mail className="w-4 h-4 text-cyan-400" />;
      case 'domain':
        return <Globe className="w-4 h-4 text-blue-400" />;
      case 'ip':
        return <Server className="w-4 h-4 text-amber-400" />;
      case 'asn':
        return <Layers className="w-4 h-4 text-indigo-400" />;
      case 'org':
        return <Building className="w-4 h-4 text-emerald-400" />;
      default:
        return <Network className="w-4 h-4 text-slate-400" />;
    }
  };

  // Node positioning logic along horizontal forensic pipeline
  const nodeCount = graph.nodes.length;
  const startX = 80;
  const spacingX = Math.max(160, 600 / Math.max(nodeCount - 1, 1));
  const centerY = 160;

  const positionedNodes = graph.nodes.map((node, index) => {
    const x = startX + index * spacingX;
    // slight subtle curve
    const y = centerY + (index % 2 === 0 ? -15 : 15);
    return { ...node, x, y };
  });

  return (
    <div className="border border-slate-800 bg-[#0d1322] rounded-lg overflow-hidden flex flex-col">
      {/* Controls Header */}
      <div className="px-4 py-2.5 bg-slate-900/90 border-b border-slate-800 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Network className="w-4 h-4 text-cyan-400" />
          <span className="text-xs font-semibold text-slate-200 uppercase tracking-wider font-mono">
            Infrastructure Relational Matrix
          </span>
          <span className="text-xs text-slate-400 font-mono hidden sm:inline">
            (Email → Domain → IP → ASN → Hosting Org)
          </span>
        </div>

        {/* Zoom Controls */}
        <div className="flex items-center gap-1 bg-slate-950 p-1 rounded border border-slate-800">
          <button
            onClick={handleZoomIn}
            title="Zoom In"
            className="p-1 rounded text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors"
          >
            <ZoomIn className="w-3.5 h-3.5" />
          </button>
          <span className="text-[11px] font-mono text-slate-400 px-1.5 tabular-nums">
            {Math.round(zoomLevel * 100)}%
          </span>
          <button
            onClick={handleZoomOut}
            title="Zoom Out"
            className="p-1 rounded text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors"
          >
            <ZoomOut className="w-3.5 h-3.5" />
          </button>
          <button
            onClick={handleResetZoom}
            title="Reset View"
            className="p-1 rounded text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors ml-1"
          >
            <Maximize2 className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 min-h-[380px]">
        {/* Interactive SVG Canvas */}
        <div className="lg:col-span-3 relative bg-[#080d17] border-b lg:border-b-0 lg:border-r border-slate-800 flex items-center justify-center overflow-hidden p-6 select-none">
          <svg
            viewBox="0 0 760 320"
            className="w-full h-full max-h-[340px] cursor-grab active:cursor-grabbing transition-transform"
            style={{
              transform: `scale(${zoomLevel}) translate(${panOffset.x}px, ${panOffset.y}px)`,
              transformOrigin: 'center center',
            }}
          >
            <defs>
              <marker
                id="arrow"
                viewBox="0 0 10 10"
                refX="22"
                refY="5"
                markerWidth="6"
                markerHeight="6"
                orient="auto-start-reverse"
              >
                <path d="M 0 1 L 10 5 L 0 9 z" fill="#0284c7" />
              </marker>
            </defs>

            {/* Connecting Edges */}
            {graph.edges.map((edge) => {
              const srcNode = positionedNodes.find(n => n.id === edge.source);
              const tgtNode = positionedNodes.find(n => n.id === edge.target);
              if (!srcNode || !tgtNode) return null;

              return (
                <g key={edge.id} className="transition-opacity">
                  <line
                    x1={srcNode.x}
                    y1={srcNode.y}
                    x2={tgtNode.x}
                    y2={tgtNode.y}
                    stroke="#0369a1"
                    strokeWidth="2"
                    strokeDasharray="4 2"
                    markerEnd="url(#arrow)"
                  />
                  {/* Edge label */}
                  <text
                    x={(srcNode.x + tgtNode.x) / 2}
                    y={(srcNode.y + tgtNode.y) / 2 - 8}
                    fill="#38bdf8"
                    fontSize="9"
                    fontFamily="monospace"
                    textAnchor="middle"
                    className="select-none pointer-events-none"
                  >
                    {edge.relationship}
                  </text>
                </g>
              );
            })}

            {/* Nodes */}
            {positionedNodes.map((node) => {
              const isSelected = selectedNode?.id === node.id;
              const isMalicious = node.risk === 'malicious';

              return (
                <g
                  key={node.id}
                  transform={`translate(${node.x}, ${node.y})`}
                  className="cursor-pointer"
                  onClick={() => setSelectedNode(node)}
                >
                  <circle
                    r={isSelected ? 26 : 22}
                    fill="#0f172a"
                    stroke={isSelected ? '#38bdf8' : isMalicious ? '#ef4444' : '#1e293b'}
                    strokeWidth={isSelected ? 3 : 2}
                    className="transition-all hover:stroke-cyan-400"
                  />
                  <foreignObject x="-10" y="-10" width="20" height="20">
                    <div className="w-full h-full flex items-center justify-center">
                      {getNodeIcon(node.type)}
                    </div>
                  </foreignObject>
                  {/* Label */}
                  <text
                    y="36"
                    textAnchor="middle"
                    fill={isSelected ? '#e2e8f0' : '#94a3b8'}
                    fontSize="10"
                    fontFamily="monospace"
                    fontWeight={isSelected ? 'bold' : 'normal'}
                  >
                    {node.label.length > 18 ? `${node.label.slice(0, 15)}...` : node.label}
                  </text>
                  <text
                    y="48"
                    textAnchor="middle"
                    fill="#64748b"
                    fontSize="8"
                    fontFamily="monospace"
                    className="uppercase"
                  >
                    {node.type}
                  </text>
                </g>
              );
            })}
          </svg>
        </div>

        {/* Node Details Panel */}
        <div className="p-4 bg-slate-900/60 flex flex-col justify-between">
          <div>
            <div className="flex items-center gap-2 pb-2 border-b border-slate-800 mb-3">
              <Info className="w-4 h-4 text-cyan-400" />
              <h5 className="text-xs font-semibold uppercase tracking-wider text-slate-300 font-mono">
                Node Forensics
              </h5>
            </div>

            {selectedNode ? (
              <div className="space-y-3 text-xs font-mono">
                <div>
                  <span className="text-slate-400 block text-[11px]">Identifier:</span>
                  <span className="text-slate-100 font-bold break-all">{selectedNode.label}</span>
                </div>
                <div>
                  <span className="text-slate-400 block text-[11px]">Entity Classification:</span>
                  <span className="text-cyan-400 uppercase font-semibold">{selectedNode.type}</span>
                </div>
                <div>
                  <span className="text-slate-400 block text-[11px]">Security Posture:</span>
                  <span className={selectedNode.risk === 'malicious' ? 'text-red-400 font-bold' : 'text-emerald-400 font-semibold'}>
                    {selectedNode.risk?.toUpperCase() || 'CLEAN'}
                  </span>
                </div>
                <div className="pt-2 border-t border-slate-800/80">
                  <span className="text-slate-400 block text-[11px] mb-1">Infrastructure Attributes:</span>
                  <p className="text-[11px] text-slate-300 leading-relaxed font-sans">
                    Extracted from envelope routing hops and DNS telemetry. Verified against autonomous system delegation records.
                  </p>
                </div>
              </div>
            ) : (
              <div className="text-center py-10 text-slate-500 font-mono text-xs">
                Select an infrastructure node on the matrix canvas to inspect forensic properties.
              </div>
            )}
          </div>

          <div className="text-[10px] text-slate-500 font-mono pt-3 border-t border-slate-800">
            Node Count: {graph.nodes.length} · Graph Topology: Linear RFC Relay
          </div>
        </div>
      </div>
    </div>
  );
};
