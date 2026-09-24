import React, { useState } from 'react';
import {
  X,
  Copy,
  Check,
  Shield,
  Clock,
  Server,
  User,
  Network,
  Terminal,
  FileCode,
  Tag,
  AlertTriangle,
} from 'lucide-react';

export interface SecurityEventDetail {
  id: string;
  timestamp: string;
  event_type: string;
  source: string;
  source_ip?: string | null;
  destination_ip?: string | null;
  source_port?: number | null;
  destination_port?: number | null;
  username?: string | null;
  user_id?: string | null;
  hostname?: string | null;
  action: string;
  status: string;
  severity: string;
  message?: string | null;
  raw_event: Record<string, any>;
  metadata?: Record<string, any>;
  created_at: string;
}

interface EventDetailsModalProps {
  event: SecurityEventDetail | null;
  onClose: () => void;
}

export const EventDetailsModal: React.FC<EventDetailsModalProps> = ({ event, onClose }) => {
  const [copiedRaw, setCopiedRaw] = useState(false);
  const [copiedId, setCopiedId] = useState(false);
  const [activeTab, setActiveTab] = useState<'overview' | 'raw' | 'metadata'>('overview');

  if (!event) return null;

  const copyToClipboard = (text: string, type: 'raw' | 'id') => {
    navigator.clipboard.writeText(text);
    if (type === 'raw') {
      setCopiedRaw(true);
      setTimeout(() => setCopiedRaw(false), 2000);
    } else {
      setCopiedId(true);
      setTimeout(() => setCopiedId(false), 2000);
    }
  };

  const getSeverityBadge = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical':
        return 'bg-rose-950/80 text-rose-300 border-rose-800 shadow-[0_0_10px_rgba(244,63,94,0.2)]';
      case 'high':
        return 'bg-amber-950/80 text-amber-300 border-amber-800 shadow-[0_0_10px_rgba(245,158,11,0.15)]';
      case 'medium':
        return 'bg-yellow-950/80 text-yellow-300 border-yellow-800/80';
      case 'low':
        return 'bg-sky-950/80 text-sky-300 border-sky-800';
      default:
        return 'bg-slate-900 text-slate-300 border-slate-700';
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status.toLowerCase()) {
      case 'success':
        return 'bg-emerald-950/80 text-emerald-300 border-emerald-800';
      case 'failure':
        return 'bg-rose-950/80 text-rose-300 border-rose-800';
      case 'blocked':
      case 'denied':
        return 'bg-amber-950/80 text-amber-300 border-amber-800';
      default:
        return 'bg-slate-900 text-slate-400 border-slate-800';
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/80 backdrop-blur-sm p-4 animate-in fade-in duration-200">
      <div className="relative w-full max-w-4xl max-h-[90vh] bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl flex flex-col overflow-hidden text-slate-100">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800 bg-slate-900/90">
          <div className="flex items-center space-x-3">
            <div className="p-2 bg-emerald-500/10 border border-emerald-500/30 rounded-lg text-emerald-400">
              <Shield className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <h2 className="text-base font-semibold font-mono tracking-tight text-white">
                  Security Event Inspector
                </h2>
                <span className={`text-[11px] font-mono font-bold px-2 py-0.5 rounded border uppercase ${getSeverityBadge(event.severity)}`}>
                  {event.severity}
                </span>
                <span className={`text-[11px] font-mono font-medium px-2 py-0.5 rounded border uppercase ${getStatusBadge(event.status)}`}>
                  {event.status}
                </span>
              </div>
              <div className="flex items-center space-x-2 text-xs text-slate-400 font-mono mt-0.5">
                <span>ID: {event.id}</span>
                <button
                  onClick={() => copyToClipboard(event.id, 'id')}
                  className="hover:text-emerald-400 transition"
                  title="Copy UUID"
                >
                  {copiedId ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                </button>
              </div>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-2 text-slate-400 hover:text-white rounded-lg hover:bg-slate-800 transition"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Navigation Tabs */}
        <div className="flex space-x-4 px-6 border-b border-slate-800 bg-slate-950/40 text-xs font-mono">
          <button
            onClick={() => setActiveTab('overview')}
            className={`py-3 border-b-2 font-medium transition ${
              activeTab === 'overview'
                ? 'border-emerald-500 text-emerald-400 font-semibold'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            Normalized Overview
          </button>
          <button
            onClick={() => setActiveTab('raw')}
            className={`py-3 border-b-2 font-medium transition flex items-center space-x-1.5 ${
              activeTab === 'raw'
                ? 'border-emerald-500 text-emerald-400 font-semibold'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <FileCode className="w-3.5 h-3.5" />
            <span>Raw Payload ({Object.keys(event.raw_event || {}).length} fields)</span>
          </button>
          <button
            onClick={() => setActiveTab('metadata')}
            className={`py-3 border-b-2 font-medium transition flex items-center space-x-1.5 ${
              activeTab === 'metadata'
                ? 'border-emerald-500 text-emerald-400 font-semibold'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Tag className="w-3.5 h-3.5" />
            <span>Metadata & Enrichment</span>
          </button>
        </div>

        {/* Content Body */}
        <div className="p-6 overflow-y-auto space-y-6 flex-1 text-sm font-sans">
          {activeTab === 'overview' && (
            <div className="space-y-6">
              {/* Message Box */}
              <div className="p-4 rounded-xl bg-slate-950/80 border border-slate-800/80">
                <span className="text-xs font-mono text-slate-500 uppercase tracking-wider block mb-1">
                  Event Message
                </span>
                <p className="text-sm font-mono text-slate-200 leading-relaxed">
                  {event.message || 'No human-readable message provided.'}
                </p>
              </div>

              {/* Grid 1: Core Attributes & Classification */}
              <div>
                <h3 className="text-xs font-mono uppercase tracking-wider text-slate-400 mb-3 flex items-center space-x-2">
                  <Terminal className="w-3.5 h-3.5 text-emerald-400" />
                  <span>Classification & Origin</span>
                </h3>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 font-mono text-xs">
                  <div className="p-3 bg-slate-950/60 rounded-lg border border-slate-800/80">
                    <span className="text-slate-500 block text-[10px] uppercase">Event Type</span>
                    <span className="text-white font-semibold mt-0.5 block">{event.event_type}</span>
                  </div>
                  <div className="p-3 bg-slate-950/60 rounded-lg border border-slate-800/80">
                    <span className="text-slate-500 block text-[10px] uppercase">Action</span>
                    <span className="text-white font-semibold mt-0.5 block">{event.action}</span>
                  </div>
                  <div className="p-3 bg-slate-950/60 rounded-lg border border-slate-800/80">
                    <span className="text-slate-500 block text-[10px] uppercase">Telemetry Source</span>
                    <span className="text-white font-semibold mt-0.5 block">{event.source}</span>
                  </div>
                  <div className="p-3 bg-slate-950/60 rounded-lg border border-slate-800/80">
                    <span className="text-slate-500 block text-[10px] uppercase">Sensor Timestamp</span>
                    <span className="text-emerald-400 font-semibold mt-0.5 block truncate" title={event.timestamp}>
                      {new Date(event.timestamp).toLocaleString()}
                    </span>
                  </div>
                </div>
              </div>

              {/* Grid 2: Identity & Asset */}
              <div>
                <h3 className="text-xs font-mono uppercase tracking-wider text-slate-400 mb-3 flex items-center space-x-2">
                  <User className="w-3.5 h-3.5 text-sky-400" />
                  <span>Subject & Identity</span>
                </h3>
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 font-mono text-xs">
                  <div className="p-3 bg-slate-950/60 rounded-lg border border-slate-800/80">
                    <span className="text-slate-500 block text-[10px] uppercase">Username</span>
                    <span className="text-white font-semibold mt-0.5 block">
                      {event.username || <span className="text-slate-600">N/A</span>}
                    </span>
                  </div>
                  <div className="p-3 bg-slate-950/60 rounded-lg border border-slate-800/80">
                    <span className="text-slate-500 block text-[10px] uppercase">User ID</span>
                    <span className="text-white font-semibold mt-0.5 block">
                      {event.user_id || <span className="text-slate-600">N/A</span>}
                    </span>
                  </div>
                  <div className="p-3 bg-slate-950/60 rounded-lg border border-slate-800/80">
                    <span className="text-slate-500 block text-[10px] uppercase">Hostname / Host</span>
                    <span className="text-white font-semibold mt-0.5 block">
                      {event.hostname || <span className="text-slate-600">N/A</span>}
                    </span>
                  </div>
                </div>
              </div>

              {/* Grid 3: Network Telemetry */}
              <div>
                <h3 className="text-xs font-mono uppercase tracking-wider text-slate-400 mb-3 flex items-center space-x-2">
                  <Network className="w-3.5 h-3.5 text-violet-400" />
                  <span>Network Context</span>
                </h3>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 font-mono text-xs">
                  <div className="p-3 bg-slate-950/60 rounded-lg border border-slate-800/80">
                    <span className="text-slate-500 block text-[10px] uppercase">Source IP</span>
                    <span className="text-emerald-300 font-semibold mt-0.5 block">
                      {event.source_ip || <span className="text-slate-600">N/A</span>}
                    </span>
                  </div>
                  <div className="p-3 bg-slate-950/60 rounded-lg border border-slate-800/80">
                    <span className="text-slate-500 block text-[10px] uppercase">Source Port</span>
                    <span className="text-slate-300 font-semibold mt-0.5 block">
                      {event.source_port ?? <span className="text-slate-600">N/A</span>}
                    </span>
                  </div>
                  <div className="p-3 bg-slate-950/60 rounded-lg border border-slate-800/80">
                    <span className="text-slate-500 block text-[10px] uppercase">Destination IP</span>
                    <span className="text-sky-300 font-semibold mt-0.5 block">
                      {event.destination_ip || <span className="text-slate-600">N/A</span>}
                    </span>
                  </div>
                  <div className="p-3 bg-slate-950/60 rounded-lg border border-slate-800/80">
                    <span className="text-slate-500 block text-[10px] uppercase">Destination Port</span>
                    <span className="text-slate-300 font-semibold mt-0.5 block">
                      {event.destination_port ?? <span className="text-slate-600">N/A</span>}
                    </span>
                  </div>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'raw' && (
            <div className="space-y-3">
              <div className="flex items-center justify-between text-xs text-slate-400 font-mono">
                <span>Exact Ingested Payload (Preserved for Forensics)</span>
                <button
                  onClick={() => copyToClipboard(JSON.stringify(event.raw_event, null, 2), 'raw')}
                  className="inline-flex items-center space-x-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg transition"
                >
                  {copiedRaw ? (
                    <>
                      <Check className="w-3.5 h-3.5 text-emerald-400" />
                      <span className="text-emerald-400">Copied</span>
                    </>
                  ) : (
                    <>
                      <Copy className="w-3.5 h-3.5" />
                      <span>Copy JSON</span>
                    </>
                  )}
                </button>
              </div>
              <div className="p-4 bg-slate-950 rounded-xl border border-slate-800 font-mono text-xs overflow-x-auto max-h-[50vh]">
                <pre className="text-emerald-400 leading-relaxed">
                  {JSON.stringify(event.raw_event, null, 2)}
                </pre>
              </div>
            </div>
          )}

          {activeTab === 'metadata' && (
            <div className="space-y-4">
              <p className="text-xs text-slate-400">
                Extracted contextual enrichment and unmapped metadata attributes.
              </p>
              {event.metadata && Object.keys(event.metadata).length > 0 ? (
                <div className="p-4 bg-slate-950 rounded-xl border border-slate-800 font-mono text-xs overflow-x-auto max-h-[50vh]">
                  <pre className="text-sky-300 leading-relaxed">
                    {JSON.stringify(event.metadata, null, 2)}
                  </pre>
                </div>
              ) : (
                <div className="p-8 text-center text-slate-500 font-mono text-xs bg-slate-950/40 rounded-xl border border-slate-800/60">
                  No additional metadata tags recorded for this event.
                </div>
              )}
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-6 py-3 border-t border-slate-800 bg-slate-950/60 flex items-center justify-between text-xs font-mono text-slate-500">
          <div className="flex items-center space-x-2">
            <Clock className="w-3.5 h-3.5 text-slate-600" />
            <span>Ingested into PostgreSQL: {new Date(event.created_at).toLocaleString()}</span>
          </div>
          <button
            onClick={onClose}
            className="px-4 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg transition"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
