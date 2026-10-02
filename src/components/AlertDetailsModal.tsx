import React, { useState, useEffect } from 'react';
import {
  X,
  ShieldAlert,
  AlertTriangle,
  Clock,
  User,
  Server,
  Globe,
  FileCode,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  Fingerprint,
  Info,
  Layers,
  ArrowRight,
  Loader2,
} from 'lucide-react';

export interface SecurityEventDetail {
  id: string;
  timestamp: string;
  event_type: string;
  source: string;
  source_ip: string | null;
  destination_ip: string | null;
  source_port: number | null;
  destination_port: number | null;
  username: string | null;
  hostname: string | null;
  action: string;
  status: string;
  severity: string;
  message: string | null;
  raw_event: Record<string, any>;
  metadata: Record<string, any>;
}

export interface AlertEvidenceItem {
  id: string;
  alert_id: string;
  event_id: string;
  evidence_role: string;
  description: string | null;
  created_at: string;
  event?: SecurityEventDetail | null;
}

export interface AlertDetail {
  id: string;
  rule_id: string;
  rule_name: string;
  title: string;
  description: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  status: 'new' | 'in_review' | 'dismissed' | 'escalated';
  dedup_key: string;
  affected_user: string | null;
  affected_ip: string | null;
  affected_hostname: string | null;
  detected_at: string;
  created_at: string;
  incident_id: string | null;
  evidence_count: number;
  metadata: Record<string, any>;
  evidence: AlertEvidenceItem[];
}

export interface AlertDetailsModalProps {
  alert?: AlertDetail | null;
  alertId?: string | null;
  isOpen?: boolean;
  onClose: () => void;
  onStatusUpdate?: (alertId: string, newStatus: string) => Promise<void>;
}

export const AlertDetailsModal: React.FC<AlertDetailsModalProps> = ({
  alert: propAlert,
  alertId,
  isOpen = true,
  onClose,
  onStatusUpdate,
}) => {
  const [internalAlert, setInternalAlert] = useState<AlertDetail | null>(propAlert || null);
  const [loading, setLoading] = useState<boolean>(false);
  const [fetchError, setFetchError] = useState<string | null>(null);
  const [expandedEventId, setExpandedEventId] = useState<string | null>(null);
  const [isUpdatingStatus, setIsUpdatingStatus] = useState(false);

  useEffect(() => {
    if (propAlert) {
      setInternalAlert(propAlert);
      return;
    }

    if (alertId) {
      setLoading(true);
      setFetchError(null);
      fetch(`/api/v1/alerts/${alertId}`)
        .then((res) => {
          if (!res.ok) throw new Error(`HTTP error ${res.status}`);
          return res.json();
        })
        .then((data: AlertDetail) => {
          setInternalAlert(data);
          setLoading(false);
        })
        .catch(() => {
          setFetchError('Unable to load alert details.');
          setLoading(false);
        });
    } else {
      setInternalAlert(null);
    }
  }, [propAlert, alertId]);

  if (!isOpen) return null;
  if (!propAlert && !alertId) return null;

  if (loading) {
    return (
      <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-8 flex flex-col items-center gap-3 text-slate-300">
          <Loader2 className="w-8 h-8 text-cyan-400 animate-spin" />
          <p className="text-sm font-mono">Loading alert evidence and telemetry...</p>
        </div>
      </div>
    );
  }

  if (fetchError || !internalAlert) {
    return (
      <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4">
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 max-w-md w-full">
          <div className="flex justify-between items-center mb-4">
            <h3 className="text-base font-semibold text-rose-400">Failed to Load Alert</h3>
            <button onClick={onClose} className="text-slate-400 hover:text-slate-200">
              <X className="w-5 h-5" />
            </button>
          </div>
          <p className="text-xs text-slate-400 mb-4">{fetchError || 'Alert not found'}</p>
          <button
            onClick={onClose}
            className="w-full py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold rounded"
          >
            Close
          </button>
        </div>
      </div>
    );
  }

  const alert = internalAlert;

  const getSeverityBadge = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical':
        return (
          <span className="px-2.5 py-1 text-xs font-semibold rounded bg-rose-950/80 text-rose-300 border border-rose-800/60 flex items-center gap-1.5 shadow-sm">
            <span className="h-2 w-2 rounded-full bg-rose-500 animate-pulse" />
            CRITICAL
          </span>
        );
      case 'high':
        return (
          <span className="px-2.5 py-1 text-xs font-semibold rounded bg-amber-950/80 text-amber-300 border border-amber-800/60 flex items-center gap-1.5">
            <span className="h-2 w-2 rounded-full bg-amber-500" />
            HIGH
          </span>
        );
      case 'medium':
        return (
          <span className="px-2.5 py-1 text-xs font-semibold rounded bg-yellow-950/80 text-yellow-300 border border-yellow-800/60 flex items-center gap-1.5">
            <span className="h-2 w-2 rounded-full bg-yellow-500" />
            MEDIUM
          </span>
        );
      default:
        return (
          <span className="px-2.5 py-1 text-xs font-semibold rounded bg-slate-800 text-slate-300 border border-slate-700 flex items-center gap-1.5">
            <span className="h-2 w-2 rounded-full bg-slate-400" />
            LOW
          </span>
        );
    }
  };

  const getRoleBadge = (role: string) => {
    switch (role) {
      case 'trigger':
      case 'privilege_escalation':
        return 'bg-rose-950/70 text-rose-300 border-rose-800/50';
      case 'successful_login':
        return 'bg-emerald-950/70 text-emerald-300 border-emerald-800/50';
      case 'preceding_failure':
      case 'failed_attempt':
        return 'bg-amber-950/70 text-amber-300 border-amber-800/50';
      case 'indicator_match':
        return 'bg-purple-950/70 text-purple-300 border-purple-800/50';
      default:
        return 'bg-slate-800 text-slate-300 border-slate-700';
    }
  };

  const handleStatusChange = async (e: React.ChangeEvent<HTMLSelectElement>) => {
    if (!onStatusUpdate) return;
    setIsUpdatingStatus(true);
    try {
      await onStatusUpdate(alert.id, e.target.value);
    } finally {
      setIsUpdatingStatus(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fade-in">
      <div className="relative w-full max-w-5xl max-h-[90vh] bg-slate-900 border border-slate-700 rounded-xl shadow-2xl flex flex-col overflow-hidden">
        {/* Header */}
        <div className="p-6 border-b border-slate-800 bg-slate-950/70 flex items-start justify-between gap-4">
          <div className="flex items-start gap-3">
            <div className="p-2.5 bg-rose-500/10 border border-rose-500/20 rounded-lg text-rose-400 mt-1">
              <ShieldAlert className="h-6 w-6" />
            </div>
            <div>
              <div className="flex items-center gap-2 flex-wrap mb-1.5">
                <span className="font-mono text-xs px-2 py-0.5 rounded bg-slate-800 border border-slate-700 text-slate-300 font-bold">
                  {alert.rule_id}
                </span>
                {getSeverityBadge(alert.severity)}
                <span className="font-mono text-xs text-slate-400">
                  {alert.rule_name}
                </span>
              </div>
              <h2 className="text-xl font-bold text-slate-100 tracking-tight">
                {alert.title}
              </h2>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-2 bg-slate-900 border border-slate-700 rounded-lg px-3 py-1.5 text-xs">
              <span className="text-slate-400">Status:</span>
              <select
                value={alert.status}
                onChange={handleStatusChange}
                disabled={isUpdatingStatus}
                className="bg-transparent text-slate-200 font-medium focus:outline-none cursor-pointer"
              >
                <option value="new" className="bg-slate-900">New</option>
                <option value="in_review" className="bg-slate-900">In Review</option>
                <option value="escalated" className="bg-slate-900">Escalated</option>
                <option value="dismissed" className="bg-slate-900">Dismissed</option>
              </select>
            </div>
            <button
              onClick={onClose}
              className="p-1.5 text-slate-400 hover:text-slate-200 hover:bg-slate-800 rounded-lg transition-colors"
            >
              <X className="h-5 w-5" />
            </button>
          </div>
        </div>

        {/* Content Body */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          {/* Narrative / Description */}
          <div className="p-4 rounded-lg bg-slate-950/50 border border-slate-800 space-y-2">
            <div className="flex items-center gap-2 text-xs font-semibold text-slate-400 uppercase tracking-wider">
              <Info className="h-4 w-4 text-emerald-400" />
              Observed Detection Analysis
            </div>
            <p className="text-sm text-slate-200 leading-relaxed font-sans">
              {alert.description}
            </p>
          </div>

          {/* Affected Entity & Context Grid */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
            <div className="p-3 rounded-lg bg-slate-950/40 border border-slate-800/80">
              <div className="text-[11px] font-medium text-slate-400 flex items-center gap-1.5 mb-1">
                <User className="h-3.5 w-3.5 text-sky-400" />
                Target User Account
              </div>
              <div className="font-mono text-xs text-slate-200 font-semibold truncate">
                {alert.affected_user || <span className="text-slate-500 font-normal">N/A</span>}
              </div>
            </div>

            <div className="p-3 rounded-lg bg-slate-950/40 border border-slate-800/80">
              <div className="text-[11px] font-medium text-slate-400 flex items-center gap-1.5 mb-1">
                <Globe className="h-3.5 w-3.5 text-amber-400" />
                Affected Network IP
              </div>
              <div className="font-mono text-xs text-slate-200 font-semibold truncate">
                {alert.affected_ip || <span className="text-slate-500 font-normal">N/A</span>}
              </div>
            </div>

            <div className="p-3 rounded-lg bg-slate-950/40 border border-slate-800/80">
              <div className="text-[11px] font-medium text-slate-400 flex items-center gap-1.5 mb-1">
                <Server className="h-3.5 w-3.5 text-purple-400" />
                Target Hostname
              </div>
              <div className="font-mono text-xs text-slate-200 font-semibold truncate">
                {alert.affected_hostname || <span className="text-slate-500 font-normal">N/A</span>}
              </div>
            </div>

            <div className="p-3 rounded-lg bg-slate-950/40 border border-slate-800/80">
              <div className="text-[11px] font-medium text-slate-400 flex items-center gap-1.5 mb-1">
                <Clock className="h-3.5 w-3.5 text-emerald-400" />
                Detection Timestamp
              </div>
              <div className="font-mono text-xs text-slate-200 truncate" title={alert.detected_at}>
                {new Date(alert.detected_at).toLocaleString()}
              </div>
            </div>
          </div>

          {/* Rule Metadata & Deduplication info */}
          <div className="p-4 rounded-lg bg-slate-950/30 border border-slate-800/80 space-y-3">
            <div className="flex items-center justify-between text-xs">
              <span className="font-semibold text-slate-400 flex items-center gap-1.5">
                <Fingerprint className="h-4 w-4 text-slate-400" />
                Deterministic Deduplication Signature
              </span>
              <span className="font-mono text-[11px] text-slate-500 truncate max-w-md">
                {alert.dedup_key}
              </span>
            </div>
            {alert.metadata && Object.keys(alert.metadata).length > 0 && (
              <div className="pt-2 border-t border-slate-800/60">
                <span className="text-xs text-slate-400 font-medium block mb-1.5">Rule Metrics Context:</span>
                <div className="flex flex-wrap gap-2">
                  {Object.entries(alert.metadata).map(([k, v]) => (
                    <span
                      key={k}
                      className="px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-[11px] font-mono text-slate-300"
                    >
                      <strong className="text-slate-400 font-normal">{k}:</strong>{' '}
                      {typeof v === 'object' ? JSON.stringify(v) : String(v)}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* Supporting Evidence Chain (The Core SOC Requirement) */}
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Layers className="h-4 w-4 text-rose-400" />
                <h3 className="text-sm font-bold text-slate-200 uppercase tracking-wider">
                  Supporting Evidence Events ({alert.evidence.length})
                </h3>
              </div>
              <span className="text-xs text-slate-400 font-mono">
                Source of Truth: Immutable SecurityEvent Telemetry
              </span>
            </div>

            <div className="space-y-2">
              {alert.evidence.length === 0 ? (
                <div className="p-6 text-center text-slate-500 bg-slate-950/40 rounded-lg border border-slate-800">
                  No evidence events linked to this alert.
                </div>
              ) : (
                alert.evidence.map((item, idx) => {
                  const ev = item.event;
                  const isExpanded = expandedEventId === item.id;

                  return (
                    <div
                      key={item.id}
                      className="rounded-lg bg-slate-950/60 border border-slate-800/90 overflow-hidden transition-all"
                    >
                      <div
                        onClick={() => setExpandedEventId(isExpanded ? null : item.id)}
                        className="p-3.5 flex items-center justify-between cursor-pointer hover:bg-slate-900/50 transition-colors"
                      >
                        <div className="flex items-center gap-3 min-w-0">
                          <span className="text-slate-500 font-mono text-xs w-5 text-right">
                            {idx + 1}.
                          </span>
                          <span
                            className={`px-2 py-0.5 text-[11px] font-mono font-medium rounded border uppercase ${getRoleBadge(
                              item.evidence_role
                            )}`}
                          >
                            {item.evidence_role.replace(/_/g, ' ')}
                          </span>
                          <div className="min-w-0">
                            <div className="text-xs text-slate-200 font-medium truncate">
                              {item.description || (ev ? ev.message : 'Supporting telemetry event')}
                            </div>
                            {ev && (
                              <div className="text-[11px] font-mono text-slate-400 flex items-center gap-2 mt-0.5">
                                <span>{ev.source}</span>
                                <span>•</span>
                                <span>{ev.action}</span>
                                <span>•</span>
                                <span
                                  className={
                                    ev.status.toLowerCase() === 'failure'
                                      ? 'text-rose-400'
                                      : 'text-emerald-400'
                                  }
                                >
                                  {ev.status}
                                </span>
                              </div>
                            )}
                          </div>
                        </div>

                        <div className="flex items-center gap-3">
                          {ev && (
                            <span className="text-xs font-mono text-slate-400 whitespace-nowrap">
                              {new Date(ev.timestamp).toLocaleTimeString()}
                            </span>
                          )}
                          {isExpanded ? (
                            <ChevronDown className="h-4 w-4 text-slate-400" />
                          ) : (
                            <ChevronRight className="h-4 w-4 text-slate-400" />
                          )}
                        </div>
                      </div>

                      {/* Expanded Event Details */}
                      {isExpanded && ev && (
                        <div className="p-4 border-t border-slate-800 bg-slate-900/60 space-y-3">
                          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs">
                            <div className="p-2 rounded bg-slate-950/40 border border-slate-800">
                              <span className="text-slate-500 block text-[10px]">Event ID</span>
                              <span className="font-mono text-slate-300 truncate block">
                                {ev.id}
                              </span>
                            </div>
                            <div className="p-2 rounded bg-slate-950/40 border border-slate-800">
                              <span className="text-slate-500 block text-[10px]">Source IP / Port</span>
                              <span className="font-mono text-slate-300">
                                {ev.source_ip || 'None'}:{ev.source_port || '-'}
                              </span>
                            </div>
                            <div className="p-2 rounded bg-slate-950/40 border border-slate-800">
                              <span className="text-slate-500 block text-[10px]">Dest IP / Port</span>
                              <span className="font-mono text-slate-300">
                                {ev.destination_ip || 'None'}:{ev.destination_port || '-'}
                              </span>
                            </div>
                            <div className="p-2 rounded bg-slate-950/40 border border-slate-800">
                              <span className="text-slate-500 block text-[10px]">User / Host</span>
                              <span className="font-mono text-slate-300">
                                {ev.username || 'None'} @ {ev.hostname || 'None'}
                              </span>
                            </div>
                          </div>

                          <div>
                            <span className="text-[11px] font-semibold text-slate-400 block mb-1">
                              Original Event Payload:
                            </span>
                            <pre className="p-3 rounded bg-black/60 border border-slate-800 text-[11px] font-mono text-emerald-300/90 overflow-x-auto max-h-48">
                              {JSON.stringify(ev.raw_event, null, 2)}
                            </pre>
                          </div>
                        </div>
                      )}
                    </div>
                  );
                })
              )}
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-slate-800 bg-slate-950/80 flex items-center justify-between">
          <div className="text-xs text-slate-400">
            Alert ID: <span className="font-mono text-slate-300">{alert.id}</span>
          </div>
          <button
            onClick={onClose}
            className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold rounded-lg transition-colors"
          >
            Close Details
          </button>
        </div>
      </div>
    </div>
  );
};
