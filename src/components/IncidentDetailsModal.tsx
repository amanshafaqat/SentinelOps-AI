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
  Activity,
  History,
  GitBranch,
  Shield,
  Tag,
  Flame,
  Check,
  Edit3,
} from 'lucide-react';
import { AlertDetail } from './AlertDetailsModal';

export interface IncidentAuditItem {
  id: string;
  incident_id: string;
  action: string;
  previous_value: string | null;
  new_value: string | null;
  notes: string | null;
  actor: string;
  created_at: string;
}

export interface IncidentTimelineItemData {
  id: string;
  item_type: 'event' | 'alert' | 'incident_action';
  timestamp: string;
  title: string;
  description: string | null;
  severity: string | null;
  status: string | null;
  entity: string | null;
  source: string | null;
  metadata: Record<string, any>;
}

export interface IncidentDetail {
  id: string;
  title: string;
  description: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  status: 'new' | 'investigating' | 'resolved' | 'closed';
  first_seen: string;
  last_seen: string;
  affected_users: string[];
  affected_ips: string[];
  affected_hostnames: string[];
  alert_count: number;
  correlation_reasons: string[];
  correlation_metadata: Record<string, any>;
  alerts?: AlertDetail[];
  audit_logs?: IncidentAuditItem[];
  created_at: string;
  updated_at: string;
}

interface IncidentDetailsModalProps {
  incidentId: string | null;
  onClose: () => void;
  onIncidentUpdated?: () => void;
  onSelectAlert?: (alertId: string) => void;
}

export const IncidentDetailsModal: React.FC<IncidentDetailsModalProps> = ({
  incidentId,
  onClose,
  onIncidentUpdated,
  onSelectAlert,
}) => {
  const [incident, setIncident] = useState<IncidentDetail | null>(null);
  const [timelineItems, setTimelineItems] = useState<IncidentTimelineItemData[]>([]);
  const [loading, setLoading] = useState(false);
  const [timelineLoading, setTimelineLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'timeline' | 'alerts' | 'correlation' | 'audit'>('timeline');

  // Status mutation state
  const [selectedStatus, setSelectedStatus] = useState<string>('');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('');
  const [analystNotes, setAnalystNotes] = useState<string>('');
  const [actorName, setActorName] = useState<string>('soc_analyst');
  const [isUpdating, setIsUpdating] = useState(false);
  const [updateSuccess, setUpdateSuccess] = useState(false);
  const [expandedTimelineId, setExpandedTimelineId] = useState<string | null>(null);
  const [expandedAlertId, setExpandedAlertId] = useState<string | null>(null);

  useEffect(() => {
    if (incidentId) {
      fetchIncidentDetails(incidentId);
      fetchTimeline(incidentId);
    }
  }, [incidentId]);

  const fetchIncidentDetails = async (id: string) => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`/api/v1/incidents/${id}`);
      if (!res.ok) throw new Error(`HTTP ${res.status}: Failed to fetch incident details`);
      const data: IncidentDetail = await res.json();
      setIncident(data);
      setSelectedStatus(data.status);
      setSelectedSeverity(data.severity);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const fetchTimeline = async (id: string) => {
    setTimelineLoading(true);
    try {
      const res = await fetch(`/api/v1/incidents/${id}/timeline`);
      if (res.ok) {
        const data = await res.json();
        setTimelineItems(data.items || []);
      }
    } catch (err: any) {
      console.warn('Failed to load timeline:', err.message);
    } finally {
      setTimelineLoading(false);
    }
  };

  const handleUpdateStatus = async () => {
    if (!incident) return;
    setIsUpdating(true);
    setUpdateSuccess(false);
    setError(null);
    try {
      const body: any = {
        actor: actorName.trim() || 'soc_analyst',
        notes: analystNotes.trim() || undefined,
      };
      if (selectedStatus !== incident.status) {
        body.status = selectedStatus;
      }
      if (selectedSeverity !== incident.severity) {
        body.severity = selectedSeverity;
      }

      const res = await fetch(`/api/v1/incidents/${incident.id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });

      if (!res.ok) {
        const errJson = await res.json().catch(() => ({}));
        throw new Error(errJson.error?.message || `Failed to update incident: HTTP ${res.status}`);
      }

      const updated = await res.json();
      setIncident(updated);
      setUpdateSuccess(true);
      setAnalystNotes('');
      fetchTimeline(incident.id);
      if (onIncidentUpdated) onIncidentUpdated();
      setTimeout(() => setUpdateSuccess(false), 3000);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setIsUpdating(false);
    }
  };

  if (!incidentId) return null;

  const getSeverityBadge = (sev: string) => {
    switch (sev.toLowerCase()) {
      case 'critical':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded bg-red-950/80 text-red-400 border border-red-800 text-xs font-mono font-semibold uppercase tracking-wider">
            <Flame className="w-3.5 h-3.5 text-red-400" />
            CRITICAL
          </span>
        );
      case 'high':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded bg-amber-950/80 text-amber-400 border border-amber-800 text-xs font-mono font-semibold uppercase tracking-wider">
            <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
            HIGH
          </span>
        );
      case 'medium':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded bg-blue-950/80 text-blue-400 border border-blue-800 text-xs font-mono font-semibold uppercase tracking-wider">
            <Info className="w-3.5 h-3.5 text-blue-400" />
            MEDIUM
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded bg-slate-900 text-slate-400 border border-slate-700 text-xs font-mono font-semibold uppercase tracking-wider">
            <CheckCircle2 className="w-3.5 h-3.5 text-slate-400" />
            LOW
          </span>
        );
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status.toLowerCase()) {
      case 'new':
        return (
          <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-mono font-medium bg-red-950/60 text-red-300 border border-red-800/60">
            NEW
          </span>
        );
      case 'investigating':
        return (
          <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-mono font-medium bg-amber-950/60 text-amber-300 border border-amber-800/60">
            INVESTIGATING
          </span>
        );
      case 'resolved':
        return (
          <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-mono font-medium bg-emerald-950/60 text-emerald-300 border border-emerald-800/60">
            RESOLVED
          </span>
        );
      case 'closed':
        return (
          <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-mono font-medium bg-slate-800 text-slate-400 border border-slate-700">
            CLOSED
          </span>
        );
      default:
        return <span className="text-xs font-mono text-slate-400">{status}</span>;
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-4 bg-slate-950/80 backdrop-blur-sm animate-fade-in">
      <div className="relative w-full max-w-5xl bg-slate-900 border border-slate-800 rounded-lg shadow-2xl flex flex-col max-h-[92vh] overflow-hidden text-slate-200">
        {/* Header */}
        <div className="flex items-start justify-between p-4 sm:p-5 border-b border-slate-800 bg-slate-950/50">
          <div className="flex items-start gap-3">
            <div className="p-2 rounded-lg bg-red-950/40 border border-red-900/60 text-red-400 shrink-0 mt-0.5">
              <ShieldAlert className="w-6 h-6" />
            </div>
            <div>
              <div className="flex flex-wrap items-center gap-2 mb-1.5">
                <span className="text-xs font-mono text-slate-400 uppercase tracking-wider">
                  INCIDENT INVESTIGATION
                </span>
                <span className="text-slate-600">•</span>
                <span className="text-xs font-mono text-slate-400">ID: {incidentId}</span>
                {incident && (
                  <>
                    <span className="text-slate-600">•</span>
                    {getSeverityBadge(incident.severity)}
                    {getStatusBadge(incident.status)}
                  </>
                )}
              </div>
              <h2 className="text-lg sm:text-xl font-bold text-slate-100 leading-snug">
                {incident ? incident.title : 'Loading Incident Investigation...'}
              </h2>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors shrink-0"
            title="Close modal"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Error Banner */}
        {error && (
          <div className="px-5 py-2.5 bg-red-950/60 border-b border-red-800/80 text-red-300 text-xs flex items-center justify-between">
            <span>{error}</span>
            <button onClick={() => setError(null)} className="underline hover:text-red-200">
              Dismiss
            </button>
          </div>
        )}

        {/* Content Body */}
        <div className="flex-1 overflow-y-auto p-4 sm:p-6 space-y-6">
          {loading ? (
            <div className="py-16 text-center text-slate-400 flex flex-col items-center justify-center gap-3">
              <div className="w-8 h-8 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin" />
              <p className="text-sm font-mono">Retrieving correlated incident record and telemetry chain...</p>
            </div>
          ) : !incident ? (
            <div className="py-12 text-center text-slate-400">Incident data not found.</div>
          ) : (
            <>
              {/* Executive Incident Header Bar */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 bg-slate-950/60 border border-slate-800/80 rounded-lg p-3 sm:p-4 text-xs">
                <div>
                  <span className="text-slate-500 uppercase tracking-wider font-mono block mb-1">
                    First Seen
                  </span>
                  <span className="font-mono text-slate-200">
                    {incident.first_seen ? new Date(incident.first_seen).toLocaleString() : 'N/A'}
                  </span>
                </div>
                <div>
                  <span className="text-slate-500 uppercase tracking-wider font-mono block mb-1">
                    Last Seen
                  </span>
                  <span className="font-mono text-slate-200">
                    {incident.last_seen ? new Date(incident.last_seen).toLocaleString() : 'N/A'}
                  </span>
                </div>
                <div>
                  <span className="text-slate-500 uppercase tracking-wider font-mono block mb-1">
                    Correlated Alerts
                  </span>
                  <span className="font-mono font-semibold text-cyan-400">
                    {incident.alert_count} Alerts Linked
                  </span>
                </div>
                <div>
                  <span className="text-slate-500 uppercase tracking-wider font-mono block mb-1">
                    Attack Progression
                  </span>
                  <span className="font-mono font-semibold text-amber-400">
                    {incident.correlation_metadata?.attack_progression_detected
                      ? 'Confirmed Multi-Stage'
                      : 'Discrete Association'}
                  </span>
                </div>
              </div>

              {/* Triage & Status Mutation Card */}
              <div className="bg-slate-950/80 border border-slate-800 rounded-lg p-4 space-y-3">
                <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800/60 pb-2.5">
                  <div className="flex items-center gap-2 text-sm font-semibold text-slate-200">
                    <Edit3 className="w-4 h-4 text-cyan-400" />
                    <span>Analyst Incident Triage & Audit Controls</span>
                  </div>
                  {updateSuccess && (
                    <span className="text-xs font-mono text-emerald-400 flex items-center gap-1">
                      <Check className="w-3.5 h-3.5" /> Updated & Logged to Audit Trail
                    </span>
                  )}
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                  <div>
                    <label className="text-xs font-mono text-slate-400 block mb-1">
                      Lifecycle Status
                    </label>
                    <select
                      value={selectedStatus}
                      onChange={(e) => setSelectedStatus(e.target.value)}
                      className="w-full bg-slate-900 border border-slate-700 rounded px-2.5 py-1.5 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
                    >
                      <option value="new">NEW (Unassigned Triage)</option>
                      <option value="investigating">INVESTIGATING (Under Active Analysis)</option>
                      <option value="resolved">RESOLVED (Threat Mitigated)</option>
                      <option value="closed">CLOSED (Archived Incident)</option>
                    </select>
                  </div>
                  <div>
                    <label className="text-xs font-mono text-slate-400 block mb-1">
                      Severity Rating
                    </label>
                    <select
                      value={selectedSeverity}
                      onChange={(e) => setSelectedSeverity(e.target.value)}
                      className="w-full bg-slate-900 border border-slate-700 rounded px-2.5 py-1.5 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
                    >
                      <option value="low">LOW</option>
                      <option value="medium">MEDIUM</option>
                      <option value="high">HIGH</option>
                      <option value="critical">CRITICAL</option>
                    </select>
                  </div>
                  <div>
                    <label className="text-xs font-mono text-slate-400 block mb-1">
                      Analyst Handle
                    </label>
                    <input
                      type="text"
                      value={actorName}
                      onChange={(e) => setActorName(e.target.value)}
                      placeholder="e.g. jdoe_analyst"
                      className="w-full bg-slate-900 border border-slate-700 rounded px-2.5 py-1.5 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500"
                    />
                  </div>
                </div>

                <div>
                  <label className="text-xs font-mono text-slate-400 block mb-1">
                    Analyst Justification / Audit Notes
                  </label>
                  <textarea
                    rows={2}
                    value={analystNotes}
                    onChange={(e) => setAnalystNotes(e.target.value)}
                    placeholder="Enter analytical rationale for status/severity change (stored in immutable audit trail)..."
                    className="w-full bg-slate-900 border border-slate-700 rounded px-2.5 py-1.5 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500 resize-none"
                  />
                </div>

                <div className="flex justify-end">
                  <button
                    onClick={handleUpdateStatus}
                    disabled={isUpdating}
                    className="px-3.5 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white text-xs font-mono font-medium transition-colors flex items-center gap-1.5"
                  >
                    {isUpdating ? (
                      'Committing Audit Entry...'
                    ) : (
                      <>
                        <CheckCircle2 className="w-3.5 h-3.5" /> Commit Triage Changes
                      </>
                    )}
                  </button>
                </div>
              </div>

              {/* Navigation Tabs */}
              <div className="flex items-center gap-2 border-b border-slate-800">
                <button
                  onClick={() => setActiveTab('timeline')}
                  className={`pb-2.5 px-3 text-xs font-mono font-semibold transition-colors border-b-2 flex items-center gap-1.5 ${
                    activeTab === 'timeline'
                      ? 'border-cyan-400 text-cyan-400'
                      : 'border-transparent text-slate-400 hover:text-slate-200'
                  }`}
                >
                  <Clock className="w-3.5 h-3.5" />
                  Chronological Timeline ({timelineItems.length})
                </button>
                <button
                  onClick={() => setActiveTab('alerts')}
                  className={`pb-2.5 px-3 text-xs font-mono font-semibold transition-colors border-b-2 flex items-center gap-1.5 ${
                    activeTab === 'alerts'
                      ? 'border-cyan-400 text-cyan-400'
                      : 'border-transparent text-slate-400 hover:text-slate-200'
                  }`}
                >
                  <ShieldAlert className="w-3.5 h-3.5" />
                  Correlated Alerts ({incident.alert_count})
                </button>
                <button
                  onClick={() => setActiveTab('correlation')}
                  className={`pb-2.5 px-3 text-xs font-mono font-semibold transition-colors border-b-2 flex items-center gap-1.5 ${
                    activeTab === 'correlation'
                      ? 'border-cyan-400 text-cyan-400'
                      : 'border-transparent text-slate-400 hover:text-slate-200'
                  }`}
                >
                  <GitBranch className="w-3.5 h-3.5" />
                  Correlation Explanation & Entities
                </button>
                <button
                  onClick={() => setActiveTab('audit')}
                  className={`pb-2.5 px-3 text-xs font-mono font-semibold transition-colors border-b-2 flex items-center gap-1.5 ${
                    activeTab === 'audit'
                      ? 'border-cyan-400 text-cyan-400'
                      : 'border-transparent text-slate-400 hover:text-slate-200'
                  }`}
                >
                  <History className="w-3.5 h-3.5" />
                  Audit Trail ({incident.audit_logs?.length || 0})
                </button>
              </div>

              {/* Tab 1: Chronological Timeline */}
              {activeTab === 'timeline' && (
                <div className="space-y-3">
                  <div className="flex items-center justify-between text-xs text-slate-400 px-1">
                    <span className="font-mono">
                      Unified sequence of Security Events, Alerts, and Analyst Actions
                    </span>
                    <span className="font-mono">Sorted chronologically (Earliest → Latest)</span>
                  </div>

                  {timelineLoading ? (
                    <div className="py-12 text-center text-slate-500 font-mono text-xs">
                      Loading unified chronological timeline...
                    </div>
                  ) : timelineItems.length === 0 ? (
                    <div className="py-12 text-center text-slate-500 font-mono text-xs">
                      No timeline records associated.
                    </div>
                  ) : (
                    <div className="relative pl-6 space-y-4 before:absolute before:left-2.5 before:top-2 before:bottom-2 before:w-0.5 before:bg-slate-800">
                      {timelineItems.map((item, idx) => {
                        const isExpanded = expandedTimelineId === item.id;
                        const isEvent = item.item_type === 'event';
                        const isAlert = item.item_type === 'alert';
                        const isAction = item.item_type === 'incident_action';

                        return (
                          <div key={item.id + idx} className="relative group">
                            {/* Marker Node */}
                            <div
                              className={`absolute -left-6 top-1.5 w-5 h-5 rounded-full border flex items-center justify-center text-[10px] font-mono z-10 ${
                                isAlert
                                  ? 'bg-amber-950 border-amber-600 text-amber-300'
                                  : isAction
                                  ? 'bg-purple-950 border-purple-600 text-purple-300'
                                  : 'bg-slate-900 border-blue-600 text-blue-300'
                              }`}
                            >
                              {isAlert ? 'A' : isAction ? 'I' : 'E'}
                            </div>

                            {/* Card Content */}
                            <div className="bg-slate-950/80 border border-slate-800/80 rounded-lg p-3 hover:border-slate-700 transition-colors">
                              <div className="flex flex-wrap items-center justify-between gap-2 mb-1">
                                <div className="flex items-center gap-2">
                                  <span
                                    className={`px-1.5 py-0.5 rounded text-[10px] font-mono font-semibold uppercase ${
                                      isAlert
                                        ? 'bg-amber-950 text-amber-300 border border-amber-800'
                                        : isAction
                                        ? 'bg-purple-950 text-purple-300 border border-purple-800'
                                        : 'bg-blue-950 text-blue-300 border border-blue-800'
                                    }`}
                                  >
                                    {isAlert ? 'ALERT' : isAction ? 'INCIDENT ACTION' : 'EVENT'}
                                  </span>
                                  <span className="text-xs font-semibold text-slate-200">
                                    {item.title}
                                  </span>
                                </div>
                                <span className="text-xs font-mono text-slate-400">
                                  {new Date(item.timestamp).toLocaleString()}
                                </span>
                              </div>

                              {item.description && (
                                <p className="text-xs text-slate-300 font-mono mb-2">
                                  {item.description}
                                </p>
                              )}

                              <div className="flex flex-wrap items-center justify-between gap-2 text-[11px] font-mono text-slate-400 pt-1 border-t border-slate-900">
                                <div className="flex items-center gap-3">
                                  {item.entity && <span>Entity: <strong className="text-slate-200">{item.entity}</strong></span>}
                                  {item.source && <span>Source: <strong className="text-slate-200">{item.source}</strong></span>}
                                  {item.severity && (
                                    <span>
                                      Severity: <strong className="text-slate-200 uppercase">{item.severity}</strong>
                                    </span>
                                  )}
                                </div>
                                {item.metadata && Object.keys(item.metadata).length > 0 && (
                                  <button
                                    onClick={() => setExpandedTimelineId(isExpanded ? null : item.id)}
                                    className="text-cyan-400 hover:text-cyan-300 flex items-center gap-1"
                                  >
                                    {isExpanded ? 'Hide Payload' : 'Inspect Details'}
                                    <ChevronDown
                                      className={`w-3 h-3 transition-transform ${
                                        isExpanded ? 'rotate-180' : ''
                                      }`}
                                    />
                                  </button>
                                )}
                              </div>

                              {/* Expanded Payload */}
                              {isExpanded && (
                                <div className="mt-2.5 pt-2 border-t border-slate-800/80">
                                  <pre className="p-2.5 bg-slate-900/90 rounded border border-slate-800 text-[10px] font-mono text-cyan-300 overflow-x-auto">
                                    {JSON.stringify(item.metadata, null, 2)}
                                  </pre>
                                </div>
                              )}
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>
              )}

              {/* Tab 2: Correlated Alerts */}
              {activeTab === 'alerts' && (
                <div className="space-y-3">
                  <div className="flex items-center justify-between text-xs text-slate-400 px-1">
                    <span className="font-mono">
                      Constituent deterministic alerts correlated into this security incident
                    </span>
                    <span className="font-mono">
                      Complete Chain: Incident → Alert → Security Event
                    </span>
                  </div>

                  {(!incident.alerts || incident.alerts.length === 0) ? (
                    <div className="py-12 text-center text-slate-500 font-mono text-xs">
                      No alerts correlated into this incident.
                    </div>
                  ) : (
                    <div className="space-y-3">
                      {incident.alerts.map((alert) => {
                        const isExpanded = expandedAlertId === alert.id;
                        return (
                          <div
                            key={alert.id}
                            className="bg-slate-950/80 border border-slate-800 rounded-lg p-3.5 hover:border-slate-700 transition-colors"
                          >
                            <div className="flex flex-wrap items-center justify-between gap-2 mb-1.5">
                              <div className="flex items-center gap-2">
                                <span className="px-2 py-0.5 rounded text-xs font-mono font-semibold bg-slate-900 border border-slate-700 text-cyan-400">
                                  {alert.rule_id}
                                </span>
                                <span className="font-semibold text-sm text-slate-100">
                                  {alert.rule_name}
                                </span>
                                {getSeverityBadge(alert.severity)}
                              </div>
                              <span className="text-xs font-mono text-slate-400">
                                Detected: {new Date(alert.detected_at).toLocaleString()}
                              </span>
                            </div>

                            <p className="text-xs text-slate-300 mb-2 font-mono">
                              {alert.description}
                            </p>

                            <div className="flex flex-wrap items-center justify-between gap-2 text-xs font-mono text-slate-400 pt-2 border-t border-slate-900">
                              <div className="flex items-center gap-3">
                                {alert.affected_user && <span>User: <strong className="text-slate-200">{alert.affected_user}</strong></span>}
                                {alert.affected_ip && <span>IP: <strong className="text-slate-200">{alert.affected_ip}</strong></span>}
                                <span>Evidence Events: <strong className="text-cyan-400">{alert.evidence_count}</strong></span>
                              </div>
                              <div className="flex items-center gap-2">
                                {onSelectAlert && (
                                  <button
                                    onClick={() => onSelectAlert(alert.id)}
                                    className="px-2 py-1 rounded bg-slate-900 hover:bg-slate-800 text-cyan-400 text-xs font-mono transition-colors flex items-center gap-1"
                                  >
                                    Open Alert Inspector <ArrowRight className="w-3 h-3" />
                                  </button>
                                )}
                                <button
                                  onClick={() => setExpandedAlertId(isExpanded ? null : alert.id)}
                                  className="text-slate-400 hover:text-slate-200 text-xs font-mono flex items-center gap-1"
                                >
                                  {isExpanded ? 'Hide Evidence' : 'Show Supporting Evidence'}
                                  <ChevronDown className={`w-3.5 h-3.5 transition-transform ${isExpanded ? 'rotate-180' : ''}`} />
                                </button>
                              </div>
                            </div>

                            {/* Supporting Evidence Breakdown */}
                            {isExpanded && alert.evidence && (
                              <div className="mt-3 pt-3 border-t border-slate-800 space-y-2">
                                <span className="text-xs font-mono text-slate-400 uppercase tracking-wider block">
                                  Linked Security Event Telemetry
                                </span>
                                {alert.evidence.map((ev, evIdx) => (
                                  <div
                                    key={ev.id || evIdx}
                                    className="p-2.5 bg-slate-900 rounded border border-slate-800 text-xs font-mono space-y-1"
                                  >
                                    <div className="flex items-center justify-between text-slate-300">
                                      <span className="text-cyan-400 font-semibold">
                                        Role: {ev.evidence_role}
                                      </span>
                                      <span className="text-slate-500">Event ID: {ev.event_id}</span>
                                    </div>
                                    {ev.description && (
                                      <p className="text-slate-400">{ev.description}</p>
                                    )}
                                    {ev.event && (
                                      <pre className="p-2 bg-slate-950 rounded text-[10px] text-slate-400 overflow-x-auto">
                                        {JSON.stringify(ev.event.raw_event || ev.event, null, 2)}
                                      </pre>
                                    )}
                                  </div>
                                ))}
                              </div>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>
              )}

              {/* Tab 3: Correlation Explanation & Entity Graph */}
              {activeTab === 'correlation' && (
                <div className="space-y-4">
                  {/* Forensic Description */}
                  <div className="bg-slate-950/80 border border-slate-800 rounded-lg p-4 space-y-2">
                    <span className="text-xs font-mono text-slate-400 uppercase tracking-wider block">
                      Incident Forensic Narrative
                    </span>
                    <p className="text-sm text-slate-200 leading-relaxed font-sans">
                      {incident.description}
                    </p>
                  </div>

                  {/* Explainable Correlation Signals */}
                  <div className="bg-slate-950/80 border border-slate-800 rounded-lg p-4 space-y-3">
                    <span className="text-xs font-mono text-slate-400 uppercase tracking-wider block">
                      Explainable Correlation Rationale (Deterministic Signals)
                    </span>
                    <ul className="space-y-2">
                      {incident.correlation_reasons.map((reason, idx) => (
                        <li
                          key={idx}
                          className="flex items-start gap-2.5 text-xs font-mono text-slate-300 bg-slate-900/60 p-2.5 rounded border border-slate-800/80"
                        >
                          <CheckCircle2 className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
                          <span>{reason}</span>
                        </li>
                      ))}
                    </ul>
                  </div>

                  {/* Affected Entities Aggregations */}
                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                    <div className="bg-slate-950/80 border border-slate-800 rounded-lg p-3.5 space-y-2">
                      <div className="flex items-center gap-2 text-xs font-mono text-slate-400 uppercase">
                        <User className="w-4 h-4 text-cyan-400" />
                        <span>Affected Accounts ({incident.affected_users.length})</span>
                      </div>
                      <div className="flex flex-wrap gap-1.5">
                        {incident.affected_users.length === 0 ? (
                          <span className="text-xs text-slate-500 font-mono">None identified</span>
                        ) : (
                          incident.affected_users.map((u, i) => (
                            <span
                              key={i}
                              className="px-2 py-0.5 rounded text-xs font-mono bg-cyan-950/60 text-cyan-300 border border-cyan-800/60"
                            >
                              {u}
                            </span>
                          ))
                        )}
                      </div>
                    </div>

                    <div className="bg-slate-950/80 border border-slate-800 rounded-lg p-3.5 space-y-2">
                      <div className="flex items-center gap-2 text-xs font-mono text-slate-400 uppercase">
                        <Globe className="w-4 h-4 text-amber-400" />
                        <span>Network Origins / IPs ({incident.affected_ips.length})</span>
                      </div>
                      <div className="flex flex-wrap gap-1.5">
                        {incident.affected_ips.length === 0 ? (
                          <span className="text-xs text-slate-500 font-mono">None identified</span>
                        ) : (
                          incident.affected_ips.map((ip, i) => (
                            <span
                              key={i}
                              className="px-2 py-0.5 rounded text-xs font-mono bg-amber-950/60 text-amber-300 border border-amber-800/60"
                            >
                              {ip}
                            </span>
                          ))
                        )}
                      </div>
                    </div>

                    <div className="bg-slate-950/80 border border-slate-800 rounded-lg p-3.5 space-y-2">
                      <div className="flex items-center gap-2 text-xs font-mono text-slate-400 uppercase">
                        <Server className="w-4 h-4 text-emerald-400" />
                        <span>Target Assets / Hosts ({incident.affected_hostnames.length})</span>
                      </div>
                      <div className="flex flex-wrap gap-1.5">
                        {incident.affected_hostnames.length === 0 ? (
                          <span className="text-xs text-slate-500 font-mono">None identified</span>
                        ) : (
                          incident.affected_hostnames.map((h, i) => (
                            <span
                              key={i}
                              className="px-2 py-0.5 rounded text-xs font-mono bg-emerald-950/60 text-emerald-300 border border-emerald-800/60"
                            >
                              {h}
                            </span>
                          ))
                        )}
                      </div>
                    </div>
                  </div>

                  {/* Engine Metadata */}
                  <div className="bg-slate-950/80 border border-slate-800 rounded-lg p-4 space-y-2">
                    <span className="text-xs font-mono text-slate-400 uppercase tracking-wider block">
                      Correlation Engine Tuning Metadata
                    </span>
                    <pre className="p-3 bg-slate-900 rounded border border-slate-800 text-xs font-mono text-cyan-300 overflow-x-auto">
                      {JSON.stringify(incident.correlation_metadata, null, 2)}
                    </pre>
                  </div>
                </div>
              )}

              {/* Tab 4: Audit History */}
              {activeTab === 'audit' && (
                <div className="space-y-3">
                  <div className="flex items-center justify-between text-xs text-slate-400 px-1">
                    <span className="font-mono">
                      Immutable forensic log of all analyst actions and engine events
                    </span>
                    <span className="font-mono">Strict Non-Repudiation</span>
                  </div>

                  {(!incident.audit_logs || incident.audit_logs.length === 0) ? (
                    <div className="py-12 text-center text-slate-500 font-mono text-xs">
                      No audit history entries recorded.
                    </div>
                  ) : (
                    <div className="space-y-2">
                      {incident.audit_logs.map((log) => (
                        <div
                          key={log.id}
                          className="p-3 bg-slate-950/80 border border-slate-800 rounded-lg text-xs font-mono space-y-1"
                        >
                          <div className="flex flex-wrap items-center justify-between gap-2">
                            <div className="flex items-center gap-2">
                              <span className="px-1.5 py-0.5 rounded bg-purple-950 text-purple-300 border border-purple-800 font-semibold uppercase text-[10px]">
                                {log.action.replace('_', ' ')}
                              </span>
                              <span className="text-slate-300">
                                Actor: <strong className="text-cyan-400">{log.actor}</strong>
                              </span>
                            </div>
                            <span className="text-slate-500">
                              {new Date(log.created_at).toLocaleString()}
                            </span>
                          </div>

                          {(log.previous_value || log.new_value) && (
                            <div className="text-slate-400 text-[11px] pt-1">
                              Transition: <span className="line-through text-slate-500">{log.previous_value || 'None'}</span> →{' '}
                              <span className="text-emerald-400">{log.new_value}</span>
                            </div>
                          )}

                          {log.notes && (
                            <p className="text-slate-300 text-[11px] bg-slate-900 p-2 rounded mt-1 border border-slate-800/80">
                              {log.notes}
                            </p>
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </>
          )}
        </div>

        {/* Modal Footer */}
        <div className="p-3 sm:p-4 border-t border-slate-800 bg-slate-950/80 flex items-center justify-between text-xs font-mono text-slate-400">
          <span>SentinelOps AI — Forensic Incident Investigation</span>
          <button
            onClick={onClose}
            className="px-3.5 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-mono transition-colors"
          >
            Close Inspector
          </button>
        </div>
      </div>
    </div>
  );
};
