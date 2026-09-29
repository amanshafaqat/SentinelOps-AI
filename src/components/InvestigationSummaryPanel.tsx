import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  AlertTriangle,
  Flame,
  Info,
  CheckCircle2,
  Clock,
  User,
  Globe,
  Server,
  Layers,
  Sparkles,
  Bot,
  GitBranch,
  Activity,
  History,
  MessageSquare,
  FileCheck2,
  ExternalLink,
  Loader2,
} from 'lucide-react';
import { IncidentDetail } from './IncidentDetailsModal';

interface InvestigationSummaryPanelProps {
  incident: IncidentDetail;
  onOpenCopilot?: () => void;
  onOpenNotes?: () => void;
  onOpenReports?: () => void;
  onOpenTimeline?: () => void;
}

export const InvestigationSummaryPanel: React.FC<InvestigationSummaryPanelProps> = ({
  incident,
  onOpenCopilot,
  onOpenNotes,
  onOpenReports,
  onOpenTimeline,
}) => {
  const [aiAnalysis, setAiAnalysis] = useState<any | null>(null);
  const [loadingAi, setLoadingAi] = useState(false);

  useEffect(() => {
    if (incident?.id) {
      fetchLatestAiAnalysis(incident.id);
    }
  }, [incident?.id]);

  const fetchLatestAiAnalysis = async (id: string) => {
    setLoadingAi(true);
    try {
      const res = await fetch(`/api/v1/incidents/${id}/ai-history`);
      if (res.ok) {
        const data = await res.json();
        if (data.analyses && data.analyses.length > 0) {
          setAiAnalysis(data.analyses[0]);
        }
      }
    } catch (e) {
      console.warn('Could not fetch AI analysis history:', e);
    } finally {
      setLoadingAi(false);
    }
  };

  // Calculate statistics from actual incident data
  const totalAlerts = incident.alerts?.length || incident.alert_count || 0;
  const totalSupportingEvents = (incident.alerts || []).reduce((acc, a: any) => {
    return acc + (a.evidence_count || a.evidence?.length || 0);
  }, 0);

  // Group alerts by severity
  const severityBreakdown = (incident.alerts || []).reduce(
    (acc: Record<string, number>, a: any) => {
      const s = (a.severity || 'medium').toLowerCase();
      acc[s] = (acc[s] || 0) + 1;
      return acc;
    },
    { critical: 0, high: 0, medium: 0, low: 0 }
  );

  // Group alerts by triggered rule
  const ruleBreakdown = (incident.alerts || []).reduce(
    (acc: Record<string, { count: number; name: string }>, a: any) => {
      const rId = a.rule_id || 'UNKNOWN';
      const rName = a.rule_name || a.title || 'Unknown Rule';
      if (!acc[rId]) {
        acc[rId] = { count: 0, name: rName };
      }
      acc[rId].count += 1;
      return acc;
    },
    {}
  );

  const getSeverityBadge = (sev: string) => {
    switch (sev.toLowerCase()) {
      case 'critical':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded bg-red-950/80 text-red-400 border border-red-800 text-xs font-mono font-semibold">
            <Flame className="w-3 h-3 text-red-400" />
            CRITICAL
          </span>
        );
      case 'high':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded bg-amber-950/80 text-amber-400 border border-amber-800 text-xs font-mono font-semibold">
            <AlertTriangle className="w-3 h-3 text-amber-400" />
            HIGH
          </span>
        );
      case 'medium':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded bg-blue-950/80 text-blue-400 border border-blue-800 text-xs font-mono font-semibold">
            <Info className="w-3 h-3 text-blue-400" />
            MEDIUM
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded bg-slate-900 text-slate-400 border border-slate-700 text-xs font-mono font-semibold">
            <CheckCircle2 className="w-3 h-3 text-slate-400" />
            LOW
          </span>
        );
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status.toLowerCase()) {
      case 'new':
        return (
          <span className="px-2 py-0.5 rounded text-xs font-mono bg-red-950/60 text-red-300 border border-red-800/60 font-semibold">
            NEW
          </span>
        );
      case 'investigating':
        return (
          <span className="px-2 py-0.5 rounded text-xs font-mono bg-amber-950/60 text-amber-300 border border-amber-800/60 font-semibold">
            INVESTIGATING
          </span>
        );
      case 'resolved':
        return (
          <span className="px-2 py-0.5 rounded text-xs font-mono bg-emerald-950/60 text-emerald-300 border border-emerald-800/60 font-semibold">
            RESOLVED
          </span>
        );
      case 'closed':
        return (
          <span className="px-2 py-0.5 rounded text-xs font-mono bg-slate-800 text-slate-400 border border-slate-700 font-semibold">
            CLOSED
          </span>
        );
      default:
        return <span className="text-xs font-mono text-slate-400">{status}</span>;
    }
  };

  return (
    <div className="space-y-6">
      {/* 1. Incident Summary Card */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-lg p-5 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-3">
          <div className="flex items-center gap-2.5">
            <ShieldAlert className="w-5 h-5 text-cyan-400 shrink-0" />
            <h3 className="text-sm font-bold text-slate-100 font-mono">1. Incident Summary</h3>
          </div>
          <div className="flex items-center gap-2">
            {getSeverityBadge(incident.severity)}
            {getStatusBadge(incident.status)}
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 text-xs font-mono">
          <div className="bg-slate-950/60 border border-slate-800/60 rounded p-3">
            <span className="text-slate-500 uppercase tracking-wider block mb-1">First Seen Telemetry</span>
            <span className="text-slate-200 font-semibold">
              {incident.first_seen ? new Date(incident.first_seen).toLocaleString() : 'N/A'}
            </span>
          </div>

          <div className="bg-slate-950/60 border border-slate-800/60 rounded p-3">
            <span className="text-slate-500 uppercase tracking-wider block mb-1">Last Seen Telemetry</span>
            <span className="text-slate-200 font-semibold">
              {incident.last_seen ? new Date(incident.last_seen).toLocaleString() : 'N/A'}
            </span>
          </div>

          <div className="bg-slate-950/60 border border-slate-800/60 rounded p-3">
            <span className="text-slate-500 uppercase tracking-wider block mb-1">Correlated Alerts</span>
            <span className="text-cyan-400 font-bold text-sm">{totalAlerts} Alert(s)</span>
          </div>

          <div className="bg-slate-950/60 border border-slate-800/60 rounded p-3">
            <span className="text-slate-500 uppercase tracking-wider block mb-1">Supporting Raw Events</span>
            <span className="text-indigo-400 font-bold text-sm">{totalSupportingEvents} Event(s)</span>
          </div>
        </div>

        {/* Affected Entities */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs font-mono pt-1">
          <div className="bg-slate-950/40 border border-slate-800/60 rounded p-2.5">
            <span className="text-slate-500 flex items-center gap-1.5 mb-1.5 font-semibold">
              <User className="w-3.5 h-3.5 text-slate-400" />
              Targeted Users ({incident.affected_users?.length || 0})
            </span>
            <div className="flex flex-wrap gap-1">
              {incident.affected_users && incident.affected_users.length > 0 ? (
                incident.affected_users.map((u) => (
                  <span key={u} className="px-2 py-0.5 bg-slate-900 border border-slate-700 text-slate-300 rounded text-[11px]">
                    {u}
                  </span>
                ))
              ) : (
                <span className="text-slate-500 italic text-[11px]">None observed</span>
              )}
            </div>
          </div>

          <div className="bg-slate-950/40 border border-slate-800/60 rounded p-2.5">
            <span className="text-slate-500 flex items-center gap-1.5 mb-1.5 font-semibold">
              <Globe className="w-3.5 h-3.5 text-slate-400" />
              Associated Network IPs ({incident.affected_ips?.length || 0})
            </span>
            <div className="flex flex-wrap gap-1">
              {incident.affected_ips && incident.affected_ips.length > 0 ? (
                incident.affected_ips.map((ip) => (
                  <span key={ip} className="px-2 py-0.5 bg-slate-900 border border-slate-700 text-slate-300 rounded text-[11px]">
                    {ip}
                  </span>
                ))
              ) : (
                <span className="text-slate-500 italic text-[11px]">None observed</span>
              )}
            </div>
          </div>

          <div className="bg-slate-950/40 border border-slate-800/60 rounded p-2.5">
            <span className="text-slate-500 flex items-center gap-1.5 mb-1.5 font-semibold">
              <Server className="w-3.5 h-3.5 text-slate-400" />
              Affected Hosts ({incident.affected_hostnames?.length || 0})
            </span>
            <div className="flex flex-wrap gap-1">
              {incident.affected_hostnames && incident.affected_hostnames.length > 0 ? (
                incident.affected_hostnames.map((h) => (
                  <span key={h} className="px-2 py-0.5 bg-slate-900 border border-slate-700 text-slate-300 rounded text-[11px]">
                    {h}
                  </span>
                ))
              ) : (
                <span className="text-slate-500 italic text-[11px]">None observed</span>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* 2. Detection Summary Card */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-lg p-5 space-y-4">
        <div className="flex items-center gap-2.5 border-b border-slate-800 pb-3">
          <Layers className="w-5 h-5 text-indigo-400 shrink-0" />
          <h3 className="text-sm font-bold text-slate-100 font-mono">2. Detection &amp; Correlation Summary</h3>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {/* Rules Triggered */}
          <div className="space-y-2">
            <span className="text-xs font-mono uppercase tracking-wider text-slate-400 font-semibold block">
              Triggered Detection Rules
            </span>
            <div className="space-y-1.5">
              {Object.entries(ruleBreakdown).map(([rId, info]) => (
                <div
                  key={rId}
                  className="flex items-center justify-between p-2 rounded bg-slate-950/60 border border-slate-800 text-xs font-mono"
                >
                  <div className="flex items-center gap-2">
                    <span className="px-1.5 py-0.5 bg-indigo-950 text-indigo-300 border border-indigo-800 text-[10px] rounded font-bold">
                      {rId}
                    </span>
                    <span className="text-slate-200">{info.name}</span>
                  </div>
                  <span className="px-2 py-0.5 bg-slate-800 rounded text-cyan-400 font-bold">
                    {info.count} alert{info.count > 1 ? 's' : ''}
                  </span>
                </div>
              ))}
            </div>
          </div>

          {/* Severity Distribution */}
          <div className="space-y-2">
            <span className="text-xs font-mono uppercase tracking-wider text-slate-400 font-semibold block">
              Alert Count by Severity
            </span>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
              <div className="bg-red-950/40 border border-red-900/60 rounded p-3 text-center">
                <span className="text-[10px] font-mono text-red-400 uppercase block mb-1">Critical</span>
                <span className="text-xl font-bold font-mono text-red-300">{severityBreakdown.critical}</span>
              </div>
              <div className="bg-amber-950/40 border border-amber-900/60 rounded p-3 text-center">
                <span className="text-[10px] font-mono text-amber-400 uppercase block mb-1">High</span>
                <span className="text-xl font-bold font-mono text-amber-300">{severityBreakdown.high}</span>
              </div>
              <div className="bg-blue-950/40 border border-blue-900/60 rounded p-3 text-center">
                <span className="text-[10px] font-mono text-blue-400 uppercase block mb-1">Medium</span>
                <span className="text-xl font-bold font-mono text-blue-300">{severityBreakdown.medium}</span>
              </div>
              <div className="bg-slate-900 border border-slate-700 rounded p-3 text-center">
                <span className="text-[10px] font-mono text-slate-400 uppercase block mb-1">Low</span>
                <span className="text-xl font-bold font-mono text-slate-300">{severityBreakdown.low}</span>
              </div>
            </div>
          </div>
        </div>

        {/* Correlation Explanation */}
        <div className="pt-2 border-t border-slate-800/80">
          <span className="text-xs font-mono text-slate-400 flex items-center gap-1.5 mb-2 font-semibold">
            <GitBranch className="w-3.5 h-3.5 text-cyan-400" />
            Explainable Correlation Narrative &amp; Signals
          </span>
          <div className="space-y-1.5">
            {incident.correlation_reasons && incident.correlation_reasons.length > 0 ? (
              incident.correlation_reasons.map((reason, idx) => (
                <div
                  key={idx}
                  className="flex items-start gap-2 p-2 bg-slate-950/60 border border-slate-800/80 rounded text-xs font-mono text-slate-300"
                >
                  <span className="text-cyan-400 font-bold shrink-0 mt-0.5">•</span>
                  <span>{reason}</span>
                </div>
              ))
            ) : (
              <p className="text-xs font-mono text-slate-500 italic">No specific correlation signals logged.</p>
            )}
          </div>
        </div>
      </div>

      {/* 3. Investigation Summary Card */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-lg p-5 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-3">
          <div className="flex items-center gap-2.5">
            <Activity className="w-5 h-5 text-emerald-400 shrink-0" />
            <h3 className="text-sm font-bold text-slate-100 font-mono">3. Investigation &amp; Case Progress</h3>
          </div>
          <div className="flex items-center gap-2">
            {onOpenNotes && (
              <button
                onClick={onOpenNotes}
                className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-mono flex items-center gap-1 transition-colors"
              >
                <MessageSquare className="w-3 h-3 text-cyan-400" />
                Notes ({incident.notes?.length || 0})
              </button>
            )}
            {onOpenCopilot && (
              <button
                onClick={onOpenCopilot}
                className="px-2.5 py-1 rounded bg-indigo-950/80 hover:bg-indigo-900 border border-indigo-800 text-indigo-300 text-xs font-mono flex items-center gap-1 transition-colors"
              >
                <Bot className="w-3 h-3 text-indigo-400" />
                Copilot
              </button>
            )}
            {onOpenReports && (
              <button
                onClick={onOpenReports}
                className="px-2.5 py-1 rounded bg-cyan-950/80 hover:bg-cyan-900 border border-cyan-800 text-cyan-300 text-xs font-mono flex items-center gap-1 transition-colors"
              >
                <FileCheck2 className="w-3 h-3 text-cyan-400" />
                Reports ({incident.reports?.length || 0})
              </button>
            )}
          </div>
        </div>

        {/* AI Copilot Status in Investigation Summary */}
        <div className="bg-slate-950/60 border border-indigo-900/40 rounded-lg p-3.5 space-y-2">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Sparkles className="w-4 h-4 text-indigo-400" />
              <span className="text-xs font-mono font-bold text-indigo-300 uppercase tracking-wider">
                AI Investigation Findings (Advisory)
              </span>
            </div>
            {aiAnalysis && (
              <span className="text-[10px] font-mono text-slate-400">
                Model: {aiAnalysis.model || 'Gemini'} • {new Date(aiAnalysis.created_at).toLocaleString()}
              </span>
            )}
          </div>

          {loadingAi ? (
            <div className="py-3 flex items-center justify-center gap-2 text-xs font-mono text-slate-400">
              <Loader2 className="w-3.5 h-3.5 animate-spin text-indigo-400" />
              Loading latest AI analysis...
            </div>
          ) : aiAnalysis ? (
            <div className="space-y-2 text-xs font-mono">
              <p className="text-slate-200 leading-relaxed">{aiAnalysis.summary}</p>
              {aiAnalysis.observed_facts && aiAnalysis.observed_facts.length > 0 && (
                <div className="pt-1">
                  <span className="text-[11px] text-emerald-400 font-semibold block mb-1">
                    Key Corroborated Facts:
                  </span>
                  <ul className="list-disc list-inside text-slate-300 space-y-0.5 text-[11px]">
                    {aiAnalysis.observed_facts.slice(0, 3).map((f: string, i: number) => (
                      <li key={i}>{f}</li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          ) : (
            <div className="py-2 flex items-center justify-between text-xs font-mono text-slate-400">
              <span>No AI analysis executed yet for this incident.</span>
              {onOpenCopilot && (
                <button
                  onClick={onOpenCopilot}
                  className="text-indigo-400 hover:text-indigo-300 underline text-xs"
                >
                  Run Gemini Copilot &rarr;
                </button>
              )}
            </div>
          )}
        </div>

        {/* Analyst Notes Preview & Investigation Activity */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-1">
          {/* Recent Notes */}
          <div className="space-y-2">
            <span className="text-xs font-mono uppercase tracking-wider text-slate-400 font-semibold flex items-center gap-1.5">
              <MessageSquare className="w-3.5 h-3.5 text-cyan-400" />
              Latest Analyst Notes ({incident.notes?.length || 0})
            </span>
            <div className="space-y-1.5">
              {incident.notes && incident.notes.length > 0 ? (
                incident.notes.slice(0, 3).map((n) => (
                  <div
                    key={n.id}
                    className="p-2.5 bg-slate-950/60 border border-slate-800 rounded text-xs font-mono space-y-1"
                  >
                    <div className="flex items-center justify-between text-[11px] text-slate-400">
                      <span className="font-semibold text-cyan-300">{n.author}</span>
                      <span>{new Date(n.created_at).toLocaleDateString()}</span>
                    </div>
                    <p className="text-slate-200 line-clamp-2">{n.content}</p>
                  </div>
                ))
              ) : (
                <div className="p-3 bg-slate-950/40 border border-slate-800/80 rounded text-xs font-mono text-slate-500 italic">
                  No analyst notes documented. Click &quot;Notes&quot; above to add triage findings.
                </div>
              )}
            </div>
          </div>

          {/* Investigation History Preview */}
          <div className="space-y-2">
            <span className="text-xs font-mono uppercase tracking-wider text-slate-400 font-semibold flex items-center gap-1.5">
              <History className="w-3.5 h-3.5 text-purple-400" />
              Recent Investigation Activity ({incident.audit_logs?.length || 0})
            </span>
            <div className="space-y-1.5">
              {incident.audit_logs && incident.audit_logs.length > 0 ? (
                incident.audit_logs.slice(0, 3).map((l) => (
                  <div
                    key={l.id}
                    className="p-2.5 bg-slate-950/60 border border-slate-800 rounded text-xs font-mono space-y-1"
                  >
                    <div className="flex items-center justify-between text-[11px]">
                      <span className="font-semibold text-purple-300 uppercase">{l.action.replace('_', ' ')}</span>
                      <span className="text-slate-500">{new Date(l.created_at).toLocaleTimeString()}</span>
                    </div>
                    <p className="text-slate-300 text-[11px] truncate">
                      {l.notes || `${l.actor}: ${l.previous_value || 'None'} → ${l.new_value || 'None'}`}
                    </p>
                  </div>
                ))
              ) : (
                <div className="p-3 bg-slate-950/40 border border-slate-800/80 rounded text-xs font-mono text-slate-500 italic">
                  No activity history recorded yet.
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
