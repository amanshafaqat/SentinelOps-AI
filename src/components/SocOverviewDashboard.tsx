import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  AlertTriangle,
  Flame,
  CheckCircle2,
  Clock,
  Layers,
  Activity,
  ArrowRight,
  Sparkles,
  GitBranch,
  RefreshCw,
  Server,
  User,
  Globe,
  Database,
  ExternalLink,
  Shield,
  Info,
} from 'lucide-react';
import { IncidentSummaryItem } from './IncidentsExplorer';
import { IncidentDetailsModal } from './IncidentDetailsModal';

interface EventStats {
  total_events: number;
  by_severity: Record<string, number>;
  by_status: Record<string, number>;
  by_event_type: Record<string, number>;
  top_sources: Record<string, number>;
}

interface AlertStats {
  total_alerts: number;
  by_severity: Record<string, number>;
  by_status: Record<string, number>;
  by_rule: Record<string, number>;
}

interface IncidentStats {
  total_incidents: number;
  open_incidents: number;
  by_severity: Record<string, number>;
  by_status: Record<string, number>;
  average_alerts_per_incident: number;
}

interface SocOverviewDashboardProps {
  onNavigateToTab: (tab: 'incidents' | 'alerts' | 'events') => void;
  onOpenIncident?: (incidentId: string) => void;
  onOpenAlert?: (alertId: string) => void;
}

export const SocOverviewDashboard: React.FC<SocOverviewDashboardProps> = ({
  onNavigateToTab,
  onOpenIncident,
  onOpenAlert,
}) => {
  const [eventStats, setEventStats] = useState<EventStats | null>(null);
  const [alertStats, setAlertStats] = useState<AlertStats | null>(null);
  const [incidentStats, setIncidentStats] = useState<IncidentStats | null>(null);
  const [recentIncidents, setRecentIncidents] = useState<IncidentSummaryItem[]>([]);
  const [recentAlerts, setRecentAlerts] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [isSeedingDemo, setIsSeedingDemo] = useState(false);
  const [seedSuccessMsg, setSeedSuccessMsg] = useState<string | null>(null);
  const [selectedIncidentId, setSelectedIncidentId] = useState<string | null>(null);

  useEffect(() => {
    fetchAllStats();
  }, []);

  const fetchAllStats = async () => {
    setLoading(true);
    setError(null);
    try {
      const [evRes, alRes, incRes, recIncRes, recAlRes] = await Promise.all([
        fetch('/api/v1/events/stats/summary'),
        fetch('/api/v1/alerts/stats'),
        fetch('/api/v1/incidents/stats'),
        fetch('/api/v1/incidents?page=1&page_size=5'),
        fetch('/api/v1/alerts?page=1&page_size=5'),
      ]);

      if (evRes.ok) setEventStats(await evRes.json());
      if (alRes.ok) setAlertStats(await alRes.json());
      if (incRes.ok) setIncidentStats(await incRes.json());
      if (recIncRes.ok) {
        const incData = await recIncRes.json();
        setRecentIncidents(incData.incidents || []);
      }
      if (recAlRes.ok) {
        const alData = await recAlRes.json();
        setRecentAlerts(alData.alerts || []);
      }
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleSeedPipeline = async () => {
    setIsSeedingDemo(true);
    setSeedSuccessMsg(null);
    try {
      const res = await fetch('/api/v1/system/demo/seed', { method: 'POST' });
      if (!res.ok) throw new Error('Failed to run demo seed pipeline');
      const data = await res.json();
      setSeedSuccessMsg(
        `Generated ${data.events_created} events → ${data.alerts_generated} alerts → ${data.incidents_created} correlated incidents!`
      );
      fetchAllStats();
      setTimeout(() => setSeedSuccessMsg(null), 6000);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setIsSeedingDemo(false);
    }
  };

  const getSeverityBadge = (sev: string) => {
    switch (sev.toLowerCase()) {
      case 'critical':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-red-950/80 text-red-400 border border-red-800 text-[10px] font-mono font-bold uppercase">
            <Flame className="w-3 h-3 text-red-400" /> CRITICAL
          </span>
        );
      case 'high':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-amber-950/80 text-amber-400 border border-amber-800 text-[10px] font-mono font-bold uppercase">
            <AlertTriangle className="w-3 h-3 text-amber-400" /> HIGH
          </span>
        );
      case 'medium':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-blue-950/80 text-blue-400 border border-blue-800 text-[10px] font-mono font-bold uppercase">
            <Info className="w-3 h-3 text-blue-400" /> MEDIUM
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700 text-[10px] font-mono font-bold uppercase">
            <CheckCircle2 className="w-3 h-3 text-slate-400" /> LOW
          </span>
        );
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Header & Fast Seeder Bar */}
      <div className="bg-slate-900 border border-slate-800 rounded-lg p-4 sm:p-5 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <Shield className="w-6 h-6 text-cyan-400" />
            <h1 className="text-lg sm:text-xl font-bold text-slate-100">
              Security Operations Center (SOC) Command Console
            </h1>
          </div>
          <p className="text-xs font-mono text-slate-400 mt-1">
            Real-Time Telemetry → Deterministic Rules → Correlated Incidents → Investigation
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2.5">
          <button
            onClick={handleSeedPipeline}
            disabled={isSeedingDemo}
            className="px-3.5 py-2 rounded bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white text-xs font-mono font-medium shadow-sm transition-all flex items-center gap-2"
          >
            {isSeedingDemo ? (
              <>
                <div className="w-3.5 h-3.5 border-2 border-white border-t-transparent rounded-full animate-spin" />
                Provisioning Scenarios 1-4...
              </>
            ) : (
              <>
                <Sparkles className="w-3.5 h-3.5 text-amber-300" />
                Provision Demo Scenarios 1-4
              </>
            )}
          </button>

          <button
            onClick={fetchAllStats}
            disabled={loading}
            className="p-2 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition-colors"
            title="Refresh All Metrics"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* Seed Success Notice */}
      {seedSuccessMsg && (
        <div className="p-3.5 bg-emerald-950/80 border border-emerald-800 text-emerald-300 rounded-lg text-xs font-mono flex items-center gap-2 animate-fade-in">
          <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
          <span>{seedSuccessMsg}</span>
        </div>
      )}

      {/* 4 Core KPIs Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 sm:gap-4">
        {/* Total Events */}
        <div
          onClick={() => onNavigateToTab('events')}
          className="bg-slate-900 border border-slate-800 rounded-lg p-4 cursor-pointer hover:border-slate-700 transition-colors group"
        >
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-mono uppercase tracking-wider">Security Events</span>
            <Activity className="w-4 h-4 text-blue-400 group-hover:scale-110 transition-transform" />
          </div>
          <div className="text-2xl sm:text-3xl font-bold font-mono text-slate-100">
            {eventStats ? eventStats.total_events : '...'}
          </div>
          <div className="text-[11px] font-mono text-slate-500 mt-2 flex items-center justify-between">
            <span>Raw Ingested Telemetry</span>
            <ArrowRight className="w-3 h-3 text-cyan-400 group-hover:translate-x-0.5 transition-transform" />
          </div>
        </div>

        {/* Total Alerts */}
        <div
          onClick={() => onNavigateToTab('alerts')}
          className="bg-slate-900 border border-slate-800 rounded-lg p-4 cursor-pointer hover:border-slate-700 transition-colors group"
        >
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-mono uppercase tracking-wider">Detection Alerts</span>
            <ShieldAlert className="w-4 h-4 text-amber-400 group-hover:scale-110 transition-transform" />
          </div>
          <div className="text-2xl sm:text-3xl font-bold font-mono text-amber-400">
            {alertStats ? alertStats.total_alerts : '...'}
          </div>
          <div className="text-[11px] font-mono text-slate-500 mt-2 flex items-center justify-between">
            <span>Deterministic Rules</span>
            <ArrowRight className="w-3 h-3 text-cyan-400 group-hover:translate-x-0.5 transition-transform" />
          </div>
        </div>

        {/* Total Incidents */}
        <div
          onClick={() => onNavigateToTab('incidents')}
          className="bg-slate-900 border border-slate-800 rounded-lg p-4 cursor-pointer hover:border-slate-700 transition-colors group"
        >
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-mono uppercase tracking-wider">Correlated Incidents</span>
            <GitBranch className="w-4 h-4 text-red-400 group-hover:scale-110 transition-transform" />
          </div>
          <div className="text-2xl sm:text-3xl font-bold font-mono text-red-400">
            {incidentStats ? incidentStats.total_incidents : '...'}
          </div>
          <div className="text-[11px] font-mono text-slate-500 mt-2 flex items-center justify-between">
            <span>Alert Clusters Formed</span>
            <ArrowRight className="w-3 h-3 text-cyan-400 group-hover:translate-x-0.5 transition-transform" />
          </div>
        </div>

        {/* Open Incidents */}
        <div
          onClick={() => onNavigateToTab('incidents')}
          className="bg-slate-900 border border-slate-800 rounded-lg p-4 cursor-pointer hover:border-slate-700 transition-colors group"
        >
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-mono uppercase tracking-wider">Open / Triage</span>
            <Flame className="w-4 h-4 text-cyan-400 group-hover:scale-110 transition-transform" />
          </div>
          <div className="text-2xl sm:text-3xl font-bold font-mono text-cyan-400">
            {incidentStats ? incidentStats.open_incidents : '...'}
          </div>
          <div className="text-[11px] font-mono text-slate-500 mt-2 flex items-center justify-between">
            <span>New or Investigating</span>
            <ArrowRight className="w-3 h-3 text-cyan-400 group-hover:translate-x-0.5 transition-transform" />
          </div>
        </div>
      </div>

      {/* Incident Severity & Status Distribution */}
      {incidentStats && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {/* Severity Breakdown */}
          <div className="bg-slate-900 border border-slate-800 rounded-lg p-4 space-y-3">
            <span className="text-xs font-mono text-slate-400 uppercase tracking-wider block">
              Incident Severity Distribution (Deterministic Risk Rating)
            </span>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
              <div className="p-3 rounded bg-red-950/40 border border-red-900/60 text-center">
                <span className="text-[10px] font-mono text-red-400 uppercase block font-semibold">Critical</span>
                <span className="text-xl font-mono font-bold text-red-300">
                  {incidentStats.by_severity.critical || 0}
                </span>
              </div>
              <div className="p-3 rounded bg-amber-950/40 border border-amber-900/60 text-center">
                <span className="text-[10px] font-mono text-amber-400 uppercase block font-semibold">High</span>
                <span className="text-xl font-mono font-bold text-amber-300">
                  {incidentStats.by_severity.high || 0}
                </span>
              </div>
              <div className="p-3 rounded bg-blue-950/40 border border-blue-900/60 text-center">
                <span className="text-[10px] font-mono text-blue-400 uppercase block font-semibold">Medium</span>
                <span className="text-xl font-mono font-bold text-blue-300">
                  {incidentStats.by_severity.medium || 0}
                </span>
              </div>
              <div className="p-3 rounded bg-slate-950 border border-slate-800 text-center">
                <span className="text-[10px] font-mono text-slate-400 uppercase block font-semibold">Low</span>
                <span className="text-xl font-mono font-bold text-slate-300">
                  {incidentStats.by_severity.low || 0}
                </span>
              </div>
            </div>
            <p className="text-[11px] font-mono text-slate-500">
              Severity is calculated deterministically from constituent alerts without AI hallucinations.
            </p>
          </div>

          {/* Lifecycle Status Breakdown */}
          <div className="bg-slate-900 border border-slate-800 rounded-lg p-4 space-y-3">
            <span className="text-xs font-mono text-slate-400 uppercase tracking-wider block">
              Incident Lifecycle Triage States
            </span>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
              <div className="p-3 rounded bg-slate-950 border border-slate-800 text-center">
                <span className="text-[10px] font-mono text-red-400 uppercase block font-semibold">New</span>
                <span className="text-xl font-mono font-bold text-slate-200">
                  {incidentStats.by_status.new || 0}
                </span>
              </div>
              <div className="p-3 rounded bg-slate-950 border border-slate-800 text-center">
                <span className="text-[10px] font-mono text-amber-400 uppercase block font-semibold">Investigating</span>
                <span className="text-xl font-mono font-bold text-slate-200">
                  {incidentStats.by_status.investigating || 0}
                </span>
              </div>
              <div className="p-3 rounded bg-slate-950 border border-slate-800 text-center">
                <span className="text-[10px] font-mono text-emerald-400 uppercase block font-semibold">Resolved</span>
                <span className="text-xl font-mono font-bold text-slate-200">
                  {incidentStats.by_status.resolved || 0}
                </span>
              </div>
              <div className="p-3 rounded bg-slate-950 border border-slate-800 text-center">
                <span className="text-[10px] font-mono text-slate-500 uppercase block font-semibold">Closed</span>
                <span className="text-xl font-mono font-bold text-slate-200">
                  {incidentStats.by_status.closed || 0}
                </span>
              </div>
            </div>
            <p className="text-[11px] font-mono text-slate-500">
              Average correlated alerts per incident: <strong className="text-cyan-400">{incidentStats.average_alerts_per_incident}</strong>
            </p>
          </div>
        </div>
      )}

      {/* Demo Scenarios Walkthrough Card */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-lg p-4 sm:p-5 space-y-3">
        <div className="flex items-center gap-2">
          <Sparkles className="w-5 h-5 text-amber-400" />
          <h3 className="text-sm font-bold text-slate-100 font-mono">
            Phase 4 Forensic Demo Scenarios & Verified Attack Pipelines
          </h3>
        </div>
        <p className="text-xs text-slate-400 font-mono">
          Each scenario injects realistic telemetry, triggers deterministic detection rules, and evaluates the correlation engine:
        </p>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3 text-xs font-mono">
          <div className="p-3 bg-slate-950 rounded border border-slate-800 space-y-1.5">
            <span className="font-bold text-amber-400 block">Scenario 1: Brute Force</span>
            <p className="text-slate-400 text-[11px]">
              5 failed passwords on 198.51.100.42 targeting Administrator.
            </p>
            <span className="text-[10px] text-cyan-400 block font-semibold">
              Outcome: RULE-001 → Correlated Incident
            </span>
          </div>

          <div className="p-3 bg-slate-950 rounded border border-slate-800 space-y-1.5">
            <span className="font-bold text-red-400 block">Scenario 2: Compromise Sequence</span>
            <p className="text-slate-400 text-[11px]">
              4 failed logons followed by successful logon for svc-deploy.
            </p>
            <span className="text-[10px] text-red-300 block font-semibold">
              Outcome: RULE-001 + 002 → Elevated Critical Incident
            </span>
          </div>

          <div className="p-3 bg-slate-950 rounded border border-slate-800 space-y-1.5">
            <span className="font-bold text-purple-400 block">Scenario 3: Privilege Escalation</span>
            <p className="text-slate-400 text-[11px]">
              VPN logon followed by sudo group escalation for jdoe.
            </p>
            <span className="text-[10px] text-purple-300 block font-semibold">
              Outcome: RULE-003 → Correlated Admin Incident
            </span>
          </div>

          <div className="p-3 bg-slate-950 rounded border border-slate-800 space-y-1.5">
            <span className="font-bold text-emerald-400 block">Scenario 4: Benign Operations</span>
            <p className="text-slate-400 text-[11px]">
              Scheduled volume backups & SSO workstation logons.
            </p>
            <span className="text-[10px] text-emerald-300 block font-semibold">
              Outcome: Isolated telemetry (Zero false alerts)
            </span>
          </div>
        </div>
      </div>

      {/* Split Section: Recent Incidents vs Recent Alerts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Recent Correlated Incidents */}
        <div className="bg-slate-900 border border-slate-800 rounded-lg p-4 space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-red-400" />
              <h3 className="text-xs font-mono font-bold text-slate-200 uppercase">
                Recent Correlated Incidents
              </h3>
            </div>
            <button
              onClick={() => onNavigateToTab('incidents')}
              className="text-xs font-mono text-cyan-400 hover:text-cyan-300 flex items-center gap-1"
            >
              View All <ArrowRight className="w-3 h-3" />
            </button>
          </div>

          {recentIncidents.length === 0 ? (
            <div className="py-8 text-center text-slate-500 font-mono text-xs">
              No incidents generated yet. Click &quot;Provision Demo Scenarios&quot; above.
            </div>
          ) : (
            <div className="space-y-2">
              {recentIncidents.map((inc) => (
                <div
                  key={inc.id}
                  onClick={() => setSelectedIncidentId(inc.id)}
                  className="p-3 bg-slate-950/80 rounded border border-slate-800 hover:border-slate-700 cursor-pointer transition-colors space-y-1 group"
                >
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-xs text-slate-200 group-hover:text-cyan-400 transition-colors line-clamp-1">
                      {inc.title}
                    </span>
                    {getSeverityBadge(inc.severity)}
                  </div>
                  <div className="flex items-center justify-between text-[11px] font-mono text-slate-400 pt-1">
                    <span>{inc.alert_count} Alerts Correlated</span>
                    <span>{inc.last_seen ? new Date(inc.last_seen).toLocaleTimeString() : 'N/A'}</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Recent Detection Alerts */}
        <div className="bg-slate-900 border border-slate-800 rounded-lg p-4 space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-amber-400" />
              <h3 className="text-xs font-mono font-bold text-slate-200 uppercase">
                Recent Detection Alerts
              </h3>
            </div>
            <button
              onClick={() => onNavigateToTab('alerts')}
              className="text-xs font-mono text-cyan-400 hover:text-cyan-300 flex items-center gap-1"
            >
              View All <ArrowRight className="w-3 h-3" />
            </button>
          </div>

          {recentAlerts.length === 0 ? (
            <div className="py-8 text-center text-slate-500 font-mono text-xs">
              No alerts generated yet.
            </div>
          ) : (
            <div className="space-y-2">
              {recentAlerts.map((alt) => (
                <div
                  key={alt.id}
                  onClick={() => {
                    if (onOpenAlert) onOpenAlert(alt.id);
                  }}
                  className="p-3 bg-slate-950/80 rounded border border-slate-800 hover:border-slate-700 cursor-pointer transition-colors space-y-1 group"
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <span className="px-1.5 py-0.5 rounded bg-slate-900 border border-slate-800 text-cyan-400 font-mono text-[10px]">
                        {alt.rule_id}
                      </span>
                      <span className="font-semibold text-xs text-slate-200 group-hover:text-cyan-400 transition-colors line-clamp-1">
                        {alt.title}
                      </span>
                    </div>
                    {getSeverityBadge(alt.severity)}
                  </div>
                  <div className="flex items-center justify-between text-[11px] font-mono text-slate-400 pt-1">
                    <span>User: {alt.affected_user || alt.affected_ip || 'N/A'}</span>
                    <span>{alt.detected_at ? new Date(alt.detected_at).toLocaleTimeString() : 'N/A'}</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Incident Detail Modal */}
      {selectedIncidentId && (
        <IncidentDetailsModal
          incidentId={selectedIncidentId}
          onClose={() => setSelectedIncidentId(null)}
          onIncidentUpdated={fetchAllStats}
          onSelectAlert={onOpenAlert}
        />
      )}
    </div>
  );
};
