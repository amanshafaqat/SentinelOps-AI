import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  Activity,
  Server,
  Database,
  Lock,
  Cpu,
  RefreshCw,
  CheckCircle2,
  Terminal,
  Layers,
  ArrowRight,
  Zap,
  Info,
  ChevronRight,
  ListFilter,
  FileCheck2,
  AlertTriangle,
  Flame,
  Fingerprint,
  Scale,
  GitBranch,
  Shield,
  Sparkles,
} from 'lucide-react';
import { EventExplorer } from './components/EventExplorer';
import { AlertsExplorer } from './components/AlertsExplorer';
import { IncidentsExplorer } from './components/IncidentsExplorer';
import { SocOverviewDashboard } from './components/SocOverviewDashboard';
import { AlertDetailsModal } from './components/AlertDetailsModal';
import { IncidentDetailsModal } from './components/IncidentDetailsModal';

interface HealthData {
  status: string;
  service: string;
  version: string;
  environment: string;
  timestamp: string;
}

interface SystemInfo {
  name: string;
  version: string;
  environment: string;
  current_phase: string;
  phase_title: string;
  architecture: {
    style: string;
    backend: string;
    database: string;
    frontend: string;
    detection_engine: string;
    correlation_engine?: string;
    ai_copilot: string;
  };
  security_features: string[];
}

export default function App() {
  const [health, setHealth] = useState<HealthData | null>(null);
  const [systemInfo, setSystemInfo] = useState<SystemInfo | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [lastCheck, setLastCheck] = useState<string>('');
  const [latency, setLatency] = useState<number | null>(null);
  const [activeTab, setActiveTab] = useState<'overview' | 'incidents' | 'alerts' | 'events' | 'rules' | 'api' | 'checklist'>('overview');

  // Inspection modals accessible from anywhere
  const [selectedAlertId, setSelectedAlertId] = useState<string | null>(null);
  const [selectedIncidentId, setSelectedIncidentId] = useState<string | null>(null);

  const fetchHealthAndInfo = async () => {
    setLoading(true);
    setError(null);
    const start = performance.now();

    try {
      const res = await fetch('/api/v1/health');
      const elapsed = Math.round(performance.now() - start);
      setLatency(elapsed);

      if (!res.ok) {
        throw new Error(`HTTP error ${res.status}: ${res.statusText}`);
      }

      const data: HealthData = await res.json();
      setHealth(data);

      const infoRes = await fetch('/api/v1/system/info');
      if (infoRes.ok) {
        const infoData: SystemInfo = await infoRes.json();
        setSystemInfo(infoData);
      }
      setLastCheck(new Date().toLocaleTimeString());
    } catch (err: any) {
      console.warn('Backend API connection note:', err.message);
      setError(err.message);
      setHealth({
        status: 'degraded',
        service: 'SentinelOps.AI',
        version: '1.0.0',
        environment: 'development',
        timestamp: new Date().toISOString(),
      });
      setLastCheck(new Date().toLocaleTimeString());
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchHealthAndInfo();
  }, []);

  const phases = [
    { num: '01', name: 'Foundation & Architecture', active: false, done: true, status: 'Completed' },
    { num: '02', name: 'Event Ingestion & Data Model', active: false, done: true, status: 'Completed' },
    { num: '03', name: 'Deterministic Detection Engine', active: false, done: true, status: 'Completed' },
    { num: '04', name: 'Incident Correlation & Dashboard', active: false, done: true, status: 'Completed' },
    { num: '05', name: 'Gemini Investigation Copilot', active: false, done: true, status: 'Completed' },
    { num: '06', name: 'Case Management & Reports', active: false, done: true, status: 'Completed' },
    { num: '07', name: 'Security Audit & Production Polish', active: true, done: true, status: 'Production Ready' },
  ];

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-rose-500/20 selection:text-rose-400">
      {/* Top SOC Navbar */}
      <header className="border-b border-slate-800/80 bg-slate-900/60 backdrop-blur-md sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="p-2 bg-rose-500/10 border border-rose-500/30 rounded-lg text-rose-400 shadow-[0_0_15px_rgba(244,63,94,0.15)]">
              <ShieldAlert className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="font-bold tracking-wider text-slate-100 text-lg uppercase font-mono">
                  SentinelOps<span className="text-cyan-400">.AI</span>
                </span>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-950/80 text-emerald-300 border border-emerald-800/60 uppercase font-semibold">
                  Phase 7 Hardened
                </span>
              </div>
              <p className="text-xs text-slate-400 hidden sm:block">
                AI SOC Analyst & Incident Response Platform
              </p>
            </div>
          </div>

          <div className="flex items-center space-x-4">
            {/* Health Badge */}
            <div className="flex items-center space-x-2 px-3 py-1.5 rounded-md bg-slate-900 border border-slate-800 text-xs font-mono">
              <span className="relative flex h-2.5 w-2.5">
                <span className={`animate-ping absolute inline-flex h-full w-full rounded-full opacity-75 ${error ? 'bg-amber-400' : 'bg-emerald-400'}`}></span>
                <span className={`relative inline-flex rounded-full h-2.5 w-2.5 ${error ? 'bg-amber-500' : 'bg-emerald-500'}`}></span>
              </span>
              <span className="text-slate-300">
                Backend: <strong className={error ? 'text-amber-400' : 'text-emerald-400'}>{health?.status || 'connected'}</strong>
              </span>
              {latency !== null && (
                <span className="text-slate-500 border-l border-slate-800 pl-2">
                  {latency}ms
                </span>
              )}
            </div>

            <button
              onClick={fetchHealthAndInfo}
              disabled={loading}
              className="p-2 rounded-md bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white transition border border-slate-700 disabled:opacity-50"
              title="Ping Backend Health"
            >
              <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin text-cyan-400' : ''}`} />
            </button>
          </div>
        </div>
      </header>

      {/* Main Container */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-6">
        {/* Banner: Current Phase Focus */}
        <div className="relative overflow-hidden rounded-xl border border-cyan-500/20 bg-gradient-to-r from-cyan-950/30 via-slate-900/60 to-slate-900/40 p-5 sm:p-6 shadow-xl">
          <div className="absolute right-0 top-0 translate-x-8 -translate-y-8 w-64 h-64 bg-cyan-500/5 rounded-full blur-3xl pointer-events-none" />
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div className="space-y-1.5">
              <div className="inline-flex items-center space-x-2 text-xs font-mono uppercase tracking-widest text-emerald-400">
                <Shield className="w-3.5 h-3.5" />
                <span>Phase 7 — Security Hardening, Testing & Production Polish</span>
              </div>
              <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-white">
                Enterprise AI SOC Analyst &amp; Incident Response Platform
              </h1>
              <p className="text-xs sm:text-sm text-slate-300 max-w-2xl leading-relaxed">
                End-to-end evidence-based security operations: Telemetry Ingestion &rarr; Deterministic Rule Detection &rarr;
                Multi-Stage Correlation &rarr; Gemini Copilot &rarr; Case Notes &rarr; Evidence-Grounded Reports with Server-Side Authorization.
              </p>
            </div>
            <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-3">
              <div className="px-4 py-2.5 rounded-lg bg-slate-900/80 border border-slate-800 text-center font-mono">
                <span className="block text-[10px] text-slate-500 uppercase tracking-wider">Security Architecture</span>
                <span className="text-xs font-semibold text-emerald-400">Server Authorization &amp; Defense</span>
              </div>
              <div className="px-4 py-2.5 rounded-lg bg-slate-900/80 border border-slate-800 text-center font-mono">
                <span className="block text-[10px] text-slate-500 uppercase tracking-wider">Traceability Chain</span>
                <span className="text-xs font-semibold text-cyan-400">Incident &rarr; Alert &rarr; Event</span>
              </div>
            </div>
          </div>
        </div>

        {/* Phase Roadmap Nav */}
        <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-2">
          {phases.map((p) => (
            <div
              key={p.num}
              className={`p-3 rounded-lg border transition text-left flex flex-col justify-between ${
                p.active
                  ? 'bg-slate-900 border-emerald-500/60 shadow-[0_0_12px_rgba(16,185,129,0.15)]'
                  : p.done
                  ? 'bg-slate-900/40 border-slate-800/80'
                  : 'bg-slate-900/40 border-slate-800/60 opacity-60'
              }`}
            >
              <div className="flex items-center justify-between mb-1">
                <span className={`text-xs font-mono font-bold ${p.active ? 'text-emerald-400' : p.done ? 'text-cyan-400' : 'text-slate-500'}`}>
                  {p.num}
                </span>
                {p.active ? (
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
                ) : p.done ? (
                  <CheckCircle2 className="w-3 h-3 text-cyan-400" />
                ) : null}
              </div>
              <div>
                <p className="text-xs font-semibold text-slate-200 line-clamp-2 leading-tight">
                  {p.name}
                </p>
                <span className="text-[10px] text-slate-500 font-mono mt-1 block">
                  {p.status}
                </span>
              </div>
            </div>
          ))}
        </div>

        {/* Tab Navigation */}
        <div className="border-b border-slate-800 flex space-x-6 text-sm font-medium overflow-x-auto">
          {[
            { id: 'overview', label: 'SOC Command Center', icon: Activity },
            { id: 'incidents', label: 'Incidents & Cases', icon: ShieldAlert },
            { id: 'alerts', label: 'Detection Alerts', icon: AlertTriangle },
            { id: 'events', label: 'Telemetry Explorer', icon: ListFilter },
            { id: 'rules', label: 'Detection Rules (001–005)', icon: Zap },
            { id: 'api', label: 'API & Diagnostics', icon: Terminal },
            { id: 'checklist', label: 'Production Verification', icon: FileCheck2 },
          ].map((tab) => {
            const Icon = tab.icon;
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id as any)}
                className={`pb-3 pt-1 flex items-center space-x-2 border-b-2 transition whitespace-nowrap text-xs font-mono ${
                  isActive
                    ? 'border-cyan-400 text-cyan-400 font-semibold'
                    : 'border-transparent text-slate-400 hover:text-slate-200 hover:border-slate-700'
                }`}
              >
                <Icon className="w-4 h-4" />
                <span>{tab.label}</span>
              </button>
            );
          })}
        </div>

        {/* Tab 1: SOC Overview Command Center */}
        {activeTab === 'overview' && (
          <SocOverviewDashboard
            onNavigateToTab={(tab) => setActiveTab(tab)}
            onOpenIncident={(incId) => setSelectedIncidentId(incId)}
            onOpenAlert={(altId) => setSelectedAlertId(altId)}
          />
        )}

        {/* Tab 2: Correlated Incidents Explorer */}
        {activeTab === 'incidents' && (
          <IncidentsExplorer onSelectAlert={(alertId) => setSelectedAlertId(alertId)} />
        )}

        {/* Tab 3: Detection Alerts Explorer */}
        {activeTab === 'alerts' && <AlertsExplorer />}

        {/* Tab 4: Security Event Telemetry Explorer */}
        {activeTab === 'events' && <EventExplorer />}

        {/* Tab 5: Detection Rules Specification */}
        {activeTab === 'rules' && (
          <div className="space-y-6 animate-fade-in font-mono">
            <div className="p-4 sm:p-5 rounded-xl bg-slate-900 border border-slate-800">
              <h3 className="text-sm sm:text-base font-bold text-slate-100 mb-1">
                Deterministic Detection Rules Specification (RULE-001 through RULE-005)
              </h3>
              <p className="text-xs text-slate-400">
                Independent, testable detection rules executed against normalized security telemetry.
                Alerts from these rules serve as the input dataset for the Phase 4 Correlation Engine.
              </p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {/* RULE-001 */}
              <div className="p-4 sm:p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
                <div className="flex items-center justify-between">
                  <span className="px-2 py-0.5 rounded font-mono text-xs font-bold bg-slate-800 border border-slate-700 text-slate-200">
                    RULE-001
                  </span>
                  <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-yellow-950/80 text-yellow-300 border border-yellow-800/60">
                    MEDIUM / HIGH
                  </span>
                </div>
                <h4 className="text-sm font-bold text-slate-100 font-sans">
                  Brute Force Authentication Attempt
                </h4>
                <p className="text-xs text-slate-400 leading-relaxed font-sans">
                  Detects repeated failed logins targeting the same account or originating from the same source IP within a sliding observation window.
                </p>
                <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800/80 text-xs font-mono space-y-1">
                  <div className="text-slate-400">Threshold: <span className="text-slate-200">≥ 3 failures</span></div>
                  <div className="text-slate-400">Window: <span className="text-slate-200">300 seconds (5m)</span></div>
                  <div className="text-slate-400">Correlation Signal: <span className="text-cyan-400">Username / Source IP</span></div>
                </div>
              </div>

              {/* RULE-002 */}
              <div className="p-4 sm:p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
                <div className="flex items-center justify-between">
                  <span className="px-2 py-0.5 rounded font-mono text-xs font-bold bg-slate-800 border border-slate-700 text-slate-200">
                    RULE-002
                  </span>
                  <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-rose-950/80 text-rose-300 border border-rose-800/60">
                    HIGH / CRITICAL
                  </span>
                </div>
                <h4 className="text-sm font-bold text-slate-100 font-sans">
                  Successful Login After Multiple Failures
                </h4>
                <p className="text-xs text-slate-400 leading-relaxed font-sans">
                  Detects successful authentication events that immediately succeed a cluster of failed authentications on the same account within a short lookback.
                </p>
                <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800/80 text-xs font-mono space-y-1">
                  <div className="text-slate-400">Preceding Failures: <span className="text-slate-200">≥ 3</span></div>
                  <div className="text-slate-400">Lookback Window: <span className="text-slate-200">900 seconds (15m)</span></div>
                  <div className="text-slate-400">Progression Trigger: <span className="text-amber-400">Compromise Sequence</span></div>
                </div>
              </div>

              {/* RULE-003 */}
              <div className="p-4 sm:p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
                <div className="flex items-center justify-between">
                  <span className="px-2 py-0.5 rounded font-mono text-xs font-bold bg-slate-800 border border-slate-700 text-slate-200">
                    RULE-003
                  </span>
                  <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-red-950/80 text-red-300 border border-red-800/60">
                    CRITICAL
                  </span>
                </div>
                <h4 className="text-sm font-bold text-slate-100 font-sans">
                  Suspicious Privilege or Role Modification
                </h4>
                <p className="text-xs text-slate-400 leading-relaxed font-sans">
                  Detects administrative privilege assignment, sudo elevation, or sensitive group additions for non-standard accounts.
                </p>
                <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800/80 text-xs font-mono space-y-1">
                  <div className="text-slate-400">Target Roles: <span className="text-slate-200">root, admin, sudo, wheel</span></div>
                  <div className="text-slate-400">Severity Elevates: <span className="text-red-400">When linked to prior auth alert</span></div>
                </div>
              </div>

              {/* RULE-004 */}
              <div className="p-4 sm:p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
                <div className="flex items-center justify-between">
                  <span className="px-2 py-0.5 rounded font-mono text-xs font-bold bg-slate-800 border border-slate-700 text-slate-200">
                    RULE-004
                  </span>
                  <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-amber-950/80 text-amber-300 border border-amber-800/60">
                    HIGH
                  </span>
                </div>
                <h4 className="text-sm font-bold text-slate-100 font-sans">
                  Anomalous Multi-Source Authentication
                </h4>
                <p className="text-xs text-slate-400 leading-relaxed font-sans">
                  Flags instances where the same account authenticates successfully from multiple distinct IP addresses within a tight temporal window.
                </p>
                <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800/80 text-xs font-mono space-y-1">
                  <div className="text-slate-400">IP Count Threshold: <span className="text-slate-200">≥ 2 distinct IPs</span></div>
                  <div className="text-slate-400">Window: <span className="text-slate-200">1800 seconds (30m)</span></div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Tab 6: API & Diagnostics */}
        {activeTab === 'api' && (
          <div className="space-y-6 font-mono text-xs">
            <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-4">
              <h3 className="text-sm font-bold text-slate-100">Phase 4 Incident & Correlation API Endpoints</h3>
              <div className="space-y-2">
                <div className="p-3 rounded bg-slate-950 border border-slate-800 flex items-center justify-between">
                  <span className="text-cyan-400 font-bold">POST /api/v1/incidents/correlate</span>
                  <span className="text-slate-400">Trigger deterministic correlation engine across alerts</span>
                </div>
                <div className="p-3 rounded bg-slate-950 border border-slate-800 flex items-center justify-between">
                  <span className="text-cyan-400 font-bold">GET /api/v1/incidents</span>
                  <span className="text-slate-400">Paginated incidents with severity, status, and entity filters</span>
                </div>
                <div className="p-3 rounded bg-slate-950 border border-slate-800 flex items-center justify-between">
                  <span className="text-cyan-400 font-bold">GET /api/v1/incidents/stats</span>
                  <span className="text-slate-400">SOC situational awareness metrics by severity and status</span>
                </div>
                <div className="p-3 rounded bg-slate-950 border border-slate-800 flex items-center justify-between">
                  <span className="text-cyan-400 font-bold">GET /api/v1/incidents/:id</span>
                  <span className="text-slate-400">Full incident record, correlated alerts, notes, reports, and audit logs</span>
                </div>
                <div className="p-3 rounded bg-slate-950 border border-slate-800 flex items-center justify-between">
                  <span className="text-cyan-400 font-bold">GET /api/v1/incidents/:id/timeline</span>
                  <span className="text-slate-400">Chronological unified timeline: events, alerts, analyst actions</span>
                </div>
                <div className="p-3 rounded bg-slate-950 border border-slate-800 flex items-center justify-between">
                  <span className="text-amber-400 font-bold">PATCH /api/v1/incidents/:id</span>
                  <span className="text-slate-400">Audited status mutation (new, investigating, resolved, closed)</span>
                </div>
                <div className="p-3 rounded bg-slate-950 border border-slate-800 flex items-center justify-between">
                  <span className="text-purple-400 font-bold">POST /api/v1/incidents/:id/investigate</span>
                  <span className="text-slate-400">Server-side Gemini investigation copilot with evidence grounding</span>
                </div>
                <div className="p-3 rounded bg-slate-950 border border-slate-800 flex items-center justify-between">
                  <span className="text-blue-400 font-bold">POST /api/v1/incidents/:id/notes</span>
                  <span className="text-slate-400">Create audited analyst investigation note with author authorization</span>
                </div>
                <div className="p-3 rounded bg-slate-950 border border-slate-800 flex items-center justify-between">
                  <span className="text-emerald-400 font-bold">POST /api/v1/incidents/:id/reports</span>
                  <span className="text-slate-400">Generate structured, evidence-grounded report with versioning</span>
                </div>
                <div className="p-3 rounded bg-slate-950 border border-slate-800 flex items-center justify-between">
                  <span className="text-emerald-400 font-bold">GET /api/v1/incidents/:id/reports/:id/export</span>
                  <span className="text-slate-400">Export report as standalone HTML or JSON document</span>
                </div>
                <div className="p-3 rounded bg-slate-950 border border-slate-800 flex items-center justify-between">
                  <span className="text-purple-400 font-bold">POST /api/v1/system/demo/seed</span>
                  <span className="text-slate-400">Provisions full Phase 1-7 demo pipeline &amp; scenarios</span>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Tab 7: Phase 7 Verification Checklist */}
        {activeTab === 'checklist' && (
          <div className="p-6 rounded-xl bg-slate-900 border border-slate-800 space-y-4 font-mono text-xs">
            <h3 className="text-sm font-bold text-slate-100">
              SentinelOps AI — Production Architecture &amp; Security Hardening Checklist (Phases 1–7)
            </h3>
            <div className="space-y-2 text-slate-300">
              {[
                { done: true, text: 'Phase 1: Modular Monolith architecture, strict CORS, Pydantic v2 validation, structured logging' },
                { done: true, text: 'Phase 2: Security event ingestion (CSV/JSON), schema normalization, time-zone UTC, path traversal guards' },
                { done: true, text: 'Phase 3: Deterministic detection rules (RULE-001–005), alert deduplication, evidence association' },
                { done: true, text: 'Phase 4: Multi-stage alert correlation engine, sliding windows, explainable narrative, SOC dashboard' },
                { done: true, text: 'Phase 5: Server-side Gemini copilot, delimited untrusted data boundary, evidence grounding validation' },
                { done: true, text: 'Phase 6: Case management, analyst notes, controlled status transitions, evidence-grounded reports' },
                { done: true, text: 'Phase 7: Server-side role-based authorization matrix, note author access control, sanitized filenames' },
                { done: true, text: 'Security: Zero client-side API keys, credentials masked in logs/audit records, secure error envelopes' },
                { done: true, text: 'Prompt Injection Defense: Delimited XML telemetry boundaries, advisory role instruction enforcement' },
                { done: true, text: 'Grounding Verification: Deterministic cross-referencing flags hallucinated evidence references' },
                { done: true, text: 'Reliability: Graceful Gemini failure degradation (offline fallback, timeouts, rate limits handled)' },
                { done: true, text: 'Testing: 120+ unit and integration tests passing cleanly across all 7 platform phases' },
              ].map((item, i) => (
                <div key={i} className="flex items-center space-x-2.5 p-2.5 rounded bg-slate-950/60 border border-slate-800">
                  <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                  <span>{item.text}</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </main>

      {/* Global Modals for alert inspection */}
      {selectedAlertId && (
        <AlertDetailsModal
          alertId={selectedAlertId}
          onClose={() => setSelectedAlertId(null)}
        />
      )}

      {selectedIncidentId && (
        <IncidentDetailsModal
          incidentId={selectedIncidentId}
          onClose={() => setSelectedIncidentId(null)}
          onSelectAlert={(alertId) => setSelectedAlertId(alertId)}
        />
      )}

      {/* Footer */}
      <footer className="border-t border-slate-800/80 bg-slate-900/40 py-4 text-center text-xs text-slate-500 font-mono">
        SentinelOps AI — Enterprise SOC Incident Response &amp; Investigation Copilot v1.0.0 • Phase 7 Production Hardened
      </footer>
    </div>
  );
}
