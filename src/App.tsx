import React, { useState, useEffect } from 'react';
import {
  Shield,
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
  ShieldAlert,
  AlertTriangle,
  Flame,
  Fingerprint,
  Scale,
} from 'lucide-react';
import { EventExplorer } from './components/EventExplorer';
import { AlertsExplorer } from './components/AlertsExplorer';

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
  const [activeTab, setActiveTab] = useState<'alerts' | 'events' | 'rules' | 'overview' | 'api' | 'checklist'>('alerts');

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
    { num: '03', name: 'Deterministic Detection Engine', active: true, done: false, status: 'Active Phase' },
    { num: '04', name: 'Incident Correlation & Dashboard', active: false, done: false, status: 'Phase 4' },
    { num: '05', name: 'Gemini Investigation Copilot', active: false, done: false, status: 'Phase 5' },
    { num: '06', name: 'Case Management & Reports', active: false, done: false, status: 'Phase 6' },
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
                  SentinelOps<span className="text-rose-400">.AI</span>
                </span>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-rose-950/80 text-rose-300 border border-rose-800/60 uppercase font-semibold">
                  Phase 3 Active
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
              <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin text-rose-400' : ''}`} />
            </button>
          </div>
        </div>
      </header>

      {/* Main Container */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
        {/* Banner: Current Phase Focus */}
        <div className="relative overflow-hidden rounded-xl border border-rose-500/20 bg-gradient-to-r from-rose-950/30 via-slate-900/60 to-slate-900/40 p-6 shadow-xl">
          <div className="absolute right-0 top-0 translate-x-8 -translate-y-8 w-64 h-64 bg-rose-500/5 rounded-full blur-3xl pointer-events-none" />
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div className="space-y-2">
              <div className="inline-flex items-center space-x-2 text-xs font-mono uppercase tracking-widest text-rose-400">
                <Activity className="w-3.5 h-3.5" />
                <span>Phase 3 Deterministic Detection Engine</span>
              </div>
              <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-white">
                Deterministic Security Detection Engine & Alerts
              </h1>
              <p className="text-sm text-slate-300 max-w-2xl leading-relaxed">
                Evaluates normalized SecurityEvents against modular detection rules (Rules 001–005).
                Generates explainable, deduplicated alerts backed by immutable event evidence.
                Completely independent of LLM/AI dependencies.
              </p>
            </div>
            <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-3">
              <div className="px-4 py-3 rounded-lg bg-slate-900/80 border border-slate-800 text-center font-mono">
                <span className="block text-xs text-slate-500 uppercase tracking-wider">Detection Mode</span>
                <span className="text-sm font-semibold text-rose-400">Deterministic Engine</span>
              </div>
              <div className="px-4 py-3 rounded-lg bg-slate-900/80 border border-slate-800 text-center font-mono">
                <span className="block text-xs text-slate-500 uppercase tracking-wider">Evidence Grounding</span>
                <span className="text-sm font-semibold text-emerald-400">Immutable Telemetry</span>
              </div>
            </div>
          </div>
        </div>

        {/* Phase Roadmap Nav */}
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2">
          {phases.map((p) => (
            <div
              key={p.num}
              className={`p-3 rounded-lg border transition text-left flex flex-col justify-between ${
                p.active
                  ? 'bg-slate-900 border-rose-500/50 shadow-[0_0_12px_rgba(244,63,94,0.15)]'
                  : p.done
                  ? 'bg-slate-900/40 border-slate-800/80'
                  : 'bg-slate-900/40 border-slate-800/60 opacity-60'
              }`}
            >
              <div className="flex items-center justify-between mb-1">
                <span className={`text-xs font-mono font-bold ${p.active ? 'text-rose-400' : p.done ? 'text-emerald-400' : 'text-slate-500'}`}>
                  {p.num}
                </span>
                {p.active ? (
                  <span className="w-1.5 h-1.5 rounded-full bg-rose-400 animate-pulse"></span>
                ) : p.done ? (
                  <CheckCircle2 className="w-3 h-3 text-emerald-400" />
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
            { id: 'alerts', label: 'Detection Alerts (Phase 3)', icon: ShieldAlert },
            { id: 'events', label: 'Event Explorer (Phase 2)', icon: ListFilter },
            { id: 'rules', label: 'Detection Rules (001–005)', icon: Zap },
            { id: 'overview', label: 'Architecture & Engine', icon: Layers },
            { id: 'api', label: 'API & Diagnostics', icon: Terminal },
            { id: 'checklist', label: 'Phase 3 Verification', icon: FileCheck2 },
          ].map((tab) => {
            const Icon = tab.icon;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id as any)}
                className={`pb-3 pt-1 flex items-center space-x-2 border-b-2 transition whitespace-nowrap ${
                  activeTab === tab.id
                    ? 'border-rose-500 text-rose-400 font-semibold'
                    : 'border-transparent text-slate-400 hover:text-slate-200 hover:border-slate-700'
                }`}
              >
                <Icon className="w-4 h-4" />
                <span>{tab.label}</span>
              </button>
            );
          })}
        </div>

        {/* Tab 1: Detection Alerts Explorer */}
        {activeTab === 'alerts' && <AlertsExplorer />}

        {/* Tab 2: Security Event Explorer */}
        {activeTab === 'events' && <EventExplorer />}

        {/* Tab 3: Detection Rules Specification */}
        {activeTab === 'rules' && (
          <div className="space-y-6 animate-fade-in">
            <div className="p-5 rounded-xl bg-slate-900 border border-slate-800">
              <h3 className="text-base font-bold text-slate-100 mb-1">
                Deterministic Rule Inventory (Rules 001 – 005)
              </h3>
              <p className="text-xs text-slate-400">
                Independent, testable detection rules executed against normalized security telemetry.
                Thresholds and observation windows are cleanly decoupled in configuration.
              </p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {/* RULE-001 */}
              <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
                <div className="flex items-center justify-between">
                  <span className="px-2 py-0.5 rounded font-mono text-xs font-bold bg-slate-800 border border-slate-700 text-slate-200">
                    RULE-001
                  </span>
                  <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-yellow-950/80 text-yellow-300 border border-yellow-800/60">
                    MEDIUM / HIGH
                  </span>
                </div>
                <h4 className="text-sm font-bold text-slate-100">
                  Brute Force Authentication Attempt
                </h4>
                <p className="text-xs text-slate-400 leading-relaxed">
                  Detects repeated failed logins targeting the same account or originating from the same source IP within a sliding observation window.
                </p>
                <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800/80 text-xs font-mono space-y-1">
                  <div className="text-slate-400">Threshold: <span className="text-slate-200">≥ 3 failures</span></div>
                  <div className="text-slate-400">Sliding Window: <span className="text-slate-200">15 minutes</span></div>
                  <div className="text-slate-400">Dynamic Severity: <span className="text-slate-200">HIGH if ≥ 6 failures</span></div>
                </div>
              </div>

              {/* RULE-002 */}
              <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
                <div className="flex items-center justify-between">
                  <span className="px-2 py-0.5 rounded font-mono text-xs font-bold bg-slate-800 border border-slate-700 text-slate-200">
                    RULE-002
                  </span>
                  <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-amber-950/80 text-amber-300 border border-amber-800/60">
                    HIGH
                  </span>
                </div>
                <h4 className="text-sm font-bold text-slate-100">
                  Successful Login After Repeated Failures
                </h4>
                <p className="text-xs text-slate-400 leading-relaxed">
                  Correlates a successful login immediately following multiple failed authentication attempts within a preceding lookback window, indicative of password guessing.
                </p>
                <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800/80 text-xs font-mono space-y-1">
                  <div className="text-slate-400">Prior Failures Threshold: <span className="text-slate-200">≥ 2 failures</span></div>
                  <div className="text-slate-400">Preceding Window: <span className="text-slate-200">30 minutes</span></div>
                  <div className="text-slate-400">Evidence Binding: <span className="text-slate-200">Failures + Triggering Success</span></div>
                </div>
              </div>

              {/* RULE-003 */}
              <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
                <div className="flex items-center justify-between">
                  <span className="px-2 py-0.5 rounded font-mono text-xs font-bold bg-slate-800 border border-slate-700 text-slate-200">
                    RULE-003
                  </span>
                  <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-rose-950/80 text-rose-300 border border-rose-800/60">
                    HIGH / CRITICAL
                  </span>
                </div>
                <h4 className="text-sm font-bold text-slate-100">
                  Suspicious Privilege or Role Modification
                </h4>
                <p className="text-xs text-slate-400 leading-relaxed">
                  Identifies administrative account elevations, sensitive group membership additions (Domain Admins, wheel), or direct interactive root shells.
                </p>
                <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800/80 text-xs font-mono space-y-1">
                  <div className="text-slate-400">Monitored Actions: <span className="text-slate-200">sudo, group_add, role_assign</span></div>
                  <div className="text-slate-400">Sensitive Roles: <span className="text-slate-200">Domain Admins, wheel, root</span></div>
                  <div className="text-slate-400">Severity: <span className="text-slate-200">CRITICAL on high-impact targets</span></div>
                </div>
              </div>

              {/* RULE-004 */}
              <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
                <div className="flex items-center justify-between">
                  <span className="px-2 py-0.5 rounded font-mono text-xs font-bold bg-slate-800 border border-slate-700 text-slate-200">
                    RULE-004
                  </span>
                  <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-yellow-950/80 text-yellow-300 border border-yellow-800/60">
                    MEDIUM
                  </span>
                </div>
                <h4 className="text-sm font-bold text-slate-100">
                  Unusual Multi-Source Authentication Pattern
                </h4>
                <p className="text-xs text-slate-400 leading-relaxed">
                  Detects anomalous authentication patterns where a single account is accessed from multiple distinct source IPs in a short window. Grounded in telemetry without fake geo-data.
                </p>
                <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800/80 text-xs font-mono space-y-1">
                  <div className="text-slate-400">Distinct Source IPs: <span className="text-slate-200">≥ 2 unique IPs</span></div>
                  <div className="text-slate-400">Observation Window: <span className="text-slate-200">60 minutes</span></div>
                  <div className="text-slate-400">Integrity: <span className="text-slate-200">Zero fabricated intelligence</span></div>
                </div>
              </div>

              {/* RULE-005 */}
              <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 md:col-span-2 space-y-3">
                <div className="flex items-center justify-between">
                  <span className="px-2 py-0.5 rounded font-mono text-xs font-bold bg-slate-800 border border-slate-700 text-slate-200">
                    RULE-005
                  </span>
                  <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-amber-950/80 text-amber-300 border border-amber-800/60">
                    HIGH / MEDIUM
                  </span>
                </div>
                <h4 className="text-sm font-bold text-slate-100">
                  Configured Demo Threat Indicator Match [Simulated IOC]
                </h4>
                <p className="text-xs text-slate-400 leading-relaxed">
                  Detects telemetry containing explicitly configured demonstration indicators (simulated external attacker IPs, persistence accounts, bad domains). Clearly tagged as simulated IOC matches.
                </p>
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 p-3 rounded-lg bg-slate-950/60 border border-slate-800/80 text-xs font-mono">
                  <div>
                    <span className="text-slate-500 block text-[10px]">Demo IPs</span>
                    <span className="text-slate-300">198.51.100.101, 198.51.100.42</span>
                  </div>
                  <div>
                    <span className="text-slate-500 block text-[10px]">Demo Usernames</span>
                    <span className="text-slate-300">backdoor_backup</span>
                  </div>
                  <div>
                    <span className="text-slate-500 block text-[10px]">Labeling Standard</span>
                    <span className="text-rose-400">[Simulated IOC] Verified</span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Tab 4: Overview */}
        {activeTab === 'overview' && (
          <div className="space-y-6">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
                <div className="p-2.5 rounded-lg bg-rose-500/10 border border-rose-500/20 text-rose-400 w-fit">
                  <ShieldAlert className="w-5 h-5" />
                </div>
                <h3 className="text-sm font-bold text-slate-100">Detection Engine</h3>
                <p className="text-xs text-slate-400 leading-relaxed">
                  Modular Python detection engine executing deterministic algorithms against stored SecurityEvents. Evaluates rules independently without LLM reliance.
                </p>
              </div>

              <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
                <div className="p-2.5 rounded-lg bg-sky-500/10 border border-sky-500/20 text-sky-400 w-fit">
                  <Fingerprint className="w-5 h-5" />
                </div>
                <h3 className="text-sm font-bold text-slate-100">Deterministic Deduplication</h3>
                <p className="text-xs text-slate-400 leading-relaxed">
                  Cryptographic hash-based deduplication signatures (<code className="text-slate-300">dedup_key</code>) enforced at application and database level to suppress duplicate alerts.
                </p>
              </div>

              <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-3">
                <div className="p-2.5 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 w-fit">
                  <Layers className="w-5 h-5" />
                </div>
                <h3 className="text-sm font-bold text-slate-100">Evidence Association</h3>
                <p className="text-xs text-slate-400 leading-relaxed">
                  Foreign-key backed <code className="text-slate-300">AlertEvidence</code> mapping connecting each generated alert to its underlying security events with functional role tags.
                </p>
              </div>
            </div>
          </div>
        )}

        {/* Tab 5: API & Diagnostics */}
        {activeTab === 'api' && (
          <div className="space-y-6">
            <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 space-y-4">
              <h3 className="text-sm font-bold text-slate-100">Phase 3 Detection & Alert API Routes</h3>
              <div className="space-y-2 font-mono text-xs">
                <div className="p-2.5 rounded bg-slate-950 border border-slate-800 flex items-center justify-between">
                  <span className="text-rose-400 font-bold">POST /api/v1/detection/run</span>
                  <span className="text-slate-400">Trigger detection sweep across security telemetry</span>
                </div>
                <div className="p-2.5 rounded bg-slate-950 border border-slate-800 flex items-center justify-between">
                  <span className="text-sky-400 font-bold">GET /api/v1/alerts</span>
                  <span className="text-slate-400">Paginated alerts queue with severity and rule filters</span>
                </div>
                <div className="p-2.5 rounded bg-slate-950 border border-slate-800 flex items-center justify-between">
                  <span className="text-sky-400 font-bold">GET /api/v1/alerts/stats</span>
                  <span className="text-slate-400">Aggregated alert metrics by severity, status, and rule</span>
                </div>
                <div className="p-2.5 rounded bg-slate-950 border border-slate-800 flex items-center justify-between">
                  <span className="text-sky-400 font-bold">GET /api/v1/alerts/:id</span>
                  <span className="text-slate-400">Full alert details including linked evidence events</span>
                </div>
                <div className="p-2.5 rounded bg-slate-950 border border-slate-800 flex items-center justify-between">
                  <span className="text-amber-400 font-bold">PATCH /api/v1/alerts/:id/status</span>
                  <span className="text-slate-400">Transition alert triage status (new, in_review, etc.)</span>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Tab 6: Phase 3 Verification Checklist */}
        {activeTab === 'checklist' && (
          <div className="p-6 rounded-xl bg-slate-900 border border-slate-800 space-y-4">
            <h3 className="text-sm font-bold text-slate-100">Phase 3 Implementation Verification Checklist</h3>
            <div className="space-y-2.5 text-xs text-slate-300">
              {[
                { done: true, text: 'Modular detection engine architecture with DetectionRule ABC and DetectionContext' },
                { done: true, text: 'PostgreSQL Alert and AlertEvidence data models with Alembic migration applied' },
                { done: true, text: 'Immutable evidence relationships linking alerts to underlying SecurityEvents' },
                { done: true, text: 'Deterministic Rule 001: Brute Force Authentication Attempt (Sliding window)' },
                { done: true, text: 'Deterministic Rule 002: Successful Login After Repeated Failures' },
                { done: true, text: 'Deterministic Rule 003: Suspicious Privilege or Role Modification' },
                { done: true, text: 'Deterministic Rule 004: Unusual Multi-Source Authentication Pattern' },
                { done: true, text: 'Deterministic Rule 005: Explicit Configured Demo Threat Indicator Match' },
                { done: true, text: 'Deterministic cryptographic deduplication (dedup_key) on database and application layers' },
                { done: true, text: 'Detection Execution API (POST /api/v1/detection/run) with structured summary' },
                { done: true, text: 'Alert Retrieval API (GET /api/v1/alerts, GET /api/v1/alerts/:id, GET /api/v1/alerts/stats)' },
                { done: true, text: 'Frontend Alerts Explorer with real-time filters, evidence modal, and run modal' },
                { done: true, text: 'Comprehensive test suite: 63 of 63 unit and integration tests passing' },
                { done: true, text: 'Simulated attack scenarios verified (Scenarios A, B, C, D and benign activity)' },
              ].map((item, i) => (
                <div key={i} className="flex items-center space-x-2.5 p-2 rounded bg-slate-950/40 border border-slate-800">
                  <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                  <span>{item.text}</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-800/80 bg-slate-900/40 py-4 text-center text-xs text-slate-500 font-mono">
        SentinelOps.AI — Deterministic Detection Engine v1.0.0 • Phase 3 Active • Zero LLM in Detection
      </footer>
    </div>
  );
}
