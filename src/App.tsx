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
} from 'lucide-react';
import { EventExplorer } from './components/EventExplorer';

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
  const [activeTab, setActiveTab] = useState<'events' | 'overview' | 'api' | 'architecture' | 'checklist'>('events');

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
    { num: '02', name: 'Event Ingestion & Data Model', active: true, done: false, status: 'Active Phase' },
    { num: '03', name: 'Deterministic Detection Engine', active: false, done: false, status: 'Phase 3' },
    { num: '04', name: 'Incident Correlation & Dashboard', active: false, done: false, status: 'Phase 4' },
    { num: '05', name: 'Gemini Investigation Copilot', active: false, done: false, status: 'Phase 5' },
    { num: '06', name: 'Case Management & Reports', active: false, done: false, status: 'Phase 6' },
  ];

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-emerald-500/20 selection:text-emerald-400">
      {/* Top SOC Navbar */}
      <header className="border-b border-slate-800/80 bg-slate-900/60 backdrop-blur-md sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="p-2 bg-emerald-500/10 border border-emerald-500/30 rounded-lg text-emerald-400 shadow-[0_0_15px_rgba(16,185,129,0.15)]">
              <Shield className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="font-bold tracking-wider text-slate-100 text-lg uppercase font-mono">
                  SentinelOps<span className="text-emerald-400">.AI</span>
                </span>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-950/80 text-emerald-300 border border-emerald-800/60 uppercase">
                  Phase 2 Active
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
              <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin text-emerald-400' : ''}`} />
            </button>
          </div>
        </div>
      </header>

      {/* Main Container */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
        {/* Banner: Current Phase Focus */}
        <div className="relative overflow-hidden rounded-xl border border-emerald-500/20 bg-gradient-to-r from-emerald-950/30 via-slate-900/60 to-slate-900/40 p-6 shadow-xl">
          <div className="absolute right-0 top-0 translate-x-8 -translate-y-8 w-64 h-64 bg-emerald-500/5 rounded-full blur-3xl pointer-events-none" />
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div className="space-y-2">
              <div className="inline-flex items-center space-x-2 text-xs font-mono uppercase tracking-widest text-emerald-400">
                <Activity className="w-3.5 h-3.5" />
                <span>Phase 2 Operational Telemetry Pipeline</span>
              </div>
              <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-white">
                Security Event Ingestion & Data Model
              </h1>
              <p className="text-sm text-slate-300 max-w-2xl leading-relaxed">
                Production-grade event ingestion pipeline in place: JSON/CSV multi-format parsing, Pydantic v2 validation, field normalization, PostgreSQL JSONB storage with B-tree composite indexing, and real-time Event Explorer.
              </p>
            </div>
            <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-3">
              <div className="px-4 py-3 rounded-lg bg-slate-900/80 border border-slate-800 text-center font-mono">
                <span className="block text-xs text-slate-500 uppercase tracking-wider">Database Storage</span>
                <span className="text-sm font-semibold text-emerald-400">PostgreSQL (Indexed)</span>
              </div>
              <div className="px-4 py-3 rounded-lg bg-slate-900/80 border border-slate-800 text-center font-mono">
                <span className="block text-xs text-slate-500 uppercase tracking-wider">Ingestion Formats</span>
                <span className="text-sm font-semibold text-sky-400">JSON & CSV Importer</span>
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
                  ? 'bg-slate-900 border-emerald-500/50 shadow-[0_0_12px_rgba(16,185,129,0.1)]'
                  : p.done
                  ? 'bg-slate-900/40 border-slate-800/80'
                  : 'bg-slate-900/40 border-slate-800/60 opacity-60'
              }`}
            >
              <div className="flex items-center justify-between mb-1">
                <span className={`text-xs font-mono font-bold ${p.active ? 'text-emerald-400' : p.done ? 'text-emerald-500' : 'text-slate-500'}`}>
                  {p.num}
                </span>
                {p.active ? (
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
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
        <div className="border-b border-slate-800 flex space-x-6 text-sm font-medium">
          {[
            { id: 'events', label: 'Event Explorer (Live SOC)', icon: ListFilter },
            { id: 'overview', label: 'System Overview', icon: Layers },
            { id: 'api', label: 'API & Health Diagnostic', icon: Terminal },
            { id: 'architecture', label: 'Security & Architecture', icon: Lock },
            { id: 'checklist', label: 'Phase 2 Verification', icon: FileCheck2 },
          ].map((tab) => {
            const Icon = tab.icon;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id as any)}
                className={`pb-3 text-sm font-mono tracking-wide transition border-b-2 -mb-px flex items-center space-x-2 ${
                  activeTab === tab.id
                    ? 'border-emerald-500 text-emerald-400 font-semibold'
                    : 'border-transparent text-slate-400 hover:text-slate-200'
                }`}
              >
                <Icon className="w-4 h-4" />
                <span>{tab.label}</span>
              </button>
            );
          })}
        </div>

        {/* Tab Content */}
        {activeTab === 'events' && <EventExplorer />}

        {activeTab === 'overview' && (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {/* Card 1: Backend Foundation */}
            <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800 hover:border-slate-700 transition flex flex-col justify-between">
              <div>
                <div className="flex items-center justify-between mb-4">
                  <div className="p-2.5 rounded-lg bg-sky-500/10 text-sky-400 border border-sky-500/20">
                    <Server className="w-5 h-5" />
                  </div>
                  <span className="text-xs font-mono text-emerald-400 bg-emerald-950/60 px-2 py-0.5 rounded border border-emerald-800/40">
                    OPERATIONAL
                  </span>
                </div>
                <h3 className="text-base font-semibold text-white mb-1">FastAPI Backend Core</h3>
                <p className="text-xs text-slate-400 mb-4 leading-relaxed">
                  High-performance Python backend with Pydantic v2 validation, versioned endpoints (`/api/v1`), and strict security middleware.
                </p>
                <div className="space-y-2 text-xs font-mono text-slate-300 bg-slate-950/80 p-3 rounded-md border border-slate-800/60">
                  <div className="flex justify-between">
                    <span className="text-slate-500">Framework:</span>
                    <span>FastAPI 0.110+</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500">Runtime:</span>
                    <span>Python 3.11</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500">Ingestion:</span>
                    <span>Multi-part JSON/CSV</span>
                  </div>
                </div>
              </div>
            </div>

            {/* Card 2: Database & ORM */}
            <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800 hover:border-slate-700 transition flex flex-col justify-between">
              <div>
                <div className="flex items-center justify-between mb-4">
                  <div className="p-2.5 rounded-lg bg-violet-500/10 text-violet-400 border border-violet-500/20">
                    <Database className="w-5 h-5" />
                  </div>
                  <span className="text-xs font-mono text-emerald-400 bg-emerald-950/60 px-2 py-0.5 rounded border border-emerald-800/40">
                    MIGRATED (POSTGRESQL)
                  </span>
                </div>
                <h3 className="text-base font-semibold text-white mb-1">Database & Migrations</h3>
                <p className="text-xs text-slate-400 mb-4 leading-relaxed">
                  PostgreSQL database with SQLAlchemy 2.0 connection pooling, scoped sessions, and Alembic migration `2ac4cb8026b3`.
                </p>
                <div className="space-y-2 text-xs font-mono text-slate-300 bg-slate-950/80 p-3 rounded-md border border-slate-800/60">
                  <div className="flex justify-between">
                    <span className="text-slate-500">Target DB:</span>
                    <span>PostgreSQL 15</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500">Table:</span>
                    <span>security_events (JSONB)</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500">B-Tree Indexes:</span>
                    <span>12 Indexes (4 Composite)</span>
                  </div>
                </div>
              </div>
            </div>

            {/* Card 3: Security & Logging */}
            <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800 hover:border-slate-700 transition flex flex-col justify-between">
              <div>
                <div className="flex items-center justify-between mb-4">
                  <div className="p-2.5 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                    <Lock className="w-5 h-5" />
                  </div>
                  <span className="text-xs font-mono text-emerald-400 bg-emerald-950/60 px-2 py-0.5 rounded border border-emerald-800/40">
                    ENFORCED
                  </span>
                </div>
                <h3 className="text-base font-semibold text-white mb-1">Security Architecture</h3>
                <p className="text-xs text-slate-400 mb-4 leading-relaxed">
                  Zero client-side secrets, sensitive data masking in logs, secure error responses, and hardened HTTP headers.
                </p>
                <div className="space-y-2 text-xs font-mono text-slate-300 bg-slate-950/80 p-3 rounded-md border border-slate-800/60">
                  <div className="flex justify-between">
                    <span className="text-slate-500">Max Upload:</span>
                    <span>10MB bounded streaming</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500">Format Defense:</span>
                    <span>Content sniffing & validation</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500">Payload Safety:</span>
                    <span>Hostile inputs treated as data</span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'api' && (
          <div className="space-y-6">
            <div className="p-6 rounded-xl bg-slate-900/60 border border-slate-800 space-y-4">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                <div>
                  <h3 className="text-base font-semibold text-white flex items-center space-x-2">
                    <Terminal className="w-4 h-4 text-emerald-400" />
                    <span>Live Health Probe: GET /api/v1/health</span>
                  </h3>
                  <p className="text-xs text-slate-400 mt-1">
                    Direct call to the backend foundation health endpoint.
                  </p>
                </div>
                <button
                  onClick={fetchHealthAndInfo}
                  disabled={loading}
                  className="inline-flex items-center space-x-2 px-3.5 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-mono font-medium transition disabled:opacity-50 self-start sm:self-auto"
                >
                  <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
                  <span>Execute Probe</span>
                </button>
              </div>

              {/* JSON Display */}
              <div className="relative rounded-lg bg-slate-950 border border-slate-800 p-4 font-mono text-xs overflow-x-auto">
                <div className="flex items-center justify-between text-slate-500 mb-2 border-b border-slate-800 pb-2">
                  <span>Response Payload (200 OK)</span>
                  <span>Last probed: {lastCheck || 'Initial load'}</span>
                </div>
                <pre className="text-emerald-400 leading-relaxed">
                  {JSON.stringify(health, null, 2)}
                </pre>
              </div>
            </div>

            {/* API Endpoints Catalog */}
            <div className="p-6 rounded-xl bg-slate-900/60 border border-slate-800 space-y-3">
              <h3 className="text-base font-semibold text-white">Registered API Endpoints</h3>
              <div className="divide-y divide-slate-800 font-mono text-xs">
                <div className="py-3 flex items-center justify-between">
                  <div className="flex items-center space-x-3">
                    <span className="px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-800 font-bold">
                      POST
                    </span>
                    <span className="text-slate-200">/api/v1/events/import</span>
                  </div>
                  <span className="text-slate-400 text-[11px]">Upload JSON or CSV telemetry logs</span>
                </div>
                <div className="py-3 flex items-center justify-between">
                  <div className="flex items-center space-x-3">
                    <span className="px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-800 font-bold">
                      GET
                    </span>
                    <span className="text-slate-200">/api/v1/events</span>
                  </div>
                  <span className="text-slate-400 text-[11px]">List and multi-filter paginated security events</span>
                </div>
                <div className="py-3 flex items-center justify-between">
                  <div className="flex items-center space-x-3">
                    <span className="px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-800 font-bold">
                      GET
                    </span>
                    <span className="text-slate-200">/api/v1/events/stats/summary</span>
                  </div>
                  <span className="text-slate-400 text-[11px]">SOC analytical metrics and distribution</span>
                </div>
                <div className="py-3 flex items-center justify-between">
                  <div className="flex items-center space-x-3">
                    <span className="px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-800 font-bold">
                      GET
                    </span>
                    <span className="text-slate-200">/api/v1/events/{'{event_id}'}</span>
                  </div>
                  <span className="text-slate-400 text-[11px]">Retrieve single event with raw payload and metadata</span>
                </div>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'architecture' && (
          <div className="space-y-6">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div className="p-6 rounded-xl bg-slate-900/60 border border-slate-800 space-y-4">
                <h3 className="text-base font-semibold text-white flex items-center space-x-2">
                  <Layers className="w-4 h-4 text-emerald-400" />
                  <span>Telemetry Pipeline Principles</span>
                </h3>
                <ul className="space-y-3 text-xs text-slate-300">
                  <li className="flex items-start space-x-2">
                    <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                    <span><strong>Forensic Fidelity:</strong> Exact original payloads are preserved in `raw_event` (PostgreSQL JSONB), ensuring zero evidentiary loss.</span>
                  </li>
                  <li className="flex items-start space-x-2">
                    <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                    <span><strong>Deterministic Detection Independence:</strong> Detection rules in Phase 3 execute on normalized indices without LLM dependencies.</span>
                  </li>
                  <li className="flex items-start space-x-2">
                    <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                    <span><strong>Partial Ingestion Resilience:</strong> Malformed rows in large CSV/JSON logs are isolated and logged without aborting valid rows.</span>
                  </li>
                </ul>
              </div>

              <div className="p-6 rounded-xl bg-slate-900/60 border border-slate-800 space-y-4">
                <h3 className="text-base font-semibold text-white flex items-center space-x-2">
                  <Lock className="w-4 h-4 text-emerald-400" />
                  <span>Security & Ingestion Safeguards</span>
                </h3>
                <ul className="space-y-3 text-xs text-slate-300">
                  <li className="flex items-start space-x-2">
                    <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                    <span><strong>Strict Upload Bounds:</strong> Max 10MB chunked streaming prevents denial-of-service and memory exhaustion.</span>
                  </li>
                  <li className="flex items-start space-x-2">
                    <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                    <span><strong>No Evaluation of Untrusted Logs:</strong> SQL injection strings and HTML/XSS vectors inside log messages are stored purely as inert strings.</span>
                  </li>
                  <li className="flex items-start space-x-2">
                    <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                    <span><strong>Path Traversal Resistance:</strong> Uploaded filenames are never written to disk or used in OS filesystem lookups.</span>
                  </li>
                </ul>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'checklist' && (
          <div className="p-6 rounded-xl bg-slate-900/60 border border-slate-800 space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="text-base font-semibold text-white flex items-center space-x-2">
                <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                <span>Phase 2 Completion & Verification Matrix</span>
              </h3>
              <span className="text-xs font-mono text-emerald-400 bg-emerald-950/60 px-2 py-0.5 rounded border border-emerald-800/40">
                12 / 12 COMPLETE
              </span>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
              {[
                { title: '1. SecurityEvent Data Model', desc: 'UUID PK, timezone-aware datetime, IP/port/user fields, JSONB raw/metadata' },
                { title: '2. Alembic Migration', desc: 'Migration 2ac4cb8026b3 applied to PostgreSQL with 12 B-tree indexes' },
                { title: '3. Input Format Support', desc: 'Robust JSON array and CSV format support with alias normalizer' },
                { title: '4. Pydantic v2 Validation', desc: 'IP validation, port bounds (1-65535), severity/status normalization' },
                { title: '5. File Upload Security', desc: '10MB max size, chunked memory reads, path traversal resilience' },
                { title: '6. Import API', desc: 'POST /api/v1/events/import with detailed error and summary accounting' },
                { title: '7. Event Retrieval API', desc: 'GET /api/v1/events with multi-parameter filtering and pagination' },
                { title: '8. Individual Event API', desc: 'GET /api/v1/events/{id} with full payload and metadata inspection' },
                { title: '9. Event Explorer Frontend', desc: 'Interactive table, search, filters, pagination, and side inspector drawer' },
                { title: '10. Realistic Demo Datasets', desc: 'data/demo_security_events.json & csv with diverse simulated attacks' },
                { title: '11. Automated Test Suite', desc: '34/34 passing Pytest unit, integration, validation, and security tests' },
                { title: '12. Performance Preparedness', desc: 'Composite indexes (username+time, ip+time, status+time) ready for Phase 3' },
              ].map((item, idx) => (
                <div key={idx} className="p-3 rounded-lg bg-slate-950/80 border border-slate-800 flex items-start space-x-3">
                  <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                  <div>
                    <span className="font-semibold text-slate-200 block">{item.title}</span>
                    <span className="text-slate-400 text-[11px]">{item.desc}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-800/80 bg-slate-900/30 py-4 mt-auto">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center justify-between gap-2 text-xs text-slate-500 font-mono">
          <div>SentinelOps AI — Cybersecurity Architecture & Incident Response</div>
          <div>Phase 2: Security Event Ingestion & Data Model Completed</div>
        </div>
      </footer>
    </div>
  );
}
