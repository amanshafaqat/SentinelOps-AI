import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  Activity,
  RefreshCw,
  Zap,
  ListFilter,
  AlertTriangle,
  Shield,
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

export default function App() {
  const [health, setHealth] = useState<HealthData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [lastCheck, setLastCheck] = useState<string>('');
  const [latency, setLatency] = useState<number | null>(null);
  const [activeTab, setActiveTab] = useState<'overview' | 'incidents' | 'alerts' | 'events' | 'rules'>('overview');

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
        throw new Error('Unable to verify backend health status.');
      }

      const data: HealthData = await res.json();
      setHealth(data);
      setLastCheck(new Date().toLocaleTimeString());
    } catch {
      setError('Unable to reach backend security services.');
      setHealth({
        status: 'degraded',
        service: 'SentinelOps AI',
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
                  Operational
                </span>
              </div>
              <p className="text-xs text-slate-400 hidden sm:block">
                AI-Assisted SOC &amp; Incident Response Copilot
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
              className="p-2 rounded-md bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white transition border border-slate-700 disabled:opacity-50 cursor-pointer"
              title="Refresh Service Status"
            >
              <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin text-cyan-400' : ''}`} />
            </button>
          </div>
        </div>
      </header>

      {/* Main Container */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-6">
        {/* Banner: Project Positioning */}
        <div className="relative overflow-hidden rounded-xl border border-cyan-500/20 bg-gradient-to-r from-cyan-950/30 via-slate-900/60 to-slate-900/40 p-5 sm:p-6 shadow-xl">
          <div className="absolute right-0 top-0 translate-x-8 -translate-y-8 w-64 h-64 bg-cyan-500/5 rounded-full blur-3xl pointer-events-none" />
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div className="space-y-1.5">
              <div className="inline-flex items-center space-x-2 text-xs font-mono uppercase tracking-widest text-cyan-400">
                <Shield className="w-3.5 h-3.5" />
                <span>Security Operations Center</span>
              </div>
              <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-white">
                AI-Assisted SOC &amp; Incident Response Copilot
              </h1>
              <p className="text-xs sm:text-sm text-slate-300 max-w-2xl leading-relaxed">
                SentinelOps AI combines deterministic security detection, explainable incident correlation,
                evidence-grounded AI investigation, and structured analyst case management.
              </p>
            </div>
            <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-3">
              <div className="px-4 py-2.5 rounded-lg bg-slate-900/80 border border-slate-800 text-center font-mono">
                <span className="block text-[10px] text-slate-500 uppercase tracking-wider">Detection &amp; AI</span>
                <span className="text-xs font-semibold text-emerald-400">Deterministic + Evidence Grounded</span>
              </div>
              <div className="px-4 py-2.5 rounded-lg bg-slate-900/80 border border-slate-800 text-center font-mono">
                <span className="block text-[10px] text-slate-500 uppercase tracking-wider">Traceability Chain</span>
                <span className="text-xs font-semibold text-cyan-400">Incident &rarr; Alert &rarr; Evidence &rarr; Event</span>
              </div>
            </div>
          </div>
        </div>

        {/* Tab Navigation */}
        <div className="border-b border-slate-800 flex space-x-6 text-sm font-medium overflow-x-auto">
          {[
            { id: 'overview', label: 'SOC Command Center', icon: Activity },
            { id: 'incidents', label: 'Incidents & Cases', icon: ShieldAlert },
            { id: 'alerts', label: 'Detection Alerts', icon: AlertTriangle },
            { id: 'events', label: 'Telemetry Explorer', icon: ListFilter },
            { id: 'rules', label: 'Detection Rules (001–005)', icon: Zap },
          ].map((tab) => {
            const Icon = tab.icon;
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id as any)}
                className={`pb-3 pt-1 flex items-center space-x-2 border-b-2 transition whitespace-nowrap text-xs font-mono cursor-pointer ${
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
              <div className="flex items-center space-x-3 mb-2">
                <div className="p-2 rounded bg-amber-500/10 border border-amber-500/30 text-amber-400">
                  <Zap className="w-5 h-5" />
                </div>
                <div>
                  <h2 className="text-base font-bold text-slate-100">Deterministic Detection Rules</h2>
                  <p className="text-xs text-slate-400">
                    Pre-compiled detection logic running deterministically against ingested security telemetry.
                  </p>
                </div>
              </div>
              <p className="text-xs text-slate-400 mt-2">
                Alerts from these rules serve as the input dataset for the Correlation Engine.
              </p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {/* RULE-001 */}
              <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 hover:border-slate-700 transition">
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center space-x-2">
                    <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-950 text-amber-400 border border-amber-800">
                      RULE-001
                    </span>
                    <span className="text-xs font-bold text-slate-200">SSH / Auth Brute Force</span>
                  </div>
                  <span className="text-[10px] text-amber-400 font-semibold uppercase">High Severity</span>
                </div>
                <p className="text-xs text-slate-400 mb-3">
                  Detects &ge;5 failed login attempts from a single source IP within a sliding 10-minute window.
                </p>
                <div className="space-y-1 text-[11px] text-slate-400 bg-slate-950/80 p-2.5 rounded border border-slate-800/80">
                  <div className="flex justify-between">
                    <span>Threshold:</span> <strong className="text-slate-200">5 events / 10m</strong>
                  </div>
                  <div className="flex justify-between">
                    <span>Grouping Entity:</span> <strong className="text-cyan-400">source_ip</strong>
                  </div>
                  <div className="flex justify-between">
                    <span>MITRE ATT&CK:</span> <strong className="text-slate-300">T1110.001 (Password Guessing)</strong>
                  </div>
                </div>
              </div>

              {/* RULE-002 */}
              <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 hover:border-slate-700 transition">
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center space-x-2">
                    <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-red-950 text-red-400 border border-red-800">
                      RULE-002
                    </span>
                    <span className="text-xs font-bold text-slate-200">Login Success After Failures</span>
                  </div>
                  <span className="text-[10px] text-red-400 font-semibold uppercase">Critical Severity</span>
                </div>
                <p className="text-xs text-slate-400 mb-3">
                  Flags a successful authentication event following 3 or more failed attempts for the same username within 15 minutes.
                </p>
                <div className="space-y-1 text-[11px] text-slate-400 bg-slate-950/80 p-2.5 rounded border border-slate-800/80">
                  <div className="flex justify-between">
                    <span>Threshold:</span> <strong className="text-slate-200">&ge;3 failures + 1 success</strong>
                  </div>
                  <div className="flex justify-between">
                    <span>Grouping Entity:</span> <strong className="text-cyan-400">username</strong>
                  </div>
                  <div className="flex justify-between">
                    <span>MITRE ATT&CK:</span> <strong className="text-slate-300">T1110.003 (Password Spraying)</strong>
                  </div>
                </div>
              </div>

              {/* RULE-003 */}
              <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 hover:border-slate-700 transition">
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center space-x-2">
                    <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-purple-950 text-purple-400 border border-purple-800">
                      RULE-003
                    </span>
                    <span className="text-xs font-bold text-slate-200">Suspicious Sudo / Privilege Escalation</span>
                  </div>
                  <span className="text-[10px] text-purple-400 font-semibold uppercase">High Severity</span>
                </div>
                <p className="text-xs text-slate-400 mb-3">
                  Identifies unauthorized or rapid sudo commands, privilege group mutations, and root account impersonation.
                </p>
                <div className="space-y-1 text-[11px] text-slate-400 bg-slate-950/80 p-2.5 rounded border border-slate-800/80">
                  <div className="flex justify-between">
                    <span>Pattern:</span> <strong className="text-slate-200">action: sudo / priv_escalation</strong>
                  </div>
                  <div className="flex justify-between">
                    <span>Grouping Entity:</span> <strong className="text-cyan-400">username, hostname</strong>
                  </div>
                  <div className="flex justify-between">
                    <span>MITRE ATT&CK:</span> <strong className="text-slate-300">T1548.003 (Sudo and Sudo Caching)</strong>
                  </div>
                </div>
              </div>

              {/* RULE-004 */}
              <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 hover:border-slate-700 transition">
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center space-x-2">
                    <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-blue-950 text-blue-400 border border-blue-800">
                      RULE-004
                    </span>
                    <span className="text-xs font-bold text-slate-200">Suspicious Service Installation</span>
                  </div>
                  <span className="text-[10px] text-blue-400 font-semibold uppercase">Medium Severity</span>
                </div>
                <p className="text-xs text-slate-400 mb-3">
                  Captures systemd, init, or Windows service installations from unexpected user contexts or staging paths.
                </p>
                <div className="space-y-1 text-[11px] text-slate-400 bg-slate-950/80 p-2.5 rounded border border-slate-800/80">
                  <div className="flex justify-between">
                    <span>Pattern:</span> <strong className="text-slate-200">service_create, daemon_reload</strong>
                  </div>
                  <div className="flex justify-between">
                    <span>Grouping Entity:</span> <strong className="text-cyan-400">hostname</strong>
                  </div>
                  <div className="flex justify-between">
                    <span>MITRE ATT&CK:</span> <strong className="text-slate-300">T1543.002 (Systemd Service Persistence)</strong>
                  </div>
                </div>
              </div>

              {/* RULE-005 */}
              <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 hover:border-slate-700 transition md:col-span-2">
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center space-x-2">
                    <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-950 text-rose-400 border border-rose-800">
                      RULE-005
                    </span>
                    <span className="text-xs font-bold text-slate-200">Indicator Matching &amp; C2 Beaconing</span>
                  </div>
                  <span className="text-[10px] text-rose-400 font-semibold uppercase">Critical Severity</span>
                </div>
                <p className="text-xs text-slate-400 mb-3">
                  Matches outbound connections against known malicious IP ranges, suspicious domain patterns, and repetitive beaconing intervals.
                </p>
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 text-[11px] text-slate-400 bg-slate-950/80 p-2.5 rounded border border-slate-800/80">
                  <div>
                    <span>Pattern:</span> <strong className="text-slate-200 block">Threat Intel Feed + Regularity</strong>
                  </div>
                  <div>
                    <span>Grouping Entity:</span> <strong className="text-cyan-400 block">destination_ip</strong>
                  </div>
                  <div>
                    <span>MITRE ATT&CK:</span> <strong className="text-slate-300 block">T1071.001 (Application Layer Protocol)</strong>
                  </div>
                </div>
              </div>
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
        SentinelOps AI &bull; AI-Assisted SOC &amp; Incident Response Copilot
      </footer>
    </div>
  );
}
