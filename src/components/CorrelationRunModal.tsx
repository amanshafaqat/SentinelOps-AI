import React, { useState } from 'react';
import {
  X,
  GitBranch,
  Play,
  CheckCircle2,
  Clock,
  Layers,
  AlertTriangle,
  RotateCcw,
  Zap,
} from 'lucide-react';

interface CorrelationRunModalProps {
  isOpen: boolean;
  onClose: () => void;
  onRunComplete: () => void;
}

interface CorrelationSummary {
  alerts_evaluated: number;
  alerts_correlated: number;
  incidents_created: number;
  incidents_updated: number;
  execution_duration_ms: number;
  created_incident_ids: string[];
  correlation_window_minutes: number;
  executed_at: string;
}

export const CorrelationRunModal: React.FC<CorrelationRunModalProps> = ({
  isOpen,
  onClose,
  onRunComplete,
}) => {
  const [timeWindow, setTimeWindow] = useState<number>(60);
  const [minSeverity, setMinSeverity] = useState<string>('all');
  const [forceRecorrelate, setForceRecorrelate] = useState<boolean>(false);
  const [isRunning, setIsRunning] = useState<boolean>(false);
  const [summary, setSummary] = useState<CorrelationSummary | null>(null);
  const [error, setError] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleExecute = async () => {
    setIsRunning(true);
    setError(null);
    setSummary(null);

    try {
      const payload: any = {
        time_window_minutes: Number(timeWindow),
        force_recorrelate: Boolean(forceRecorrelate),
      };
      if (minSeverity !== 'all') {
        payload.min_severity = minSeverity;
      }

      const res = await fetch('/api/v1/incidents/correlate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });

      if (!res.ok) {
        const errJson = await res.json().catch(() => ({}));
        throw new Error(errJson.error?.message || `Correlation failed with HTTP ${res.status}`);
      }

      const data: CorrelationSummary = await res.json();
      setSummary(data);
      onRunComplete();
    } catch (err: any) {
      setError(err.message);
    } finally {
      setIsRunning(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-fade-in">
      <div className="relative w-full max-w-xl bg-slate-900 border border-slate-800 rounded-lg shadow-2xl overflow-hidden text-slate-200">
        {/* Header */}
        <div className="flex items-center justify-between p-4 sm:p-5 border-b border-slate-800 bg-slate-950/50">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-cyan-950/60 border border-cyan-800/80 text-cyan-400">
              <GitBranch className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-base sm:text-lg font-bold text-slate-100">
                Execute Correlation Engine
              </h2>
              <p className="text-xs font-mono text-slate-400">
                Synthesize discrete detection alerts into correlated incidents
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Body */}
        <div className="p-5 space-y-4">
          {error && (
            <div className="p-3 bg-red-950/60 border border-red-800/80 rounded text-xs text-red-300 font-mono">
              {error}
            </div>
          )}

          {/* Configuration Form */}
          <div className="space-y-3.5 bg-slate-950/60 border border-slate-800/80 rounded-lg p-4 text-xs font-mono">
            <div>
              <label className="block text-slate-300 font-semibold mb-1">
                Correlation Time Window (Minutes)
              </label>
              <div className="flex items-center gap-3">
                <input
                  type="range"
                  min="5"
                  max="240"
                  step="5"
                  value={timeWindow}
                  onChange={(e) => setTimeWindow(Number(e.target.value))}
                  className="w-full accent-cyan-500 cursor-pointer"
                />
                <span className="w-16 px-2 py-1 bg-slate-900 border border-slate-700 rounded text-center text-cyan-400 font-bold">
                  {timeWindow}m
                </span>
              </div>
              <span className="text-[11px] text-slate-500 mt-1 block">
                Alerts sharing entities within this window will be evaluated for grouping.
              </span>
            </div>

            <div>
              <label className="block text-slate-300 font-semibold mb-1">
                Minimum Alert Severity
              </label>
              <select
                value={minSeverity}
                onChange={(e) => setMinSeverity(e.target.value)}
                className="w-full bg-slate-900 border border-slate-700 rounded px-2.5 py-1.5 text-slate-200 focus:outline-none focus:border-cyan-500"
              >
                <option value="all">All Severities (Low, Medium, High, Critical)</option>
                <option value="medium">Medium, High & Critical</option>
                <option value="high">High & Critical Only</option>
                <option value="critical">Critical Only</option>
              </select>
            </div>

            <div className="pt-2 border-t border-slate-800/80 flex items-center justify-between">
              <div>
                <label className="text-slate-300 font-semibold block">
                  Force Re-correlation
                </label>
                <span className="text-[11px] text-slate-500 block">
                  Re-evaluates all historical alerts and rebuilds incidents from scratch.
                </span>
              </div>
              <input
                type="checkbox"
                checked={forceRecorrelate}
                onChange={(e) => setForceRecorrelate(e.target.checked)}
                className="w-4 h-4 accent-cyan-500 rounded cursor-pointer"
              />
            </div>
          </div>

          {/* Execution Results Summary */}
          {summary && (
            <div className="p-4 bg-slate-950 border border-cyan-900/60 rounded-lg space-y-2.5 animate-fade-in text-xs font-mono">
              <div className="flex items-center gap-2 text-cyan-400 font-bold">
                <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                <span>Correlation Pass Complete ({summary.execution_duration_ms}ms)</span>
              </div>

              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 pt-1">
                <div className="bg-slate-900 p-2.5 rounded border border-slate-800">
                  <span className="text-[10px] text-slate-500 uppercase block">Alerts Evaluated</span>
                  <span className="text-base font-bold text-slate-100">{summary.alerts_evaluated}</span>
                </div>
                <div className="bg-slate-900 p-2.5 rounded border border-slate-800">
                  <span className="text-[10px] text-slate-500 uppercase block">Alerts Correlated</span>
                  <span className="text-base font-bold text-cyan-400">{summary.alerts_correlated}</span>
                </div>
                <div className="bg-slate-900 p-2.5 rounded border border-slate-800">
                  <span className="text-[10px] text-slate-500 uppercase block">Incidents Created</span>
                  <span className="text-base font-bold text-emerald-400">{summary.incidents_created}</span>
                </div>
                <div className="bg-slate-900 p-2.5 rounded border border-slate-800">
                  <span className="text-[10px] text-slate-500 uppercase block">Incidents Updated</span>
                  <span className="text-base font-bold text-amber-400">{summary.incidents_updated}</span>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-slate-800 bg-slate-950/80 flex items-center justify-between">
          <span className="text-[11px] font-mono text-slate-500">
            Explainable & Deterministic Correlation
          </span>
          <div className="flex items-center gap-2">
            <button
              onClick={onClose}
              className="px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-mono transition-colors"
            >
              Close
            </button>
            <button
              onClick={handleExecute}
              disabled={isRunning}
              className="px-4 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white text-xs font-mono font-medium transition-colors flex items-center gap-1.5"
            >
              {isRunning ? (
                <>
                  <div className="w-3.5 h-3.5 border-2 border-white border-t-transparent rounded-full animate-spin" />
                  Correlating Alerts...
                </>
              ) : (
                <>
                  <Play className="w-3.5 h-3.5 fill-current" />
                  Run Correlation
                </>
              )}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
