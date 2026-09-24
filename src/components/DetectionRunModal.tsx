import React, { useState } from 'react';
import {
  X,
  Play,
  CheckCircle2,
  AlertTriangle,
  Clock,
  Layers,
  ShieldCheck,
  RefreshCw,
  Zap,
} from 'lucide-react';

interface DetectionRunModalProps {
  isOpen: boolean;
  onClose: () => void;
  onRunSuccess: () => void;
}

export interface DetectionRunResult {
  events_evaluated: number;
  rules_executed: number;
  alerts_generated: number;
  alerts_deduplicated: number;
  execution_duration_ms: number;
  generated_alert_ids: string[];
  rule_breakdown: Record<string, number>;
  executed_at: string;
}

export const DetectionRunModal: React.FC<DetectionRunModalProps> = ({
  isOpen,
  onClose,
  onRunSuccess,
}) => {
  const [scope, setScope] = useState<'all' | '60m' | '24h'>('all');
  const [limit, setLimit] = useState<number>(1000);
  const [isLoading, setIsLoading] = useState(false);
  const [result, setResult] = useState<DetectionRunResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleExecute = async () => {
    setIsLoading(true);
    setError(null);
    setResult(null);

    const payload: { limit: number; time_window_minutes?: number } = { limit };
    if (scope === '60m') {
      payload.time_window_minutes = 60;
    } else if (scope === '24h') {
      payload.time_window_minutes = 1440;
    }

    try {
      const resp = await fetch('/api/v1/detection/run', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });

      if (!resp.ok) {
        const errJson = await resp.json().catch(() => ({}));
        throw new Error(errJson.detail || `Server returned HTTP ${resp.status}`);
      }

      const data: DetectionRunResult = await resp.json();
      setResult(data);
      onRunSuccess();
    } catch (err: any) {
      setError(err.message || 'Failed to execute detection engine');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-fade-in">
      <div className="relative w-full max-w-xl bg-slate-900 border border-slate-700 rounded-xl shadow-2xl flex flex-col overflow-hidden">
        {/* Header */}
        <div className="p-5 border-b border-slate-800 bg-slate-950/70 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-rose-500/10 border border-rose-500/20 rounded-lg text-rose-400">
              <Zap className="h-5 w-5" />
            </div>
            <div>
              <h3 className="text-base font-bold text-slate-100">
                Execute Detection Engine
              </h3>
              <p className="text-xs text-slate-400">
                Evaluate deterministic rules against ingested SecurityEvent telemetry
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 text-slate-400 hover:text-slate-200 hover:bg-slate-800 rounded-lg transition-colors"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Content */}
        <div className="p-6 space-y-5">
          {!result ? (
            <>
              <div className="space-y-3">
                <label className="text-xs font-semibold text-slate-300 block">
                  Evaluation Scope
                </label>
                <div className="grid grid-cols-3 gap-2">
                  <button
                    type="button"
                    onClick={() => setScope('all')}
                    className={`p-3 rounded-lg border text-left transition-all ${
                      scope === 'all'
                        ? 'bg-rose-950/40 border-rose-600/60 text-rose-300'
                        : 'bg-slate-950/40 border-slate-800 text-slate-400 hover:border-slate-700'
                    }`}
                  >
                    <span className="text-xs font-bold block">All Events</span>
                    <span className="text-[11px] text-slate-400">Full database scan</span>
                  </button>

                  <button
                    type="button"
                    onClick={() => setScope('60m')}
                    className={`p-3 rounded-lg border text-left transition-all ${
                      scope === '60m'
                        ? 'bg-rose-950/40 border-rose-600/60 text-rose-300'
                        : 'bg-slate-950/40 border-slate-800 text-slate-400 hover:border-slate-700'
                    }`}
                  >
                    <span className="text-xs font-bold block">Last 60 Minutes</span>
                    <span className="text-[11px] text-slate-400">Recent telemetry</span>
                  </button>

                  <button
                    type="button"
                    onClick={() => setScope('24h')}
                    className={`p-3 rounded-lg border text-left transition-all ${
                      scope === '24h'
                        ? 'bg-rose-950/40 border-rose-600/60 text-rose-300'
                        : 'bg-slate-950/40 border-slate-800 text-slate-400 hover:border-slate-700'
                    }`}
                  >
                    <span className="text-xs font-bold block">Last 24 Hours</span>
                    <span className="text-[11px] text-slate-400">Daily triage window</span>
                  </button>
                </div>
              </div>

              <div className="space-y-2">
                <div className="flex items-center justify-between text-xs">
                  <label className="font-semibold text-slate-300">Max Event Scan Batch</label>
                  <span className="text-slate-400 font-mono">{limit} events</span>
                </div>
                <input
                  type="range"
                  min={50}
                  max={5000}
                  step={50}
                  value={limit}
                  onChange={(e) => setLimit(Number(e.target.value))}
                  className="w-full accent-rose-500 cursor-pointer"
                />
              </div>

              <div className="p-3.5 rounded-lg bg-slate-950/60 border border-slate-800 text-xs text-slate-400 space-y-1">
                <div className="font-semibold text-slate-300 flex items-center gap-1.5">
                  <ShieldCheck className="h-4 w-4 text-emerald-400" />
                  Deterministic & Deduplicated:
                </div>
                <p>
                  Rules 001 through 005 will execute sequentially. Candidate alerts are verified
                  against existing database signatures. Duplicate alerts are automatically suppressed.
                </p>
              </div>

              {error && (
                <div className="p-3 bg-rose-950/60 border border-rose-800/80 rounded-lg text-rose-300 text-xs flex items-center gap-2">
                  <AlertTriangle className="h-4 w-4 shrink-0 text-rose-400" />
                  <span>{error}</span>
                </div>
              )}
            </>
          ) : (
            /* Execution Summary Output */
            <div className="space-y-4 animate-fade-in">
              <div className="p-3.5 bg-emerald-950/30 border border-emerald-800/50 rounded-lg flex items-center gap-3">
                <CheckCircle2 className="h-6 w-6 text-emerald-400 shrink-0" />
                <div>
                  <h4 className="text-sm font-bold text-emerald-200">
                    Detection Sweep Completed Successfully
                  </h4>
                  <p className="text-xs text-emerald-400/80">
                    Execution finished in {result.execution_duration_ms}ms
                  </p>
                </div>
              </div>

              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5 text-center">
                <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800">
                  <span className="text-[11px] text-slate-400 block">Events Evaluated</span>
                  <span className="text-lg font-bold font-mono text-slate-100">
                    {result.events_evaluated}
                  </span>
                </div>

                <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800">
                  <span className="text-[11px] text-slate-400 block">Rules Run</span>
                  <span className="text-lg font-bold font-mono text-slate-100">
                    {result.rules_executed}
                  </span>
                </div>

                <div className="p-3 rounded-lg bg-slate-950/60 border border-rose-900/30">
                  <span className="text-[11px] text-rose-300/80 block">New Alerts</span>
                  <span className="text-lg font-bold font-mono text-rose-400">
                    {result.alerts_generated}
                  </span>
                </div>

                <div className="p-3 rounded-lg bg-slate-950/60 border border-slate-800">
                  <span className="text-[11px] text-slate-400 block">Deduplicated</span>
                  <span className="text-lg font-bold font-mono text-slate-400">
                    {result.alerts_deduplicated}
                  </span>
                </div>
              </div>

              {result.rule_breakdown && Object.keys(result.rule_breakdown).length > 0 && (
                <div className="p-3.5 rounded-lg bg-slate-950/40 border border-slate-800 space-y-2">
                  <span className="text-xs font-semibold text-slate-300 block">
                    Detections Generated by Rule:
                  </span>
                  <div className="grid grid-cols-2 gap-2">
                    {Object.entries(result.rule_breakdown).map(([ruleId, count]) => (
                      <div
                        key={ruleId}
                        className="flex items-center justify-between p-2 rounded bg-slate-900 border border-slate-800/80 text-xs font-mono"
                      >
                        <span className="text-slate-400">{ruleId}</span>
                        <span className="font-bold text-slate-200">{count}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-slate-800 bg-slate-950/80 flex items-center justify-between">
          <button
            onClick={onClose}
            className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium rounded-lg transition-colors"
          >
            {result ? 'Done' : 'Cancel'}
          </button>

          {!result ? (
            <button
              onClick={handleExecute}
              disabled={isLoading}
              className="px-4 py-2 bg-rose-600 hover:bg-rose-500 disabled:opacity-50 text-white text-xs font-bold rounded-lg shadow-lg shadow-rose-950/40 flex items-center gap-2 transition-all"
            >
              {isLoading ? (
                <>
                  <RefreshCw className="h-4 w-4 animate-spin" />
                  Running Detections...
                </>
              ) : (
                <>
                  <Play className="h-4 w-4 fill-current" />
                  Run Detection Sweep
                </>
              )}
            </button>
          ) : (
            <button
              onClick={() => setResult(null)}
              className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold rounded-lg transition-colors"
            >
              Run Again
            </button>
          )}
        </div>
      </div>
    </div>
  );
};
