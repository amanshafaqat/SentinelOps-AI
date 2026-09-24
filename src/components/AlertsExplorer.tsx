import React, { useState, useEffect, useCallback } from 'react';
import {
  ShieldAlert,
  AlertTriangle,
  Flame,
  Search,
  RefreshCw,
  Filter,
  Play,
  Layers,
  Clock,
  User,
  Globe,
  Server,
  Eye,
  CheckCircle2,
  ChevronLeft,
  ChevronRight,
  SlidersHorizontal,
} from 'lucide-react';
import { AlertDetailsModal, AlertDetail } from './AlertDetailsModal';
import { DetectionRunModal } from './DetectionRunModal';

export interface AlertSummaryItem {
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
}

export interface AlertStats {
  total_alerts: number;
  by_severity: Record<string, number>;
  by_status: Record<string, number>;
  by_rule: Record<string, number>;
}

export const AlertsExplorer: React.FC = () => {
  const [alerts, setAlerts] = useState<AlertSummaryItem[]>([]);
  const [totalAlerts, setTotalAlerts] = useState(0);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);
  const [totalPages, setTotalPages] = useState(1);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Stats
  const [stats, setStats] = useState<AlertStats | null>(null);

  // Filters
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>('');
  const [statusFilter, setStatusFilter] = useState<string>('');
  const [ruleFilter, setRuleFilter] = useState<string>('');

  // Modals
  const [selectedAlert, setSelectedAlert] = useState<AlertDetail | null>(null);
  const [isDetailModalOpen, setIsDetailModalOpen] = useState(false);
  const [isRunModalOpen, setIsRunModalOpen] = useState(false);

  // Fetch alert statistics
  const fetchStats = async () => {
    try {
      const resp = await fetch('/api/v1/alerts/stats');
      if (resp.ok) {
        const data: AlertStats = await resp.json();
        setStats(data);
      }
    } catch {
      // Non-blocking for stats
    }
  };

  // Fetch paginated alerts
  const fetchAlerts = useCallback(async () => {
    setIsLoading(true);
    setError(null);

    const queryParams = new URLSearchParams({
      page: page.toString(),
      page_size: pageSize.toString(),
    });

    if (searchTerm.trim()) queryParams.append('search', searchTerm.trim());
    if (severityFilter) queryParams.append('severity', severityFilter);
    if (statusFilter) queryParams.append('status', statusFilter);
    if (ruleFilter) queryParams.append('rule_id', ruleFilter);

    try {
      const resp = await fetch(`/api/v1/alerts?${queryParams.toString()}`);
      if (!resp.ok) {
        throw new Error(`Failed to fetch alerts (HTTP ${resp.status})`);
      }
      const data = await resp.json();
      setAlerts(data.alerts || []);
      setTotalAlerts(data.total || 0);
      setTotalPages(data.total_pages || 1);
    } catch (err: any) {
      setError(err.message || 'Error communicating with Alerts API');
    } finally {
      setIsLoading(false);
    }
  }, [page, pageSize, searchTerm, severityFilter, statusFilter, ruleFilter]);

  useEffect(() => {
    fetchAlerts();
    fetchStats();
  }, [fetchAlerts]);

  // Open full detail modal with evidence
  const handleOpenAlert = async (alertId: string) => {
    try {
      const resp = await fetch(`/api/v1/alerts/${alertId}`);
      if (!resp.ok) throw new Error('Failed to load alert details');
      const data: AlertDetail = await resp.json();
      setSelectedAlert(data);
      setIsDetailModalOpen(true);
    } catch (err: any) {
      alert(`Error loading alert: ${err.message}`);
    }
  };

  // Update alert status
  const handleStatusUpdate = async (alertId: string, newStatus: string) => {
    try {
      const resp = await fetch(`/api/v1/alerts/${alertId}/status`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: newStatus }),
      });
      if (!resp.ok) throw new Error('Status update failed');
      const updated = await resp.json();

      // Update local state
      setAlerts((prev) =>
        prev.map((a) => (a.id === alertId ? { ...a, status: updated.status } : a))
      );
      if (selectedAlert && selectedAlert.id === alertId) {
        setSelectedAlert((prev) => (prev ? { ...prev, status: updated.status } : null));
      }
      fetchStats();
    } catch (err: any) {
      alert(`Failed to update status: ${err.message}`);
    }
  };

  const getSeverityBadge = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical':
        return (
          <span className="px-2 py-0.5 text-[11px] font-bold rounded bg-rose-950/80 text-rose-300 border border-rose-800/60 inline-flex items-center gap-1 shadow-sm">
            <span className="h-1.5 w-1.5 rounded-full bg-rose-500 animate-pulse" />
            CRITICAL
          </span>
        );
      case 'high':
        return (
          <span className="px-2 py-0.5 text-[11px] font-semibold rounded bg-amber-950/80 text-amber-300 border border-amber-800/60 inline-flex items-center gap-1">
            <span className="h-1.5 w-1.5 rounded-full bg-amber-500" />
            HIGH
          </span>
        );
      case 'medium':
        return (
          <span className="px-2 py-0.5 text-[11px] font-semibold rounded bg-yellow-950/80 text-yellow-300 border border-yellow-800/60 inline-flex items-center gap-1">
            <span className="h-1.5 w-1.5 rounded-full bg-yellow-500" />
            MEDIUM
          </span>
        );
      default:
        return (
          <span className="px-2 py-0.5 text-[11px] font-semibold rounded bg-slate-800 text-slate-300 border border-slate-700 inline-flex items-center gap-1">
            <span className="h-1.5 w-1.5 rounded-full bg-slate-400" />
            LOW
          </span>
        );
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'new':
        return 'bg-blue-950/60 text-blue-300 border-blue-800/50';
      case 'in_review':
        return 'bg-amber-950/60 text-amber-300 border-amber-800/50';
      case 'escalated':
        return 'bg-purple-950/60 text-purple-300 border-purple-800/50';
      case 'dismissed':
        return 'bg-slate-800 text-slate-400 border-slate-700';
      default:
        return 'bg-slate-800 text-slate-300 border-slate-700';
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Banner & Metric Cards */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 flex items-center justify-between">
          <div>
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider block">
              Total Alerts
            </span>
            <span className="text-2xl font-extrabold font-mono text-slate-100">
              {stats ? stats.total_alerts : totalAlerts}
            </span>
          </div>
          <div className="p-2.5 bg-rose-500/10 border border-rose-500/20 rounded-lg text-rose-400">
            <ShieldAlert className="h-5 w-5" />
          </div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/90 border border-rose-900/30 flex items-center justify-between">
          <div>
            <span className="text-xs font-semibold text-rose-300/80 uppercase tracking-wider block">
              Critical
            </span>
            <span className="text-2xl font-extrabold font-mono text-rose-400">
              {stats?.by_severity?.critical || 0}
            </span>
          </div>
          <div className="p-2.5 bg-rose-500/10 border border-rose-500/20 rounded-lg text-rose-400">
            <Flame className="h-5 w-5" />
          </div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/90 border border-amber-900/30 flex items-center justify-between">
          <div>
            <span className="text-xs font-semibold text-amber-300/80 uppercase tracking-wider block">
              High
            </span>
            <span className="text-2xl font-extrabold font-mono text-amber-400">
              {stats?.by_severity?.high || 0}
            </span>
          </div>
          <div className="p-2.5 bg-amber-500/10 border border-amber-500/20 rounded-lg text-amber-400">
            <AlertTriangle className="h-5 w-5" />
          </div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 flex items-center justify-between">
          <div>
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider block">
              Medium / Low
            </span>
            <span className="text-2xl font-extrabold font-mono text-slate-200">
              {(stats?.by_severity?.medium || 0) + (stats?.by_severity?.low || 0)}
            </span>
          </div>
          <div className="p-2.5 bg-yellow-500/10 border border-yellow-500/20 rounded-lg text-yellow-400">
            <Layers className="h-5 w-5" />
          </div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 flex items-center justify-between col-span-2 md:col-span-1">
          <div>
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider block">
              Active Rules
            </span>
            <span className="text-2xl font-extrabold font-mono text-emerald-400">
              5
            </span>
          </div>
          <div className="p-2.5 bg-emerald-500/10 border border-emerald-500/20 rounded-lg text-emerald-400">
            <CheckCircle2 className="h-5 w-5" />
          </div>
        </div>
      </div>

      {/* Action Header & Filter Controls */}
      <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <h2 className="text-lg font-bold text-slate-100 flex items-center gap-2">
              <ShieldAlert className="h-5 w-5 text-rose-500" />
              Security Detection Alerts
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Deterministic alerts generated from normalized security events with evidence traceability.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => {
                fetchAlerts();
                fetchStats();
              }}
              disabled={isLoading}
              className="p-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg text-xs font-medium border border-slate-700 flex items-center gap-1.5 transition-colors"
              title="Refresh alerts"
            >
              <RefreshCw className={`h-4 w-4 ${isLoading ? 'animate-spin' : ''}`} />
              <span className="hidden sm:inline">Refresh</span>
            </button>

            <button
              onClick={() => setIsRunModalOpen(true)}
              className="px-3.5 py-2 bg-rose-600 hover:bg-rose-500 text-white rounded-lg text-xs font-bold shadow-lg shadow-rose-950/50 flex items-center gap-2 transition-all cursor-pointer"
            >
              <Play className="h-4 w-4 fill-current" />
              Run Detection Engine
            </button>
          </div>
        </div>

        {/* Search & Filter Bar */}
        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-5 gap-2.5 pt-2 border-t border-slate-800/80">
          {/* Search input */}
          <div className="relative md:col-span-2">
            <Search className="h-4 w-4 absolute left-3 top-2.5 text-slate-500" />
            <input
              type="text"
              placeholder="Search alert title, host, description..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full bg-slate-950/60 border border-slate-800 rounded-lg pl-9 pr-3 py-2 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-rose-500/60 transition-colors"
            />
          </div>

          {/* Severity selector */}
          <div>
            <select
              value={severityFilter}
              onChange={(e) => {
                setSeverityFilter(e.target.value);
                setPage(1);
              }}
              className="w-full bg-slate-950/60 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-rose-500/60"
            >
              <option value="">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          </div>

          {/* Status selector */}
          <div>
            <select
              value={statusFilter}
              onChange={(e) => {
                setStatusFilter(e.target.value);
                setPage(1);
              }}
              className="w-full bg-slate-950/60 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-rose-500/60"
            >
              <option value="">All Statuses</option>
              <option value="new">New</option>
              <option value="in_review">In Review</option>
              <option value="escalated">Escalated</option>
              <option value="dismissed">Dismissed</option>
            </select>
          </div>

          {/* Rule selector */}
          <div>
            <select
              value={ruleFilter}
              onChange={(e) => {
                setRuleFilter(e.target.value);
                setPage(1);
              }}
              className="w-full bg-slate-950/60 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-rose-500/60"
            >
              <option value="">All Rules (001-005)</option>
              <option value="RULE-001">RULE-001 (Brute Force)</option>
              <option value="RULE-002">RULE-002 (Login After Failures)</option>
              <option value="RULE-003">RULE-003 (Privilege Change)</option>
              <option value="RULE-004">RULE-004 (Auth Pattern)</option>
              <option value="RULE-005">RULE-005 (Indicator Match)</option>
            </select>
          </div>
        </div>
      </div>

      {/* Error state */}
      {error && (
        <div className="p-4 bg-rose-950/40 border border-rose-800/80 rounded-xl text-rose-300 text-xs flex items-center gap-3">
          <AlertTriangle className="h-5 w-5 shrink-0 text-rose-400" />
          <div className="flex-1">
            <span className="font-bold">Error loading alerts:</span> {error}
          </div>
          <button
            onClick={fetchAlerts}
            className="px-2.5 py-1 bg-rose-900/60 hover:bg-rose-900 border border-rose-700/60 rounded text-xs font-semibold"
          >
            Retry
          </button>
        </div>
      )}

      {/* Alerts Table */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl overflow-hidden shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-slate-800 bg-slate-950/80 text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
                <th className="py-3 px-4">Severity</th>
                <th className="py-3 px-4">Alert Title & Rule</th>
                <th className="py-3 px-4">Affected Entity</th>
                <th className="py-3 px-4">Detected At</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4">Evidence</th>
                <th className="py-3 px-4 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-xs font-sans">
              {isLoading ? (
                <tr>
                  <td colSpan={7} className="py-12 text-center text-slate-500">
                    <RefreshCw className="h-6 w-6 animate-spin mx-auto mb-2 text-rose-500" />
                    Loading alerts queue...
                  </td>
                </tr>
              ) : alerts.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-12 text-center text-slate-500">
                    <ShieldAlert className="h-8 w-8 mx-auto mb-2 text-slate-600" />
                    <p className="font-semibold text-slate-400">No security alerts found</p>
                    <p className="text-xs text-slate-500 mt-1 max-w-md mx-auto">
                      Execute the detection engine above to scan ingested events against
                      deterministic detection rules.
                    </p>
                    <button
                      onClick={() => setIsRunModalOpen(true)}
                      className="mt-4 px-3 py-1.5 bg-rose-600/80 hover:bg-rose-600 text-white rounded text-xs font-semibold inline-flex items-center gap-1.5"
                    >
                      <Play className="h-3.5 w-3.5 fill-current" />
                      Run Detection Engine
                    </button>
                  </td>
                </tr>
              ) : (
                alerts.map((alert) => (
                  <tr
                    key={alert.id}
                    onClick={() => handleOpenAlert(alert.id)}
                    className="hover:bg-slate-800/40 cursor-pointer transition-colors group"
                  >
                    <td className="py-3 px-4 whitespace-nowrap">
                      {getSeverityBadge(alert.severity)}
                    </td>

                    <td className="py-3 px-4 max-w-sm">
                      <div className="font-semibold text-slate-200 group-hover:text-rose-400 transition-colors truncate">
                        {alert.title}
                      </div>
                      <div className="text-[11px] text-slate-400 font-mono mt-0.5 flex items-center gap-1.5">
                        <span className="font-bold text-slate-300">{alert.rule_id}</span>
                        <span>•</span>
                        <span className="truncate">{alert.rule_name}</span>
                      </div>
                    </td>

                    <td className="py-3 px-4">
                      <div className="space-y-0.5 text-xs font-mono">
                        {alert.affected_user && (
                          <div className="flex items-center gap-1 text-slate-300 truncate max-w-[160px]">
                            <User className="h-3 w-3 text-sky-400 shrink-0" />
                            <span>{alert.affected_user}</span>
                          </div>
                        )}
                        {alert.affected_ip && (
                          <div className="flex items-center gap-1 text-slate-400 truncate max-w-[160px]">
                            <Globe className="h-3 w-3 text-amber-400 shrink-0" />
                            <span>{alert.affected_ip}</span>
                          </div>
                        )}
                        {alert.affected_hostname && !alert.affected_user && !alert.affected_ip && (
                          <div className="flex items-center gap-1 text-slate-400 truncate max-w-[160px]">
                            <Server className="h-3 w-3 text-purple-400 shrink-0" />
                            <span>{alert.affected_hostname}</span>
                          </div>
                        )}
                      </div>
                    </td>

                    <td className="py-3 px-4 whitespace-nowrap text-slate-400 font-mono text-[11px]">
                      {new Date(alert.detected_at).toLocaleString()}
                    </td>

                    <td className="py-3 px-4 whitespace-nowrap">
                      <span
                        className={`px-2 py-0.5 text-[11px] font-mono rounded border uppercase font-medium ${getStatusBadge(
                          alert.status
                        )}`}
                      >
                        {alert.status.replace(/_/g, ' ')}
                      </span>
                    </td>

                    <td className="py-3 px-4 whitespace-nowrap">
                      <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-mono text-[11px] border border-slate-700 flex items-center gap-1 w-fit">
                        <Layers className="h-3 w-3 text-rose-400" />
                        {alert.evidence_count} event{alert.evidence_count === 1 ? '' : 's'}
                      </span>
                    </td>

                    <td className="py-3 px-4 text-right whitespace-nowrap">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          handleOpenAlert(alert.id);
                        }}
                        className="p-1.5 text-slate-400 hover:text-slate-200 hover:bg-slate-800 rounded transition-colors"
                        title="View alert details & evidence"
                      >
                        <Eye className="h-4 w-4" />
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination Footer */}
        <div className="p-4 border-t border-slate-800 bg-slate-950/80 flex flex-col sm:flex-row items-center justify-between gap-3 text-xs text-slate-400">
          <div>
            Showing <strong className="text-slate-200">{alerts.length}</strong> of{' '}
            <strong className="text-slate-200">{totalAlerts}</strong> alerts
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => setPage((p) => Math.max(1, p - 1))}
              disabled={page <= 1}
              className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 disabled:opacity-40 rounded text-slate-200 flex items-center gap-1 transition-colors"
            >
              <ChevronLeft className="h-4 w-4" />
              Prev
            </button>

            <span className="font-mono px-2">
              Page {page} of {totalPages}
            </span>

            <button
              onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
              disabled={page >= totalPages}
              className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 disabled:opacity-40 rounded text-slate-200 flex items-center gap-1 transition-colors"
            >
              Next
              <ChevronRight className="h-4 w-4" />
            </button>
          </div>
        </div>
      </div>

      {/* Modals */}
      <AlertDetailsModal
        alert={selectedAlert}
        isOpen={isDetailModalOpen}
        onClose={() => setIsDetailModalOpen(false)}
        onStatusUpdate={handleStatusUpdate}
      />

      <DetectionRunModal
        isOpen={isRunModalOpen}
        onClose={() => setIsRunModalOpen(false)}
        onRunSuccess={() => {
          fetchAlerts();
          fetchStats();
        }}
      />
    </div>
  );
};
