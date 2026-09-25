import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  AlertTriangle,
  Flame,
  CheckCircle2,
  Clock,
  Search,
  RefreshCw,
  GitBranch,
  ChevronLeft,
  ChevronRight,
  Filter,
  ArrowRight,
  User,
  Globe,
  Server,
  Layers,
  Sparkles,
  Info,
} from 'lucide-react';
import { IncidentDetailsModal } from './IncidentDetailsModal';
import { CorrelationRunModal } from './CorrelationRunModal';

export interface IncidentSummaryItem {
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
  created_at: string;
  updated_at: string;
}

interface IncidentsExplorerProps {
  onSelectAlert?: (alertId: string) => void;
}

export const IncidentsExplorer: React.FC<IncidentsExplorerProps> = ({ onSelectAlert }) => {
  const [incidents, setIncidents] = useState<IncidentSummaryItem[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Filters and pagination
  const [statusFilter, setStatusFilter] = useState<string>('all');
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [page, setPage] = useState<number>(1);
  const [pageSize] = useState<number>(15);
  const [totalPages, setTotalPages] = useState<number>(1);
  const [totalCount, setTotalCount] = useState<number>(0);

  // Modals
  const [selectedIncidentId, setSelectedIncidentId] = useState<string | null>(null);
  const [isCorrelationModalOpen, setIsCorrelationModalOpen] = useState<boolean>(false);
  const [isSeedingDemo, setIsSeedingDemo] = useState<boolean>(false);
  const [demoSeedMessage, setDemoSeedMessage] = useState<string | null>(null);

  useEffect(() => {
    fetchIncidents();
  }, [page, statusFilter, severityFilter]);

  const fetchIncidents = async () => {
    setLoading(true);
    setError(null);
    try {
      const params = new URLSearchParams();
      params.append('page', page.toString());
      params.append('page_size', pageSize.toString());

      if (statusFilter !== 'all') {
        params.append('status', statusFilter);
      }
      if (severityFilter !== 'all') {
        params.append('severity', severityFilter);
      }
      if (searchQuery.trim()) {
        params.append('search', searchQuery.trim());
      }

      const res = await fetch(`/api/v1/incidents?${params.toString()}`);
      if (!res.ok) throw new Error(`HTTP ${res.status}: Failed to fetch incidents`);

      const data = await res.json();
      setIncidents(data.incidents || []);
      setTotalCount(data.total || 0);
      setTotalPages(data.total_pages || 1);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setPage(1);
    fetchIncidents();
  };

  const handleSeedDemoScenarios = async () => {
    setIsSeedingDemo(true);
    setDemoSeedMessage(null);
    try {
      const res = await fetch('/api/v1/system/demo/seed', {
        method: 'POST',
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}: Failed to seed demo pipeline`);
      const data = await res.json();
      setDemoSeedMessage(
        `Provisioned ${data.events_created} events → ${data.alerts_generated} alerts → ${data.incidents_created} correlated incidents!`
      );
      setPage(1);
      fetchIncidents();
      setTimeout(() => setDemoSeedMessage(null), 5000);
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
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-red-950/80 text-red-400 border border-red-800 text-[11px] font-mono font-bold uppercase">
            <Flame className="w-3 h-3 text-red-400" /> CRITICAL
          </span>
        );
      case 'high':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-amber-950/80 text-amber-400 border border-amber-800 text-[11px] font-mono font-bold uppercase">
            <AlertTriangle className="w-3 h-3 text-amber-400" /> HIGH
          </span>
        );
      case 'medium':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-blue-950/80 text-blue-400 border border-blue-800 text-[11px] font-mono font-bold uppercase">
            <Info className="w-3 h-3 text-blue-400" /> MEDIUM
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700 text-[11px] font-mono font-bold uppercase">
            <CheckCircle2 className="w-3 h-3 text-slate-400" /> LOW
          </span>
        );
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status.toLowerCase()) {
      case 'new':
        return (
          <span className="px-2 py-0.5 rounded text-[11px] font-mono font-semibold bg-red-950/70 text-red-300 border border-red-800">
            NEW
          </span>
        );
      case 'investigating':
        return (
          <span className="px-2 py-0.5 rounded text-[11px] font-mono font-semibold bg-amber-950/70 text-amber-300 border border-amber-800">
            INVESTIGATING
          </span>
        );
      case 'resolved':
        return (
          <span className="px-2 py-0.5 rounded text-[11px] font-mono font-semibold bg-emerald-950/70 text-emerald-300 border border-emerald-800">
            RESOLVED
          </span>
        );
      case 'closed':
        return (
          <span className="px-2 py-0.5 rounded text-[11px] font-mono font-semibold bg-slate-800 text-slate-400 border border-slate-700">
            CLOSED
          </span>
        );
      default:
        return <span className="text-xs font-mono text-slate-400">{status}</span>;
    }
  };

  return (
    <div className="space-y-4">
      {/* Action Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-slate-900 border border-slate-800 rounded-lg p-3 sm:p-4">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-base sm:text-lg font-bold text-slate-100 flex items-center gap-2">
              <ShieldAlert className="w-5 h-5 text-red-400" />
              Correlated Security Incidents
            </h2>
            <span className="px-2 py-0.5 rounded-full bg-slate-800 text-cyan-400 text-xs font-mono font-bold">
              {totalCount} Total
            </span>
          </div>
          <p className="text-xs text-slate-400 font-mono mt-0.5">
            Phase 4: Deterministic Alert Correlation Engine & Forensic Investigation
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button
            onClick={handleSeedDemoScenarios}
            disabled={isSeedingDemo}
            className="px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-mono font-medium transition-colors flex items-center gap-1.5"
            title="Seed Scenarios 1-4 telemetry, detect and correlate"
          >
            {isSeedingDemo ? (
              <>
                <div className="w-3.5 h-3.5 border-2 border-cyan-400 border-t-transparent rounded-full animate-spin" />
                Seeding Scenarios...
              </>
            ) : (
              <>
                <Sparkles className="w-3.5 h-3.5 text-amber-400" />
                Seed Demo Scenarios
              </>
            )}
          </button>

          <button
            onClick={() => setIsCorrelationModalOpen(true)}
            className="px-3.5 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-mono font-medium transition-colors flex items-center gap-1.5 shadow-sm"
          >
            <GitBranch className="w-3.5 h-3.5" />
            Run Correlation Engine
          </button>

          <button
            onClick={fetchIncidents}
            disabled={loading}
            className="p-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-slate-200 border border-slate-700 transition-colors"
            title="Refresh incidents"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* Demo Seed Feedback */}
      {demoSeedMessage && (
        <div className="p-3 bg-emerald-950/80 border border-emerald-800 text-emerald-300 rounded-lg text-xs font-mono flex items-center gap-2 animate-fade-in">
          <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
          <span>{demoSeedMessage}</span>
        </div>
      )}

      {/* Search and Filters */}
      <div className="flex flex-col md:flex-row gap-3 bg-slate-900 border border-slate-800 rounded-lg p-3 text-xs font-mono">
        <form onSubmit={handleSearchSubmit} className="flex-1 flex items-center gap-2">
          <div className="relative flex-1">
            <Search className="absolute left-2.5 top-2.5 w-3.5 h-3.5 text-slate-500" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search incidents by title, description, or IOCs..."
              className="w-full bg-slate-950 border border-slate-800 rounded pl-8 pr-3 py-1.5 text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
            />
          </div>
          <button
            type="submit"
            className="px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-colors"
          >
            Search
          </button>
        </form>

        <div className="flex flex-wrap items-center gap-2">
          <div className="flex items-center gap-1.5">
            <Filter className="w-3.5 h-3.5 text-slate-500" />
            <span className="text-slate-400">Severity:</span>
            <select
              value={severityFilter}
              onChange={(e) => {
                setSeverityFilter(e.target.value);
                setPage(1);
              }}
              className="bg-slate-950 border border-slate-800 rounded px-2 py-1 text-slate-200 focus:outline-none focus:border-cyan-500"
            >
              <option value="all">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          </div>

          <div className="flex items-center gap-1.5">
            <span className="text-slate-400">Status:</span>
            <select
              value={statusFilter}
              onChange={(e) => {
                setStatusFilter(e.target.value);
                setPage(1);
              }}
              className="bg-slate-950 border border-slate-800 rounded px-2 py-1 text-slate-200 focus:outline-none focus:border-cyan-500"
            >
              <option value="all">All Statuses</option>
              <option value="new">New</option>
              <option value="investigating">Investigating</option>
              <option value="resolved">Resolved</option>
              <option value="closed">Closed</option>
            </select>
          </div>
        </div>
      </div>

      {/* Incidents Table / Queue */}
      <div className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden">
        {loading ? (
          <div className="py-20 text-center text-slate-400 flex flex-col items-center justify-center gap-3">
            <div className="w-8 h-8 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin" />
            <span className="text-xs font-mono">Loading correlated security incidents...</span>
          </div>
        ) : error ? (
          <div className="py-12 text-center text-red-400 text-xs font-mono">{error}</div>
        ) : incidents.length === 0 ? (
          <div className="py-16 text-center text-slate-500 font-mono text-xs space-y-3">
            <ShieldAlert className="w-8 h-8 mx-auto text-slate-600" />
            <p>No security incidents found matching current filters.</p>
            <button
              onClick={handleSeedDemoScenarios}
              className="px-3.5 py-1.5 rounded bg-cyan-600/80 hover:bg-cyan-600 text-white text-xs font-mono inline-flex items-center gap-1.5"
            >
              <Sparkles className="w-3.5 h-3.5 text-amber-300" />
              Seed Demo Incident Scenarios
            </button>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono border-collapse">
              <thead>
                <tr className="bg-slate-950/80 border-b border-slate-800 text-slate-400 uppercase tracking-wider text-[11px]">
                  <th className="py-3 px-4">Severity</th>
                  <th className="py-3 px-4">Incident Details</th>
                  <th className="py-3 px-4">Status</th>
                  <th className="py-3 px-4">Alerts</th>
                  <th className="py-3 px-4">Target Accounts / IPs</th>
                  <th className="py-3 px-4">Last Activity</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {incidents.map((incident) => (
                  <tr
                    key={incident.id}
                    className="hover:bg-slate-800/40 transition-colors cursor-pointer group"
                    onClick={() => setSelectedIncidentId(incident.id)}
                  >
                    <td className="py-3.5 px-4 whitespace-nowrap">
                      {getSeverityBadge(incident.severity)}
                    </td>
                    <td className="py-3.5 px-4 max-w-md">
                      <div className="font-semibold text-slate-200 group-hover:text-cyan-400 transition-colors text-sm line-clamp-1">
                        {incident.title}
                      </div>
                      <p className="text-[11px] text-slate-400 line-clamp-1 mt-0.5">
                        {incident.description}
                      </p>
                      {incident.correlation_reasons.length > 0 && (
                        <div className="flex items-center gap-1.5 mt-1.5 text-[10px] text-cyan-400/90 font-mono">
                          <CheckCircle2 className="w-3 h-3 text-cyan-400" />
                          <span className="line-clamp-1">{incident.correlation_reasons[0]}</span>
                        </div>
                      )}
                    </td>
                    <td className="py-3.5 px-4 whitespace-nowrap">
                      {getStatusBadge(incident.status)}
                    </td>
                    <td className="py-3.5 px-4 whitespace-nowrap">
                      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-slate-950 border border-slate-800 text-cyan-400 font-bold">
                        {incident.alert_count} Alerts
                      </span>
                    </td>
                    <td className="py-3.5 px-4">
                      <div className="space-y-1">
                        {incident.affected_users.length > 0 && (
                          <div className="flex items-center gap-1 text-[11px] text-slate-300">
                            <User className="w-3 h-3 text-cyan-400 shrink-0" />
                            <span className="truncate max-w-[140px]">
                              {incident.affected_users.join(', ')}
                            </span>
                          </div>
                        )}
                        {incident.affected_ips.length > 0 && (
                          <div className="flex items-center gap-1 text-[11px] text-amber-300">
                            <Globe className="w-3 h-3 text-amber-400 shrink-0" />
                            <span className="truncate max-w-[140px]">
                              {incident.affected_ips.join(', ')}
                            </span>
                          </div>
                        )}
                      </div>
                    </td>
                    <td className="py-3.5 px-4 whitespace-nowrap text-slate-400 text-[11px]">
                      {incident.last_seen ? new Date(incident.last_seen).toLocaleString() : 'N/A'}
                    </td>
                    <td className="py-3.5 px-4 text-right whitespace-nowrap">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedIncidentId(incident.id);
                        }}
                        className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-cyan-400 hover:text-cyan-300 border border-slate-700 transition-colors inline-flex items-center gap-1 text-xs"
                      >
                        Investigate <ArrowRight className="w-3 h-3" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Pagination Footer */}
        {totalPages > 1 && (
          <div className="p-3 border-t border-slate-800 bg-slate-950/60 flex items-center justify-between text-xs font-mono text-slate-400">
            <span>
              Showing page {page} of {totalPages} ({totalCount} total incidents)
            </span>
            <div className="flex items-center gap-2">
              <button
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                disabled={page <= 1}
                className="px-2.5 py-1 rounded bg-slate-900 border border-slate-800 disabled:opacity-40 hover:bg-slate-800 text-slate-200 transition-colors"
              >
                <ChevronLeft className="w-3.5 h-3.5 inline mr-1" /> Prev
              </button>
              <button
                onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                disabled={page >= totalPages}
                className="px-2.5 py-1 rounded bg-slate-900 border border-slate-800 disabled:opacity-40 hover:bg-slate-800 text-slate-200 transition-colors"
              >
                Next <ChevronRight className="w-3.5 h-3.5 inline ml-1" />
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Modals */}
      {selectedIncidentId && (
        <IncidentDetailsModal
          incidentId={selectedIncidentId}
          onClose={() => setSelectedIncidentId(null)}
          onIncidentUpdated={fetchIncidents}
          onSelectAlert={onSelectAlert}
        />
      )}

      {isCorrelationModalOpen && (
        <CorrelationRunModal
          isOpen={isCorrelationModalOpen}
          onClose={() => setIsCorrelationModalOpen(false)}
          onRunComplete={fetchIncidents}
        />
      )}
    </div>
  );
};
