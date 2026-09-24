import React, { useState, useEffect } from 'react';
import {
  Search,
  Filter,
  RefreshCw,
  Upload,
  Shield,
  AlertCircle,
  CheckCircle2,
  XCircle,
  Eye,
  ChevronLeft,
  ChevronRight,
  Database,
  Terminal,
  Layers,
  Sparkles,
  Server,
  User,
  ArrowRight,
} from 'lucide-react';
import { EventDetailsModal, SecurityEventDetail } from './EventDetailsModal';
import { EventImportModal } from './EventImportModal';

interface EventStats {
  total_events: number;
  by_severity: Record<string, number>;
  by_status: Record<string, number>;
  by_event_type: Record<string, number>;
  top_sources: Record<string, number>;
}

export const EventExplorer: React.FC = () => {
  const [events, setEvents] = useState<SecurityEventDetail[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);
  const [totalPages, setTotalPages] = useState(1);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Stats
  const [stats, setStats] = useState<EventStats | null>(null);

  // Filters
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [eventTypeFilter, setEventTypeFilter] = useState('');

  // Modals
  const [selectedEvent, setSelectedEvent] = useState<SecurityEventDetail | null>(null);
  const [isImportModalOpen, setIsImportModalOpen] = useState(false);

  const fetchStats = async () => {
    try {
      const res = await fetch('/api/v1/events/stats/summary');
      if (res.ok) {
        const data: EventStats = await res.json();
        setStats(data);
      }
    } catch (e) {
      console.warn('Failed to load event stats:', e);
    }
  };

  const fetchEvents = async () => {
    setLoading(true);
    setError(null);
    try {
      const params = new URLSearchParams({
        page: page.toString(),
        page_size: pageSize.toString(),
      });

      if (search.trim()) params.append('search', search.trim());
      if (severityFilter) params.append('severity', severityFilter);
      if (statusFilter) params.append('status', statusFilter);
      if (eventTypeFilter) params.append('event_type', eventTypeFilter);

      const res = await fetch(`/api/v1/events?${params.toString()}`);
      if (!res.ok) {
        throw new Error(`HTTP error ${res.status}: ${res.statusText}`);
      }

      const data = await res.json();
      setEvents(data.items || []);
      setTotal(data.total || 0);
      setTotalPages(data.total_pages || 1);
    } catch (err: any) {
      setError(err.message || 'Failed to retrieve security events.');
    } finally {
      setLoading(false);
    }
  };

  const inspectEvent = async (eventId: string) => {
    try {
      const res = await fetch(`/api/v1/events/${eventId}`);
      if (res.ok) {
        const fullEvent: SecurityEventDetail = await res.json();
        setSelectedEvent(fullEvent);
      }
    } catch (err) {
      console.error('Failed to load event details:', err);
    }
  };

  useEffect(() => {
    fetchEvents();
    fetchStats();
  }, [page, pageSize, severityFilter, statusFilter, eventTypeFilter]);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setPage(1);
    fetchEvents();
  };

  const clearFilters = () => {
    setSearch('');
    setSeverityFilter('');
    setStatusFilter('');
    setEventTypeFilter('');
    setPage(1);
  };

  const getSeverityBadgeClass = (sev: string) => {
    switch (sev.toLowerCase()) {
      case 'critical':
        return 'bg-rose-950/80 text-rose-300 border-rose-800 shadow-[0_0_8px_rgba(244,63,94,0.15)]';
      case 'high':
        return 'bg-amber-950/80 text-amber-300 border-amber-800 shadow-[0_0_8px_rgba(245,158,11,0.12)]';
      case 'medium':
        return 'bg-yellow-950/80 text-yellow-300 border-yellow-800/80';
      case 'low':
        return 'bg-sky-950/80 text-sky-300 border-sky-800';
      default:
        return 'bg-slate-900 text-slate-400 border-slate-700';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status.toLowerCase()) {
      case 'success':
        return <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />;
      case 'failure':
        return <XCircle className="w-3.5 h-3.5 text-rose-400" />;
      case 'blocked':
      case 'denied':
        return <Shield className="w-3.5 h-3.5 text-amber-400" />;
      default:
        return <AlertCircle className="w-3.5 h-3.5 text-slate-400" />;
    }
  };

  return (
    <div className="space-y-6">
      {/* Top SOC Metrics Summary Bar */}
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
        <div
          onClick={() => {
            setSeverityFilter('');
            setPage(1);
          }}
          className="p-3.5 rounded-xl bg-slate-900/80 border border-slate-800 hover:border-slate-700 transition cursor-pointer"
        >
          <span className="text-[10px] font-mono text-slate-500 uppercase tracking-wider block">
            Total Ingested
          </span>
          <div className="flex items-baseline space-x-2 mt-0.5">
            <span className="text-xl font-bold font-mono text-white">
              {stats?.total_events ?? total}
            </span>
            <span className="text-xs text-slate-400 font-mono">Events</span>
          </div>
        </div>

        <div
          onClick={() => {
            setSeverityFilter('critical');
            setPage(1);
          }}
          className={`p-3.5 rounded-xl border transition cursor-pointer ${
            severityFilter === 'critical'
              ? 'bg-rose-950/40 border-rose-600 shadow-[0_0_12px_rgba(244,63,94,0.15)]'
              : 'bg-slate-900/80 border-slate-800 hover:border-rose-900/50'
          }`}
        >
          <span className="text-[10px] font-mono text-rose-400 uppercase tracking-wider block">
            Critical
          </span>
          <div className="flex items-baseline space-x-2 mt-0.5">
            <span className="text-xl font-bold font-mono text-rose-300">
              {stats?.by_severity?.critical ?? 0}
            </span>
            <span className="text-xs text-slate-500 font-mono">Events</span>
          </div>
        </div>

        <div
          onClick={() => {
            setSeverityFilter('high');
            setPage(1);
          }}
          className={`p-3.5 rounded-xl border transition cursor-pointer ${
            severityFilter === 'high'
              ? 'bg-amber-950/40 border-amber-600 shadow-[0_0_12px_rgba(245,158,11,0.15)]'
              : 'bg-slate-900/80 border-slate-800 hover:border-amber-900/50'
          }`}
        >
          <span className="text-[10px] font-mono text-amber-400 uppercase tracking-wider block">
            High Severity
          </span>
          <div className="flex items-baseline space-x-2 mt-0.5">
            <span className="text-xl font-bold font-mono text-amber-300">
              {stats?.by_severity?.high ?? 0}
            </span>
            <span className="text-xs text-slate-500 font-mono">Events</span>
          </div>
        </div>

        <div
          onClick={() => {
            setSeverityFilter('medium');
            setPage(1);
          }}
          className={`p-3.5 rounded-xl border transition cursor-pointer ${
            severityFilter === 'medium'
              ? 'bg-yellow-950/40 border-yellow-600'
              : 'bg-slate-900/80 border-slate-800 hover:border-yellow-900/50'
          }`}
        >
          <span className="text-[10px] font-mono text-yellow-400 uppercase tracking-wider block">
            Medium Severity
          </span>
          <div className="flex items-baseline space-x-2 mt-0.5">
            <span className="text-xl font-bold font-mono text-yellow-300">
              {stats?.by_severity?.medium ?? 0}
            </span>
            <span className="text-xs text-slate-500 font-mono">Events</span>
          </div>
        </div>

        <div
          onClick={() => {
            setSeverityFilter('low');
            setPage(1);
          }}
          className={`p-3.5 rounded-xl border transition cursor-pointer ${
            severityFilter === 'low'
              ? 'bg-sky-950/40 border-sky-600'
              : 'bg-slate-900/80 border-slate-800 hover:border-sky-900/50'
          }`}
        >
          <span className="text-[10px] font-mono text-sky-400 uppercase tracking-wider block">
            Low / Info
          </span>
          <div className="flex items-baseline space-x-2 mt-0.5">
            <span className="text-xl font-bold font-mono text-sky-300">
              {(stats?.by_severity?.low ?? 0) + (stats?.by_severity?.info ?? 0)}
            </span>
            <span className="text-xs text-slate-500 font-mono">Events</span>
          </div>
        </div>
      </div>

      {/* Action Toolbar & Filters */}
      <div className="p-4 rounded-xl bg-slate-900/70 border border-slate-800 space-y-3">
        <div className="flex flex-col md:flex-row items-stretch md:items-center justify-between gap-3">
          {/* Search Form */}
          <form onSubmit={handleSearchSubmit} className="flex-1 relative">
            <Search className="w-4 h-4 text-slate-500 absolute left-3.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search by IP, username, hostname, action, message..."
              className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-10 pr-4 py-2 text-xs font-mono text-white placeholder-slate-500 focus:outline-none focus:border-emerald-500 transition"
            />
          </form>

          {/* Action Buttons */}
          <div className="flex items-center space-x-2">
            <button
              onClick={() => {
                fetchEvents();
                fetchStats();
              }}
              disabled={loading}
              className="p-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white transition border border-slate-700 disabled:opacity-50"
              title="Refresh Event Table"
            >
              <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin text-emerald-400' : ''}`} />
            </button>

            <button
              onClick={() => setIsImportModalOpen(true)}
              className="inline-flex items-center space-x-2 px-3.5 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-mono font-medium transition shadow-[0_0_12px_rgba(16,185,129,0.2)]"
            >
              <Upload className="w-3.5 h-3.5" />
              <span>Ingest Telemetry (JSON/CSV)</span>
            </button>
          </div>
        </div>

        {/* Filter Dropdowns */}
        <div className="flex flex-wrap items-center gap-2 pt-2 border-t border-slate-800/80 text-xs font-mono">
          <div className="flex items-center space-x-1.5 text-slate-400">
            <Filter className="w-3.5 h-3.5 text-emerald-400" />
            <span>Filters:</span>
          </div>

          <select
            value={severityFilter}
            onChange={(e) => {
              setSeverityFilter(e.target.value);
              setPage(1);
            }}
            className="bg-slate-950 border border-slate-800 rounded-md px-2.5 py-1 text-slate-300 focus:outline-none focus:border-emerald-500"
          >
            <option value="">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="info">Info</option>
          </select>

          <select
            value={statusFilter}
            onChange={(e) => {
              setStatusFilter(e.target.value);
              setPage(1);
            }}
            className="bg-slate-950 border border-slate-800 rounded-md px-2.5 py-1 text-slate-300 focus:outline-none focus:border-emerald-500"
          >
            <option value="">All Outcomes</option>
            <option value="success">Success</option>
            <option value="failure">Failure</option>
            <option value="blocked">Blocked</option>
            <option value="denied">Denied</option>
          </select>

          <select
            value={eventTypeFilter}
            onChange={(e) => {
              setEventTypeFilter(e.target.value);
              setPage(1);
            }}
            className="bg-slate-950 border border-slate-800 rounded-md px-2.5 py-1 text-slate-300 focus:outline-none focus:border-emerald-500"
          >
            <option value="">All Event Types</option>
            <option value="authentication">Authentication</option>
            <option value="privilege_change">Privilege Change</option>
            <option value="network">Network</option>
            <option value="cloud_audit">Cloud Audit</option>
            <option value="process">Process Execution</option>
            <option value="file_access">File Access</option>
            <option value="user_management">User Management</option>
          </select>

          {(search || severityFilter || statusFilter || eventTypeFilter) && (
            <button
              onClick={clearFilters}
              className="text-slate-400 hover:text-white underline underline-offset-2 ml-auto"
            >
              Reset Filters
            </button>
          )}
        </div>
      </div>

      {/* Events Table Container */}
      <div className="rounded-xl border border-slate-800 bg-slate-900/60 overflow-hidden shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono border-collapse">
            <thead>
              <tr className="bg-slate-950/80 border-b border-slate-800 text-slate-400 uppercase tracking-wider text-[11px]">
                <th className="py-3 px-4">Timestamp (UTC)</th>
                <th className="py-3 px-3">Severity</th>
                <th className="py-3 px-3">Type & Action</th>
                <th className="py-3 px-3">Status</th>
                <th className="py-3 px-3">Actor / Host</th>
                <th className="py-3 px-3">Network Flow</th>
                <th className="py-3 px-4">Summary Message</th>
                <th className="py-3 px-3 text-right">Inspect</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {loading && events.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-16 text-center text-slate-400">
                    <div className="flex flex-col items-center justify-center space-y-2">
                      <RefreshCw className="w-6 h-6 animate-spin text-emerald-400" />
                      <span>Loading security events from PostgreSQL...</span>
                    </div>
                  </td>
                </tr>
              ) : events.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-16 text-center">
                    <div className="max-w-md mx-auto space-y-3">
                      <div className="p-3 bg-slate-800/60 rounded-full inline-block text-slate-400">
                        <Database className="w-6 h-6" />
                      </div>
                      <h4 className="text-sm font-semibold text-white">No Security Events Found</h4>
                      <p className="text-xs text-slate-400 leading-relaxed font-sans">
                        {search || severityFilter || statusFilter || eventTypeFilter
                          ? 'No logs matched the current search criteria. Try resetting filters.'
                          : 'The security event datastore is empty. Ingest real logs or load the bundled demo dataset to begin.'}
                      </p>
                      <div className="pt-2 flex justify-center space-x-3">
                        {search || severityFilter || statusFilter || eventTypeFilter ? (
                          <button
                            onClick={clearFilters}
                            className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg transition"
                          >
                            Reset Active Filters
                          </button>
                        ) : (
                          <button
                            onClick={() => setIsImportModalOpen(true)}
                            className="inline-flex items-center space-x-2 px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg transition"
                          >
                            <Upload className="w-3.5 h-3.5" />
                            <span>Ingest Telemetry</span>
                          </button>
                        )}
                      </div>
                    </div>
                  </td>
                </tr>
              ) : (
                events.map((evt) => (
                  <tr
                    key={evt.id}
                    onClick={() => inspectEvent(evt.id)}
                    className="hover:bg-slate-800/40 transition cursor-pointer group"
                  >
                    {/* Timestamp */}
                    <td className="py-3 px-4 whitespace-nowrap text-slate-300">
                      <div className="flex flex-col">
                        <span className="font-semibold text-white">
                          {new Date(evt.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                        </span>
                        <span className="text-[10px] text-slate-500">
                          {new Date(evt.timestamp).toISOString().split('T')[0]}
                        </span>
                      </div>
                    </td>

                    {/* Severity */}
                    <td className="py-3 px-3 whitespace-nowrap">
                      <span className={`px-2 py-0.5 rounded text-[10px] uppercase font-bold border ${getSeverityBadgeClass(evt.severity)}`}>
                        {evt.severity}
                      </span>
                    </td>

                    {/* Type & Action */}
                    <td className="py-3 px-3 whitespace-nowrap">
                      <div className="flex flex-col">
                        <span className="text-white font-medium">{evt.action}</span>
                        <span className="text-[10px] text-slate-500">{evt.event_type}</span>
                      </div>
                    </td>

                    {/* Status */}
                    <td className="py-3 px-3 whitespace-nowrap">
                      <div className="inline-flex items-center space-x-1.5 px-2 py-0.5 rounded bg-slate-950/80 border border-slate-800">
                        {getStatusIcon(evt.status)}
                        <span className="text-slate-300 capitalize text-[11px]">{evt.status}</span>
                      </div>
                    </td>

                    {/* Subject / Host */}
                    <td className="py-3 px-3 whitespace-nowrap">
                      <div className="flex flex-col">
                        <span className="text-slate-200 font-semibold truncate max-w-[130px]">
                          {evt.username || <span className="text-slate-600">—</span>}
                        </span>
                        <span className="text-[10px] text-slate-500 truncate max-w-[130px]">
                          {evt.hostname || evt.source}
                        </span>
                      </div>
                    </td>

                    {/* Network */}
                    <td className="py-3 px-3 whitespace-nowrap text-[11px]">
                      {evt.source_ip ? (
                        <div className="flex items-center space-x-1 text-slate-300">
                          <span className="text-emerald-400">{evt.source_ip}</span>
                          {evt.destination_ip && (
                            <>
                              <ArrowRight className="w-2.5 h-2.5 text-slate-600" />
                              <span className="text-sky-400">{evt.destination_ip}</span>
                            </>
                          )}
                        </div>
                      ) : (
                        <span className="text-slate-600">Local / N/A</span>
                      )}
                    </td>

                    {/* Message */}
                    <td className="py-3 px-4 max-w-xs truncate text-slate-400 font-sans text-xs">
                      {evt.message}
                    </td>

                    {/* Action */}
                    <td className="py-3 px-3 text-right whitespace-nowrap">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          inspectEvent(evt.id);
                        }}
                        className="p-1.5 text-slate-400 group-hover:text-emerald-400 hover:bg-slate-800 rounded transition"
                        title="Inspect Event"
                      >
                        <Eye className="w-4 h-4" />
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination Footer */}
        <div className="px-4 py-3 bg-slate-950/80 border-t border-slate-800 flex flex-col sm:flex-row items-center justify-between gap-3 text-xs font-mono text-slate-400">
          <div>
            Showing <strong className="text-white">{events.length}</strong> of{' '}
            <strong className="text-white">{total}</strong> security events
          </div>

          <div className="flex items-center space-x-4">
            <div className="flex items-center space-x-2">
              <span className="text-slate-500">Rows per page:</span>
              <select
                value={pageSize}
                onChange={(e) => {
                  setPageSize(Number(e.target.value));
                  setPage(1);
                }}
                className="bg-slate-900 border border-slate-800 rounded px-2 py-1 text-slate-200 focus:outline-none"
              >
                <option value={10}>10</option>
                <option value={25}>25</option>
                <option value={50}>50</option>
                <option value={100}>100</option>
              </select>
            </div>

            <div className="flex items-center space-x-1">
              <button
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                disabled={page <= 1 || loading}
                className="p-1.5 rounded bg-slate-900 border border-slate-800 hover:bg-slate-800 disabled:opacity-40 transition text-slate-300"
                title="Previous Page"
              >
                <ChevronLeft className="w-4 h-4" />
              </button>

              <span className="px-2">
                Page <strong className="text-white">{page}</strong> of{' '}
                <strong className="text-white">{totalPages || 1}</strong>
              </span>

              <button
                onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                disabled={page >= totalPages || loading}
                className="p-1.5 rounded bg-slate-900 border border-slate-800 hover:bg-slate-800 disabled:opacity-40 transition text-slate-300"
                title="Next Page"
              >
                <ChevronRight className="w-4 h-4" />
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Inspector Modal */}
      <EventDetailsModal
        event={selectedEvent}
        onClose={() => setSelectedEvent(null)}
      />

      {/* Ingestion Modal */}
      <EventImportModal
        isOpen={isImportModalOpen}
        onClose={() => setIsImportModalOpen(false)}
        onImportComplete={() => {
          fetchEvents();
          fetchStats();
        }}
      />
    </div>
  );
};
