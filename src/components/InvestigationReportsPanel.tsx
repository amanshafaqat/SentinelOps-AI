import React, { useState, useEffect } from 'react';
import {
  FileCheck2,
  Download,
  Printer,
  Eye,
  Plus,
  Clock,
  User,
  Shield,
  CheckCircle2,
  AlertCircle,
  Loader2,
  FileText,
  Sparkles,
  Layers,
  ChevronDown,
  ChevronRight,
  ExternalLink,
  Flame,
  AlertTriangle,
  Info,
  X,
} from 'lucide-react';
import { IncidentDetail } from './IncidentDetailsModal';

export interface ReportItem {
  id: string;
  incident_id: string;
  title: string;
  report_type: string;
  generated_by: string;
  summary: string;
  metadata: Record<string, any>;
  created_at: string;
}

export interface ReportDetail extends ReportItem {
  content: {
    header: Record<string, any>;
    incident_info: Record<string, any>;
    affected_entities: Record<string, any>;
    executive_summary: string;
    detection_summary: Record<string, any>;
    evidence_traceability: any[];
    timeline: any[];
    ai_assisted_analysis: any | null;
    analyst_notes: any[];
    investigation_history: any[];
    current_status: Record<string, any>;
  };
  rendered_html: string;
}

interface InvestigationReportsPanelProps {
  incident: IncidentDetail;
  actorName: string;
  onReportCreated?: () => void;
}

export const InvestigationReportsPanel: React.FC<InvestigationReportsPanelProps> = ({
  incident,
  actorName,
  onReportCreated,
}) => {
  const [reports, setReports] = useState<ReportItem[]>([]);
  const [loading, setLoading] = useState(false);
  const [generating, setGenerating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  // Generate Report Modal
  const [showGenerateModal, setShowGenerateModal] = useState(false);
  const [reportType, setReportType] = useState('investigation_summary');
  const [customTitle, setCustomTitle] = useState('');
  const [includeAi, setIncludeAi] = useState(true);

  // Preview Modal
  const [previewReport, setPreviewReport] = useState<ReportDetail | null>(null);
  const [loadingPreview, setLoadingPreview] = useState(false);

  useEffect(() => {
    if (incident?.id) {
      fetchReports();
    }
  }, [incident?.id]);

  const fetchReports = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`/api/v1/incidents/${incident.id}/reports`);
      if (!res.ok) {
        throw new Error('Unable to load investigation reports.');
      }
      const data = await res.json();
      setReports(data.reports || []);
    } catch {
      setError('Unable to load investigation reports.');
    } finally {
      setLoading(false);
    }
  };

  const handleGenerateReport = async (e: React.FormEvent) => {
    e.preventDefault();
    setGenerating(true);
    setError(null);

    try {
      const payload = {
        report_type: reportType,
        title: customTitle.trim() || undefined,
        generated_by: actorName || 'soc_analyst',
        include_ai_analysis: includeAi,
      };

      const res = await fetch(`/api/v1/incidents/${incident.id}/reports`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });

      if (!res.ok) {
        throw new Error('Unable to generate investigation report.');
      }

      const created: ReportDetail = await res.json();
      setReports((prev) => [created, ...prev]);
      setShowGenerateModal(false);
      setCustomTitle('');
      setSuccessMessage(`Investigation Report "${created.title}" successfully generated & audited.`);
      setPreviewReport(created); // Immediately open preview
      if (onReportCreated) onReportCreated();
      setTimeout(() => setSuccessMessage(null), 4000);
    } catch (err: any) {
      setError(err.message || 'Unable to generate investigation report.');
    } finally {
      setGenerating(false);
    }
  };

  const handleOpenPreview = async (reportId: string) => {
    setLoadingPreview(true);
    setError(null);
    try {
      const res = await fetch(`/api/v1/incidents/${incident.id}/reports/${reportId}`);
      if (!res.ok) {
        throw new Error(`HTTP ${res.status}: Failed to retrieve report details`);
      }
      const data: ReportDetail = await res.json();
      setPreviewReport(data);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoadingPreview(false);
    }
  };

  const handleExportDownload = (reportId: string, format: 'html' | 'json') => {
    const url = `/api/v1/incidents/${incident.id}/reports/${reportId}/export?format=${format}&actor=${encodeURIComponent(
      author
    )}`;
    const link = document.createElement('a');
    link.href = url;
    link.setAttribute('download', `report_${reportId}.${format}`);
    document.body.appendChild(link);
    link.click();
    link.remove();
  };

  const handlePrint = (reportHtml: string) => {
    const printWindow = window.open('', '_blank');
    if (printWindow) {
      printWindow.document.write(reportHtml);
      printWindow.document.close();
      printWindow.focus();
      setTimeout(() => {
        printWindow.print();
      }, 500);
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Banner & Generation CTA */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-slate-950/60 border border-slate-800 rounded-lg p-5">
        <div>
          <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2 font-mono">
            <FileCheck2 className="w-4 h-4 text-cyan-400" />
            Security Incident Investigation Reports ({reports.length})
          </h3>
          <p className="text-xs text-slate-400 font-mono mt-1">
            Produce evidence-grounded reports with Incident &rarr; Alert &rarr; Event traceability, AI advisory, and audit logs.
          </p>
        </div>
        <button
          onClick={() => setShowGenerateModal(true)}
          className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg text-xs font-mono font-medium transition-colors flex items-center gap-2 shadow-sm shrink-0 self-start sm:self-auto"
        >
          <Plus className="w-3.5 h-3.5" />
          Generate New Report
        </button>
      </div>

      {/* Success Notification */}
      {successMessage && (
        <div className="p-3 bg-emerald-950/70 border border-emerald-800 text-emerald-300 rounded-lg text-xs font-mono flex items-center gap-2">
          <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
          <span>{successMessage}</span>
        </div>
      )}

      {/* Error Alert */}
      {error && (
        <div className="p-3 bg-red-950/70 border border-red-800 text-red-300 rounded-lg text-xs font-mono flex items-center justify-between">
          <div className="flex items-center gap-2">
            <AlertCircle className="w-4 h-4 text-red-400 shrink-0" />
            <span>{error}</span>
          </div>
          <button onClick={() => setError(null)} className="underline text-xs hover:text-red-200">
            Dismiss
          </button>
        </div>
      )}

      {/* Historical Reports List */}
      <div className="space-y-3">
        <h4 className="text-xs font-mono uppercase tracking-wider text-slate-400 font-semibold px-1">
          Report Versions &amp; Historical Archives
        </h4>

        {loading ? (
          <div className="py-12 text-center text-slate-400 flex flex-col items-center justify-center gap-2">
            <Loader2 className="w-6 h-6 animate-spin text-cyan-400" />
            <p className="text-xs font-mono">Loading investigation reports...</p>
          </div>
        ) : reports.length === 0 ? (
          <div className="py-12 text-center bg-slate-950/40 border border-slate-800/80 rounded-lg p-6 space-y-2">
            <FileText className="w-8 h-8 text-slate-600 mx-auto" />
            <p className="text-xs font-mono text-slate-400 font-medium">No investigation reports generated yet.</p>
            <p className="text-[11px] font-mono text-slate-500">
              Click &quot;Generate New Report&quot; to synthesize factual telemetry, chronological timelines, and analyst findings.
            </p>
          </div>
        ) : (
          <div className="space-y-2.5">
            {reports.map((report) => (
              <div
                key={report.id}
                className="bg-slate-950/80 border border-slate-800 hover:border-slate-700 transition-colors rounded-lg p-4 flex flex-col md:flex-row md:items-center justify-between gap-4"
              >
                <div className="space-y-1.5 flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="px-2 py-0.5 rounded bg-cyan-950/90 border border-cyan-800 text-cyan-300 text-[10px] font-mono font-bold">
                      v{report.metadata?.version || 1}
                    </span>
                    <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 text-[10px] font-mono uppercase">
                      {report.report_type.replace('_', ' ')}
                    </span>
                    <h5 className="text-xs font-bold text-slate-200 font-mono truncate">{report.title}</h5>
                  </div>
                  <p className="text-[11px] font-mono text-slate-400 line-clamp-1">{report.summary}</p>
                  <div className="flex items-center gap-3 text-[10px] font-mono text-slate-500">
                    <span className="flex items-center gap-1">
                      <User className="w-3 h-3 text-slate-500" />
                      {report.generated_by}
                    </span>
                    <span>•</span>
                    <span className="flex items-center gap-1">
                      <Clock className="w-3 h-3 text-slate-500" />
                      {new Date(report.created_at).toLocaleString()}
                    </span>
                    <span>•</span>
                    <span>{report.metadata?.alert_count || 0} Alerts</span>
                    <span>•</span>
                    <span>{report.metadata?.event_count || 0} Events</span>
                  </div>
                </div>

                {/* Actions */}
                <div className="flex items-center gap-2 shrink-0">
                  <button
                    onClick={() => handleOpenPreview(report.id)}
                    className="px-3 py-1.5 bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-200 rounded text-xs font-mono flex items-center gap-1.5 transition-colors"
                  >
                    <Eye className="w-3.5 h-3.5 text-cyan-400" />
                    Preview
                  </button>
                  <button
                    onClick={() => handleExportDownload(report.id, 'html')}
                    className="px-3 py-1.5 bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-200 rounded text-xs font-mono flex items-center gap-1.5 transition-colors"
                    title="Download Standalone HTML Report"
                  >
                    <Download className="w-3.5 h-3.5 text-emerald-400" />
                    HTML
                  </button>
                  <button
                    onClick={() => handleExportDownload(report.id, 'json')}
                    className="px-2.5 py-1.5 bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-300 rounded text-xs font-mono transition-colors"
                    title="Download Structured JSON Report"
                  >
                    JSON
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Generate Report Modal */}
      {showGenerateModal && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-700 rounded-xl max-w-lg w-full p-5 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-sm font-bold text-slate-100 font-mono flex items-center gap-2">
                <FileCheck2 className="w-4 h-4 text-cyan-400" />
                Configure &amp; Generate Investigation Report
              </h3>
              <button
                onClick={() => setShowGenerateModal(false)}
                className="p-1 rounded text-slate-400 hover:text-slate-200 hover:bg-slate-800"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleGenerateReport} className="space-y-4 text-xs font-mono">
              <div>
                <label className="text-slate-300 block mb-1 font-semibold">Report Classification / Type</label>
                <select
                  value={reportType}
                  onChange={(e) => setReportType(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-700 rounded p-2 text-slate-200 focus:outline-none focus:border-cyan-500"
                >
                  <option value="investigation_summary">Investigation Summary (Complete Technical Forensic Dossier)</option>
                  <option value="executive_brief">Executive Brief (High-level Management Summary)</option>
                  <option value="post_incident_review">Post-Incident Review (Lessons Learned &amp; Root Cause)</option>
                </select>
              </div>

              <div>
                <label className="text-slate-300 block mb-1 font-semibold">Custom Report Title (Optional)</label>
                <input
                  type="text"
                  value={customTitle}
                  onChange={(e) => setCustomTitle(e.target.value)}
                  placeholder={`Investigation Report: ${incident.title}`}
                  className="w-full bg-slate-950 border border-slate-700 rounded p-2 text-slate-200 focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div>
                <label className="text-slate-300 block mb-1 font-semibold">Lead Analyst Identity</label>
                <div className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-slate-200 flex items-center justify-between text-xs font-mono">
                  <span>{actorName || 'Authenticated SOC Analyst'}</span>
                  <span className="text-[10px] text-emerald-400 bg-emerald-950/80 border border-emerald-800/60 px-2 py-0.5 rounded font-semibold">
                    Verified
                  </span>
                </div>
              </div>

              <div className="flex items-center gap-2 p-3 bg-slate-950/60 border border-slate-800 rounded">
                <input
                  type="checkbox"
                  id="include_ai"
                  checked={includeAi}
                  onChange={(e) => setIncludeAi(e.target.checked)}
                  className="w-4 h-4 text-cyan-600 rounded bg-slate-900 border-slate-700 focus:ring-0"
                />
                <label htmlFor="include_ai" className="text-slate-300 select-none cursor-pointer">
                  Incorporate verified AI Copilot findings (clearly labeled as advisory)
                </label>
              </div>

              <div className="p-3 bg-slate-950 border border-slate-800 rounded text-[11px] text-slate-400 space-y-1">
                <div className="font-semibold text-slate-300">Evidence Grounding Guarantee:</div>
                <p>
                  Reports are synthesized strictly from actual incident telemetry, correlated alerts, and audit records.
                  No hypothetical events or indicators will be fabricated.
                </p>
              </div>

              <div className="flex justify-end gap-2 pt-2 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowGenerateModal(false)}
                  className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded text-xs transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={generating}
                  className="px-4 py-1.5 bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white rounded text-xs font-semibold transition-colors flex items-center gap-1.5"
                >
                  {generating ? (
                    <>
                      <Loader2 className="w-3.5 h-3.5 animate-spin" />
                      Generating &amp; Auditing...
                    </>
                  ) : (
                    <>
                      <FileCheck2 className="w-3.5 h-3.5" />
                      Generate Report
                    </>
                  )}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Report Preview Modal */}
      {previewReport && (
        <div className="fixed inset-0 z-50 bg-black/85 backdrop-blur-xs flex items-center justify-center p-2 sm:p-4">
          <div className="bg-slate-900 border border-slate-700 rounded-xl max-w-5xl w-full h-[90vh] flex flex-col shadow-2xl overflow-hidden">
            {/* Modal Header */}
            <div className="p-4 bg-slate-950 border-b border-slate-800 flex items-center justify-between shrink-0">
              <div className="flex items-center gap-2">
                <FileCheck2 className="w-4 h-4 text-cyan-400" />
                <h3 className="text-sm font-bold text-slate-100 font-mono truncate max-w-md">
                  {previewReport.title}
                </h3>
                <span className="px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 text-[10px] font-mono border border-cyan-800">
                  v{previewReport.metadata?.version || 1}
                </span>
              </div>

              <div className="flex items-center gap-2">
                <button
                  onClick={() => handlePrint(previewReport.rendered_html)}
                  className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded text-xs font-mono flex items-center gap-1.5 transition-colors cursor-pointer"
                  title="Print / Save as PDF"
                >
                  <Printer className="w-3.5 h-3.5 text-slate-300" />
                  Print
                </button>

                <button
                  onClick={() => handleExportDownload(previewReport.id, 'html')}
                  className="px-3 py-1.5 bg-emerald-700 hover:bg-emerald-600 text-white rounded text-xs font-mono flex items-center gap-1.5 transition-colors cursor-pointer"
                >
                  <Download className="w-3.5 h-3.5" />
                  Export HTML
                </button>

                <button
                  onClick={() => handleExportDownload(previewReport.id, 'json')}
                  className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded text-xs font-mono flex items-center gap-1.5 transition-colors cursor-pointer"
                >
                  <Download className="w-3.5 h-3.5" />
                  Export JSON
                </button>

                <button
                  onClick={() => setPreviewReport(null)}
                  className="p-1.5 rounded text-slate-400 hover:text-slate-200 hover:bg-slate-800 ml-1 cursor-pointer"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>
            </div>

            {/* Modal Body */}
            <div className="flex-1 overflow-y-auto bg-slate-950 p-4 sm:p-6 text-xs font-mono">
              <div className="max-w-4xl mx-auto bg-slate-900 border border-slate-800 rounded-xl p-6 sm:p-8 space-y-6 text-slate-200">
                  {/* Report Header */}
                  <div className="border-b-2 border-slate-700 pb-4 flex flex-col sm:flex-row sm:items-start justify-between gap-4">
                    <div>
                      <h2 className="text-xl font-bold text-slate-100 tracking-tight">SENTINELOPS AI</h2>
                      <div className="text-xs uppercase tracking-widest text-slate-400 font-semibold mt-0.5">
                        Security Incident Investigation Report
                      </div>
                    </div>
                    <div className="text-right text-xs text-slate-400 space-y-0.5">
                      <div>Generated: <span className="text-slate-200">{new Date(previewReport.created_at).toLocaleString()}</span></div>
                      <div>Author: <span className="text-slate-200">{previewReport.generated_by}</span></div>
                      <div>Type: <span className="text-cyan-400 font-semibold">{previewReport.report_type.replace('_', ' ').toUpperCase()}</span></div>
                    </div>
                  </div>

                  {/* Incident Info Header */}
                  <div className="space-y-2">
                    <div className="flex items-center gap-2">
                      <span className="px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 text-[10px] font-bold border border-cyan-800">
                        {previewReport.content?.incident_info?.severity || incident.severity.toUpperCase()}
                      </span>
                      <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 text-[10px] font-bold">
                        STATUS: {previewReport.content?.incident_info?.status || incident.status.toUpperCase()}
                      </span>
                      <span className="text-slate-500 text-[11px]">ID: {incident.id}</span>
                    </div>
                    <h3 className="text-lg font-bold text-slate-100">{previewReport.title}</h3>
                  </div>

                  {/* Executive Summary */}
                  <div className="bg-slate-950/80 border border-slate-800 rounded-lg p-4 space-y-2">
                    <h4 className="text-xs font-bold text-cyan-400 uppercase tracking-wider flex items-center gap-1.5">
                      <Info className="w-3.5 h-3.5" />
                      1. Executive Summary
                    </h4>
                    <p className="text-slate-300 leading-relaxed whitespace-pre-wrap">
                      {previewReport.summary || previewReport.content?.executive_summary}
                    </p>
                  </div>

                  {/* Detection & Correlation Summary */}
                  <div className="bg-slate-950/80 border border-slate-800 rounded-lg p-4 space-y-3">
                    <h4 className="text-xs font-bold text-cyan-400 uppercase tracking-wider flex items-center gap-1.5">
                      <Layers className="w-3.5 h-3.5" />
                      2. Detection &amp; Correlation Narrative
                    </h4>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                      <div>
                        <span className="text-[11px] text-slate-400 block mb-1 font-semibold">Rules Triggered:</span>
                        <div className="space-y-1">
                          {previewReport.content?.detection_summary?.rules_triggered?.map((r: any, idx: number) => (
                            <div key={idx} className="flex justify-between p-1.5 bg-slate-900 rounded text-[11px]">
                              <span>{r.rule_name}</span>
                              <span className="text-cyan-400 font-bold">{r.count} alert(s)</span>
                            </div>
                          ))}
                        </div>
                      </div>
                      <div>
                        <span className="text-[11px] text-slate-400 block mb-1 font-semibold">Correlation Signals:</span>
                        <ul className="list-disc list-inside space-y-1 text-[11px] text-slate-300">
                          {previewReport.content?.detection_summary?.correlation_reasons?.map((r: string, idx: number) => (
                            <li key={idx}>{r}</li>
                          ))}
                        </ul>
                      </div>
                    </div>
                  </div>

                  {/* AI-Assisted Analysis Section */}
                  {previewReport.content?.ai_assisted_analysis && (
                    <div className="bg-indigo-950/30 border border-indigo-900/60 rounded-lg p-4 space-y-3">
                      <div className="flex items-center justify-between border-b border-indigo-900/40 pb-2">
                        <h4 className="text-xs font-bold text-indigo-300 uppercase tracking-wider flex items-center gap-1.5">
                          <Sparkles className="w-3.5 h-3.5 text-indigo-400" />
                          3. AI-Assisted Analysis
                        </h4>
                        <span className="px-2 py-0.5 rounded bg-indigo-900/80 text-indigo-200 text-[10px] font-bold">
                          Advisory &bull; Model: {previewReport.content.ai_assisted_analysis.model_used}
                        </span>
                      </div>
                      <p className="text-slate-200 leading-relaxed">
                        {previewReport.content.ai_assisted_analysis.summary}
                      </p>
                      {previewReport.content.ai_assisted_analysis.observed_facts?.length > 0 && (
                        <div>
                          <span className="text-[11px] text-emerald-400 font-semibold block mb-1">
                            Observed Facts:
                          </span>
                          <ul className="list-disc list-inside text-slate-300 space-y-0.5 text-[11px]">
                            {previewReport.content.ai_assisted_analysis.observed_facts.map((f: string, i: number) => (
                              <li key={i}>{f}</li>
                            ))}
                          </ul>
                        </div>
                      )}
                      <div className="text-[10px] text-indigo-300/80 bg-indigo-950/60 p-2 rounded border border-indigo-900/40">
                        {previewReport.content.ai_assisted_analysis.disclaimer}
                      </div>
                    </div>
                  )}

                  {/* Evidence Traceability */}
                  <div className="bg-slate-950/80 border border-slate-800 rounded-lg p-4 space-y-3">
                    <h4 className="text-xs font-bold text-cyan-400 uppercase tracking-wider flex items-center gap-1.5">
                      <Shield className="w-3.5 h-3.5" />
                      4. Evidence Traceability (Incident &rarr; Alert &rarr; Telemetry Events)
                    </h4>
                    <div className="space-y-3">
                      {previewReport.content?.evidence_traceability?.map((alertItem: any, idx: number) => (
                        <div key={idx} className="border border-slate-800 rounded p-3 bg-slate-900 space-y-2">
                          <div className="flex items-center justify-between text-xs">
                            <span className="font-bold text-slate-200">
                              {alertItem.rule_name} [{alertItem.rule_id}]
                            </span>
                            <span className="px-2 py-0.5 rounded text-[10px] bg-slate-800 text-slate-300 uppercase">
                              {alertItem.severity}
                            </span>
                          </div>
                          <p className="text-slate-400 text-[11px]">{alertItem.description}</p>
                          {alertItem.supporting_events?.length > 0 && (
                            <div className="pt-1">
                              <span className="text-[10px] uppercase text-slate-500 font-bold block mb-1">
                                Linked Telemetry Events ({alertItem.supporting_events.length}):
                              </span>
                              <div className="space-y-1">
                                {alertItem.supporting_events.map((ev: any, evIdx: number) => (
                                  <div
                                    key={evIdx}
                                    className="p-1.5 bg-slate-950 rounded text-[11px] flex items-center justify-between gap-2 text-slate-300"
                                  >
                                    <span>{ev.timestamp?.substring(0, 19)} &bull; {ev.event_type} &bull; {ev.message}</span>
                                    <span className="text-cyan-400 text-[10px] shrink-0 font-mono">{ev.source_ip} &rarr; {ev.destination_ip}</span>
                                  </div>
                                ))}
                              </div>
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Analyst Notes */}
                  {previewReport.content?.analyst_notes?.length > 0 && (
                    <div className="bg-slate-950/80 border border-slate-800 rounded-lg p-4 space-y-2">
                      <h4 className="text-xs font-bold text-cyan-400 uppercase tracking-wider">
                        5. Analyst Investigation Notes
                      </h4>
                      <div className="space-y-2">
                        {previewReport.content.analyst_notes.map((n: any, idx: number) => (
                          <div key={idx} className="p-2.5 bg-slate-900 rounded border border-slate-800 space-y-1 text-xs">
                            <div className="text-[11px] text-slate-400 flex justify-between">
                              <span className="text-cyan-300 font-semibold">{n.author}</span>
                              <span>{n.created_at?.substring(0, 19)} UTC</span>
                            </div>
                            <p className="text-slate-200">{n.content}</p>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Footer */}
                  <div className="text-center text-[11px] text-slate-500 pt-4 border-t border-slate-800">
                    SentinelOps AI Evidence-Grounded Investigation Report &bull; Incident ID: {incident.id}
                  </div>
                </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
