import React, { useState, useRef } from 'react';
import {
  X,
  Upload,
  FileText,
  CheckCircle2,
  AlertTriangle,
  Loader2,
  Database,
  ArrowRight,
  Sparkles,
} from 'lucide-react';

interface ImportSummary {
  total_records: number;
  imported_records: number;
  rejected_records: number;
  errors: Array<{
    record_index: number;
    field?: string | null;
    error: string;
    raw_sample?: Record<string, any> | null;
  }>;
  sample_imported_ids: string[];
}

interface EventImportModalProps {
  isOpen: boolean;
  onClose: () => void;
  onImportComplete: () => void;
}

export const EventImportModal: React.FC<EventImportModalProps> = ({
  isOpen,
  onClose,
  onImportComplete,
}) => {
  const [file, setFile] = useState<File | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [summary, setSummary] = useState<ImportSummary | null>(null);
  const [dragActive, setDragActive] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  if (!isOpen) return null;

  const handleDrag = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true);
    } else if (e.type === 'dragleave') {
      setDragActive(false);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      validateAndSetFile(e.dataTransfer.files[0]);
    }
  };

  const handleFileInput = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      validateAndSetFile(e.target.files[0]);
    }
  };

  const validateAndSetFile = (selectedFile: File) => {
    const ext = selectedFile.name.toLowerCase();
    if (!ext.endsWith('.json') && !ext.endsWith('.csv')) {
      setError('Unsupported file type. Please select a valid .json or .csv log file.');
      setFile(null);
      return;
    }
    if (selectedFile.size > 10 * 1024 * 1024) {
      setError('File exceeds 10MB limit.');
      setFile(null);
      return;
    }
    setError(null);
    setFile(selectedFile);
    setSummary(null);
  };

  const handleUpload = async () => {
    if (!file) return;
    setLoading(true);
    setError(null);

    const formData = new FormData();
    formData.append('file', file);

    try {
      const res = await fetch('/api/v1/events/import', {
        method: 'POST',
        body: formData,
      });

      if (!res.ok) {
        const errorData = await res.json().catch(() => ({}));
        throw new Error(errorData.error?.message || `HTTP error ${res.status}`);
      }

      const data: ImportSummary = await res.json();
      setSummary(data);
      onImportComplete();
    } catch (err: any) {
      setError(err.message || 'An error occurred during log ingestion.');
    } finally {
      setLoading(false);
    }
  };

  const handleLoadDemo = async (type: 'json' | 'csv') => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`/api/v1/events/import`, {
        method: 'POST',
        headers: {
          'Content-Type': 'multipart/form-data',
        },
      });
      // Or fetch from demo file endpoint or load pre-packaged data
      const demoRes = await fetch(type === 'json' ? '/data/demo_security_events.json' : '/data/demo_security_events.csv');
      if (!demoRes.ok) {
        // Fallback: trigger batch API with the built-in json demo events
        const samplePayload = [
          {
            timestamp: new Date().toISOString(),
            event_type: "authentication",
            source: "linux_auth",
            source_ip: "198.51.100.42",
            username: "root",
            hostname: "prod-bastion-01",
            action: "login",
            status: "failure",
            severity: "medium",
            message: "Failed password for root from 198.51.100.42 port 49210 ssh2"
          },
          {
            timestamp: new Date(Date.now() + 15000).toISOString(),
            event_type: "authentication",
            source: "linux_auth",
            source_ip: "198.51.100.42",
            username: "svc-deploy",
            hostname: "prod-bastion-01",
            action: "login",
            status: "success",
            severity: "high",
            message: "Accepted password for svc-deploy from 198.51.100.42 port 49235 ssh2"
          },
          {
            timestamp: new Date(Date.now() + 30000).toISOString(),
            event_type: "privilege_change",
            source: "linux_auth",
            source_ip: "198.51.100.42",
            username: "svc-deploy",
            hostname: "prod-bastion-01",
            action: "sudo",
            status: "success",
            severity: "critical",
            message: "COMMAND=/bin/bash executed by user svc-deploy with sudo privileges"
          }
        ];
        const batchRes = await fetch('/api/v1/events/batch', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(samplePayload),
        });
        const batchData = await batchRes.json();
        setSummary(batchData);
        onImportComplete();
        return;
      }
      const blob = await demoRes.blob();
      const demoFile = new File([blob], `demo_security_events.${type}`, {
        type: type === 'json' ? 'application/json' : 'text/csv',
      });
      const fd = new FormData();
      fd.append('file', demoFile);
      const uploadRes = await fetch('/api/v1/events/import', {
        method: 'POST',
        body: fd,
      });
      if (!uploadRes.ok) {
        throw new Error('Failed to import demo telemetry.');
      }
      const data: ImportSummary = await uploadRes.json();
      setSummary(data);
      onImportComplete();
    } catch (err: any) {
      setError(err.message || 'Failed to load demo telemetry.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/80 backdrop-blur-sm p-4 animate-in fade-in duration-200">
      <div className="relative w-full max-w-2xl bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl flex flex-col overflow-hidden text-slate-100">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800 bg-slate-900/90">
          <div className="flex items-center space-x-3">
            <div className="p-2 bg-emerald-500/10 border border-emerald-500/30 rounded-lg text-emerald-400">
              <Upload className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-base font-semibold font-mono tracking-tight text-white">
                Ingest Security Telemetry
              </h2>
              <p className="text-xs text-slate-400 font-mono">
                Import JSON or CSV logs into normalized PostgreSQL storage
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-2 text-slate-400 hover:text-white rounded-lg hover:bg-slate-800 transition"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content */}
        <div className="p-6 space-y-6">
          {!summary ? (
            <>
              {/* Dropzone */}
              <div
                onDragEnter={handleDrag}
                onDragLeave={handleDrag}
                onDragOver={handleDrag}
                onDrop={handleDrop}
                onClick={() => fileInputRef.current?.click()}
                className={`relative border-2 border-dashed rounded-xl p-8 text-center cursor-pointer transition flex flex-col items-center justify-center space-y-3 ${
                  dragActive
                    ? 'border-emerald-500 bg-emerald-950/20'
                    : file
                    ? 'border-emerald-500/50 bg-slate-950/60'
                    : 'border-slate-800 hover:border-slate-700 bg-slate-950/40 hover:bg-slate-950/60'
                }`}
              >
                <input
                  ref={fileInputRef}
                  type="file"
                  accept=".json,.csv"
                  className="hidden"
                  onChange={handleFileInput}
                />
                <div className="p-3 bg-slate-900 rounded-full border border-slate-800 text-emerald-400">
                  <FileText className="w-6 h-6" />
                </div>
                <div>
                  {file ? (
                    <div>
                      <p className="text-sm font-semibold text-white">{file.name}</p>
                      <p className="text-xs text-slate-400 font-mono mt-0.5">
                        {(file.size / 1024).toFixed(1)} KB — Ready to normalize & ingest
                      </p>
                    </div>
                  ) : (
                    <div>
                      <p className="text-sm font-semibold text-slate-200">
                        Drag and drop your security log file, or{' '}
                        <span className="text-emerald-400 underline underline-offset-2">browse</span>
                      </p>
                      <p className="text-xs text-slate-500 font-mono mt-1">
                        Supports JSON (array of objects) and CSV up to 10MB
                      </p>
                    </div>
                  )}
                </div>
              </div>

              {/* Quick Preset Buttons */}
              <div className="pt-2 border-t border-slate-800">
                <span className="text-xs font-mono text-slate-500 uppercase tracking-wider block mb-2">
                  Or Load Pre-Packaged Demo Datasets
                </span>
                <div className="grid grid-cols-2 gap-3">
                  <button
                    type="button"
                    onClick={() => handleLoadDemo('json')}
                    disabled={loading}
                    className="p-3 rounded-lg bg-slate-950/80 border border-slate-800 hover:border-emerald-500/50 text-left transition group disabled:opacity-50"
                  >
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-xs font-mono font-semibold text-white group-hover:text-emerald-400">
                        Demo JSON Telemetry
                      </span>
                      <Sparkles className="w-3.5 h-3.5 text-emerald-400" />
                    </div>
                    <p className="text-[11px] text-slate-400 font-mono">
                      10 events (Linux auth, Sudo, Palo Alto FW, Okta MFA, CrowdStrike EDR)
                    </p>
                  </button>

                  <button
                    type="button"
                    onClick={() => handleLoadDemo('csv')}
                    disabled={loading}
                    className="p-3 rounded-lg bg-slate-950/80 border border-slate-800 hover:border-emerald-500/50 text-left transition group disabled:opacity-50"
                  >
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-xs font-mono font-semibold text-white group-hover:text-emerald-400">
                        Demo CSV Telemetry
                      </span>
                      <Sparkles className="w-3.5 h-3.5 text-sky-400" />
                    </div>
                    <p className="text-[11px] text-slate-400 font-mono">
                      8 events (Windows Event Log, Cisco ASA, Auditd, Azure AD)
                    </p>
                  </button>
                </div>
              </div>

              {error && (
                <div className="p-3 rounded-lg bg-rose-950/40 border border-rose-800 text-rose-300 text-xs flex items-start space-x-2">
                  <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
                  <span>{error}</span>
                </div>
              )}
            </>
          ) : (
            /* Import Summary View */
            <div className="space-y-4">
              <div className="p-4 rounded-xl bg-slate-950/80 border border-slate-800 space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-2">
                    <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                    <span className="text-sm font-semibold text-white">Ingestion Completed</span>
                  </div>
                  <span className="text-xs font-mono px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-800">
                    PostgreSQL Persisted
                  </span>
                </div>

                <div className="grid grid-cols-3 gap-3 font-mono text-xs pt-2">
                  <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 text-center">
                    <span className="text-slate-500 block text-[10px] uppercase">Total Read</span>
                    <span className="text-lg font-bold text-white">{summary.total_records}</span>
                  </div>
                  <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 text-center">
                    <span className="text-emerald-500 block text-[10px] uppercase">Imported</span>
                    <span className="text-lg font-bold text-emerald-400">{summary.imported_records}</span>
                  </div>
                  <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 text-center">
                    <span className="text-rose-500 block text-[10px] uppercase">Rejected</span>
                    <span className="text-lg font-bold text-rose-400">{summary.rejected_records}</span>
                  </div>
                </div>
              </div>

              {summary.errors && summary.errors.length > 0 && (
                <div className="p-4 rounded-xl bg-rose-950/20 border border-rose-900/60 space-y-2">
                  <div className="flex items-center space-x-2 text-rose-300 text-xs font-semibold">
                    <AlertTriangle className="w-4 h-4" />
                    <span>Rejected Records Breakdown ({summary.errors.length})</span>
                  </div>
                  <div className="max-h-40 overflow-y-auto space-y-1 font-mono text-[11px]">
                    {summary.errors.map((err, idx) => (
                      <div key={idx} className="p-2 bg-slate-900/80 rounded border border-rose-900/40 text-slate-300">
                        <span className="text-rose-400 font-bold">Row #{err.record_index}:</span>{' '}
                        {err.error}
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-6 py-4 border-t border-slate-800 bg-slate-950/60 flex items-center justify-between">
          <button
            onClick={onClose}
            className="px-4 py-2 text-xs font-mono text-slate-400 hover:text-white rounded-lg hover:bg-slate-800 transition"
          >
            {summary ? 'Done' : 'Cancel'}
          </button>

          {!summary ? (
            <button
              onClick={handleUpload}
              disabled={!file || loading}
              className="inline-flex items-center space-x-2 px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white text-xs font-mono font-medium transition"
            >
              {loading ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  <span>Processing Telemetry...</span>
                </>
              ) : (
                <>
                  <span>Ingest File</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </>
              )}
            </button>
          ) : (
            <button
              onClick={() => {
                setSummary(null);
                setFile(null);
              }}
              className="px-4 py-2 text-xs font-mono bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg transition"
            >
              Ingest Another File
            </button>
          )}
        </div>
      </div>
    </div>
  );
};
