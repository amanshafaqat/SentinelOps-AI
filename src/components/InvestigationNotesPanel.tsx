import React, { useState, useEffect } from 'react';
import {
  FileText,
  Plus,
  Trash2,
  Edit2,
  Check,
  X,
  AlertCircle,
  Clock,
  User,
  Send,
  Loader2,
  CheckCircle2,
  MessageSquare,
} from 'lucide-react';

export interface CaseNoteItem {
  id: string;
  incident_id: string;
  author: string;
  content: string;
  created_at: string;
  updated_at: string;
}

interface InvestigationNotesPanelProps {
  incidentId: string;
  actorName: string;
  onNoteAdded?: () => void;
}

export const InvestigationNotesPanel: React.FC<InvestigationNotesPanelProps> = ({
  incidentId,
  actorName,
  onNoteAdded,
}) => {
  const [notes, setNotes] = useState<CaseNoteItem[]>([]);
  const [loading, setLoading] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  // New note form state
  const [newContent, setNewContent] = useState('');
  const [validationError, setValidationError] = useState<string | null>(null);

  // Editing state
  const [editingNoteId, setEditingNoteId] = useState<string | null>(null);
  const [editContent, setEditContent] = useState('');
  const [isUpdating, setIsUpdating] = useState(false);

  useEffect(() => {
    if (incidentId) {
      fetchNotes();
    }
  }, [incidentId]);

  const fetchNotes = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`/api/v1/incidents/${incidentId}/notes`);
      if (!res.ok) {
        throw new Error('Unable to load investigation notes.');
      }
      const data = await res.json();
      setNotes(data.notes || []);
    } catch {
      setError('Unable to load investigation notes.');
    } finally {
      setLoading(false);
    }
  };

  const handleCreateNote = async (e: React.FormEvent) => {
    e.preventDefault();
    setValidationError(null);
    setError(null);

    const trimmed = newContent.trim();
    if (!trimmed) {
      setValidationError('Note content cannot be empty.');
      return;
    }
    if (trimmed.length > 5000) {
      setValidationError('Note content exceeds maximum allowed length of 5000 characters.');
      return;
    }

    setSubmitting(true);
    try {
      const res = await fetch(`/api/v1/incidents/${incidentId}/notes`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          author: actorName || 'soc_analyst',
          content: trimmed,
        }),
      });

      if (!res.ok) {
        throw new Error('Unable to record investigation note.');
      }

      const createdNote: CaseNoteItem = await res.json();
      setNotes((prev) => [createdNote, ...prev]);
      setNewContent('');
      setSuccessMessage('Investigation note successfully recorded and audited.');
      if (onNoteAdded) onNoteAdded();
      setTimeout(() => setSuccessMessage(null), 3500);
    } catch (err: any) {
      setError(err.message || 'Unable to record investigation note.');
    } finally {
      setSubmitting(false);
    }
  };

  const handleStartEdit = (note: CaseNoteItem) => {
    setEditingNoteId(note.id);
    setEditContent(note.content);
    setValidationError(null);
  };

  const handleCancelEdit = () => {
    setEditingNoteId(null);
    setEditContent('');
    setValidationError(null);
  };

  const handleSaveEdit = async (noteId: string) => {
    const trimmed = editContent.trim();
    if (!trimmed) {
      setValidationError('Note content cannot be empty.');
      return;
    }
    if (trimmed.length > 5000) {
      setValidationError('Note content exceeds maximum allowed length of 5000 characters.');
      return;
    }

    setIsUpdating(true);
    setError(null);
    try {
      const res = await fetch(`/api/v1/incidents/${incidentId}/notes/${noteId}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          author: actorName || 'soc_analyst',
          content: trimmed,
        }),
      });

      if (!res.ok) {
        throw new Error('Unable to update investigation note.');
      }

      const updatedNote: CaseNoteItem = await res.json();
      setNotes((prev) => prev.map((n) => (n.id === noteId ? updatedNote : n)));
      setEditingNoteId(null);
      setEditContent('');
      setSuccessMessage('Investigation note updated and audited.');
      if (onNoteAdded) onNoteAdded();
      setTimeout(() => setSuccessMessage(null), 3000);
    } catch (err: any) {
      setError(err.message || 'Unable to update note.');
    } finally {
      setIsUpdating(false);
    }
  };

  const handleDeleteNote = async (noteId: string) => {
    if (!confirm('Are you sure you want to delete this investigation note? This action will be audited.')) {
      return;
    }

    try {
      const res = await fetch(`/api/v1/incidents/${incidentId}/notes/${noteId}?author=${encodeURIComponent(actorName || 'soc_analyst')}`, {
        method: 'DELETE',
      });

      if (!res.ok) {
        throw new Error('Unable to delete note.');
      }

      setNotes((prev) => prev.filter((n) => n.id !== noteId));
      setSuccessMessage('Note deleted and audit log recorded.');
      if (onNoteAdded) onNoteAdded();
      setTimeout(() => setSuccessMessage(null), 3000);
    } catch (err: any) {
      setError(err.message || 'Unable to delete note.');
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Header & Context */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 bg-slate-950/60 border border-slate-800 rounded-lg p-4">
        <div>
          <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2 font-mono">
            <MessageSquare className="w-4 h-4 text-cyan-400" />
            Case Investigation Notes ({notes.length})
          </h3>
          <p className="text-xs text-slate-400 font-mono mt-0.5">
            Immutable forensic commentary, hypothesis tracking, and peer handoff notes.
          </p>
        </div>
        <div className="flex items-center gap-2 text-xs font-mono text-slate-400 bg-slate-900/80 px-3 py-1.5 rounded border border-slate-800">
          <span>Analyst:</span>
          <strong className="text-cyan-400">{actorName || 'Authenticated SOC Analyst'}</strong>
          <span className="text-[10px] text-emerald-400 bg-emerald-950/60 border border-emerald-800/40 px-1.5 py-0.5 rounded font-semibold uppercase">Verified</span>
        </div>
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
        <div className="p-3 bg-red-950/70 border border-red-800 text-red-300 rounded-lg text-xs font-mono flex items-center gap-2 justify-between">
          <div className="flex items-center gap-2">
            <AlertCircle className="w-4 h-4 text-red-400 shrink-0" />
            <span>{error}</span>
          </div>
          <button onClick={() => setError(null)} className="text-xs underline hover:text-red-200">
            Dismiss
          </button>
        </div>
      )}

      {/* Add New Note Card */}
      <form onSubmit={handleCreateNote} className="bg-slate-900/80 border border-slate-800 rounded-lg p-4 space-y-3">
        <div className="flex items-center justify-between">
          <label className="text-xs font-mono font-semibold text-slate-300 flex items-center gap-1.5">
            <Plus className="w-3.5 h-3.5 text-cyan-400" />
            Add Investigation Observation / Triage Note
          </label>
          <span className={`text-[11px] font-mono ${newContent.length > 4500 ? 'text-amber-400' : 'text-slate-500'}`}>
            {newContent.length} / 5000 chars
          </span>
        </div>

        <textarea
          rows={3}
          value={newContent}
          onChange={(e) => {
            setNewContent(e.target.value);
            if (validationError) setValidationError(null);
          }}
          placeholder="Document observed artifacts, containment actions taken, victim interview details, or next steps..."
          className={`w-full bg-slate-950 border ${
            validationError ? 'border-red-600' : 'border-slate-700'
          } rounded-lg p-3 text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500 resize-y`}
        />

        {validationError && (
          <p className="text-xs font-mono text-red-400 flex items-center gap-1.5">
            <AlertCircle className="w-3.5 h-3.5" />
            {validationError}
          </p>
        )}

        <div className="flex justify-end gap-2 pt-1">
          <button
            type="submit"
            disabled={submitting || !newContent.trim()}
            className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 disabled:opacity-40 text-white rounded-lg text-xs font-mono font-medium transition-colors flex items-center gap-1.5 shadow-sm"
          >
            {submitting ? (
              <>
                <Loader2 className="w-3.5 h-3.5 animate-spin" />
                Auditing &amp; Saving...
              </>
            ) : (
              <>
                <Send className="w-3.5 h-3.5" />
                Commit Case Note
              </>
            )}
          </button>
        </div>
      </form>

      {/* Notes Stream */}
      <div className="space-y-3">
        <h4 className="text-xs font-mono uppercase tracking-wider text-slate-400 font-semibold px-1">
          Investigation Record History
        </h4>

        {loading ? (
          <div className="py-12 text-center text-slate-400 flex flex-col items-center justify-center gap-2">
            <Loader2 className="w-6 h-6 animate-spin text-cyan-400" />
            <p className="text-xs font-mono">Loading case notes...</p>
          </div>
        ) : notes.length === 0 ? (
          <div className="py-12 text-center bg-slate-950/40 border border-slate-800/80 rounded-lg p-6 space-y-2">
            <FileText className="w-8 h-8 text-slate-600 mx-auto" />
            <p className="text-xs font-mono text-slate-400 font-medium">No investigation notes recorded for this case yet.</p>
            <p className="text-[11px] font-mono text-slate-500">
              Analysts can document triage findings, indicators of compromise, and peer updates above.
            </p>
          </div>
        ) : (
          notes.map((note) => {
            const isEditing = editingNoteId === note.id;

            return (
              <div
                key={note.id}
                className="bg-slate-950/80 border border-slate-800 hover:border-slate-700 transition-colors rounded-lg p-4 space-y-2.5"
              >
                {/* Note Meta Header */}
                <div className="flex items-center justify-between text-xs">
                  <div className="flex items-center gap-2 font-mono">
                    <span className="px-2 py-0.5 rounded bg-cyan-950/80 border border-cyan-800/80 text-cyan-300 font-semibold text-[11px] flex items-center gap-1">
                      <User className="w-3 h-3 text-cyan-400" />
                      {note.author}
                    </span>
                    <span className="text-slate-500">•</span>
                    <span className="text-slate-400 text-[11px] flex items-center gap-1">
                      <Clock className="w-3 h-3 text-slate-500" />
                      {new Date(note.created_at).toLocaleString()}
                    </span>
                    {note.updated_at && note.updated_at !== note.created_at && (
                      <span className="text-[10px] text-slate-500 italic">
                        (edited {new Date(note.updated_at).toLocaleTimeString()})
                      </span>
                    )}
                  </div>

                  {!isEditing && (
                    <div className="flex items-center gap-1.5 opacity-80 group-hover:opacity-100">
                      <button
                        onClick={() => handleStartEdit(note)}
                        className="p-1 rounded text-slate-400 hover:text-cyan-300 hover:bg-slate-800 transition-colors"
                        title="Edit note"
                      >
                        <Edit2 className="w-3.5 h-3.5" />
                      </button>
                      <button
                        onClick={() => handleDeleteNote(note.id)}
                        className="p-1 rounded text-slate-400 hover:text-red-400 hover:bg-slate-800 transition-colors"
                        title="Delete note"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  )}
                </div>

                {/* Note Content */}
                {isEditing ? (
                  <div className="space-y-2 pt-1">
                    <textarea
                      rows={3}
                      value={editContent}
                      onChange={(e) => setEditContent(e.target.value)}
                      className="w-full bg-slate-900 border border-cyan-500/80 rounded-lg p-2.5 text-xs font-mono text-slate-100 focus:outline-none resize-y"
                    />
                    <div className="flex justify-end gap-2">
                      <button
                        onClick={handleCancelEdit}
                        className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded text-xs font-mono flex items-center gap-1"
                      >
                        <X className="w-3 h-3" /> Cancel
                      </button>
                      <button
                        onClick={() => handleSaveEdit(note.id)}
                        disabled={isUpdating || !editContent.trim()}
                        className="px-3 py-1 bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white rounded text-xs font-mono flex items-center gap-1"
                      >
                        {isUpdating ? <Loader2 className="w-3 h-3 animate-spin" /> : <Check className="w-3 h-3" />}
                        Save Update
                      </button>
                    </div>
                  </div>
                ) : (
                  <div className="text-xs font-mono text-slate-200 whitespace-pre-wrap leading-relaxed pl-1">
                    {note.content}
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};
