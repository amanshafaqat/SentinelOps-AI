import React, { useState, useEffect } from 'react';
import {
  Sparkles,
  Bot,
  Send,
  Loader2,
  AlertTriangle,
  CheckCircle2,
  HelpCircle,
  ShieldAlert,
  ArrowRight,
  RefreshCw,
  ExternalLink,
  ChevronDown,
  ChevronRight,
  Info,
  Clock,
  User,
  Terminal,
  FileQuestion,
  Search,
} from 'lucide-react';

export interface EvidenceReferenceItem {
  id: string;
  type: string;
  description?: string | null;
  valid: boolean;
  observed_at?: string | null;
  severity?: string | null;
}

export interface IncidentInvestigationAnalysis {
  incident_id: string;
  analysis_type: string;
  model_used: string;
  summary: string;
  observed_facts: string[];
  potential_explanations: string[];
  evidence_references: EvidenceReferenceItem[];
  missing_information: string[];
  recommended_next_steps: string[];
  uncertainty_assessment: string;
  evidence_truncated: boolean;
  disclaimer: string;
  created_at: string;
}

export interface AnalystQuestionResponse {
  incident_id: string;
  question: string;
  answer: string;
  observed_facts: string[];
  evidence_references: EvidenceReferenceItem[];
  uncertainty_assessment: string;
  recommended_next_steps: string[];
  missing_information: string[];
  model_used: string;
  evidence_truncated: boolean;
  disclaimer: string;
  created_at: string;
}

export interface QnAPair {
  id: string;
  question: string;
  response: AnalystQuestionResponse;
  timestamp: string;
}

interface IncidentInvestigationPanelProps {
  incidentId: string;
  incidentTitle: string;
  incidentSeverity: string;
  onSelectAlert?: (alertId: string) => void;
}

export const IncidentInvestigationPanel: React.FC<IncidentInvestigationPanelProps> = ({
  incidentId,
  incidentTitle,
  incidentSeverity,
  onSelectAlert,
}) => {
  const [analysis, setAnalysis] = useState<IncidentInvestigationAnalysis | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [analysisError, setAnalysisError] = useState<string | null>(null);

  // Q&A chat
  const [question, setQuestion] = useState('');
  const [isAsking, setIsAsking] = useState(false);
  const [qnaHistory, setQnaHistory] = useState<QnAPair[]>([]);
  const [qnaError, setQnaError] = useState<string | null>(null);

  // Copilot system readiness status
  const [copilotStatus, setCopilotStatus] = useState<{
    status: string;
    model: string;
    api_key_configured: boolean;
  } | null>(null);

  // Quick pre-set questions
  const sampleQuestions = [
    'What evidence suggests malicious credential compromise?',
    'Could there be a legitimate or benign explanation?',
    'What critical telemetry is missing to confirm attack success?',
    'What immediate containment steps should be prioritized?',
  ];

  // Fetch Copilot Status on mount
  useEffect(() => {
    fetch('/api/v1/investigation/status')
      .then((res) => (res.ok ? res.json() : null))
      .then((data) => {
        if (data) setCopilotStatus(data);
      })
      .catch((e) => console.warn('Copilot status fetch error:', e));

    // Fetch prior AI history if available
    fetch(`/api/v1/incidents/${incidentId}/ai-history`)
      .then((res) => (res.ok ? res.json() : []))
      .then((records: any[]) => {
        if (!records || records.length === 0) return;
        // Find most recent incident_summary
        const summaryRecord = records.find((r) => r.analysis_type === 'incident_summary');
        if (summaryRecord) {
          setAnalysis({
            incident_id: summaryRecord.incident_id,
            analysis_type: summaryRecord.analysis_type,
            model_used: summaryRecord.model,
            summary: summaryRecord.summary,
            observed_facts: summaryRecord.observed_facts || [],
            potential_explanations: summaryRecord.potential_explanations || [],
            evidence_references: summaryRecord.evidence_references || [],
            missing_information: summaryRecord.missing_information || [],
            recommended_next_steps: summaryRecord.recommended_next_steps || [],
            uncertainty_assessment: summaryRecord.uncertainty_assessment || '',
            evidence_truncated: summaryRecord.evidence_truncated || false,
            disclaimer:
              'AI-generated analysis is advisory and must be reviewed by a human analyst. Deterministic telemetry remains the primary source of truth.',
            created_at: summaryRecord.created_at,
          });
        }

        // Reconstruct Q&A
        const qnaRecords = records
          .filter((r) => r.analysis_type === 'analyst_query' && r.query)
          .map((r) => ({
            id: r.id,
            question: r.query,
            response: {
              incident_id: r.incident_id,
              question: r.query,
              answer: r.summary,
              observed_facts: r.observed_facts || [],
              evidence_references: r.evidence_references || [],
              uncertainty_assessment: r.uncertainty_assessment || '',
              recommended_next_steps: r.recommended_next_steps || [],
              missing_information: r.missing_information || [],
              model_used: r.model,
              evidence_truncated: r.evidence_truncated || false,
              disclaimer:
                'AI-generated analysis is advisory and must be reviewed by a human analyst.',
              created_at: r.created_at,
            },
            timestamp: r.created_at,
          }));
        setQnaHistory(qnaRecords.reverse());
      })
      .catch((e) => console.warn('Failed to load prior AI history:', e));
  }, [incidentId]);

  const handleRunAnalysis = async () => {
    setIsAnalyzing(true);
    setAnalysisError(null);

    try {
      const res = await fetch(`/api/v1/incidents/${incidentId}/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data?.error?.message || `HTTP ${res.status}: Failed to analyze incident`);
      }

      setAnalysis(data);
    } catch (err: any) {
      setAnalysisError(err.message || 'An unexpected error occurred during AI analysis');
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleAskQuestion = async (textToAsk?: string) => {
    const q = (textToAsk || question).trim();
    if (!q || isAsking) return;

    setIsAsking(true);
    setQnaError(null);

    try {
      const res = await fetch(`/api/v1/incidents/${incidentId}/ask`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ question: q }),
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data?.error?.message || `HTTP ${res.status}: Failed to answer question`);
      }

      const newPair: QnAPair = {
        id: `qna-${Date.now()}`,
        question: q,
        response: data,
        timestamp: new Date().toISOString(),
      };

      setQnaHistory((prev) => [...prev, newPair]);
      setQuestion('');
    } catch (err: any) {
      setQnaError(err.message || 'Error communicating with investigation copilot');
    } finally {
      setIsAsking(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Copilot Header & Banner */}
      <div className="p-4 rounded-lg bg-gradient-to-r from-indigo-950/40 via-purple-950/20 to-slate-900 border border-indigo-800/50 flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div className="flex items-start gap-3">
          <div className="p-2.5 rounded-lg bg-indigo-900/60 border border-indigo-700/60 text-indigo-300 shrink-0">
            <Bot className="w-5 h-5 text-indigo-400" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-sm font-semibold text-slate-100 flex items-center gap-1.5 font-mono">
                Gemini Investigation Copilot
              </h3>
              <span className="px-2 py-0.5 text-[10px] font-mono font-semibold rounded bg-indigo-950 text-indigo-300 border border-indigo-800/80">
                AI-Assisted • Advisory Only
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-1 max-w-2xl">
              Provides evidence-grounded hypotheses, identifies telemetry gaps, and suggests manual
              triage steps. Deterministic detection rules remain the authoritative source of truth.
            </p>
          </div>
        </div>

        {/* Action Button */}
        <div className="flex items-center gap-2 w-full md:w-auto">
          <button
            onClick={handleRunAnalysis}
            disabled={isAnalyzing}
            className="w-full md:w-auto px-4 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white text-xs font-mono font-medium transition-all shadow-lg shadow-indigo-900/30 flex items-center justify-center gap-2 shrink-0"
          >
            {isAnalyzing ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin text-indigo-200" />
                <span>Grounding Telemetry &amp; Reasoning...</span>
              </>
            ) : (
              <>
                <Sparkles className="w-4 h-4 text-indigo-200" />
                <span>{analysis ? 'Re-Analyze Incident' : 'Analyze Incident with Gemini'}</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Analysis Error Alert */}
      {analysisError && (
        <div className="p-3.5 rounded-lg bg-rose-950/60 border border-rose-800/80 text-rose-300 text-xs flex items-start gap-2.5">
          <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5 text-rose-400" />
          <div className="flex-1">
            <span className="font-semibold block font-mono">Copilot Execution Note</span>
            <span>{analysisError}</span>
          </div>
        </div>
      )}

      {/* Main Analysis Findings Card */}
      {analysis && (
        <div className="bg-slate-950/80 border border-slate-800 rounded-lg overflow-hidden shadow-xl">
          {/* Findings Header */}
          <div className="px-4 py-3 bg-slate-900/80 border-b border-slate-800 flex flex-wrap items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              <Sparkles className="w-4 h-4 text-indigo-400" />
              <span className="text-xs font-semibold text-slate-200 uppercase tracking-wider font-mono">
                Structured Investigation Findings
              </span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                Model: {analysis.model_used}
              </span>
              {analysis.evidence_truncated && (
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-amber-950/80 text-amber-300 border border-amber-800/60">
                  Telemetry Budget Capped
                </span>
              )}
            </div>
            <span className="text-[10px] text-slate-500 font-mono">
              Generated: {new Date(analysis.created_at).toLocaleTimeString()}
            </span>
          </div>

          <div className="p-4 sm:p-5 space-y-5 text-xs">
            {/* 1. Forensic Executive Summary */}
            <div>
              <span className="text-slate-400 uppercase tracking-wider font-mono font-semibold block mb-1.5 flex items-center gap-1.5">
                <Info className="w-3.5 h-3.5 text-indigo-400" /> Forensic Incident Summary
              </span>
              <div className="p-3.5 rounded-lg bg-indigo-950/20 border border-indigo-900/40 text-slate-200 leading-relaxed font-sans text-sm">
                {analysis.summary}
              </div>
            </div>

            {/* 2. Grid: Observed Facts vs Potential Explanations */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {/* Observed Facts */}
              <div className="p-3.5 rounded-lg bg-slate-900/60 border border-slate-800 space-y-2">
                <span className="text-emerald-400 uppercase tracking-wider font-mono font-semibold text-[11px] flex items-center gap-1.5">
                  <CheckCircle2 className="w-3.5 h-3.5" /> Observed Facts (Directly Corroborated)
                </span>
                {analysis.observed_facts.length === 0 ? (
                  <p className="text-slate-500 italic">No specific facts enumerated.</p>
                ) : (
                  <ul className="space-y-1.5 list-disc list-inside text-slate-300 leading-relaxed">
                    {analysis.observed_facts.map((fact, idx) => (
                      <li key={idx} className="pl-1">
                        <span className="text-slate-200">{fact}</span>
                      </li>
                    ))}
                  </ul>
                )}
              </div>

              {/* Potential Explanations */}
              <div className="p-3.5 rounded-lg bg-slate-900/60 border border-slate-800 space-y-2">
                <span className="text-amber-400 uppercase tracking-wider font-mono font-semibold text-[11px] flex items-center gap-1.5">
                  <FileQuestion className="w-3.5 h-3.5" /> Potential Explanations (Hypotheses)
                </span>
                {analysis.potential_explanations.length === 0 ? (
                  <p className="text-slate-500 italic">No alternative hypotheses noted.</p>
                ) : (
                  <ul className="space-y-1.5 list-disc list-inside text-slate-300 leading-relaxed">
                    {analysis.potential_explanations.map((hypo, idx) => (
                      <li key={idx} className="pl-1">
                        <span className="text-slate-200">{hypo}</span>
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            </div>

            {/* 3. Evidence References (Traceability) */}
            <div>
              <div className="flex items-center justify-between mb-2">
                <span className="text-cyan-400 uppercase tracking-wider font-mono font-semibold text-[11px] flex items-center gap-1.5">
                  <Terminal className="w-3.5 h-3.5" /> Cited Evidence Grounding References (
                  {analysis.evidence_references.length})
                </span>
                <span className="text-[10px] text-slate-500 font-mono">
                  Verified against incident telemetry catalog
                </span>
              </div>

              {analysis.evidence_references.length === 0 ? (
                <div className="p-3 rounded bg-slate-900/40 border border-slate-800/80 text-slate-500 italic">
                  No specific evidence IDs cited by the model.
                </div>
              ) : (
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
                  {analysis.evidence_references.map((ref, idx) => (
                    <div
                      key={idx}
                      className={`p-2.5 rounded-lg border flex flex-col justify-between transition-colors ${
                        ref.valid
                          ? 'bg-slate-900/80 border-slate-800 hover:border-cyan-800/60'
                          : 'bg-rose-950/20 border-rose-900/40'
                      }`}
                    >
                      <div className="flex items-start justify-between gap-2 mb-1.5">
                        <div className="flex items-center gap-1.5">
                          <span
                            className={`px-1.5 py-0.5 text-[10px] font-mono uppercase font-semibold rounded ${
                              ref.type === 'alert'
                                ? 'bg-amber-950 text-amber-300 border border-amber-800/80'
                                : 'bg-blue-950 text-blue-300 border border-blue-800/80'
                            }`}
                          >
                            {ref.type}
                          </span>
                          <span className="font-mono text-slate-300 text-[11px] font-semibold truncate max-w-[180px]">
                            {ref.id}
                          </span>
                        </div>
                        {ref.valid ? (
                          <span className="text-[10px] font-mono text-emerald-400 flex items-center gap-1">
                            <CheckCircle2 className="w-3 h-3" /> Grounded
                          </span>
                        ) : (
                          <span className="text-[10px] font-mono text-rose-400 flex items-center gap-1">
                            <AlertTriangle className="w-3 h-3" /> Unverified ID
                          </span>
                        )}
                      </div>
                      <p className="text-[11px] text-slate-400 line-clamp-2">{ref.description}</p>
                      {ref.type === 'alert' && onSelectAlert && ref.valid && (
                        <button
                          onClick={() => onSelectAlert(ref.id)}
                          className="mt-2 text-[10px] text-cyan-400 hover:text-cyan-300 font-mono flex items-center gap-1 self-start"
                        >
                          View Alert Telemetry <ArrowRight className="w-3 h-3" />
                        </button>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* 4. Telemetry Gaps & Recommended Next Steps */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {/* Missing Information */}
              <div className="p-3.5 rounded-lg bg-slate-900/60 border border-slate-800 space-y-2">
                <span className="text-purple-400 uppercase tracking-wider font-mono font-semibold text-[11px] flex items-center gap-1.5">
                  <HelpCircle className="w-3.5 h-3.5" /> Missing Telemetry &amp; Blind Spots
                </span>
                {analysis.missing_information.length === 0 ? (
                  <p className="text-slate-500 italic">No missing telemetry specified.</p>
                ) : (
                  <ul className="space-y-1.5 list-disc list-inside text-slate-300 leading-relaxed">
                    {analysis.missing_information.map((item, idx) => (
                      <li key={idx} className="pl-1">
                        <span className="text-slate-300">{item}</span>
                      </li>
                    ))}
                  </ul>
                )}
              </div>

              {/* Recommended Next Steps */}
              <div className="p-3.5 rounded-lg bg-slate-900/60 border border-slate-800 space-y-2">
                <span className="text-indigo-400 uppercase tracking-wider font-mono font-semibold text-[11px] flex items-center gap-1.5">
                  <ArrowRight className="w-3.5 h-3.5" /> Recommended Analyst Triage Steps
                </span>
                {analysis.recommended_next_steps.length === 0 ? (
                  <p className="text-slate-500 italic">No specific steps recommended.</p>
                ) : (
                  <ol className="space-y-1.5 list-decimal list-inside text-slate-300 leading-relaxed">
                    {analysis.recommended_next_steps.map((step, idx) => (
                      <li key={idx} className="pl-1">
                        <span className="text-slate-200">{step}</span>
                      </li>
                    ))}
                  </ol>
                )}
              </div>
            </div>

            {/* 5. Uncertainty Assessment & Advisory Notice */}
            <div className="pt-2 border-t border-slate-800/80 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 text-[11px] text-slate-400">
              <div className="flex items-center gap-1.5">
                <span className="font-mono font-semibold text-slate-300">Confidence Boundaries:</span>
                <span>{analysis.uncertainty_assessment || 'Evaluated within available evidence context.'}</span>
              </div>
              <div className="font-mono text-[10px] text-slate-500 italic">
                {analysis.disclaimer}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Investigation Q&A Chat Section */}
      <div className="bg-slate-950/80 border border-slate-800 rounded-lg p-4 sm:p-5 space-y-4">
        <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
          <div className="flex items-center gap-2">
            <Bot className="w-4 h-4 text-cyan-400" />
            <h4 className="text-xs font-semibold text-slate-200 uppercase tracking-wider font-mono">
              Ask Copilot About This Incident
            </h4>
          </div>
          <span className="text-[10px] text-slate-500 font-mono">
            Scoped strictly to this incident's telemetry evidence
          </span>
        </div>

        {/* Quick Sample Questions */}
        <div>
          <span className="text-[11px] text-slate-400 block mb-1.5 font-mono">
            Suggested Investigation Prompts:
          </span>
          <div className="flex flex-wrap gap-2">
            {sampleQuestions.map((sq, i) => (
              <button
                key={i}
                onClick={() => handleAskQuestion(sq)}
                disabled={isAsking}
                className="px-2.5 py-1 text-xs rounded bg-slate-900 hover:bg-slate-800 text-slate-300 hover:text-cyan-300 border border-slate-800 hover:border-cyan-800/60 transition-colors text-left font-sans disabled:opacity-50"
              >
                {sq}
              </button>
            ))}
          </div>
        </div>

        {/* Q&A Conversation Stream */}
        {qnaHistory.length > 0 && (
          <div className="space-y-4 pt-2">
            {qnaHistory.map((item) => (
              <div key={item.id} className="space-y-2">
                {/* Analyst Question */}
                <div className="flex items-start gap-2.5 max-w-2xl">
                  <div className="p-1.5 rounded bg-slate-800 text-slate-300 shrink-0 mt-0.5">
                    <User className="w-3.5 h-3.5" />
                  </div>
                  <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 text-xs text-slate-200 font-sans shadow-sm">
                    {item.question}
                  </div>
                </div>

                {/* AI Response */}
                <div className="flex items-start gap-2.5 pl-6 max-w-3xl">
                  <div className="p-1.5 rounded bg-indigo-950 text-indigo-400 border border-indigo-800 shrink-0 mt-0.5">
                    <Bot className="w-3.5 h-3.5" />
                  </div>
                  <div className="p-4 rounded-lg bg-indigo-950/20 border border-indigo-900/50 space-y-3 text-xs shadow-md">
                    <p className="text-slate-200 leading-relaxed text-sm font-sans">
                      {item.response.answer}
                    </p>

                    {/* Cited Evidence */}
                    {item.response.evidence_references && item.response.evidence_references.length > 0 && (
                      <div className="pt-2 border-t border-indigo-900/40">
                        <span className="text-[10px] font-mono text-cyan-400 block mb-1">
                          Cited Telemetry Grounding:
                        </span>
                        <div className="flex flex-wrap gap-2">
                          {item.response.evidence_references.map((ref, idx) => (
                            <span
                              key={idx}
                              className={`px-2 py-0.5 text-[10px] font-mono rounded border ${
                                ref.valid
                                  ? 'bg-slate-900 text-slate-300 border-slate-700'
                                  : 'bg-rose-950 text-rose-300 border-rose-800'
                              }`}
                            >
                              {ref.type.toUpperCase()}: {ref.id.slice(0, 8)}... (
                              {ref.valid ? 'Verified' : 'Unverified'})
                            </span>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Uncertainty Assessment */}
                    {item.response.uncertainty_assessment && (
                      <p className="text-[11px] text-slate-400 italic">
                        Note: {item.response.uncertainty_assessment}
                      </p>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}

        {/* Q&A Error Alert */}
        {qnaError && (
          <div className="p-3 rounded-lg bg-rose-950/50 border border-rose-800 text-rose-300 text-xs flex items-center justify-between">
            <span>{qnaError}</span>
            <button onClick={() => setQnaError(null)} className="underline hover:text-rose-200">
              Dismiss
            </button>
          </div>
        )}

        {/* Input Bar */}
        <div className="pt-2">
          <form
            onSubmit={(e) => {
              e.preventDefault();
              handleAskQuestion();
            }}
            className="flex items-center gap-2"
          >
            <input
              type="text"
              value={question}
              onChange={(e) => setQuestion(e.target.value)}
              disabled={isAsking}
              placeholder="Ask an investigation question (e.g., 'What IP addresses were targeted?', 'Is there evidence of lateral movement?')..."
              className="flex-1 bg-slate-900/90 border border-slate-800 focus:border-cyan-500 rounded-lg px-3.5 py-2.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:ring-1 focus:ring-cyan-500 transition-all font-sans"
              maxLength={500}
            />
            <button
              type="submit"
              disabled={!question.trim() || isAsking}
              className="px-4 py-2.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-40 text-white text-xs font-mono font-semibold transition-colors flex items-center gap-1.5 shrink-0"
            >
              {isAsking ? (
                <>
                  <Loader2 className="w-3.5 h-3.5 animate-spin" />
                  <span>Thinking...</span>
                </>
              ) : (
                <>
                  <Send className="w-3.5 h-3.5" />
                  <span>Ask Copilot</span>
                </>
              )}
            </button>
          </form>
          <div className="flex items-center justify-between mt-1.5 px-1 text-[10px] text-slate-500 font-mono">
            <span>Security logs and questions are evaluated within untrusted forensic boundaries.</span>
            <span>Max 500 characters</span>
          </div>
        </div>
      </div>
    </div>
  );
};
