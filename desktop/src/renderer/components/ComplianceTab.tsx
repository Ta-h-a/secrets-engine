import React, { useState, useEffect, useRef, useCallback } from 'react';
import {
  ComplianceRuleSummary,
  ComplianceProgressEvent,
  ComplianceProgressStep,
  SEVERITY_COLORS,
  SEVERITY_LABELS,
} from '../../shared/types';

// ─── Types ───────────────────────────────────────────────────────────────────

type TabState = 'idle' | 'processing' | 'done' | 'error';

interface PipelineStep {
  id: ComplianceProgressStep;
  label: string;
  sublabel: string;
}

const PIPELINE_STEPS: PipelineStep[] = [
  { id: 'pdf-extract', label: 'PDF TEXT EXTRACTED',      sublabel: 'Python / pdfplumber' },
  { id: 'ai-parse',    label: 'AGENT 1 — PARSE CONTROLS', sublabel: 'Gemini 1.5 Flash' },
  { id: 'ai-generate', label: 'AGENT 2 — GENERATE RULES', sublabel: 'Gemini 1.5 Flash' },
  { id: 'validate',    label: 'VALIDATE RULES',           sublabel: 'Regex + schema check' },
  { id: 'save',        label: 'WRITE TO DISK',            sublabel: '~/.secretlens/bin/rules/' },
];

const STEP_ORDER = PIPELINE_STEPS.map((s) => s.id);

function stepIndex(step: ComplianceProgressStep): number {
  return STEP_ORDER.indexOf(step);
}

// ─── Sub-components ──────────────────────────────────────────────────────────

const StepIndicator: React.FC<{
  step: PipelineStep;
  status: 'pending' | 'active' | 'done';
  detail?: string;
}> = ({ step, status, detail }) => (
  <div className="flex items-start gap-4 py-3 border-b border-gray-100 last:border-0">
    {/* State icon */}
    <div className="w-5 h-5 flex-shrink-0 mt-0.5 flex items-center justify-center">
      {status === 'done' && (
        <span className="w-5 h-5 bg-black flex items-center justify-center">
          <svg className="w-3 h-3 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="square" strokeWidth={3} d="M5 13l4 4L19 7" />
          </svg>
        </span>
      )}
      {status === 'active' && (
        <span className="w-5 h-5 border-2 border-black border-t-transparent animate-spin" />
      )}
      {status === 'pending' && (
        <span className="w-5 h-5 border border-gray-300" />
      )}
    </div>

    {/* Labels */}
    <div className="flex-1 min-w-0">
      <p
        className={`text-[11px] font-extrabold uppercase tracking-widest leading-none ${
          status === 'pending' ? 'text-gray-300' : 'text-black'
        }`}
      >
        {step.label}
      </p>
      <p
        className={`mt-1 text-[10px] font-mono ${
          status === 'pending' ? 'text-gray-200' : 'text-gray-500'
        }`}
      >
        {detail && status !== 'pending' ? detail : step.sublabel}
      </p>
    </div>
  </div>
);

const RuleRow: React.FC<{ rule: ComplianceRuleSummary }> = ({ rule }) => (
  <div className="flex items-center gap-3 py-2.5 border-b border-gray-100 last:border-0">
    <span
      className="text-[8px] font-extrabold uppercase tracking-widest border px-1.5 py-0.5 flex-shrink-0"
      style={{
        borderColor: SEVERITY_COLORS[rule.severity] ?? '#000',
        color: SEVERITY_COLORS[rule.severity] ?? '#000',
      }}
    >
      {SEVERITY_LABELS[rule.severity] ?? rule.severity.toUpperCase()}
    </span>
    <span className="text-[10px] font-mono text-gray-500 flex-shrink-0 w-20 truncate">
      {rule.ruleId}
    </span>
    <span className="text-[11px] font-medium text-black truncate flex-1">{rule.name}</span>
  </div>
);

// ─── Drop zone ────────────────────────────────────────────────────────────────

const DropZone: React.FC<{
  onFile: (path: string) => void;
  disabled: boolean;
}> = ({ onFile, disabled }) => {
  const inputRef = useRef<HTMLInputElement>(null);
  const [dragOver, setDragOver] = useState(false);

  const handleDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setDragOver(false);
      if (disabled) return;
      const file = e.dataTransfer.files[0];
      // Electron exposes .path on File objects
      const fp = (file as File & { path?: string }).path ?? file.name;
      if (fp && fp.toLowerCase().endsWith('.pdf')) onFile(fp);
    },
    [disabled, onFile],
  );

  const handleChange = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const file = e.target.files?.[0];
      if (!file) return;
      const fp = (file as File & { path?: string }).path ?? file.name;
      if (fp) onFile(fp);
      // Reset so the same file can be re-selected
      e.target.value = '';
    },
    [onFile],
  );

  const handleBrowse = useCallback(async () => {
    if (disabled) return;
    // Try native dialog first (cleaner path resolution)
    const picked: string | null = await window.electronAPI.pickPdf();
    if (picked) { onFile(picked); return; }
    // Fallback: HTML file input
    inputRef.current?.click();
  }, [disabled, onFile]);

  return (
    <div
      className={`border-2 border-dashed transition-colors cursor-pointer select-none ${
        disabled
          ? 'border-gray-200 cursor-not-allowed'
          : dragOver
          ? 'border-black bg-gray-50'
          : 'border-gray-300 hover:border-gray-500'
      }`}
      onDragOver={(e) => { e.preventDefault(); if (!disabled) setDragOver(true); }}
      onDragLeave={() => setDragOver(false)}
      onDrop={handleDrop}
      onClick={handleBrowse}
    >
      <div className="flex flex-col items-center justify-center gap-3 py-12 px-8">
        {/* Upload icon */}
        <div className="w-10 h-10 border border-gray-300 flex items-center justify-center">
          <svg className="w-5 h-5 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="square" strokeWidth={1.5} d="M4 16v2a2 2 0 002 2h12a2 2 0 002-2v-2M16 12l-4-4m0 0L8 12m4-4v12" />
          </svg>
        </div>
        <div className="text-center">
          <p className="text-[13px] font-semibold text-gray-700">
            Drop a compliance PDF here
          </p>
          <p className="text-[11px] text-gray-400 mt-1">
            or click to browse — ISO 42001, SOC 2, GDPR, etc.
          </p>
        </div>
      </div>
      <input
        ref={inputRef}
        type="file"
        accept=".pdf"
        className="hidden"
        onChange={handleChange}
      />
    </div>
  );
};

// ─── Main component ───────────────────────────────────────────────────────────

interface ComplianceTabProps {
  onClose: () => void;
}

export const ComplianceTab: React.FC<ComplianceTabProps> = ({ onClose }) => {
  const [tabState, setTabState] = useState<TabState>('idle');
  const [selectedFile, setSelectedFile] = useState<string | null>(null);
  const [progress, setProgress] = useState(0);
  const [currentMessage, setCurrentMessage] = useState('');
  const [currentDetail, setCurrentDetail] = useState('');
  const [activeStep, setActiveStep] = useState<ComplianceProgressStep | null>(null);
  const [completedSteps, setCompletedSteps] = useState<Set<ComplianceProgressStep>>(new Set());
  const [stepDetails, setStepDetails] = useState<Partial<Record<ComplianceProgressStep, string>>>({});
  const [installedRules, setInstalledRules] = useState<ComplianceRuleSummary[]>([]);
  const [errorMessage, setErrorMessage] = useState('');
  const [showRules, setShowRules] = useState(false);
  const unsubscribeRef = useRef<(() => void) | null>(null);

  // Load existing rules on mount
  useEffect(() => {
    window.electronAPI.getComplianceRules().then((rules) => {
      setInstalledRules(rules);
      if (rules.length > 0) setTabState('done');
    });
  }, []);

  // Cleanup IPC listener on unmount
  useEffect(() => {
    return () => { unsubscribeRef.current?.(); };
  }, []);

  const handleFile = useCallback(async (filePath: string) => {
    setSelectedFile(filePath);
    setTabState('processing');
    setProgress(0);
    setCurrentMessage('Initialising pipeline…');
    setCurrentDetail('');
    setActiveStep(null);
    setCompletedSteps(new Set());
    setStepDetails({});
    setErrorMessage('');

    // Unsubscribe from previous listener
    unsubscribeRef.current?.();

    // Subscribe to progress events
    const unsub = window.electronAPI.onComplianceProgress((event: ComplianceProgressEvent) => {
      setProgress(event.progress);
      setCurrentMessage(event.message);
      setCurrentDetail(event.detail ?? '');

      if (event.step === 'error') {
        setErrorMessage(event.message);
        setTabState('error');
        return;
      }

      if (event.step === 'complete') {
        setActiveStep(null);
        return;
      }

      // Mark previous steps done
      const idx = stepIndex(event.step);
      setCompletedSteps((prev) => {
        const next = new Set(prev);
        // mark all earlier steps done
        STEP_ORDER.slice(0, idx).forEach((s) => next.add(s as ComplianceProgressStep));
        return next;
      });
      setActiveStep(event.step);

      if (event.detail) {
        setStepDetails((prev) => ({ ...prev, [event.step]: event.detail }));
      }
    });
    unsubscribeRef.current = unsub;

    // Kick off the pipeline
    const result = await window.electronAPI.processPdf(filePath);
    unsubscribeRef.current?.();

    if (result.success && result.rules) {
      setInstalledRules(result.rules);
      setCompletedSteps(new Set(STEP_ORDER as ComplianceProgressStep[]));
      setActiveStep(null);
      setProgress(100);
      setTabState('done');
    } else if (!result.success) {
      setErrorMessage(result.error ?? 'Unknown error');
      setTabState('error');
    }
  }, []);

  const handleDeleteRules = useCallback(async () => {
    await window.electronAPI.deleteComplianceRules();
    setInstalledRules([]);
    setTabState('idle');
    setSelectedFile(null);
    setProgress(0);
  }, []);

  // ── Rendering ──────────────────────────────────────────────────────────────

  return (
    <div className="fixed inset-0 bg-white z-50 flex flex-col overflow-hidden">

      {/* ── Header ─────────────────────────────────────────────────────── */}
      <div className="flex items-center justify-between px-8 py-5 border-b border-gray-200 flex-shrink-0">
        <div className="flex items-center gap-4">
          <button
            onClick={onClose}
            className="flex items-center gap-2 text-[11px] font-extrabold uppercase tracking-widest text-gray-400 hover:text-black transition-colors"
          >
            <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="square" strokeWidth={2.5} d="M15 19l-7-7 7-7" />
            </svg>
            Back
          </button>
          <div className="w-px h-4 bg-gray-200" />
          <span className="text-[11px] font-extrabold uppercase tracking-[0.2em] text-black">
            Compliance Rules
          </span>
        </div>

        {installedRules.length > 0 && tabState !== 'processing' && (
          <span className="text-[10px] font-mono text-gray-400">
            {installedRules.length} rules active
          </span>
        )}
      </div>

      {/* ── Body ───────────────────────────────────────────────────────── */}
      <div className="flex-1 overflow-y-auto px-8 py-8">

        {/* ── IDLE: drop zone ──────────────────────────────────────────── */}
        {tabState === 'idle' && (
          <div className="max-w-xl mx-auto">
            <div className="mb-8">
              <h2 className="text-[15px] font-extrabold uppercase tracking-widest text-black mb-3">
                Upload Compliance Document
              </h2>
              <p className="text-[12px] text-gray-500 leading-relaxed">
                Upload any compliance standard PDF — ISO/IEC 42001, SOC 2, GDPR, PCI-DSS, or custom.
                A multi-agent AI pipeline will parse your document and generate detection rules
                that run on every git commit.
              </p>
            </div>
            <DropZone onFile={handleFile} disabled={false} />
          </div>
        )}

        {/* ── PROCESSING: step-by-step timeline ────────────────────────── */}
        {tabState === 'processing' && (
          <div className="max-w-xl mx-auto">
            {/* File label */}
            <div className="mb-6 flex items-center gap-3">
              <div className="w-4 h-4 border border-gray-400 flex-shrink-0">
                <svg className="w-full h-full p-0.5 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="square" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                </svg>
              </div>
              <span className="text-[11px] font-mono text-gray-600 truncate">
                {selectedFile ? selectedFile.split('/').pop() : '…'}
              </span>
            </div>

            {/* Pipeline steps */}
            <div className="border border-gray-200 mb-6">
              {PIPELINE_STEPS.map((step) => {
                const done   = completedSteps.has(step.id);
                const active = activeStep === step.id;
                return (
                  <StepIndicator
                    key={step.id}
                    step={step}
                    status={done ? 'done' : active ? 'active' : 'pending'}
                    detail={stepDetails[step.id]}
                  />
                );
              })}
            </div>

            {/* Progress bar */}
            <div className="mb-4">
              <div className="flex justify-between items-center mb-1.5">
                <span className="text-[10px] font-mono text-gray-400">{currentMessage}</span>
                <span className="text-[10px] font-mono text-gray-400">{progress}%</span>
              </div>
              <div className="h-1 bg-gray-100 w-full">
                <div
                  className="h-1 bg-black transition-all duration-300 ease-out"
                  style={{ width: `${progress}%` }}
                />
              </div>
            </div>

            {/* Detail line */}
            {currentDetail && (
              <p className="text-[10px] font-mono text-gray-400 truncate">{currentDetail}</p>
            )}
          </div>
        )}

        {/* ── DONE: rules list ─────────────────────────────────────────── */}
        {tabState === 'done' && (
          <div className="max-w-xl mx-auto">
            {/* Success header */}
            <div className="flex items-center gap-4 mb-8">
              <div className="w-8 h-8 bg-black flex items-center justify-center flex-shrink-0">
                <svg className="w-4 h-4 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="square" strokeWidth={2.5} d="M5 13l4 4L19 7" />
                </svg>
              </div>
              <div>
                <p className="text-[13px] font-extrabold uppercase tracking-widest text-black">
                  {installedRules.length} Rules Installed
                </p>
                <p className="text-[11px] text-gray-400 mt-0.5">
                  Active on every git commit — compliance findings appear in the findings view
                </p>
              </div>
            </div>

            {/* Rules list toggle */}
            <div className="mb-4">
              <button
                onClick={() => setShowRules((v) => !v)}
                className="text-[11px] font-extrabold uppercase tracking-widest text-black border-b border-black pb-0.5 flex items-center gap-2"
              >
                {showRules ? 'Hide' : 'Show'} Rules
                <svg
                  className={`w-3 h-3 transition-transform ${showRules ? 'rotate-180' : ''}`}
                  fill="none" stroke="currentColor" viewBox="0 0 24 24"
                >
                  <path strokeLinecap="square" strokeWidth={2.5} d="M19 9l-7 7-7-7" />
                </svg>
              </button>
            </div>

            {showRules && (
              <div className="border border-gray-200 mb-6 max-h-80 overflow-y-auto">
                {installedRules.map((r) => (
                  <RuleRow key={r.ruleId} rule={r} />
                ))}
              </div>
            )}

            {/* Actions */}
            <div className="flex gap-3 pt-4 border-t border-gray-200">
              <button
                onClick={() => { setTabState('idle'); setSelectedFile(null); }}
                className="text-[11px] font-extrabold uppercase tracking-widest border border-black text-black px-5 py-2.5 hover:bg-black hover:text-white transition-colors"
              >
                Add More
              </button>
              <button
                onClick={handleDeleteRules}
                className="text-[11px] font-extrabold uppercase tracking-widest border border-gray-300 text-gray-400 px-5 py-2.5 hover:border-red-500 hover:text-red-500 transition-colors"
              >
                Clear All Rules
              </button>
            </div>
          </div>
        )}

        {/* ── ERROR ────────────────────────────────────────────────────── */}
        {tabState === 'error' && (
          <div className="max-w-xl mx-auto">
            <div className="flex items-start gap-4 p-6 border border-[#FF0000]">
              <div className="w-5 h-5 flex-shrink-0 mt-0.5 flex items-center justify-center bg-[#FF0000]">
                <svg className="w-3 h-3 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="square" strokeWidth={2.5} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </div>
              <div>
                <p className="text-[11px] font-extrabold uppercase tracking-widest text-[#FF0000] mb-2">
                  Pipeline Error
                </p>
                <p className="text-[12px] font-mono text-gray-700 break-words whitespace-pre-wrap">
                  {errorMessage}
                </p>
              </div>
            </div>

            <div className="flex gap-3 mt-6">
              <button
                onClick={() => selectedFile && handleFile(selectedFile)}
                className="text-[11px] font-extrabold uppercase tracking-widest border border-black text-black px-5 py-2.5 hover:bg-black hover:text-white transition-colors"
              >
                Retry
              </button>
              <button
                onClick={() => { setTabState('idle'); setSelectedFile(null); }}
                className="text-[11px] font-extrabold uppercase tracking-widest border border-gray-300 text-gray-400 px-5 py-2.5 hover:border-gray-500 hover:text-gray-600 transition-colors"
              >
                Choose Different File
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
