import React, { useState, useEffect, useCallback } from 'react';
import {
  Finding,
  ResolutionStatus,
  FindingResolution,
  CommitDecision,
  CommitStats,
  SecretIngestResponse,
  AwsCredentials,
  AwsCredentialCheckResult,
  AwsCredentialSaveResult,
  ComplianceRuleSummary,
  ComplianceProgressEvent,
  SEVERITY_COLORS,
  SEVERITY_LABELS,
  detectLanguage,
} from '../shared/types';
import { SecretIngestionService } from './services/SecretIngestionService';
import { ScriptModal } from './components/ScriptModal';
import { AllResolvedScreen } from './components/AllResolvedScreen';
import { PartialResolutionScreen } from './components/PartialResolutionScreen';
import { AwsCredentialsModal } from './components/AwsCredentialsModal';
import { ComplianceTab } from './components/ComplianceTab';

// ─── ElectronAPI type declaration ────────────────────────────────────────────

declare global {
  interface Window {
    electronAPI: {
      getFindings: () => Promise<Finding[]>;
      resolveCommit: (data: CommitDecision) => Promise<{ success: boolean }>;
      extractSecret: (filePath: string, lineNumber: number) => Promise<{ success: boolean; secret_value: string; error?: string }>;
      executeScript: (script: string, language: string) => Promise<{ success: boolean; output: string; error?: string; aws_key_name?: string }>;
      replaceSecret: (filePath: string, lineNumber: number, secretValue: string, awsKeyName: string) => Promise<{ success: boolean; error?: string }>;
      getSettings: () => Promise<{ aiProvider: string; theme: string; autoBlock: boolean }>;
      checkAwsCredentials: () => Promise<AwsCredentialCheckResult>;
      saveAwsCredentials: (creds: AwsCredentials) => Promise<AwsCredentialSaveResult>;
      getRepoName: () => Promise<string>;
      onFindingsReceived: (callback: (findings: Finding[]) => void) => void;
      // Compliance
      pickPdf: () => Promise<string | null>;
      processPdf: (filePath: string) => Promise<{ success: boolean; rules?: ComplianceRuleSummary[]; error?: string }>;
      getComplianceRules: () => Promise<ComplianceRuleSummary[]>;
      deleteComplianceRules: () => Promise<{ count: number }>;
      onComplianceProgress: (callback: (event: ComplianceProgressEvent) => void) => () => void;
    };
  }
}

// ─── Types ───────────────────────────────────────────────────────────────────

type AppScreen = 'findings' | 'all-resolved' | 'partial-resolved';

interface ModalState {
  findingId: string;
  findingTitle: string;
  filePath: string;
  lineNumber: number;
  saveScript: string;
  secretKey: string;
}

/** Tracks whether the AWS credentials modal is open and why */
interface AwsModalState {
  /** The finding to resolve once credentials are confirmed */
  pendingFinding: Finding;
  /** Optional error hint to pre-populate (e.g. "expired") */
  errorHint?: string;
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function groupFindingsByFile(findings: Finding[]): Record<string, Finding[]> {
  return findings.reduce<Record<string, Finding[]>>((acc, f) => {
    if (!acc[f.filePath]) acc[f.filePath] = [];
    acc[f.filePath].push(f);
    return acc;
  }, {});
}

// ─── Severity badge ──────────────────────────────────────────────────────────

const SeverityBadge: React.FC<{ severity: string }> = ({ severity }) => (
  <span
    className="text-[9px] font-extrabold uppercase tracking-widest border px-2 py-0.5"
    style={{ borderColor: SEVERITY_COLORS[severity] ?? '#000', color: SEVERITY_COLORS[severity] ?? '#000' }}
  >
    {SEVERITY_LABELS[severity] ?? severity.toUpperCase()}
  </span>
);

// ─── Finding row ─────────────────────────────────────────────────────────────

interface FindingRowProps {
  finding: Finding;
  resolution: FindingResolution | undefined;
  onResolve: (finding: Finding) => void;
  onSkip: (findingId: string) => void;
}

const FindingRow: React.FC<FindingRowProps> = ({ finding, resolution, onResolve, onSkip }) => {
  const status = resolution?.status ?? 'pending';

  const statusBadge = () => {
    switch (status) {
      case 'resolved':
        return (
          <span className="flex items-center gap-1.5 text-[10px] font-extrabold uppercase tracking-widest text-black">
            <span className="w-3.5 h-3.5 bg-black flex items-center justify-center flex-shrink-0">
              <svg className="w-2.5 h-2.5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="square" strokeWidth={3} d="M5 13l4 4L19 7" />
              </svg>
            </span>
            Resolved
          </span>
        );
      case 'resolving':
        return (
          <span className="flex items-center gap-1.5 text-[10px] font-extrabold uppercase tracking-widest text-gray-500">
            <span className="w-3.5 h-3.5 border-2 border-gray-400 border-t-transparent animate-spin flex-shrink-0" />
            Resolving…
          </span>
        );
      case 'failed':
        return (
          <span className="text-[10px] font-extrabold uppercase tracking-widest text-[#FF0000]">
            Failed
          </span>
        );
      case 'skipped':
        return (
          <span className="text-[10px] font-extrabold uppercase tracking-widest text-gray-400">
            {resolution?.skipReason ? 'Not applicable' : 'Skipped'}
          </span>
        );
      default:
        return null;
    }
  };

  return (
    <div
      className={`flex flex-col gap-1 py-4 border-b border-gray-100 last:border-0 transition-opacity ${
        status === 'resolved' ? 'opacity-50' : ''
      }`}
    >
      <div className="flex items-center gap-4">
        {/* Severity bar */}
        <div
          className="w-1 self-stretch flex-shrink-0"
          style={{ backgroundColor: SEVERITY_COLORS[finding.severity] ?? '#000' }}
        />

        {/* Details */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-0.5">
            <SeverityBadge severity={finding.severity} />
            {finding.type === 'Compliance' && (
              <span className="text-[9px] font-extrabold uppercase tracking-widest border border-purple-500 text-purple-600 px-2 py-0.5">
                {finding.ruleId?.replace(/^COMP-/, '').replace(/-/g, '.') ?? 'Compliance'}
              </span>
            )}
            <span className="text-xs font-bold uppercase tracking-tight truncate">{finding.title}</span>
          </div>
          <p className="text-[11px] font-mono text-gray-400 uppercase">
            Line {finding.lineNumber}
          </p>
          {finding.message && (
            <p className="text-[11px] text-gray-500 mt-0.5 line-clamp-1">{finding.message}</p>
          )}
        </div>

        {/* Status or actions */}
        <div className="flex items-center gap-2 flex-shrink-0">
          {statusBadge()}
          {(status === 'pending' || status === 'failed') && (
            <>
              <button
                onClick={() => onResolve(finding)}
                className="bg-black text-white text-[10px] font-extrabold uppercase px-3 py-1.5 tracking-widest hover:bg-zinc-700 transition-colors"
              >
                Resolve
              </button>
              <button
                onClick={() => onSkip(finding.id)}
                className="border border-gray-300 text-gray-500 text-[10px] font-extrabold uppercase px-3 py-1.5 tracking-widest hover:border-black hover:text-black transition-colors"
              >
                Skip
              </button>
            </>
          )}
        </div>
      </div>

      {/* Skip reason hint — shown below the row when auto-skipped */}
      {status === 'skipped' && resolution?.skipReason && (
        <div className="ml-5 pl-3 border-l-2 border-gray-200">
          <p className="text-[10px] text-gray-400 leading-relaxed">{resolution.skipReason}</p>
        </div>
      )}
    </div>
  );
};

// ─── File card ───────────────────────────────────────────────────────────────

interface FileCardProps {
  filePath: string;
  findings: Finding[];
  resolutions: Map<string, FindingResolution>;
  onResolve: (finding: Finding) => void;
  onSkip: (findingId: string) => void;
}

const FileCard: React.FC<FileCardProps> = ({ filePath, findings, resolutions, onResolve, onSkip }) => {
  const resolvedCount = findings.filter((f) => resolutions.get(f.id)?.status === 'resolved').length;
  const skippedCount = findings.filter((f) => resolutions.get(f.id)?.status === 'skipped').length;
  const hasCritical = findings.some((f) => f.severity === 'critical');
  const allDone = resolvedCount + skippedCount === findings.length;

  return (
    <div className={`border border-gray-200 hover:border-black transition-colors ${allDone ? 'opacity-60' : ''}`}>
      {/* File header */}
      <div className="flex items-center justify-between px-6 py-4 bg-gray-50 border-b border-gray-200">
        <div className="flex items-center gap-3 min-w-0">
          <div className="w-1.5 h-1.5 bg-black flex-shrink-0" />
          <span className="text-xs font-mono font-bold uppercase tracking-tight truncate">{filePath}</span>
        </div>
        <div className="flex items-center gap-3 flex-shrink-0 ml-4">
          {resolvedCount > 0 && (
            <span className="text-[10px] font-extrabold uppercase tracking-widest text-black">
              {resolvedCount}/{findings.length} resolved
            </span>
          )}
          <span
            className="text-[9px] font-extrabold uppercase tracking-widest border px-2 py-0.5"
            style={{
              borderColor: hasCritical ? '#FF0000' : '#FF8A00',
              color: hasCritical ? '#FF0000' : '#FF8A00',
            }}
          >
            {findings.length} finding{findings.length !== 1 ? 's' : ''}
          </span>
        </div>
      </div>

      {/* Findings rows */}
      <div className="px-6">
        {findings.map((f) => (
          <FindingRow
            key={f.id}
            finding={f}
            resolution={resolutions.get(f.id)}
            onResolve={onResolve}
            onSkip={onSkip}
          />
        ))}
      </div>
    </div>
  );
};

// ─── Main App ────────────────────────────────────────────────────────────────

function App() {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [repoName, setRepoName] = useState<string>('unknown-repo');
  const [resolutions, setResolutions] = useState<Map<string, FindingResolution>>(new Map());
  const [modal, setModal] = useState<ModalState | null>(null);
  const [screen, setScreen] = useState<AppScreen>('findings');
  const [stats, setStats] = useState<CommitStats | null>(null);
  const [ingesting, setIngesting] = useState<string | null>(null); // findingId currently fetching API
  const [showCompliance, setShowCompliance] = useState(false);

  // AWS credentials state
  const [awsCredentialsValid, setAwsCredentialsValid] = useState(false);
  const [awsModal, setAwsModal] = useState<AwsModalState | null>(null);

  useEffect(() => {
    const load = async () => {
      try {
        const [data, credCheck, name] = await Promise.all([
          window.electronAPI.getFindings(),
          window.electronAPI.checkAwsCredentials(),
          window.electronAPI.getRepoName(),
        ]);
        setFindings(data ?? []);
        setAwsCredentialsValid(credCheck.valid);
        setRepoName(name);
      } catch (e) {
        console.error('Failed to load findings or check AWS credentials:', e);
      } finally {
        setLoading(false);
      }
    };

    load();

    window.electronAPI.onFindingsReceived((data) => {
      setFindings(data ?? []);
    });
  }, []);

  // ── Resolution helpers ────────────────────────────────────────────────────

  const setResolutionStatus = useCallback((findingId: string, update: Partial<FindingResolution>) => {
    setResolutions((prev) => {
      const next = new Map(prev);
      const existing = next.get(findingId) ?? { findingId, status: 'pending' };
      next.set(findingId, { ...existing, ...update });
      return next;
    });
  }, []);

  // ── Skip a finding ────────────────────────────────────────────────────────

  const handleSkip = useCallback((findingId: string) => {
    setResolutionStatus(findingId, { status: 'skipped' });
  }, [setResolutionStatus]);

  // ── Open resolve modal - calls API first ──────────────────────────────────

  const handleResolve = useCallback(async (finding: Finding) => {
    if (ingesting) return; // Already fetching

    // Gate: require valid AWS credentials before invoking the resolve flow
    if (!awsCredentialsValid) {
      setAwsModal({ pendingFinding: finding });
      return;
    }

    await doResolve(finding);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [ingesting, awsCredentialsValid]);

  // ── Internal: execute the actual resolve flow ─────────────────────────────

  const doResolve = useCallback(async (finding: Finding) => {
    if (ingesting) return;

    setIngesting(finding.id);
    setResolutionStatus(finding.id, { status: 'resolving' });

    try {
      // Extract the raw secret value from the file
      const extracted = await window.electronAPI.extractSecret(finding.filePath, finding.lineNumber);
      if (!extracted.success || !extracted.secret_value) {
        // No literal secret on this line — this is a code-quality/injection finding
        // (e.g. exec(), eval(), SQL injection) rather than a hardcoded credential.
        // Auto-skip it with a clear reason instead of surfacing an error.
        const reason = 'No secret literal on this line — this finding flags dangerous code, not a stored credential. Review and fix the code manually.';
        setResolutionStatus(finding.id, { status: 'skipped', skipReason: reason });
        setIngesting(null);
        return;
      }

      const language = detectLanguage(finding.filePath);
      const secretType = deriveSecretType(finding);

      const apiResponse: SecretIngestResponse = await SecretIngestionService.ingestSecret(
        secretType,
        extracted.secret_value,
        language,
        repoName,
        'development',
      );

      // Extract the secret name directly from the script source — this is more
      // reliable than waiting for runtime output since the API always embeds it
      // as `secret_name = "codeguard/type/repo/env"`.
      const secretKey = extractSecretNameFromScript(apiResponse.save_script) ?? 'codeguard-secret';

      // Open modal with the returned script
      setModal({
        findingId: finding.id,
        findingTitle: finding.title,
        filePath: finding.filePath,
        lineNumber: finding.lineNumber,
        saveScript: apiResponse.save_script,
        secretKey,
      });

      // Reset status back to pending while user reviews the modal
      setResolutionStatus(finding.id, { status: 'pending' });
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      console.error('Failed to fetch save script:', msg);
      setResolutionStatus(finding.id, { status: 'failed', errorMessage: msg });
    } finally {
      setIngesting(null);
    }
  }, [ingesting, setResolutionStatus]);

  // ── Script ran successfully ───────────────────────────────────────────────

  const handleScriptSuccess = useCallback((findingId: string, awsKeyName: string) => {
    setResolutionStatus(findingId, { status: 'resolved', awsKeyName });
    setModal(null);
  }, [setResolutionStatus]);

  // ── AWS credentials modal handlers ────────────────────────────────────────

  const handleAwsCredentialsSaved = useCallback(async () => {
    setAwsCredentialsValid(true);
    const pending = awsModal?.pendingFinding;
    setAwsModal(null);
    if (pending) {
      // Auto-proceed with the resolve flow now that credentials are confirmed
      await doResolve(pending);
    }
  }, [awsModal, doResolve]);

  const handleAwsCredentialsCancelled = useCallback(() => {
    setAwsModal(null);
  }, []);

  // ── Finalize - calculate stats and show correct screen ───────────────────

  const handleFinalize = useCallback(async () => {
    const findingsByFile = groupFindingsByFile(findings);
    const allFilePaths = Object.keys(findingsByFile);

    const resolvedFiles: string[] = [];
    const blockedFiles: string[] = [];
    const modifiedFiles: string[] = [];

    for (const filePath of allFilePaths) {
      const fileFindings = findingsByFile[filePath];
      const allResolved = fileFindings.every((f) => {
        const r = resolutions.get(f.id);
        return r?.status === 'resolved' || r?.status === 'skipped';
      });
      const hasResolved = fileFindings.some((f) => resolutions.get(f.id)?.status === 'resolved');
      const hasUnresolved = fileFindings.some((f) => {
        const r = resolutions.get(f.id);
        return !r || r.status === 'pending' || r.status === 'failed';
      });

      if (!hasUnresolved) {
        resolvedFiles.push(filePath);
      } else {
        blockedFiles.push(filePath);
      }

      if (hasResolved) {
        modifiedFiles.push(filePath);
      }
    }

    const resolvedCount = Array.from(resolutions.values()).filter((r) => r.status === 'resolved').length;
    const skippedCount = Array.from(resolutions.values()).filter((r) => r.status === 'skipped').length;

    const computedStats: CommitStats = {
      total_findings: findings.length,
      resolved: resolvedCount,
      skipped: skippedCount,
      files_modified: modifiedFiles,
      files_committed: resolvedFiles,
      files_blocked: blockedFiles,
    };

    setStats(computedStats);

    if (blockedFiles.length === 0) {
      setScreen('all-resolved');
    } else {
      setScreen('partial-resolved');
    }
  }, [findings, resolutions]);

  // ── Commit resolved files ─────────────────────────────────────────────────

  const commitResolved = useCallback(async () => {
    if (!stats) return;

    const decision: CommitDecision = {
      allowed: stats.files_committed,
      blocked: stats.files_blocked,
      resolved_count: stats.resolved,
      skipped_count: stats.skipped,
      modified_files: stats.files_modified,
      stats,
    };

    await window.electronAPI.resolveCommit(decision);
    window.close();
  }, [stats]);

  const abortCommit = useCallback(async () => {
    const decision: CommitDecision = {
      allowed: [],
      blocked: findings.map((f) => f.filePath).filter((v, i, a) => a.indexOf(v) === i),
      resolved_count: 0,
      skipped_count: 0,
      modified_files: [],
      stats: {
        total_findings: findings.length,
        resolved: 0,
        skipped: 0,
        files_modified: [],
        files_committed: [],
        files_blocked: findings.map((f) => f.filePath).filter((v, i, a) => a.indexOf(v) === i),
      },
    };

    await window.electronAPI.resolveCommit(decision);
    window.close();
  }, [findings]);

  // ── Derived state ────────────────────────────────────────────────────────

  const pendingCount = findings.filter((f) => {
    const r = resolutions.get(f.id);
    return !r || r.status === 'pending' || r.status === 'failed';
  }).length;

  const resolvedCount = Array.from(resolutions.values()).filter((r) => r.status === 'resolved').length;
  const skippedCount = Array.from(resolutions.values()).filter((r) => r.status === 'skipped').length;
  const processedCount = resolvedCount + skippedCount;
  const allProcessed = processedCount === findings.length && findings.length > 0;

  // ── Screen routing ────────────────────────────────────────────────────────

  if (screen === 'all-resolved' && stats) {
    return <AllResolvedScreen stats={stats} onCommit={commitResolved} />;
  }

  if (screen === 'partial-resolved' && stats) {
    return (
      <PartialResolutionScreen
        stats={stats}
        onCommitResolved={commitResolved}
        onAbort={abortCommit}
      />
    );
  }

  // ── Loading ───────────────────────────────────────────────────────────────

  if (loading) {
    return (
      <div className="min-h-screen bg-white flex items-center justify-center">
        <div className="text-center">
          <div className="w-10 h-10 border-2 border-black border-t-transparent animate-spin mx-auto mb-6" />
          <p className="text-xs font-extrabold uppercase tracking-[0.3em]">Loading findings…</p>
        </div>
      </div>
    );
  }

  // ── Main findings screen ──────────────────────────────────────────────────

  const findingsByFile = groupFindingsByFile(findings);
  const criticalCount = findings.filter((f) => f.severity === 'critical').length;
  const highCount = findings.filter((f) => f.severity === 'high').length;
  const mediumCount = findings.filter((f) => f.severity === 'medium').length;
  const lowCount = findings.filter((f) => f.severity === 'low').length;

  return (
    <div className="min-h-screen bg-white flex flex-col">

      {/* Header */}
      <header className="bg-black text-white px-8 py-7 flex items-center justify-between flex-shrink-0">
        <div className="flex items-center gap-3">
          <div className="w-7 h-7 border border-white flex items-center justify-center">
            <svg className="w-4 h-4 text-white" fill="currentColor" viewBox="0 0 48 48">
              <path d="M24 4C25.7818 14.2173 33.7827 22.2182 44 24C33.7827 25.7818 25.7818 33.7827 24 44C22.2182 33.7827 14.2173 25.7818 4 24C14.2173 22.2182 22.2182 14.2173 24 4Z" />
            </svg>
          </div>
          <h1 className="text-lg font-black tracking-tighter uppercase">SecretLens</h1>
        </div>
        <div className="flex items-center gap-6">
          {/* Compliance button */}
          <button
            onClick={() => setShowCompliance(true)}
            className="flex items-center gap-1.5 text-[9px] font-extrabold uppercase tracking-widest text-gray-400 hover:text-white transition-colors"
            title="Open Compliance Manager"
          >
            <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="square" strokeLinejoin="miter" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
            </svg>
            Compliance
          </button>
          {/* AWS credential indicator — only show the "required" prompt when not yet configured */}
          {!awsCredentialsValid && (
            <button
              onClick={() => {
                if (findings.length > 0) {
                  setAwsModal({ pendingFinding: findings[0]! });
                }
              }}
              className="flex items-center gap-1.5 text-[9px] font-extrabold uppercase tracking-widest text-yellow-400 hover:text-yellow-300 transition-colors"
              title="Click to configure AWS credentials"
            >
              <span className="w-1.5 h-1.5 rounded-full bg-yellow-400" />
              AWS Required
            </button>
          )}
          {awsCredentialsValid && (
            <span className="flex items-center gap-1.5 text-[9px] font-extrabold uppercase tracking-widest text-green-400">
              <span className="w-1.5 h-1.5 rounded-full bg-green-400" />
              AWS Ready
            </span>
          )}
          <div className="text-right">
            <p className="text-[9px] font-extrabold uppercase tracking-[0.2em] text-gray-400">Commit blocked</p>
            <p className="text-[11px] font-bold text-white">{findings.length} finding{findings.length !== 1 ? 's' : ''} detected</p>
          </div>
        </div>
      </header>

      {/* Severity summary bar */}
      <div className="border-b border-gray-200 px-8 py-4 bg-white flex items-center gap-8 flex-shrink-0">
        {criticalCount > 0 && (
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-black leading-none">{criticalCount}</span>
            <span className="text-[10px] font-extrabold uppercase tracking-widest" style={{ color: '#FF0000' }}>Critical</span>
          </div>
        )}
        {highCount > 0 && (
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-black leading-none">{highCount}</span>
            <span className="text-[10px] font-extrabold uppercase tracking-widest" style={{ color: '#FF8A00' }}>High</span>
          </div>
        )}
        {mediumCount > 0 && (
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-black leading-none">{mediumCount}</span>
            <span className="text-[10px] font-extrabold uppercase tracking-widest" style={{ color: '#FFD600' }}>Medium</span>
          </div>
        )}
        {lowCount > 0 && (
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-black leading-none">{lowCount}</span>
            <span className="text-[10px] font-extrabold uppercase tracking-widest" style={{ color: '#007AFF' }}>Low</span>
          </div>
        )}
        <div className="ml-auto border-l border-gray-200 pl-8 flex items-baseline gap-2">
          <span className="text-[10px] font-extrabold uppercase tracking-widest text-gray-400">Processed</span>
          <span className="text-xl font-black">{processedCount}/{findings.length}</span>
        </div>
      </div>

      {/* Resolve all / skip all bar */}
      <div className="border-b border-gray-200 px-8 py-3 bg-gray-50 flex items-center gap-3 flex-shrink-0">
        <p className="text-[10px] font-extrabold uppercase tracking-widest text-gray-500 flex-1">
          Resolve each finding to secure your secrets in AWS Secrets Manager
        </p>
        {pendingCount > 0 && (
          <button
            onClick={() => {
              findings.forEach((f) => {
                const r = resolutions.get(f.id);
                if (!r || r.status === 'pending') {
                  handleSkip(f.id);
                }
              });
            }}
            className="text-[10px] font-extrabold uppercase tracking-widest text-gray-400 hover:text-black transition-colors"
          >
            Skip all remaining ({pendingCount})
          </button>
        )}
      </div>

      {/* Findings list */}
      <main className="flex-1 overflow-y-auto px-8 py-6">
        <div className="max-w-3xl mx-auto space-y-4">
          {Object.entries(findingsByFile).map(([filePath, fileFindings]) => (
            <FileCard
              key={filePath}
              filePath={filePath}
              findings={fileFindings}
              resolutions={resolutions}
              onResolve={handleResolve}
              onSkip={handleSkip}
            />
          ))}
        </div>
      </main>

      {/* Footer actions */}
      <footer className="border-t border-black px-8 py-5 bg-white flex items-center justify-between flex-shrink-0">
        <div>
          {resolvedCount > 0 && (
            <p className="text-[11px] font-bold text-black">
              {resolvedCount} secret{resolvedCount !== 1 ? 's' : ''} secured in AWS
              {skippedCount > 0 ? `, ${skippedCount} skipped` : ''}
            </p>
          )}
          {pendingCount > 0 && resolvedCount === 0 && (
            <p className="text-[11px] text-gray-500 font-medium">
              Resolve findings or skip them to proceed
            </p>
          )}
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={abortCommit}
            className="px-6 py-3 border border-gray-300 text-gray-500 font-black uppercase tracking-widest text-xs hover:border-black hover:text-black transition-colors"
          >
            Abort
          </button>
          <button
            onClick={handleFinalize}
            disabled={!allProcessed}
            className={`px-10 py-3 font-black uppercase tracking-widest text-sm transition-colors ${
              allProcessed
                ? 'bg-black text-white hover:bg-zinc-800'
                : 'bg-gray-200 text-gray-400 cursor-not-allowed'
            }`}
          >
            {allProcessed ? 'Finalize Commit' : `${pendingCount} pending`}
          </button>
        </div>
      </footer>

      {/* Script modal overlay */}
      {modal && (
        <ScriptModal
          findingId={modal.findingId}
          findingTitle={modal.findingTitle}
          filePath={modal.filePath}
          lineNumber={modal.lineNumber}
          saveScript={modal.saveScript}
          secretKey={modal.secretKey}
          onSuccess={handleScriptSuccess}
          onClose={() => {
            setModal(null);
            // Reset back to pending so user can try again
            setResolutionStatus(modal.findingId, { status: 'pending' });
          }}
        />
      )}

      {/* AWS credentials modal overlay */}
      {awsModal && (
        <AwsCredentialsModal
          onSuccess={handleAwsCredentialsSaved}
          onCancel={handleAwsCredentialsCancelled}
          errorHint={awsModal.errorHint}
        />
      )}

      {/* Compliance tab overlay */}
      {showCompliance && (
        <ComplianceTab onClose={() => setShowCompliance(false)} />
      )}
    </div>
  );
}

// ─── Derive secret type from finding metadata ─────────────────────────────

function deriveSecretType(finding: Finding): string {
  // Primary: map by ruleId — derived from actual engine output
  const ruleMap: Record<string, string> = {
    'SEC-001': 'aws',           // AWS Access Key Exposed
    'SEC-002': 'api_key',       // Generic API Key Exposed
    'SEC-003': 'google',        // Google API Key Exposed
    'SEC-004': 'password',      // Hardcoded Password
    'SEC-005': 'stripe',        // Stripe Live Secret Key Exposed
    'SEC-006': 'stripe',        // Stripe API Key Exposed (alt rule)
    'SEC-007': 'github',        // GitHub Token Exposed
    'SEC-008': 'twilio',        // Twilio Credential Exposed
    'SEC-009': 'api_key',       // Cloudflare / generic token
    'SEC-010': 'sendgrid',      // SendGrid API Key Exposed
    'SEC-011': 'datadog',       // Datadog API Key Exposed
    'SEC-012': 'jwt',           // JWT Secret Exposed
    'SEC-013': 'private_key',   // Private Key Exposed
  };
  if (finding.ruleId && ruleMap[finding.ruleId]) {
    // Title-aware override: SEC-009 can also be slack or openai depending on title
    if (finding.ruleId === 'SEC-009') {
      const t = (finding.title ?? '').toLowerCase();
      if (/slack/.test(t))  return 'slack';
      if (/openai|gpt/.test(t)) return 'openai';
      if (/github/.test(t)) return 'github';
    }
    return ruleMap[finding.ruleId];
  }

  // Fallback: keyword match on title (handles unknown ruleIds)
  const title = (finding.title ?? '').toLowerCase();
  if (/aws|amazon/.test(title))             return 'aws';
  if (/openai|gpt/.test(title))            return 'openai';
  if (/stripe/.test(title))                return 'stripe';
  if (/github|gh token/.test(title))       return 'github';
  if (/google/.test(title))                return 'google';
  if (/slack/.test(title))                 return 'slack';
  if (/twilio/.test(title))                return 'twilio';
  if (/sendgrid/.test(title))              return 'sendgrid';
  if (/datadog/.test(title))               return 'datadog';
  if (/cloudflare/.test(title))            return 'api_key';
  if (/jwt|json web token/.test(title))    return 'jwt';
  if (/private.?key|rsa|ssh/.test(title)) return 'private_key';
  if (/password|passwd|pwd/.test(title))  return 'password';
  if (/api.?key/.test(title))             return 'api_key';
  if (/token/.test(title))                return 'generic_token';

  return 'generic_secret';
}

/**
 * Extract the AWS secret name from the save script returned by the API.
 * The API always includes a `secret_name = "codeguard/type/repo/env"` line.
 * This is our reliable fallback when we can't parse runtime output.
 */
function extractSecretNameFromScript(script: string): string | undefined {
  // Python: secret_name = "codeguard/openai/repo/env"
  const pyMatch = script.match(/\bsecret_name\s*=\s*["']([^"'\n]+)["']/i);
  if (pyMatch?.[1]) return pyMatch[1];

  // JS: const secretName = "codeguard/..."
  const jsMatch = script.match(/\bsecretName\s*=\s*["']([^"'\n]+)["']/i);
  if (jsMatch?.[1]) return jsMatch[1];

  return undefined;
}

export default App;
