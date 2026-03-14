import { contextBridge, ipcRenderer } from 'electron';
import {
  Finding,
  CommitDecision,
  ScriptExecutionResult,
  SecretExtractionResult,
  AwsCredentials,
  AwsCredentialCheckResult,
  AwsCredentialSaveResult,
  ComplianceRuleSummary,
  ComplianceProgressEvent,
} from '../shared/types';

contextBridge.exposeInMainWorld('electronAPI', {
  /** Load findings that were passed via --findings-file CLI arg */
  getFindings: (): Promise<Finding[]> => ipcRenderer.invoke('get-findings'),

  /** Write commit decision to output file and let the hook proceed */
  resolveCommit: (data: CommitDecision): Promise<{ success: boolean }> =>
    ipcRenderer.invoke('resolve-commit', data),

  /** Extract raw secret value from a source file at a given line */
  extractSecret: (
    filePath: string,
    lineNumber: number,
  ): Promise<SecretExtractionResult> =>
    ipcRenderer.invoke('extract-secret', { filePath, lineNumber }),

  /** Execute a Python or shell script returned by the SecretLens API */
  executeScript: (
    script: string,
    language: string,
  ): Promise<ScriptExecutionResult> =>
    ipcRenderer.invoke('execute-script', { script, language }),

  /** Replace the raw secret in a source file with an AWS SDK reference */
  replaceSecret: (
    filePath: string,
    lineNumber: number,
    secretValue: string,
    awsKeyName: string,
  ): Promise<{ success: boolean; error?: string }> =>
    ipcRenderer.invoke('replace-secret', { filePath, lineNumber, secretValue, awsKeyName }),

  /** App settings */
  getSettings: (): Promise<{ aiProvider: string; theme: string; autoBlock: boolean }> =>
    ipcRenderer.invoke('get-settings'),

  /** Check whether AWS credentials are already configured and valid */
  checkAwsCredentials: (): Promise<AwsCredentialCheckResult> =>
    ipcRenderer.invoke('check-aws-credentials'),

  /** Verify and persist new AWS credentials under the [secretlens] profile */
  saveAwsCredentials: (creds: AwsCredentials): Promise<AwsCredentialSaveResult> =>
    ipcRenderer.invoke('save-aws-credentials', creds),

  /** Get the real git repository name (basename of git rev-parse --show-toplevel) */
  getRepoName: (): Promise<string> => ipcRenderer.invoke('get-repo-name'),

  /** Listen for findings pushed from main process */
  onFindingsReceived: (callback: (findings: Finding[]) => void): void => {
    ipcRenderer.on('findings-received', (_event, findings) => callback(findings));
  },

  // ── Compliance ──────────────────────────────────────────────────────────────

  /** Open native file-open dialog, returns selected PDF path or null */
  pickPdf: (): Promise<string | null> =>
    ipcRenderer.invoke('compliance:pick-pdf'),

  /**
   * Run the full PDF → multi-agent → YAML pipeline.
   * Progress events are streamed via onComplianceProgress while this resolves.
   */
  processPdf: (
    filePath: string,
  ): Promise<{ success: boolean; rules?: ComplianceRuleSummary[]; error?: string }> =>
    ipcRenderer.invoke('compliance:process-pdf', filePath),

  /** Return the list of currently installed compliance YAML rules */
  getComplianceRules: (): Promise<ComplianceRuleSummary[]> =>
    ipcRenderer.invoke('compliance:get-rules'),

  /** Delete all installed compliance rules, returns count removed */
  deleteComplianceRules: (): Promise<{ count: number }> =>
    ipcRenderer.invoke('compliance:delete-rules'),

  /** Subscribe to compliance pipeline progress events */
  onComplianceProgress: (callback: (event: ComplianceProgressEvent) => void): () => void => {
    const listener = (_e: Electron.IpcRendererEvent, data: ComplianceProgressEvent) =>
      callback(data);
    ipcRenderer.on('compliance:progress', listener);
    // Return an unsubscribe function so the component can clean up
    return () => ipcRenderer.removeListener('compliance:progress', listener);
  },
});
