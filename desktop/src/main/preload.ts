import { contextBridge, ipcRenderer } from 'electron';
import {
  Finding,
  CommitDecision,
  ScriptExecutionResult,
  SecretExtractionResult,
  AwsCredentials,
  AwsCredentialCheckResult,
  AwsCredentialSaveResult,
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
});
