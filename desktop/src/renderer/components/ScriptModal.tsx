import React, { useState } from 'react';
import { ScriptExecutionResult } from '../../shared/types';

interface ScriptModalProps {
  findingId: string;
  findingTitle: string;
  filePath: string;
  lineNumber: number;
  saveScript: string;
  secretKey: string;
  onSuccess: (findingId: string, awsKeyName: string) => void;
  onClose: () => void;
}

type RunState = 'idle' | 'running' | 'success' | 'error';

export const ScriptModal: React.FC<ScriptModalProps> = ({
  findingId,
  findingTitle,
  filePath,
  lineNumber,
  saveScript,
  secretKey,
  onSuccess,
  onClose,
}) => {
  const [runState, setRunState] = useState<RunState>('idle');
  const [output, setOutput] = useState('');
  const [errorMsg, setErrorMsg] = useState('');
  const [awsKey, setAwsKey] = useState('');

  const detectScriptLanguage = (script: string): string => {
    if (script.trimStart().startsWith('#!/usr/bin/env python') || /^import\s/m.test(script)) {
      return 'python';
    }
    if (/^#!/.test(script) || /\baws\s+secretsmanager\b/.test(script)) {
      return 'shell';
    }
    // Check for python-style keywords
    if (/\bimport\b|\bdef\b|\bprint\(/.test(script)) return 'python';
    return 'python'; // Default to python for SecretLens API scripts
  };

  const handleRunScript = async () => {
    setRunState('running');
    setOutput('');
    setErrorMsg('');

    try {
      const lang = detectScriptLanguage(saveScript);
      const result: ScriptExecutionResult = await window.electronAPI.executeScript(
        saveScript,
        lang,
      );

      if (result.success) {
        // Determine the AWS key name: prefer extracted from output, then use secretKey from API
        const resolvedKey = result.aws_key_name ?? secretKey;
        setAwsKey(resolvedKey);
        setOutput(result.output || 'Script completed successfully.');
        setRunState('success');

        // Replace the secret in the source file
        const extractResult = await window.electronAPI.extractSecret(filePath, lineNumber);
        if (extractResult.success && extractResult.secret_value) {
          await window.electronAPI.replaceSecret(
            filePath,
            lineNumber,
            extractResult.secret_value,
            resolvedKey,
          );
        }

        // Notify parent after a short delay so user can see the success
        setTimeout(() => onSuccess(findingId, resolvedKey), 1500);
      } else {
        setErrorMsg(result.error ?? 'Script failed with unknown error.');
        setOutput(result.output);
        setRunState('error');
      }
    } catch (e) {
      setErrorMsg(e instanceof Error ? e.message : String(e));
      setRunState('error');
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div className="bg-white w-full max-w-2xl mx-4 border-2 border-black flex flex-col max-h-[90vh]">

        {/* Header */}
        <div className="px-8 py-6 border-b border-black flex items-start justify-between">
          <div>
            <p className="text-[10px] font-extrabold uppercase tracking-[0.2em] text-gray-400 mb-1">
              AWS Save Script
            </p>
            <h2 className="text-2xl font-black tracking-tighter uppercase leading-tight">
              {findingTitle}
            </h2>
            <p className="text-xs font-mono text-gray-500 mt-1 uppercase">
              {filePath}:{lineNumber}
            </p>
          </div>
          <button
            onClick={onClose}
            disabled={runState === 'running'}
            className="p-1 hover:bg-gray-100 transition-colors disabled:opacity-40"
            aria-label="Close"
          >
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="square" strokeLinejoin="miter" strokeWidth={2.5} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        {/* Script body */}
        <div className="flex-1 overflow-y-auto">
          <div className="px-8 py-6 border-b border-gray-200">
            <p className="text-[10px] font-extrabold uppercase tracking-[0.2em] text-gray-400 mb-3">
              Generated Save Script
            </p>
            <pre className="bg-gray-50 border border-gray-200 p-4 text-xs font-mono overflow-x-auto whitespace-pre-wrap leading-relaxed text-black">
              {saveScript}
            </pre>
            <p className="text-[10px] text-gray-400 mt-2 font-medium">
              This script will store the secret in AWS Secrets Manager and return an environment key.
            </p>
          </div>

          {/* Output / status area */}
          {(runState === 'success' || runState === 'error' || output) && (
            <div className="px-8 py-6 border-b border-gray-200">
              {runState === 'success' && (
                <div className="mb-4 flex items-center gap-3">
                  <div className="w-5 h-5 bg-black flex items-center justify-center flex-shrink-0">
                    <svg className="w-3 h-3 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="square" strokeLinejoin="miter" strokeWidth={3} d="M5 13l4 4L19 7" />
                    </svg>
                  </div>
                  <div>
                    <p className="text-sm font-black uppercase tracking-widest">Secret stored successfully</p>
                    {awsKey && (
                      <p className="text-xs font-mono text-gray-500 mt-0.5">Key: {awsKey}</p>
                    )}
                  </div>
                </div>
              )}
              {runState === 'error' && (
                <div className="mb-4 flex items-start gap-3">
                  <div className="w-5 h-5 bg-[#FF0000] flex items-center justify-center flex-shrink-0 mt-0.5">
                    <svg className="w-3 h-3 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="square" strokeLinejoin="miter" strokeWidth={3} d="M6 18L18 6M6 6l12 12" />
                    </svg>
                  </div>
                  <div>
                    <p className="text-sm font-black uppercase tracking-widest text-[#FF0000]">Script failed</p>
                    <p className="text-xs text-gray-600 mt-0.5">{errorMsg}</p>
                  </div>
                </div>
              )}
              {output && (
                <div>
                  <p className="text-[10px] font-extrabold uppercase tracking-[0.2em] text-gray-400 mb-2">Output</p>
                  <pre className="bg-gray-900 text-green-400 p-4 text-xs font-mono overflow-x-auto whitespace-pre-wrap leading-relaxed">
                    {output}
                  </pre>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Actions */}
        <div className="px-8 py-6 border-t border-black flex items-center gap-4">
          {runState === 'idle' && (
            <>
              <button
                onClick={handleRunScript}
                className="flex-1 bg-black text-white font-black py-4 uppercase tracking-widest text-sm hover:bg-zinc-800 transition-colors"
              >
                Run Script
              </button>
              <button
                onClick={onClose}
                className="px-8 py-4 border border-black text-black font-black uppercase tracking-widest text-sm hover:bg-gray-100 transition-colors"
              >
                Cancel
              </button>
            </>
          )}
          {runState === 'running' && (
            <div className="flex-1 flex items-center gap-4 py-4">
              <div className="w-5 h-5 border-2 border-black border-t-transparent animate-spin flex-shrink-0" />
              <span className="font-black uppercase tracking-widest text-sm">Running script...</span>
            </div>
          )}
          {runState === 'success' && (
            <div className="flex-1 flex items-center gap-3 py-4">
              <span className="font-black uppercase tracking-widest text-sm">Resolved — closing...</span>
            </div>
          )}
          {runState === 'error' && (
            <>
              <button
                onClick={handleRunScript}
                className="flex-1 bg-black text-white font-black py-4 uppercase tracking-widest text-sm hover:bg-zinc-800 transition-colors"
              >
                Retry
              </button>
              <button
                onClick={onClose}
                className="px-8 py-4 border border-black text-black font-black uppercase tracking-widest text-sm hover:bg-gray-100 transition-colors"
              >
                Cancel
              </button>
            </>
          )}
        </div>
      </div>
    </div>
  );
};
