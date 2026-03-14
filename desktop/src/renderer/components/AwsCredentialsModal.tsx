import React, { useState, useCallback } from 'react';
import { AwsCredentials, AwsCredentialSaveResult } from '../../shared/types';

// ─── Props ────────────────────────────────────────────────────────────────────

interface AwsCredentialsModalProps {
  /**
   * Called after credentials have been verified and saved.
   * The modal closes itself and the caller can proceed with the resolve flow.
   */
  onSuccess: () => void;
  /**
   * Called when the user explicitly dismisses the modal without saving.
   * The pending resolve action should be cancelled.
   */
  onCancel: () => void;
  /** Optional prefill hint shown below the header (e.g. "Credentials invalid or expired") */
  errorHint?: string;
}

// ─── Region options ───────────────────────────────────────────────────────────

const AWS_REGIONS = [
  'us-east-1',
  'us-east-2',
  'us-west-1',
  'us-west-2',
  'eu-west-1',
  'eu-west-2',
  'eu-central-1',
  'ap-southeast-1',
  'ap-southeast-2',
  'ap-northeast-1',
  'sa-east-1',
  'ca-central-1',
];

// ─── Component ────────────────────────────────────────────────────────────────

export const AwsCredentialsModal: React.FC<AwsCredentialsModalProps> = ({
  onSuccess,
  onCancel,
  errorHint,
}) => {
  const [accessKeyId, setAccessKeyId] = useState('');
  const [secretAccessKey, setSecretAccessKey] = useState('');
  const [region, setRegion] = useState('us-east-1');
  const [showSecret, setShowSecret] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(errorHint ?? null);

  const isValid = accessKeyId.trim().length >= 16 && secretAccessKey.trim().length >= 16;

  const handleSave = useCallback(async () => {
    if (!isValid || saving) return;

    setSaving(true);
    setError(null);

    try {
      const creds: AwsCredentials = {
        accessKeyId: accessKeyId.trim(),
        secretAccessKey: secretAccessKey.trim(),
        region: region,
      };

      const result: AwsCredentialSaveResult = await window.electronAPI.saveAwsCredentials(creds);

      if (result.success) {
        onSuccess();
      } else {
        setError(result.error ?? 'Credentials could not be verified. Please check and try again.');
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Unexpected error saving credentials.');
    } finally {
      setSaving(false);
    }
  }, [accessKeyId, secretAccessKey, region, isValid, saving, onSuccess]);

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      if (e.key === 'Enter' && isValid && !saving) {
        handleSave();
      } else if (e.key === 'Escape') {
        onCancel();
      }
    },
    [handleSave, isValid, saving, onCancel],
  );

  return (
    /* Backdrop */
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60"
      onKeyDown={handleKeyDown}
    >
      {/* Modal panel */}
      <div className="bg-white border-2 border-black w-full max-w-lg mx-4 relative">

        {/* Header */}
        <div className="bg-black px-8 py-6">
          <div className="flex items-center gap-3 mb-1">
            <div className="w-5 h-5 border border-white flex items-center justify-center flex-shrink-0">
              <svg className="w-3 h-3 text-white" fill="currentColor" viewBox="0 0 48 48">
                <path d="M24 4C25.7818 14.2173 33.7827 22.2182 44 24C33.7827 25.7818 25.7818 33.7827 24 44C22.2182 33.7827 14.2173 25.7818 4 24C14.2173 22.2182 22.2182 14.2173 24 4Z" />
              </svg>
            </div>
            <h2 className="text-white text-sm font-black uppercase tracking-widest">
              AWS Credentials Required
            </h2>
          </div>
          <p className="text-gray-400 text-[11px] leading-relaxed pl-8">
            SecretLens stores secrets in AWS Secrets Manager on your behalf.
            Enter your IAM credentials to continue.
          </p>
        </div>

        {/* Body */}
        <div className="px-8 py-6 space-y-5">

          {/* Error banner */}
          {error && (
            <div className="border border-[#FF0000] bg-[#FF0000]/5 px-4 py-3">
              <p className="text-[11px] font-bold text-[#FF0000] uppercase tracking-wider">Error</p>
              <p className="text-[11px] text-[#FF0000] mt-0.5">{error}</p>
            </div>
          )}

          {/* Access Key ID */}
          <div>
            <label className="block text-[9px] font-extrabold uppercase tracking-[0.2em] text-gray-500 mb-1.5">
              AWS Access Key ID
            </label>
            <input
              type="text"
              value={accessKeyId}
              onChange={(e) => setAccessKeyId(e.target.value)}
              placeholder="AKIA..."
              autoFocus
              spellCheck={false}
              autoComplete="off"
              className="w-full border border-gray-300 focus:border-black outline-none px-3 py-2.5 text-sm font-mono transition-colors"
            />
          </div>

          {/* Secret Access Key */}
          <div>
            <label className="block text-[9px] font-extrabold uppercase tracking-[0.2em] text-gray-500 mb-1.5">
              AWS Secret Access Key
            </label>
            <div className="relative">
              <input
                type={showSecret ? 'text' : 'password'}
                value={secretAccessKey}
                onChange={(e) => setSecretAccessKey(e.target.value)}
                placeholder="Enter your secret access key"
                spellCheck={false}
                autoComplete="off"
                className="w-full border border-gray-300 focus:border-black outline-none px-3 py-2.5 text-sm font-mono transition-colors pr-16"
              />
              <button
                type="button"
                onClick={() => setShowSecret((v) => !v)}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-[9px] font-extrabold uppercase tracking-widest text-gray-400 hover:text-black transition-colors"
              >
                {showSecret ? 'Hide' : 'Show'}
              </button>
            </div>
          </div>

          {/* Region */}
          <div>
            <label className="block text-[9px] font-extrabold uppercase tracking-[0.2em] text-gray-500 mb-1.5">
              Default Region
            </label>
            <select
              value={region}
              onChange={(e) => setRegion(e.target.value)}
              className="w-full border border-gray-300 focus:border-black outline-none px-3 py-2.5 text-sm font-mono bg-white transition-colors appearance-none cursor-pointer"
            >
              {AWS_REGIONS.map((r) => (
                <option key={r} value={r}>{r}</option>
              ))}
            </select>
          </div>

          {/* Info note */}
          <div className="border-l-2 border-gray-300 pl-3">
            <p className="text-[10px] text-gray-500 leading-relaxed">
              Credentials are verified with <span className="font-mono font-bold">sts:GetCallerIdentity</span> and
              saved to <span className="font-mono font-bold">~/.aws/credentials</span> under the{' '}
              <span className="font-mono font-bold">[secretlens]</span> profile. They are never sent to SecretLens servers.
            </p>
          </div>
        </div>

        {/* Footer actions */}
        <div className="border-t border-gray-200 px-8 py-5 flex items-center justify-between bg-gray-50">
          <button
            onClick={onCancel}
            disabled={saving}
            className="text-[10px] font-extrabold uppercase tracking-widest text-gray-400 hover:text-black transition-colors disabled:opacity-40"
          >
            Cancel
          </button>

          <button
            onClick={handleSave}
            disabled={!isValid || saving}
            className={`flex items-center gap-2.5 px-8 py-3 font-black uppercase tracking-widest text-xs transition-colors ${
              isValid && !saving
                ? 'bg-black text-white hover:bg-zinc-800'
                : 'bg-gray-200 text-gray-400 cursor-not-allowed'
            }`}
          >
            {saving ? (
              <>
                <span className="w-3.5 h-3.5 border-2 border-gray-400 border-t-transparent animate-spin" />
                Verifying…
              </>
            ) : (
              'Verify & Save'
            )}
          </button>
        </div>
      </div>
    </div>
  );
};
