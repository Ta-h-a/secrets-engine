import React from 'react';
import { CommitStats } from '../../shared/types';

interface PartialResolutionScreenProps {
  stats: CommitStats;
  onCommitResolved: () => void;
  onAbort: () => void;
}

export const PartialResolutionScreen: React.FC<PartialResolutionScreenProps> = ({
  stats,
  onCommitResolved,
  onAbort,
}) => {
  return (
    <div className="min-h-screen bg-white flex flex-col">
      {/* Header */}
      <header className="px-8 py-6 border-b border-gray-200 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <div className="w-6 h-6 bg-black flex items-center justify-center">
            <svg className="w-4 h-4 text-white" fill="currentColor" viewBox="0 0 48 48">
              <path d="M24 4C25.7818 14.2173 33.7827 22.2182 44 24C33.7827 25.7818 25.7818 33.7827 24 44C22.2182 33.7827 14.2173 25.7818 4 24C14.2173 22.2182 22.2182 14.2173 24 4Z" />
            </svg>
          </div>
          <span className="text-lg font-black tracking-tighter uppercase">SecretLens</span>
        </div>
      </header>

      {/* Main */}
      <main className="flex-1 flex items-center justify-center p-8">
        <div className="w-full max-w-2xl border-2 border-black p-12 md:p-16">
          {/* Warning icon */}
          <div className="mb-10">
            <div className="w-16 h-16 border-2 border-black flex items-center justify-center">
              <svg className="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path
                  strokeLinecap="square"
                  strokeLinejoin="miter"
                  strokeWidth={2}
                  d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z"
                />
              </svg>
            </div>
          </div>

          {/* Headline */}
          <h1 className="text-5xl md:text-7xl font-black tracking-tighter uppercase leading-none mb-4">
            Partial<br />Resolution
          </h1>
          <p className="text-sm text-gray-500 font-medium uppercase tracking-wider mb-12">
            {stats.skipped} finding(s) remain unresolved
          </p>

          {/* Stats */}
          <div className="grid grid-cols-3 border-y border-black/10 mb-10">
            <div className="py-6 border-r border-black/10 text-center">
              <p className="text-4xl font-black leading-none mb-1">{stats.resolved}</p>
              <p className="text-[10px] uppercase tracking-widest font-bold text-gray-500">Resolved</p>
            </div>
            <div className="py-6 border-r border-black/10 text-center">
              <p className="text-4xl font-black leading-none mb-1 text-[#FF0000]">{stats.skipped}</p>
              <p className="text-[10px] uppercase tracking-widest font-bold text-gray-500">Skipped</p>
            </div>
            <div className="py-6 text-center">
              <p className="text-4xl font-black leading-none mb-1">{stats.files_committed.length}</p>
              <p className="text-[10px] uppercase tracking-widest font-bold text-gray-500">Files OK</p>
            </div>
          </div>

          {/* Warning block */}
          <div className="border border-[#FFD600] bg-white p-4 mb-8">
            <p className="text-xs font-extrabold uppercase tracking-wider mb-1">Security Notice</p>
            <p className="text-xs text-gray-600 leading-relaxed">
              Files with unresolved secrets will be excluded from this commit.
              Only clean and resolved files will be committed.
            </p>
          </div>

          {/* File lists */}
          <div className="grid grid-cols-2 gap-4 mb-10">
            {stats.files_committed.length > 0 && (
              <div className="p-4 border border-gray-200 bg-gray-50">
                <p className="text-[10px] uppercase tracking-[0.2em] font-extrabold text-gray-400 mb-2">
                  Will commit
                </p>
                <div className="space-y-1">
                  {stats.files_committed.map((f) => (
                    <p key={f} className="text-[11px] font-mono text-black truncate">
                      ✓ {f}
                    </p>
                  ))}
                </div>
              </div>
            )}
            {stats.files_blocked.length > 0 && (
              <div className="p-4 border border-gray-200 bg-gray-50">
                <p className="text-[10px] uppercase tracking-[0.2em] font-extrabold text-gray-400 mb-2">
                  Will skip
                </p>
                <div className="space-y-1">
                  {stats.files_blocked.map((f) => (
                    <p key={f} className="text-[11px] font-mono text-[#FF0000] truncate">
                      ✗ {f}
                    </p>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* Actions */}
          <div className="flex flex-col gap-3">
            {stats.files_committed.length > 0 ? (
              <button
                onClick={onCommitResolved}
                className="w-full bg-black text-white font-black text-base py-5 uppercase tracking-widest hover:bg-zinc-800 transition-colors"
              >
                Commit Resolved Files Only
              </button>
            ) : null}
            <button
              onClick={onAbort}
              className={`w-full font-black text-base py-5 uppercase tracking-widest transition-colors ${
                stats.files_committed.length === 0
                  ? 'bg-black text-white hover:bg-zinc-800'
                  : 'border-2 border-black text-black hover:bg-gray-100'
              }`}
            >
              Abort Commit
            </button>
          </div>
        </div>
      </main>

      {/* Footer */}
      <footer className="py-6 border-t border-gray-100 flex justify-center">
        <p className="text-[10px] uppercase tracking-[0.3em] font-bold text-gray-400">
          SecretLens · Partial commit mode
        </p>
      </footer>
    </div>
  );
};
