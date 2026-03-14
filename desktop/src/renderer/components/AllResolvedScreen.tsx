import React from 'react';
import { CommitStats } from '../../shared/types';

interface AllResolvedScreenProps {
  stats: CommitStats;
  onCommit: () => void;
}

export const AllResolvedScreen: React.FC<AllResolvedScreenProps> = ({ stats, onCommit }) => {
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
        <div className="w-full max-w-2xl border-2 border-black p-12 md:p-16 text-center">
          {/* Big checkmark */}
          <div className="mb-10">
            <svg
              className="w-24 h-24 mx-auto"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path
                strokeLinecap="square"
                strokeLinejoin="miter"
                strokeWidth={1.5}
                d="M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
              />
            </svg>
          </div>

          {/* Headline */}
          <h1 className="text-6xl md:text-8xl font-black tracking-tighter uppercase leading-none mb-12">
            All<br />Resolved
          </h1>

          {/* Stats grid */}
          <div className="grid grid-cols-3 border-y border-black/10 mb-12">
            <div className="py-8 border-r border-black/10">
              <p className="text-5xl font-black leading-none mb-2">{stats.resolved}</p>
              <p className="text-[10px] uppercase tracking-widest font-bold text-gray-500">
                Secrets Resolved
              </p>
            </div>
            <div className="py-8 border-r border-black/10">
              <p className="text-5xl font-black leading-none mb-2">{stats.files_modified.length}</p>
              <p className="text-[10px] uppercase tracking-widest font-bold text-gray-500">
                Files Modified
              </p>
            </div>
            <div className="py-8">
              <p className="text-5xl font-black leading-none mb-2">{stats.files_committed.length}</p>
              <p className="text-[10px] uppercase tracking-widest font-bold text-gray-500">
                Files Committed
              </p>
            </div>
          </div>

          {/* Files list */}
          {stats.files_committed.length > 0 && (
            <div className="text-left mb-12 p-6 border border-gray-200 bg-gray-50">
              <p className="text-[10px] uppercase tracking-[0.2em] font-extrabold text-gray-400 mb-3">
                Files in commit
              </p>
              <div className="space-y-1">
                {stats.files_committed.map((f) => (
                  <p key={f} className="text-xs font-mono text-black">
                    ✓ {f}
                  </p>
                ))}
              </div>
            </div>
          )}

          {/* Commit button */}
          <button
            onClick={onCommit}
            className="w-full bg-black text-white font-black text-lg py-6 uppercase tracking-widest hover:bg-zinc-800 transition-colors"
          >
            Continue with Commit
          </button>
        </div>
      </main>

      {/* Footer */}
      <footer className="py-6 border-t border-gray-100 flex justify-center">
        <p className="text-[10px] uppercase tracking-[0.3em] font-bold text-gray-400">
          SecretLens · All secrets secured in AWS
        </p>
      </footer>
    </div>
  );
};
