import React from 'react';

interface Finding {
  id: string;
  filePath: string;
  lineNumber: number;
  ruleId: string;
  type: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  title: string;
  message: string;
  description: string;
  rawFindingData: string;
  recommendations: string[];
  references: string[];
  tags: string[];
  impact?: string;
  suggestedFix?: string;
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#ec1313',
  high: '#ff8a00', 
  medium: '#ffd600',
  low: '#007aff',
};

const SEVERITY_LABELS: Record<string, string> = {
  critical: 'CRITICAL',
  high: 'HIGH',
  medium: 'MEDIUM',
  low: 'LOW',
};

interface Props {
  finding: Finding;
  onBack: () => void;
  onAllow: () => void;
  onBlock: () => void;
}

const FindingDetail: React.FC<Props> = ({ finding, onBack, onAllow, onBlock }) => {
  return (
    <div className="min-h-screen bg-white flex flex-col">
      {/* Top Navigation */}
      <header className="border-b border-gray-200 px-8 py-4 flex items-center gap-4">
        <button 
          onClick={onBack}
          className="flex items-center gap-2 text-sm font-bold uppercase tracking-wider hover:text-gray-600"
        >
          <span className="material-symbols-outlined">arrow_back</span>
          Back
        </button>
        <div className="h-6 w-px bg-gray-300"></div>
        <div className="flex items-center gap-2">
          <span className="material-symbols-outlined text-black">shield_lock</span>
          <span className="font-extrabold tracking-tighter uppercase">SecretLens</span>
        </div>
      </header>

      {/* Main Content */}
      <div className="flex-1 flex flex-col lg:flex-row">
        {/* Left Panel - Code Viewer */}
        <div className="flex-1 lg:border-r border-gray-200 p-8">
          <div className="flex items-center justify-between mb-6">
            <h3 className="text-sm font-black uppercase tracking-[0.2em]">Source Code</h3>
            <span className="text-[10px] font-mono text-gray-400 uppercase tracking-widest">
              {finding.filePath}:{finding.lineNumber}
            </span>
          </div>
          
          <div className="bg-gray-50 border border-gray-200 p-6 font-mono text-sm leading-relaxed overflow-x-auto">
            <div className="flex gap-6">
              <div className="flex flex-col text-right text-gray-400 min-w-[30px]">
                <span>{finding.lineNumber - 1}</span>
                <span>{finding.lineNumber}</span>
                <span>{finding.lineNumber + 1}</span>
              </div>
              <div className="flex flex-col">
                <span>import os</span>
                <div className="bg-red-50 -mx-6 px-6 border-l-4 border-red-500 my-1">
                  <span className="text-red-600 font-bold">AWS_KEY = "AKIAIOSFODNN7EXAMPLE"</span>
                </div>
                <span># Other code...</span>
              </div>
            </div>
          </div>

          <div className="mt-8 p-6 border-l-4 border-black bg-gray-50">
            <h4 className="text-sm font-black uppercase tracking-widest mb-2">Vulnerability Analysis</h4>
            <p className="text-sm text-gray-700 leading-relaxed">
              {finding.description}
            </p>
          </div>
        </div>

        {/* Right Panel - Details & Actions */}
        <div className="w-full lg:w-[450px] p-8 flex flex-col">
          <div className="flex items-center gap-2 mb-6">
            <span className="material-symbols-outlined text-black">auto_awesome</span>
            <h3 className="text-sm font-black uppercase tracking-[0.2em]">AI Remediation</h3>
          </div>

          <div className="space-y-8 flex-1">
            <section>
              <h4 className="text-[11px] font-bold text-gray-400 uppercase tracking-[0.2em] mb-3">
                Proposed Solution
              </h4>
              <p className="text-sm leading-relaxed text-gray-900">
                Move the sensitive key to an environment variable or a secure secret manager. 
                Update the code to reference <code className="bg-gray-100 px-1 font-mono">os.getenv()</code> 
                to ensure secrets are injected at runtime.
              </p>
            </section>

            {finding.recommendations && finding.recommendations.length > 0 && (
              <section>
                <h4 className="text-[11px] font-bold text-gray-400 uppercase tracking-[0.2em] mb-3">
                  Recommendations
                </h4>
                <ul className="space-y-2">
                  {finding.recommendations.map((rec, i) => (
                    <li key={i} className="text-sm flex items-start gap-2">
                      <span className="text-green-600 mt-1">✓</span>
                      <span>{rec}</span>
                    </li>
                  ))}
                </ul>
              </section>
            )}

            {finding.suggestedFix && (
              <section>
                <h4 className="text-[11px] font-bold text-gray-400 uppercase tracking-[0.2em] mb-3">
                  Suggested Fix
                </h4>
                <div className="bg-gray-100 p-4 font-mono text-xs space-y-1">
                  <div className="text-gray-500">- AWS_KEY = "AKIAIOSFODNN7EXAMPLE"</div>
                  <div className="text-green-600 font-bold">+ AWS_KEY = os.getenv("AWS_ACCESS_KEY")</div>
                </div>
              </section>
            )}
          </div>

          {/* Actions */}
          <div className="pt-8 space-y-3 mt-auto">
            <button 
              onClick={onBlock}
              className="w-full bg-black text-white font-black py-4 uppercase tracking-[0.2em] text-xs hover:bg-zinc-800 transition-opacity"
            >
              Apply Fix
            </button>
            <div className="grid grid-cols-2 gap-3">
              <button 
                onClick={onBack}
                className="border border-black text-black font-bold py-3 uppercase tracking-[0.2em] text-[10px] hover:bg-black hover:text-white transition-all"
              >
                Dismiss
              </button>
              <button 
                onClick={onAllow}
                className="border border-black text-black font-bold py-3 uppercase tracking-[0.2em] text-[10px] hover:bg-black hover:text-white transition-all"
              >
                Allow
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Severity Badge */}
      <div 
        className="fixed top-8 right-8 px-6 py-3 font-black text-lg tracking-widest"
        style={{ backgroundColor: SEVERITY_COLORS[finding.severity], color: 'white' }}
      >
        {SEVERITY_LABELS[finding.severity]}
      </div>
    </div>
  );
};

export default FindingDetail;
