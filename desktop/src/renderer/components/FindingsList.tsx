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
  findings: Finding[];
  onSelectFinding: (finding: Finding) => void;
  onAllow: () => void;
  onBlock: () => void;
}

const FindingsList: React.FC<Props> = ({ findings, onSelectFinding, onAllow, onBlock }) => {
  const critical = findings.filter(f => f.severity === 'critical');
  const high = findings.filter(f => f.severity === 'high');
  const other = findings.filter(f => !['critical', 'high'].includes(f.severity));

  return (
    <div className="min-h-screen bg-white flex flex-col">
      {/* Header */}
      <header className="bg-red-600 text-white px-8 py-6">
        <div className="max-w-4xl mx-auto">
          <h1 className="text-5xl md:text-7xl font-black tracking-tight uppercase leading-none">
            Commit<br/>Blocked
          </h1>
        </div>
      </header>

      {/* Summary */}
      <div className="border-b border-gray-200 px-8 py-6 bg-gray-50">
        <div className="max-w-4xl mx-auto flex flex-wrap gap-8">
          <div className="flex items-baseline gap-2">
            <span className="text-4xl font-extrabold text-red-600">{critical.length}</span>
            <span className="text-xs font-extrabold uppercase tracking-widest text-red-600">Critical</span>
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-4xl font-extrabold text-orange-500">{high.length}</span>
            <span className="text-xs font-extrabold uppercase tracking-widest text-orange-500">High</span>
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-4xl font-extrabold text-gray-400">{other.length}</span>
            <span className="text-xs font-extrabold uppercase tracking-widest text-gray-400">Other</span>
          </div>
        </div>
      </div>

      {/* Findings List */}
      <main className="flex-1 p-8">
        <div className="max-w-4xl mx-auto space-y-4">
          {findings.map((finding, index) => (
            <div
              key={finding.id}
              onClick={() => onSelectFinding(finding)}
              className="swiss-border p-6 flex items-start gap-6 cursor-pointer hover:border-4 transition-all bg-white group fade-in"
              style={{ animationDelay: `${index * 50}ms` }}
            >
              <div 
                className="w-3 h-3 mt-2 flex-shrink-0"
                style={{ backgroundColor: SEVERITY_COLORS[finding.severity] || '#999' }}
              />
              <div className="flex-1">
                <div className="flex items-start justify-between mb-2">
                  <h3 className="text-xl font-extrabold uppercase tracking-tight">
                    {finding.title}
                  </h3>
                  <span 
                    className="text-[10px] font-extrabold uppercase tracking-widest border border-black px-2 py-0.5"
                    style={{ color: SEVERITY_COLORS[finding.severity] }}
                  >
                    {SEVERITY_LABELS[finding.severity]}
                  </span>
                </div>
                <p className="text-sm font-mono text-gray-500 mb-2">
                  {finding.filePath}:{finding.lineNumber}
                </p>
                <p className="text-sm text-gray-700 line-clamp-2">
                  {finding.message}
                </p>
              </div>
              <span className="material-symbols-outlined text-gray-300 group-hover:text-black transition-colors">
                arrow_forward
              </span>
            </div>
          ))}
        </div>
      </main>

      {/* Actions */}
      <footer className="border-t border-gray-200 p-8 bg-white">
        <div className="max-w-4xl mx-auto flex flex-col md:flex-row gap-4">
          <button
            onClick={onBlock}
            className="flex-1 bg-black text-white font-black text-xl py-5 px-8 uppercase tracking-tight hover:bg-zinc-800 transition-colors"
          >
            Review & Fix
          </button>
          <button
            onClick={onAllow}
            className="flex-1 border-2 border-black text-black font-black text-xl py-5 px-8 uppercase tracking-tight hover:bg-black hover:text-white transition-colors"
          >
            Commit Anyway
          </button>
        </div>
        <div className="max-w-4xl mx-auto mt-4 text-center">
          <p className="text-xs text-red-600 font-bold uppercase tracking-widest">
            ⚠️ Not recommended - secrets will be committed
          </p>
        </div>
      </footer>
    </div>
  );
};

export default FindingsList;
