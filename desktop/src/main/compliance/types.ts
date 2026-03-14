// ─── Compliance module types (main-process only) ─────────────────────────────

export interface ComplianceControl {
  id: string;           // e.g. "A.7.2"
  name: string;         // e.g. "Data for Development and Enhancement"
  domain: string;       // e.g. "Data / Data Governance"
  severity: 'critical' | 'high' | 'medium' | 'low';
  expectation: string;
  flagIf: string;
  keywords: string[];
  evidence: string;
  standard: string;     // e.g. "ISO/IEC 42001:2023"
}

export interface RuleData {
  controlId: string;    // original control id, e.g. "A.7.2"
  ruleId: string;       // engine rule id, e.g. "COMP-A7-2"
  name: string;
  type: string;         // always "compliance"
  severity: string;
  language: string;     // always "*"
  analyzer: string;     // always "regex"
  pattern: string;
  message: string;
  title: string;
  description: string;
  redact: boolean;      // always false
  recommendations: string[];
  references: string[];
  tags: string[];
}

export interface ValidatedRule {
  data: RuleData;
  isValid: boolean;
  error?: string;
  filePath?: string;
}

export type ComplianceProgressStep =
  | 'pdf-extract'
  | 'ai-parse'
  | 'ai-generate'
  | 'validate'
  | 'save'
  | 'complete'
  | 'error';

export interface ComplianceProgressEvent {
  step: ComplianceProgressStep;
  message: string;
  progress: number;     // 0–100
  detail?: string;
}
