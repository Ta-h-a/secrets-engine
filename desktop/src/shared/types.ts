export interface Finding {
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

export interface FindingsPayload {
  total: number;
  blocking: number;
  nonBlocking: number;
  findings: Finding[];
  blockingFindings: Finding[];
}

export interface AppSettings {
  aiProvider: 'none' | 'local' | 'cloud';
  theme: 'light' | 'dark' | 'system';
  autoBlock: boolean;
}

// Resolution status for each finding
export type ResolutionStatus = 'pending' | 'resolving' | 'resolved' | 'skipped' | 'failed';

export interface FindingResolution {
  findingId: string;
  status: ResolutionStatus;
  awsKeyName?: string;
  errorMessage?: string;
  /** Set when auto-skipped because no secret literal could be extracted (e.g. exec(), eval()) */
  skipReason?: string;
}

// API types for SecretLens ingest endpoint
export interface SecretIngestRequest {
  secrets: Array<{
    type: string;
    language: string;
    secret_value: string;
  }>;
  retrieval_language: string;
}

export interface SecretIngestResponse {
  status: string;
  total_secrets: number;
  successful: number;
  failed: number;
  save_script: string;
  timestamp: string;
  note: string;
}

// Output written to output file for the hook
export interface CommitDecision {
  allowed: string[];
  blocked: string[];
  resolved_count: number;
  skipped_count: number;
  modified_files: string[];
  stats: CommitStats;
}

export interface CommitStats {
  total_findings: number;
  resolved: number;
  skipped: number;
  files_modified: string[];
  files_committed: string[];
  files_blocked: string[];
}

// Script execution result from main process
export interface ScriptExecutionResult {
  success: boolean;
  output: string;
  error?: string;
  aws_key_name?: string;
}

// Secret extraction result from main process
export interface SecretExtractionResult {
  success: boolean;
  secret_value: string;
  error?: string;
}

// AWS credentials the user provides
export interface AwsCredentials {
  accessKeyId: string;
  secretAccessKey: string;
  region: string;
}

// Result of checking whether usable AWS credentials exist
export interface AwsCredentialCheckResult {
  /** Credentials found and verified against STS */
  valid: boolean;
  /** The IAM identity string if valid, e.g. "arn:aws:iam::123456789:user/myname" */
  identity?: string;
  /** Where the credentials came from */
  source?: 'env' | 'aws-file' | 'secretlens-profile';
  /** Human-readable error if not valid */
  error?: string;
}

// Result of saving credentials
export interface AwsCredentialSaveResult {
  success: boolean;
  /** STS verified identity after saving */
  identity?: string;
  error?: string;
}

export const SEVERITY_COLORS: Record<string, string> = {
  critical: '#FF0000',
  high: '#FF8A00',
  medium: '#FFD600',
  low: '#007AFF',
};

export const SEVERITY_BG_CLASSES: Record<string, string> = {
  critical: 'bg-[#FF0000]',
  high: 'bg-[#FF8A00]',
  medium: 'bg-[#FFD600]',
  low: 'bg-[#007AFF]',
};

export const SEVERITY_TEXT_CLASSES: Record<string, string> = {
  critical: 'text-[#FF0000]',
  high: 'text-[#FF8A00]',
  medium: 'text-[#FFD600]',
  low: 'text-[#007AFF]',
};

export const SEVERITY_LABELS: Record<string, string> = {
  critical: 'CRITICAL',
  high: 'HIGH',
  medium: 'MEDIUM',
  low: 'LOW',
};

// Detect language from file extension
export function detectLanguage(filePath: string): string {
  const ext = filePath.split('.').pop()?.toLowerCase() ?? '';
  const map: Record<string, string> = {
    py: 'python',
    js: 'javascript',
    ts: 'typescript',
    jsx: 'javascript',
    tsx: 'typescript',
    rb: 'ruby',
    go: 'go',
    java: 'java',
    cs: 'csharp',
    php: 'php',
    rs: 'rust',
    env: 'shell',
    sh: 'shell',
    bash: 'shell',
    yaml: 'yaml',
    yml: 'yaml',
    json: 'json',
    toml: 'toml',
    ini: 'ini',
    cfg: 'ini',
    conf: 'ini',
  };
  return map[ext] ?? 'shell';
}

// Generate AWS SDK replacement code for a given language and key name
export function generateAwsReplacement(language: string, awsKeyName: string): string {
  // Normalise the key name to a valid env-var identifier:
  // replace any non-alphanumeric character (/, -, ., space, …) with _
  const keyUpper = awsKeyName.toUpperCase().replace(/[^A-Z0-9]/g, '_');
  switch (language) {
    case 'python':
      return `os.environ.get('${keyUpper}')`;
    case 'javascript':
    case 'typescript':
      return `process.env.${keyUpper}`;
    case 'ruby':
      return `ENV['${keyUpper}']`;
    case 'go':
      return `os.Getenv("${keyUpper}")`;
    case 'java':
      return `System.getenv("${keyUpper}")`;
    case 'csharp':
      return `Environment.GetEnvironmentVariable("${keyUpper}")`;
    case 'php':
      return `getenv('${keyUpper}')`;
    case 'shell':
    case 'yaml':
    case 'ini':
      return `\${${keyUpper}}`;
    default:
      return `\${${keyUpper}}`;
  }
}
