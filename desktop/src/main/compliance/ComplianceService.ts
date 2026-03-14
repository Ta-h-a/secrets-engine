import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { extractPdfText } from './PdfParser';
import {
  parseComplianceControls,
  generateComplianceRules,
  validateAndSaveRules,
} from './ComplianceAgents';
import { ComplianceProgressEvent } from './types';
import { ComplianceRuleSummary } from '../../shared/types';

// Compliance YAML rules live alongside the built-in security rules so the
// engine picks them up automatically with its default --rules-dir.
const RULES_DIR = path.join(os.homedir(), '.secretlens', 'bin', 'rules');

// ─── Main pipeline ─────────────────────────────────────────────────────────

export async function processPdfAndGenerateRules(
  filePath: string,
  onProgress: (event: ComplianceProgressEvent) => void,
): Promise<ComplianceRuleSummary[]> {

  // ── Step 1: extract PDF text ──────────────────────────────────────────────
  onProgress({ step: 'pdf-extract', message: 'Extracting text from PDF…', progress: 5 });

  const pdfText = await extractPdfText(filePath);
  const pageCount = (pdfText.match(/=== PAGE \d+ ===/g) ?? []).length;

  onProgress({
    step: 'pdf-extract',
    message: `PDF read — ${pageCount} pages, ${pdfText.length.toLocaleString()} characters`,
    progress: 18,
    detail: path.basename(filePath),
  });

  // ── Step 2: Agent 1 — parse compliance controls ───────────────────────────
  onProgress({ step: 'ai-parse', message: 'Agent 1 — Parsing compliance controls…', progress: 20 });

  const controls = await parseComplianceControls(pdfText, onProgress);

  onProgress({
    step: 'ai-parse',
    message: `Agent 1 — ${controls.length} controls extracted`,
    progress: 45,
    detail: controls.map((c) => c.id).join('  ·  '),
  });

  // ── Step 3: Agent 2 — generate YAML rules ────────────────────────────────
  onProgress({ step: 'ai-generate', message: 'Agent 2 — Generating detection rules…', progress: 48 });

  const ruleDefs = await generateComplianceRules(controls, onProgress);

  onProgress({
    step: 'ai-generate',
    message: `Agent 2 — ${ruleDefs.length} rule definitions produced`,
    progress: 75,
  });

  // ── Step 4: validate + save ───────────────────────────────────────────────
  onProgress({ step: 'validate', message: 'Validating rules and writing to disk…', progress: 76 });

  const saved = validateAndSaveRules(ruleDefs, RULES_DIR, onProgress);

  onProgress({
    step: 'save',
    message: `${saved.length} compliance rules installed in engine rules directory`,
    progress: 97,
  });

  onProgress({
    step: 'complete',
    message: `Done — ${saved.length} compliance rules active`,
    progress: 100,
  });

  return saved;
}

// ─── List installed compliance rules ──────────────────────────────────────

export function getInstalledComplianceRules(): ComplianceRuleSummary[] {
  if (!fs.existsSync(RULES_DIR)) return [];

  return fs
    .readdirSync(RULES_DIR)
    .filter((f) => f.startsWith('compliance-') && f.endsWith('.yaml'))
    .map((f): ComplianceRuleSummary | null => {
      try {
        const raw = fs.readFileSync(path.join(RULES_DIR, f), 'utf-8');
        const id       = raw.match(/^id:\s+"?([^"\n]+)"?/m)?.[1]?.trim() ?? f;
        const name     = raw.match(/^name:\s+"?([^"\n]+)"?/m)?.[1]?.trim() ?? '';
        const severity = raw.match(/^severity:\s+"?([^"\n]+)"?/m)?.[1]?.trim() ?? 'medium';
        const pattern  = raw.match(/^pattern:\s+"?([^"\n]+)"?/m)?.[1]?.trim() ?? '';
        const domainTag =
          raw.match(/^tags:[\s\S]*?-\s+((?!compliance|iso42001)[^\n]+)/m)?.[1]?.trim() ?? '';
        const controlId = id.replace(/^COMP-/, '').replace(/-/g, '.');

        return {
          ruleId: id,
          controlId,
          name,
          severity,
          domain: domainTag,
          pattern,
          filePath: path.join(RULES_DIR, f),
        };
      } catch {
        return null;
      }
    })
    .filter((r): r is ComplianceRuleSummary => r !== null);
}

// ─── Remove all compliance rules ──────────────────────────────────────────

export function deleteComplianceRules(): number {
  if (!fs.existsSync(RULES_DIR)) return 0;
  const files = fs
    .readdirSync(RULES_DIR)
    .filter((f) => f.startsWith('compliance-') && f.endsWith('.yaml'));
  files.forEach((f) => fs.unlinkSync(path.join(RULES_DIR, f)));
  return files.length;
}
