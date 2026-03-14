import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as yaml from 'js-yaml';
import { GoogleGenerativeAI, GenerativeModel } from '@google/generative-ai';
import {
  ComplianceControl,
  RuleData,
  ValidatedRule,
  ComplianceProgressEvent,
} from './types';
import { ComplianceRuleSummary } from '../../shared/types';

// ─── Gemini key resolution ────────────────────────────────────────────────────

function resolveGeminiKey(): string {
  const configPath = path.join(os.homedir(), '.secretlens', 'config.json');
  if (fs.existsSync(configPath)) {
    try {
      const cfg = JSON.parse(fs.readFileSync(configPath, 'utf-8'));
      if (cfg.gemini_api_key) return cfg.gemini_api_key as string;
    } catch { /* fall through */ }
  }
  const env = process.env.GEMINI_API_KEY ?? process.env.GOOGLE_API_KEY;
  if (env) return env;
  throw new Error(
    'Gemini API key not found. Add "gemini_api_key" to ~/.secretlens/config.json',
  );
}

function getModel(): GenerativeModel {
  const genAI = new GoogleGenerativeAI(resolveGeminiKey());
  return genAI.getGenerativeModel({
    model: 'gemini-2.0-flash',
    generationConfig: {
      responseMimeType: 'application/json',
      temperature: 0.1,
    },
  });
}

// ─── Agent 1 — Parse compliance controls from PDF text ────────────────────────

const PARSE_PROMPT = `You are a compliance document parser.

Extract every compliance control from the document below into a JSON array.
Each element must have exactly these fields:
  "id"          – control identifier exactly as written (e.g. "A.7.2", "A.5", "A.6.1.2")
  "name"        – control name
  "domain"      – domain / section heading
  "severity"    – one of: "critical" | "high" | "medium" | "low"  (lowercase)
  "expectation" – the EXPECTATION paragraph (what the control requires)
  "flagIf"      – the FLAG IF paragraph (conditions that must be flagged)
  "keywords"    – array of keyword strings from the "Keywords:" line
  "evidence"    – the EVIDENCE TO COLLECT paragraph
  "standard"    – always "ISO/IEC 42001:2023"

Rules:
- Include ALL controls, do not skip any.
- severity must be lowercase.
- keywords must be an array of strings (split the comma-separated list).
- Return ONLY a valid JSON array — no markdown, no prose.

Document:
`;

export async function parseComplianceControls(
  pdfText: string,
  onProgress?: (e: ComplianceProgressEvent) => void,
): Promise<ComplianceControl[]> {
  onProgress?.({
    step: 'ai-parse',
    message: 'Agent 1 — Sending document to Gemini…',
    progress: 22,
  });

  const model = getModel();
  const result = await model.generateContent(PARSE_PROMPT + pdfText);
  const raw = result.response.text();

  let controls: ComplianceControl[];
  try {
    controls = JSON.parse(raw) as ComplianceControl[];
  } catch {
    // Gemini occasionally wraps in a top-level object
    const match = raw.match(/\[[\s\S]*\]/);
    if (!match) throw new Error('Agent 1 returned unparseable JSON');
    controls = JSON.parse(match[0]) as ComplianceControl[];
  }

  if (!Array.isArray(controls) || controls.length === 0) {
    throw new Error('Agent 1 returned no controls');
  }

  onProgress?.({
    step: 'ai-parse',
    message: `Agent 1 — Extracted ${controls.length} compliance controls`,
    progress: 42,
    detail: controls.map((c) => c.id).join(', '),
  });

  return controls;
}

// ─── Agent 2 — Generate YAML rules from controls ─────────────────────────────

const RULE_SYSTEM_PROMPT = `You are a code-analysis rule generator for a static analysis engine that scans source code files in git commits.

For each compliance control I give you, generate ONE detection rule.

Return a JSON array where each element has these exact fields:
  "controlId"       – original control id (e.g. "A.7.2")
  "ruleId"          – "COMP-" + sanitized id (replace dots, slashes, spaces with hyphens; e.g. COMP-A7-2)
  "name"            – "ISO 42001 {id} — {name}"
  "type"            – always "compliance"
  "severity"        – same as control severity (lowercase)
  "language"        – always "*"
  "analyzer"        – always "regex"
  "pattern"         – a valid Python/Rust regex string (see guidelines below)
  "message"         – "{id}: {one-line detection description}"
  "title"           – "ISO 42001 {id} — {short title}"
  "description"     – what this control requires and why this pattern flags it
  "redact"          – always false
  "recommendations" – array of 2 actionable strings
  "references"      – ["ISO/IEC 42001:2023 Control {id}"]
  "tags"            – ["compliance", "iso42001", "{domain-in-kebab-case}"]

Pattern guidelines:
- Use alternation groups: (pattern1|pattern2|pattern3) — aim for 3–6 alternatives
- Escape dots as \\\\. and other special chars as needed in the JSON string
- The pattern should match SOURCE CODE lines relevant to the control that a developer should review
- Data controls  → dataset loading: (pd\\\\.read_csv\\\\(|load_dataset\\\\(|np\\\\.load\\\\(|DataLoader\\\\(|open\\\\()
- Model training → (model\\\\.fit\\\\(|trainer\\\\.train\\\\(|\\\\.fit_transform\\\\(|train_model\\\\()
- Deployment     → (deploy\\\\(|push_to_hub\\\\(|\\\\.serve\\\\(|app\\\\.run\\\\(|uvicorn|gunicorn)
- Logging gaps   → (except:\\\\s*$|except\\\\s+Exception|except:\\\\s*pass|raise\\\\s+\\\\w+Error\\\\()
- AI inference   → (\\\\.predict\\\\(|\\\\.generate\\\\(|openai\\\\.|anthropic\\\\.|llm\\\\.)
- Governance     → (#\\\\s*TODO|#\\\\s*FIXME|#\\\\s*HACK|#\\\\s*noqa|# type: ignore)
- Doc/review     → (assert\\\\s+False|raise\\\\s+NotImplementedError|pass\\\\s*#)
- Use case-insensitive matching where the literal case varies
- Keep patterns valid for both Python and Rust "regex" crate (no look-ahead/behind)

Return ONLY a valid JSON array — no markdown, no prose.

Controls:
`;

const BATCH_SIZE = 12;

export async function generateComplianceRules(
  controls: ComplianceControl[],
  onProgress?: (e: ComplianceProgressEvent) => void,
): Promise<RuleData[]> {
  const model = getModel();
  const allRules: RuleData[] = [];

  for (let i = 0; i < controls.length; i += BATCH_SIZE) {
    const batch = controls.slice(i, i + BATCH_SIZE);
    const batchEnd = Math.min(i + BATCH_SIZE, controls.length);

    onProgress?.({
      step: 'ai-generate',
      message: `Agent 2 — Generating rules ${i + 1}–${batchEnd} of ${controls.length}…`,
      progress: 50 + Math.round((i / controls.length) * 22),
    });

    const batchRules = await generateRuleBatch(model, batch);
    allRules.push(...batchRules);
  }

  onProgress?.({
    step: 'ai-generate',
    message: `Agent 2 — Generated ${allRules.length} rule definitions`,
    progress: 74,
  });

  return allRules;
}

async function generateRuleBatch(
  model: GenerativeModel,
  batch: ComplianceControl[],
): Promise<RuleData[]> {
  const prompt = RULE_SYSTEM_PROMPT + JSON.stringify(batch, null, 2);
  const result = await model.generateContent(prompt);
  const raw = result.response.text();

  let parsed: RuleData[];
  try {
    parsed = JSON.parse(raw) as RuleData[];
  } catch {
    const match = raw.match(/\[[\s\S]*\]/);
    if (!match) return [];
    parsed = JSON.parse(match[0]) as RuleData[];
  }

  return (Array.isArray(parsed) ? parsed : []).map((r) => ({
    controlId: String(r.controlId ?? ''),
    ruleId: String(r.ruleId ?? ''),
    name: String(r.name ?? ''),
    type: 'compliance',
    severity: String(r.severity ?? 'medium').toLowerCase(),
    language: '*',
    analyzer: 'regex',
    pattern: String(r.pattern ?? ''),
    message: String(r.message ?? ''),
    title: String(r.title ?? r.name ?? ''),
    description: String(r.description ?? ''),
    redact: false,
    recommendations: Array.isArray(r.recommendations) ? r.recommendations.map(String) : [],
    references: Array.isArray(r.references) ? r.references.map(String) : [],
    tags: Array.isArray(r.tags) ? r.tags.map(String) : ['compliance', 'iso42001'],
  }));
}

// ─── Agent 3 — Validate and save rules (deterministic, no LLM) ───────────────

export function validateAndSaveRules(
  rules: RuleData[],
  rulesDir: string,
  onProgress?: (e: ComplianceProgressEvent) => void,
): ComplianceRuleSummary[] {
  if (!fs.existsSync(rulesDir)) {
    fs.mkdirSync(rulesDir, { recursive: true });
  }

  const saved: ComplianceRuleSummary[] = [];
  let checked = 0;

  for (const rule of rules) {
    checked++;
    onProgress?.({
      step: 'validate',
      message: `Validating rule ${checked}/${rules.length}: ${rule.ruleId}`,
      progress: 76 + Math.round((checked / rules.length) * 14),
    });

    // Required field checks
    if (!rule.ruleId || !rule.pattern || !rule.severity || !rule.name) continue;
    if (!['critical', 'high', 'medium', 'low'].includes(rule.severity)) continue;

    // Regex validity check (Rust regex crate is close enough to JS for this validation)
    try {
      new RegExp(rule.pattern);
    } catch {
      continue; // skip invalid regex
    }

    // Build the YAML object that matches the engine's Rule schema exactly
    const yamlObj: Record<string, unknown> = {
      id: rule.ruleId,
      name: rule.name,
      type: 'compliance',
      severity: rule.severity,
      language: rule.language ?? '*',
      analyzer: 'regex',
      pattern: rule.pattern,
      message: rule.message,
      title: rule.title || rule.name,
      description: rule.description,
      redact: false,
    };

    if (rule.recommendations?.length) yamlObj.recommendations = rule.recommendations;
    if (rule.references?.length)      yamlObj.references      = rule.references;
    if (rule.tags?.length)            yamlObj.tags            = rule.tags;

    let yamlStr: string;
    try {
      yamlStr = yaml.dump(yamlObj, {
        lineWidth: 160,
        indent: 2,
        quotingType: '"',
        forceQuotes: false,
        sortKeys: false,
      });
    } catch {
      continue;
    }

    // Write file — prefix "compliance-" so we can find/remove them later
    const filename = `compliance-${rule.ruleId.toLowerCase()}.yaml`;
    const filePath = path.join(rulesDir, filename);
    fs.writeFileSync(filePath, `# ISO/IEC 42001:2023 — ${rule.controlId}: ${rule.name}\n${yamlStr}`, 'utf-8');

    const domainTag = (rule.tags ?? []).find(
      (t) => t !== 'compliance' && t !== 'iso42001',
    ) ?? '';

    saved.push({
      ruleId: rule.ruleId,
      controlId: rule.controlId,
      name: rule.name,
      severity: rule.severity,
      domain: domainTag,
      pattern: rule.pattern,
      filePath,
    });
  }

  return saved;
}
