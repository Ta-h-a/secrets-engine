use crate::deduplicator::Deduplicator;
use crate::error::PipelineError;
use crate::redactor::Redactor;
use rayon::prelude::*;
use secretlens_ai::{AiProvider, EnrichmentRequest};
use secretlens_analyzers::{AstAnalyzer, RegexAnalyzer};
use secretlens_core::{AnalyzerKind, Finding, FileChange, Rule};
use tracing::{debug, info, warn};

/// Maximum file size to analyze (200 KB)
const MAX_FILE_BYTES: usize = 200 * 1024;

/// The three-stage analysis pipeline:
///
/// Stage 1 — Analysis: run regex + AST analyzers across all files×rules in parallel (rayon)
/// Stage 2 — Redaction: per-rule redact/preserve raw_finding_data
/// Stage 3 — Deduplication: drop (file, line, rule_id) duplicates
/// Stage 4 (optional) — AI enrichment: enrich surviving findings (async, sequential)
pub struct AnalysisPipeline {
    rules: Vec<Rule>,
}

impl AnalysisPipeline {
    /// Create a new pipeline with the given rules.
    pub fn new(rules: Vec<Rule>) -> Self {
        Self { rules }
    }

    /// Run the full synchronous pipeline (stages 1–3) on a set of files.
    /// Returns deduplicated, redacted findings.
    pub fn run(&self, files: &[FileChange]) -> Vec<Finding> {
        info!(
            "Pipeline starting: {} files, {} rules",
            files.len(),
            self.rules.len()
        );

        // Partition rules by analyzer kind once — avoids repeated filtering in inner loops
        let regex_rules: Vec<&Rule> = self
            .rules
            .iter()
            .filter(|r| r.analyzer == AnalyzerKind::Regex)
            .collect();
        let ast_rules: Vec<&Rule> = self
            .rules
            .iter()
            .filter(|r| r.analyzer == AnalyzerKind::Ast)
            .collect();

        // Stage 1: Parallel analysis across files
        let raw_findings: Vec<Finding> = files
            .par_iter()
            .flat_map(|file| {
                if file.is_too_large(MAX_FILE_BYTES) {
                    warn!(
                        "Skipping '{}': file is too large ({} bytes)",
                        file.file_path,
                        file.content.len()
                    );
                    return vec![];
                }

                let line_table = file.build_line_table();
                let mut file_findings = Vec::new();

                // Regex pass
                if !regex_rules.is_empty() {
                    let regex_rules_owned: Vec<Rule> =
                        regex_rules.iter().map(|r| (*r).clone()).collect();
                    file_findings.extend(RegexAnalyzer::analyze(
                        file,
                        &regex_rules_owned,
                        &line_table,
                    ));
                }

                // AST pass
                if !ast_rules.is_empty() {
                    let ast_rules_owned: Vec<Rule> =
                        ast_rules.iter().map(|r| (*r).clone()).collect();
                    file_findings.extend(AstAnalyzer::analyze(
                        file,
                        &ast_rules_owned,
                        &line_table,
                    ));
                }

                debug!(
                    "'{}': {} raw finding(s)",
                    file.file_path,
                    file_findings.len()
                );
                file_findings
            })
            .collect();

        info!(
            "Stage 1 complete: {} raw findings before dedup/redact",
            raw_findings.len()
        );

        // Stage 2: Redaction
        let mut findings = raw_findings;
        Redactor::apply(&mut findings, &self.rules);

        // Stage 3: Deduplication
        let findings = Deduplicator::deduplicate(findings);

        info!("Pipeline complete: {} final findings", findings.len());
        findings
    }

    /// Enrich findings with AI-generated impact + fix suggestions (async stage 4).
    /// Findings are enriched in-place. Non-fatal: failures are logged and skipped.
    pub async fn enrich_with_ai(
        findings: &mut Vec<Finding>,
        files: &[FileChange],
        provider: &(dyn AiProvider + Send + Sync),
    ) {
        if provider.name() == "null" {
            return;
        }

        info!(
            "AI enrichment starting: {} findings via provider '{}'",
            findings.len(),
            provider.name()
        );

        // Build a quick content lookup for snippet extraction
        let file_map: std::collections::HashMap<&str, &str> = files
            .iter()
            .map(|f| (f.file_path.as_str(), f.content.as_str()))
            .collect();

        for finding in findings.iter_mut() {
            let snippet = extract_snippet(
                file_map.get(finding.file_path.as_str()).copied().unwrap_or(""),
                finding.line_number,
                3,
            );

            let request = EnrichmentRequest {
                finding: finding.clone(),
                code_snippet: snippet,
            };

            match provider.enrich(request).await {
                Ok(Some(enrichment)) => {
                    finding.impact = Some(enrichment.impact);
                    finding.suggested_fix = Some(enrichment.suggested_fix);
                }
                Ok(None) => {}
                Err(e) => {
                    warn!(
                        "AI enrichment failed for finding {} ({}): {}",
                        finding.id, finding.rule_id, e
                    );
                }
            }
        }

        info!("AI enrichment complete");
    }
}

/// Extract a code snippet around a given line (1-indexed) with `context` lines of context.
fn extract_snippet(content: &str, line_number: u32, context: u32) -> String {
    let lines: Vec<&str> = content.lines().collect();
    if lines.is_empty() || line_number == 0 {
        return String::new();
    }

    let idx = (line_number as usize).saturating_sub(1);
    let start = idx.saturating_sub(context as usize);
    let end = (idx + context as usize + 1).min(lines.len());

    lines[start..end].join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use secretlens_core::{AnalyzerKind, RuleConditions};

    fn aws_key_rule() -> Rule {
        Rule {
            id: "SEC-001".to_string(),
            name: "AWS Key".to_string(),
            finding_type: "security".to_string(),
            severity: "critical".to_string(),
            language: "*".to_string(),
            analyzer: AnalyzerKind::Regex,
            pattern: r"(AKIA[0-9A-Z]{16})".to_string(),
            message: "AWS key found".to_string(),
            title: String::new(),
            description: String::new(),
            redact: true,
            redact_replacement: "REDACTED".to_string(),
            recommendations: vec![],
            references: vec![],
            tags: vec![],
            conditions: RuleConditions::default(),
        }
    }

    #[test]
    fn pipeline_finds_and_deduplicates() {
        let pipeline = AnalysisPipeline::new(vec![aws_key_rule()]);
        let files = vec![FileChange {
            file_path: "secrets.py".to_string(),
            content: "key = \"AKIAIOSFODNN7EXAMPLE\"\nkey2 = \"AKIAIOSFODNN7EXAMPLE\"".to_string(),
        }];
        let findings = pipeline.run(&files);
        // Two matches on different lines — should both survive dedup
        assert_eq!(findings.len(), 2);
    }

    #[test]
    fn pipeline_deduplicates_same_line_same_rule() {
        let pipeline = AnalysisPipeline::new(vec![aws_key_rule()]);
        // Regex will match twice on the same line if pattern appears twice
        // but they have same (file, line, rule_id) -> should be deduped to 1
        let files = vec![FileChange {
            file_path: "secrets.py".to_string(),
            content: "AKIAIOSFODNN7EXAMPLE AKIAIOSFODNN7EXAMPLE".to_string(),
        }];
        let findings = pipeline.run(&files);
        assert_eq!(findings.len(), 1, "Same line, same rule -> deduped to 1");
    }

    #[test]
    fn pipeline_redacts_raw_data() {
        let pipeline = AnalysisPipeline::new(vec![aws_key_rule()]);
        let files = vec![FileChange {
            file_path: "secrets.py".to_string(),
            content: "AKIAIOSFODNN7EXAMPLE".to_string(),
        }];
        let findings = pipeline.run(&files);
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].raw_finding_data.as_deref(),
            Some("REDACTED"),
            "raw_finding_data should be redacted"
        );
    }

    #[test]
    fn pipeline_empty_files_returns_empty() {
        let pipeline = AnalysisPipeline::new(vec![aws_key_rule()]);
        let findings = pipeline.run(&[]);
        assert!(findings.is_empty());
    }

    #[test]
    fn extract_snippet_correct_window() {
        let content = "line1\nline2\nline3\nline4\nline5";
        let snippet = extract_snippet(content, 3, 1);
        assert!(snippet.contains("line2"));
        assert!(snippet.contains("line3"));
        assert!(snippet.contains("line4"));
    }
}
