use crate::error::AnalyzerError;
use dashmap::DashMap;
use once_cell::sync::Lazy;
use regex::Regex;
use secretlens_core::{FileChange, Finding, FindingType, Rule, Severity};
use std::sync::Arc;
use tracing::warn;
use uuid::Uuid;

/// Global compiled-regex cache — keyed by rule ID.
/// Regex compilation is expensive; we compile once and reuse across files/threads.
static REGEX_CACHE: Lazy<DashMap<String, Arc<Regex>>> = Lazy::new(DashMap::new);

/// Applies all regex-based rules against a set of files and returns findings.
///
/// Parallelism: The caller (pipeline) maps over files with rayon; this function
/// is called per-file and is `Send + Sync`.
pub struct RegexAnalyzer;

impl RegexAnalyzer {
    /// Analyze a single file against a slice of regex rules.
    ///
    /// Returns all findings, unsorted and undeduped (pipeline handles that).
    pub fn analyze(file: &FileChange, rules: &[Rule], line_table: &[usize]) -> Vec<Finding> {
        let lang = file.language();
        let mut findings = Vec::new();

        for rule in rules {
            // Language filter
            if rule.language != "*" && rule.language != lang {
                continue;
            }

            // Path exclusion
            if rule.should_exclude_path(&file.file_path) {
                continue;
            }

            // Get or compile regex
            let re = match get_or_compile_regex(rule) {
                Ok(r) => r,
                Err(e) => {
                    warn!("{}", e);
                    continue;
                }
            };

            // Run the regex against the full file content
            for mat in re.find_iter(&file.content) {
                let byte_offset = mat.start();
                let line_number = offset_to_line(byte_offset, line_table);
                let raw_text = mat.as_str().to_string();

                let mut finding = Finding::new(
                    file.file_path.clone(),
                    line_number,
                    FindingType::from_str(&rule.finding_type),
                    Severity::from_str(&rule.severity),
                    rule.message.clone(),
                    rule.effective_title().to_string(),
                    rule.description.clone(),
                    rule.id.clone(),
                );
                finding.id = Uuid::new_v4();
                finding.recommendations = rule.recommendations.clone();
                finding.references = rule.references.clone();
                finding.tags = rule.tags.clone();

                // Redaction: store raw text only if redact is true (will be redacted later)
                // If redact is false, we still store the raw finding for context
                finding.raw_finding_data = Some(raw_text);

                findings.push(finding);
            }
        }

        findings
    }
}

/// Get a compiled regex from the cache, compiling on first access.
fn get_or_compile_regex(rule: &Rule) -> Result<Arc<Regex>, AnalyzerError> {
    if let Some(entry) = REGEX_CACHE.get(&rule.id) {
        return Ok(Arc::clone(&*entry));
    }

    let re = Regex::new(&rule.pattern).map_err(|e| AnalyzerError::RegexCompile {
        rule_id: rule.id.clone(),
        source: e,
    })?;
    let arc = Arc::new(re);
    REGEX_CACHE.insert(rule.id.clone(), Arc::clone(&arc));
    Ok(arc)
}

/// Convert a byte offset to a 1-indexed line number using a pre-built line table.
/// Uses binary search — O(log n) per lookup.
pub fn offset_to_line(byte_offset: usize, line_table: &[usize]) -> u32 {
    match line_table.binary_search(&byte_offset) {
        Ok(idx) => (idx + 1) as u32,
        Err(idx) => idx as u32, // idx is the insertion point, so line = idx (1-indexed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secretlens_core::{AnalyzerKind, RuleConditions};

    fn make_rule(id: &str, pattern: &str) -> Rule {
        Rule {
            id: id.to_string(),
            name: format!("Test rule {}", id),
            finding_type: "security".to_string(),
            severity: "high".to_string(),
            language: "*".to_string(),
            analyzer: AnalyzerKind::Regex,
            pattern: pattern.to_string(),
            message: "Test finding".to_string(),
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
    fn finds_aws_key_in_content() {
        let file = FileChange {
            file_path: "config.py".to_string(),
            content: "key = \"AKIAIOSFODNN7EXAMPLE\"".to_string(),
        };
        let line_table = file.build_line_table();
        let rule = make_rule("SEC-001", r"(AKIA[0-9A-Z]{16})");
        let findings = RegexAnalyzer::analyze(&file, &[rule], &line_table);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].line_number, 1);
        assert_eq!(findings[0].rule_id, "SEC-001");
    }

    #[test]
    fn no_findings_on_clean_file() {
        let file = FileChange {
            file_path: "clean.py".to_string(),
            content: "x = 1\ny = 2\n".to_string(),
        };
        let line_table = file.build_line_table();
        let rule = make_rule("SEC-001", r"(AKIA[0-9A-Z]{16})");
        let findings = RegexAnalyzer::analyze(&file, &[rule], &line_table);
        assert!(findings.is_empty());
    }

    #[test]
    fn language_filter_skips_wrong_language() {
        let file = FileChange {
            file_path: "app.rs".to_string(), // rust
            content: "eval(something)".to_string(),
        };
        let line_table = file.build_line_table();
        let mut rule = make_rule("TEST-JS", r"eval\(");
        rule.language = "javascript".to_string(); // only JS
        let findings = RegexAnalyzer::analyze(&file, &[rule], &line_table);
        assert!(findings.is_empty());
    }

    #[test]
    fn exclude_path_suppresses_finding() {
        let file = FileChange {
            file_path: "node_modules/lib/index.js".to_string(),
            content: "AKIAIOSFODNN7EXAMPLE".to_string(),
        };
        let line_table = file.build_line_table();
        let mut rule = make_rule("SEC-001", r"(AKIA[0-9A-Z]{16})");
        rule.conditions = RuleConditions {
            exclude_paths: vec!["node_modules/".to_string()],
        };
        let findings = RegexAnalyzer::analyze(&file, &[rule], &line_table);
        assert!(findings.is_empty());
    }

    #[test]
    fn multiline_file_correct_line_numbers() {
        let content = "line1\nline2\nAKIAIOSFODNN7EXAMPLE\nline4\n";
        let file = FileChange {
            file_path: "test.py".to_string(),
            content: content.to_string(),
        };
        let line_table = file.build_line_table();
        let rule = make_rule("SEC-001", r"(AKIA[0-9A-Z]{16})");
        let findings = RegexAnalyzer::analyze(&file, &[rule], &line_table);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].line_number, 3);
    }

    #[test]
    fn offset_to_line_single_line() {
        let table = vec![0usize];
        assert_eq!(offset_to_line(0, &table), 1);
        assert_eq!(offset_to_line(10, &table), 1);
    }

    #[test]
    fn offset_to_line_multiple_lines() {
        // "abc\ndef\nghi" -> offsets [0, 4, 8]
        let table = vec![0, 4, 8];
        assert_eq!(offset_to_line(0, &table), 1);
        assert_eq!(offset_to_line(3, &table), 1);
        assert_eq!(offset_to_line(4, &table), 2);
        assert_eq!(offset_to_line(7, &table), 2);
        assert_eq!(offset_to_line(8, &table), 3);
    }
}
