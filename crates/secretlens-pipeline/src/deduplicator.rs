use secretlens_core::Finding;
use std::collections::HashSet;

/// Deduplicates findings by (file_path, line_number, rule_id).
/// The first occurrence of each unique key is kept; subsequent ones are dropped.
pub struct Deduplicator;

impl Deduplicator {
    pub fn deduplicate(findings: Vec<Finding>) -> Vec<Finding> {
        let mut seen = HashSet::new();
        let mut result = Vec::with_capacity(findings.len());

        for finding in findings {
            let key = (
                finding.file_path.clone(),
                finding.line_number,
                finding.rule_id.clone(),
            );
            if seen.insert(key) {
                result.push(finding);
            }
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secretlens_core::{FindingType, Severity};

    fn make_finding(file: &str, line: u32, rule: &str) -> Finding {
        Finding::new(
            file,
            line,
            FindingType::Security,
            Severity::High,
            "msg",
            "title",
            "desc",
            rule,
        )
    }

    #[test]
    fn dedup_removes_exact_duplicates() {
        let findings = vec![
            make_finding("a.py", 10, "SEC-001"),
            make_finding("a.py", 10, "SEC-001"), // duplicate
            make_finding("a.py", 11, "SEC-001"), // different line
        ];
        let result = Deduplicator::deduplicate(findings);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn dedup_keeps_different_rules_same_line() {
        let findings = vec![
            make_finding("a.py", 5, "SEC-001"),
            make_finding("a.py", 5, "SEC-002"), // same line, different rule
        ];
        let result = Deduplicator::deduplicate(findings);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn dedup_empty_vec_is_fine() {
        let result = Deduplicator::deduplicate(vec![]);
        assert!(result.is_empty());
    }
}
