use secretlens_core::{Finding, Rule};

/// Applies per-rule redaction to findings before they leave the pipeline.
///
/// For each finding:
/// - If `rule.redact` is true (the default), the `raw_finding_data` field is
///   replaced with `rule.redact_replacement` (default "REDACTED").
/// - If `rule.redact` is false, `raw_finding_data` is preserved as-is.
///
/// This fully fixes the C# bug where `redact: false` was never wired through.
pub struct Redactor;

impl Redactor {
    /// Apply redaction rules to all findings in-place.
    /// `rule_map` maps rule_id -> Rule for O(1) lookups.
    pub fn apply(findings: &mut Vec<Finding>, rules: &[Rule]) {
        // Build a lookup map
        let rule_map: std::collections::HashMap<&str, &Rule> =
            rules.iter().map(|r| (r.id.as_str(), r)).collect();

        for finding in findings.iter_mut() {
            match rule_map.get(finding.rule_id.as_str()) {
                Some(rule) => {
                    if rule.redact {
                        if finding.raw_finding_data.is_some() {
                            finding.raw_finding_data = Some(rule.redact_replacement.clone());
                        }
                    }
                    // If redact == false, leave raw_finding_data as-is
                }
                None => {
                    // Unknown rule — default to redacting to be safe
                    if finding.raw_finding_data.is_some() {
                        finding.raw_finding_data = Some("REDACTED".to_string());
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secretlens_core::{AnalyzerKind, FindingType, RuleConditions, Severity};

    fn make_rule(id: &str, redact: bool, replacement: &str) -> Rule {
        Rule {
            id: id.to_string(),
            name: "test".to_string(),
            finding_type: "security".to_string(),
            severity: "high".to_string(),
            language: "*".to_string(),
            analyzer: AnalyzerKind::Regex,
            pattern: "test".to_string(),
            message: "msg".to_string(),
            title: String::new(),
            description: String::new(),
            redact,
            redact_replacement: replacement.to_string(),
            recommendations: vec![],
            references: vec![],
            tags: vec![],
            conditions: RuleConditions::default(),
        }
    }

    fn make_finding_with_raw(rule_id: &str, raw: &str) -> Finding {
        let mut f = Finding::new(
            "a.py",
            1,
            FindingType::Security,
            Severity::High,
            "msg",
            "title",
            "desc",
            rule_id,
        );
        f.raw_finding_data = Some(raw.to_string());
        f
    }

    #[test]
    fn redacts_when_redact_true() {
        let rules = vec![make_rule("SEC-001", true, "REDACTED")];
        let mut findings = vec![make_finding_with_raw("SEC-001", "AKIAIOSFODNN7EXAMPLE")];
        Redactor::apply(&mut findings, &rules);
        assert_eq!(findings[0].raw_finding_data.as_deref(), Some("REDACTED"));
    }

    #[test]
    fn preserves_raw_when_redact_false() {
        let rules = vec![make_rule("AST-JS-001", false, "REDACTED")];
        let mut findings = vec![make_finding_with_raw("AST-JS-001", "eval(x)")];
        Redactor::apply(&mut findings, &rules);
        assert_eq!(
            findings[0].raw_finding_data.as_deref(),
            Some("eval(x)"),
            "raw_finding_data should be preserved when redact=false"
        );
    }

    #[test]
    fn uses_custom_replacement_text() {
        let rules = vec![make_rule("SEC-005", true, "[STRIPE KEY REDACTED]")];
        let mut findings = vec![make_finding_with_raw("SEC-005", "sk_live_abc123")];
        Redactor::apply(&mut findings, &rules);
        assert_eq!(
            findings[0].raw_finding_data.as_deref(),
            Some("[STRIPE KEY REDACTED]")
        );
    }
}
