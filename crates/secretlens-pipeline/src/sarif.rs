use secretlens_core::Finding;
use serde_json::{json, Value};

/// Generate a SARIF 2.1.0 document from a list of findings.
///
/// Compatible with GitHub Advanced Security and any SARIF-consuming CI tool.
pub fn to_sarif(findings: &[Finding], tool_version: &str) -> Value {
    let rules: Vec<Value> = {
        // Collect unique rule IDs in stable order
        let mut seen = LinkedHashSet::new();
        let mut rule_list = Vec::new();
        for f in findings {
            if seen.insert(f.rule_id.clone()) {
                rule_list.push(json!({
                    "id": f.rule_id,
                    "name": f.title,
                    "shortDescription": {
                        "text": f.message
                    },
                    "fullDescription": {
                        "text": f.description
                    },
                    "helpUri": f.references.first().cloned().unwrap_or_default(),
                    "properties": {
                        "tags": f.tags,
                        "severity": format!("{:?}", f.severity).to_lowercase()
                    }
                }));
            }
        }
        rule_list
    };

    let results: Vec<Value> = findings
        .iter()
        .map(|f| {
            let level = severity_to_sarif_level(&format!("{:?}", f.severity));
            let mut result = json!({
                "ruleId": f.rule_id,
                "level": level,
                "message": {
                    "text": f.message
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": f.file_path,
                            "uriBaseId": "%SRCROOT%"
                        },
                        "region": {
                            "startLine": f.line_number
                        }
                    }
                }]
            });

            // Attach AI enrichment as a code flow if present
            if let Some(impact) = &f.impact {
                result["properties"] = json!({
                    "impact": impact,
                    "suggestedFix": f.suggested_fix
                });
            }

            result
        })
        .collect();

    json!({
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "SecretLens",
                    "version": tool_version,
                    "informationUri": "https://github.com/anomalyco/secretlens",
                    "rules": rules
                }
            },
            "results": results
        }]
    })
}

fn severity_to_sarif_level(severity: &str) -> &'static str {
    match severity.to_lowercase().as_str() {
        "critical" | "high" => "error",
        "medium" => "warning",
        "low" | "info" => "note",
        _ => "warning",
    }
}

// LinkedHashSet — use IndexSet from indexmap, or just a Vec+contains for now
// Since we don't have indexmap in scope, use a simple ordered-insert approach via Vec
mod linked_hash_set {
    pub struct LinkedHashSet(Vec<String>);
    impl LinkedHashSet {
        pub fn new() -> Self {
            Self(Vec::new())
        }
        pub fn insert(&mut self, val: String) -> bool {
            if self.0.contains(&val) {
                return false;
            }
            self.0.push(val);
            true
        }
    }
}

// Re-open the module as a type alias for cleaner use above
use linked_hash_set::LinkedHashSet;

#[cfg(test)]
mod tests {
    use super::*;
    use secretlens_core::{FindingType, Severity};

    #[test]
    fn sarif_output_has_correct_schema() {
        let findings = vec![Finding::new(
            "src/main.py",
            10,
            FindingType::Security,
            Severity::Critical,
            "AWS key found",
            "AWS Key",
            "An AWS key",
            "SEC-001",
        )];
        let sarif = to_sarif(&findings, "1.0.0");
        assert_eq!(sarif["version"], "2.1.0");
        assert!(sarif["runs"][0]["results"][0]["ruleId"] == "SEC-001");
        assert_eq!(sarif["runs"][0]["results"][0]["level"], "error");
    }

    #[test]
    fn sarif_empty_findings() {
        let sarif = to_sarif(&[], "1.0.0");
        assert_eq!(sarif["runs"][0]["results"].as_array().unwrap().len(), 0);
    }
}
