use serde::{Deserialize, Serialize};

/// A rule loaded from YAML (or built-in defaults).
/// This is the canonical, validated rule type used throughout the engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    /// Unique rule identifier (e.g. "SEC-001")
    pub id: String,

    /// Human-readable name
    pub name: String,

    /// Finding type this rule produces
    #[serde(rename = "type")]
    pub finding_type: String,

    /// Severity level
    pub severity: String,

    /// Language filter: "*" for all, or a specific language name
    pub language: String,

    /// Which analyzer runs this rule
    pub analyzer: AnalyzerKind,

    /// The pattern — regex string for Regex rules, structured for AST rules
    pub pattern: String,

    /// Short message shown in findings
    pub message: String,

    /// Optional title (defaults to `name` if absent)
    #[serde(default)]
    pub title: String,

    /// Extended description
    #[serde(default)]
    pub description: String,

    /// Whether to redact matched text before AI enrichment (default: true)
    #[serde(default = "default_true")]
    pub redact: bool,

    /// Custom redaction replacement text (default: "REDACTED")
    #[serde(default = "default_redacted")]
    pub redact_replacement: String,

    /// Remediation recommendations
    #[serde(default)]
    pub recommendations: Vec<String>,

    /// Reference links
    #[serde(default)]
    pub references: Vec<String>,

    /// Tags for categorization / filtering
    #[serde(default)]
    pub tags: Vec<String>,

    /// Path/file conditions
    #[serde(default)]
    pub conditions: RuleConditions,
}

fn default_true() -> bool {
    true
}
fn default_redacted() -> String {
    "REDACTED".to_string()
}

impl Rule {
    /// Returns whether this rule uses the AST analyzer
    pub fn is_ast_based(&self) -> bool {
        self.analyzer == AnalyzerKind::Ast
    }

    /// Returns the effective title (falls back to name)
    pub fn effective_title(&self) -> &str {
        if self.title.is_empty() {
            &self.name
        } else {
            &self.title
        }
    }

    /// Check if a file path should be excluded based on rule conditions
    pub fn should_exclude_path(&self, path: &str) -> bool {
        self.conditions
            .exclude_paths
            .iter()
            .any(|excl| path.contains(excl.as_str()))
    }

    /// Validate that this rule has all required fields set correctly
    pub fn validate(&self) -> Result<(), String> {
        if self.id.is_empty() {
            return Err("Rule is missing required field: id".to_string());
        }
        if self.name.is_empty() {
            return Err(format!(
                "Rule '{}' is missing required field: name",
                self.id
            ));
        }
        if self.pattern.is_empty() {
            return Err(format!(
                "Rule '{}' is missing required field: pattern",
                self.id
            ));
        }
        if self.message.is_empty() {
            return Err(format!(
                "Rule '{}' is missing required field: message",
                self.id
            ));
        }
        Ok(())
    }
}

/// Which analyzer should process this rule
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AnalyzerKind {
    #[serde(rename = "regex", alias = "Regex")]
    Regex,
    #[serde(rename = "ast", alias = "AST")]
    Ast,
}

impl Default for AnalyzerKind {
    fn default() -> Self {
        Self::Regex
    }
}

/// Typed AST pattern — parsed from the YAML `pattern` field for AST rules.
///
/// Instead of fragile JSONPath strings, patterns are expressed in a small
/// typed DSL:
///   - `call:<name>`                   — any call to a named function
///   - `member_call:<object>.<method>` — method call on a specific object
///   - `crypto_weak:<algorithm>`       — use of a known-weak crypto algorithm
///   - `import:<module>`               — import of a specific module
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AstPattern {
    /// Matches any call expression to a function with the given name
    /// Pattern syntax: `call:eval`
    Call { name: String },

    /// Matches a method call on a specific receiver
    /// Pattern syntax: `member_call:fs.readFileSync`
    MemberCall { object: String, method: String },

    /// Matches use of a specific weak cryptographic algorithm
    /// Pattern syntax: `crypto_weak:md5`
    CryptoWeak { algorithm: String },

    /// Matches an import of a specific module
    /// Pattern syntax: `import:subprocess`
    Import { module: String },
}

impl AstPattern {
    /// Parse a pattern string into a typed AstPattern.
    /// Falls back to `Call { name }` for bare names (backward compat with simple cases).
    pub fn parse(s: &str) -> Result<Self, String> {
        if let Some(rest) = s.strip_prefix("call:") {
            return Ok(AstPattern::Call {
                name: rest.to_string(),
            });
        }
        if let Some(rest) = s.strip_prefix("member_call:") {
            let parts: Vec<&str> = rest.splitn(2, '.').collect();
            if parts.len() != 2 {
                return Err(format!(
                    "Invalid member_call pattern '{}': expected 'object.method'",
                    s
                ));
            }
            return Ok(AstPattern::MemberCall {
                object: parts[0].to_string(),
                method: parts[1].to_string(),
            });
        }
        if let Some(rest) = s.strip_prefix("crypto_weak:") {
            return Ok(AstPattern::CryptoWeak {
                algorithm: rest.to_string(),
            });
        }
        if let Some(rest) = s.strip_prefix("import:") {
            return Ok(AstPattern::Import {
                module: rest.to_string(),
            });
        }
        // Bare name — treat as a function call match for simplicity
        Ok(AstPattern::Call {
            name: s.to_string(),
        })
    }
}

/// Conditions controlling when a rule applies
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RuleConditions {
    /// Path substrings to exclude (e.g. "node_modules/", ".git/")
    #[serde(default)]
    pub exclude_paths: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ast_pattern_parse_call() {
        let p = AstPattern::parse("call:eval").unwrap();
        assert_eq!(
            p,
            AstPattern::Call {
                name: "eval".to_string()
            }
        );
    }

    #[test]
    fn ast_pattern_parse_member_call() {
        let p = AstPattern::parse("member_call:fs.readFileSync").unwrap();
        assert_eq!(
            p,
            AstPattern::MemberCall {
                object: "fs".to_string(),
                method: "readFileSync".to_string(),
            }
        );
    }

    #[test]
    fn ast_pattern_parse_crypto_weak() {
        let p = AstPattern::parse("crypto_weak:md5").unwrap();
        assert_eq!(
            p,
            AstPattern::CryptoWeak {
                algorithm: "md5".to_string()
            }
        );
    }

    #[test]
    fn ast_pattern_parse_import() {
        let p = AstPattern::parse("import:subprocess").unwrap();
        assert_eq!(
            p,
            AstPattern::Import {
                module: "subprocess".to_string()
            }
        );
    }

    #[test]
    fn ast_pattern_bare_name_fallback() {
        let p = AstPattern::parse("eval").unwrap();
        assert_eq!(
            p,
            AstPattern::Call {
                name: "eval".to_string()
            }
        );
    }

    #[test]
    fn rule_validation_catches_empty_id() {
        let r = Rule {
            id: String::new(),
            name: "Test".to_string(),
            finding_type: "Security".to_string(),
            severity: "high".to_string(),
            language: "*".to_string(),
            analyzer: AnalyzerKind::Regex,
            pattern: "test".to_string(),
            message: "msg".to_string(),
            title: String::new(),
            description: String::new(),
            redact: true,
            redact_replacement: "REDACTED".to_string(),
            recommendations: vec![],
            references: vec![],
            tags: vec![],
            conditions: RuleConditions::default(),
        };
        assert!(r.validate().is_err());
    }
}
