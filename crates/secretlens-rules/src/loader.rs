use crate::defaults::default_rules;
use crate::error::RulesError;
use secretlens_core::{AnalyzerKind, Rule};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tracing::{error, info, warn};

/// Loads and validates rules from a directory of YAML files.
///
/// Loading semantics:
///   - All `.yaml` and `.yml` files in the directory are loaded recursively.
///   - Rules with duplicate IDs emit an error and the duplicate is skipped (first-wins).
///   - Rules that fail validation (missing id/name/pattern/message) emit a warning and are skipped.
///   - Rules with invalid regex patterns fail loudly (Error).
///   - If the directory does not exist or is empty, built-in default rules are returned.
pub struct RuleLoader {
    rules_dir: Option<PathBuf>,
    /// Maximum number of rules to load (None = unlimited)
    max_rules: Option<usize>,
}

impl RuleLoader {
    /// Create a loader pointing at a rules directory
    pub fn from_dir(dir: impl AsRef<Path>) -> Self {
        Self {
            rules_dir: Some(dir.as_ref().to_path_buf()),
            max_rules: None,
        }
    }

    /// Create a loader that only returns built-in default rules
    pub fn defaults_only() -> Self {
        Self {
            rules_dir: None,
            max_rules: None,
        }
    }

    /// Load all rules. Returns (loaded_rules, Vec<warnings>)
    pub fn load(&self) -> (Vec<Rule>, Vec<String>) {
        let mut warnings = Vec::new();

        let Some(ref dir) = self.rules_dir else {
            info!("No rules directory configured — using built-in default rules");
            return (default_rules(), warnings);
        };

        if !dir.exists() {
            warn!(
                "Rules directory '{}' not found — using built-in default rules",
                dir.display()
            );
            warnings.push(format!("Rules directory '{}' not found", dir.display()));
            return (default_rules(), warnings);
        }

        let yaml_files = collect_yaml_files(dir);
        if yaml_files.is_empty() {
            warn!(
                "No YAML files found in '{}' — using built-in default rules",
                dir.display()
            );
            warnings.push(format!("No YAML files in '{}'", dir.display()));
            return (default_rules(), warnings);
        }

        let mut rules: Vec<Rule> = Vec::new();
        let mut seen_ids: HashMap<String, String> = HashMap::new();

        for file_path in &yaml_files {
            let file_name = file_path.display().to_string();

            let content = match std::fs::read_to_string(file_path) {
                Ok(c) => c,
                Err(e) => {
                    let msg = format!("Could not read '{}': {}", file_name, e);
                    error!("{}", msg);
                    warnings.push(msg);
                    continue;
                }
            };

            let rule: Rule = match serde_yaml::from_str(&content) {
                Ok(r) => r,
                Err(e) => {
                    let msg = format!("YAML parse error in '{}': {}", file_name, e);
                    error!("{}", msg);
                    warnings.push(msg);
                    continue;
                }
            };

            // Validate required fields
            if let Err(e) = rule.validate() {
                let msg = format!("Validation failed for '{}': {}", file_name, e);
                warn!("{}", msg);
                warnings.push(msg);
                continue;
            }

            // Validate regex pattern for regex rules
            if rule.analyzer == AnalyzerKind::Regex {
                if let Err(e) = regex::Regex::new(&rule.pattern) {
                    let msg = format!("Invalid regex in rule '{}' ({}): {}", rule.id, file_name, e);
                    error!("{}", msg);
                    warnings.push(msg);
                    continue;
                }
            }

            // Deduplication — first-wins
            if let Some(original) = seen_ids.get(&rule.id) {
                let msg = format!(
                    "Duplicate rule ID '{}' in '{}' (already loaded from '{}') — skipping",
                    rule.id, file_name, original
                );
                warn!("{}", msg);
                warnings.push(msg);
                continue;
            }

            seen_ids.insert(rule.id.clone(), file_name.clone());
            info!("Loaded rule: {} ({})", rule.id, rule.name);
            rules.push(rule);

            if let Some(max) = self.max_rules {
                if rules.len() >= max {
                    warn!("Rule limit of {} reached — stopping load", max);
                    break;
                }
            }
        }

        if rules.is_empty() {
            warn!("No valid rules loaded from directory — falling back to built-in defaults");
            warnings.push("No valid rules loaded; using built-in defaults".to_string());
            return (default_rules(), warnings);
        }

        info!("Loaded {} rules from '{}'", rules.len(), dir.display());
        (rules, warnings)
    }
}

/// Recursively collect all .yaml / .yml files under a directory
fn collect_yaml_files(dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return files;
    };

    let mut entries: Vec<_> = entries.flatten().collect();
    // Sort for deterministic load order
    entries.sort_by_key(|e| e.path());

    for entry in entries {
        let path = entry.path();
        if path.is_dir() {
            files.extend(collect_yaml_files(&path));
        } else if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            if ext == "yaml" || ext == "yml" {
                files.push(path);
            }
        }
    }
    files
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::tempdir;

    #[test]
    fn loader_returns_defaults_when_dir_missing() {
        let loader = RuleLoader::from_dir("/nonexistent/path/that/does/not/exist");
        let (rules, warnings) = loader.load();
        assert!(!rules.is_empty(), "Should return default rules");
        assert!(!warnings.is_empty(), "Should emit a warning");
    }

    #[test]
    fn loader_returns_defaults_only() {
        let loader = RuleLoader::defaults_only();
        let (rules, _) = loader.load();
        assert!(!rules.is_empty());
    }

    #[test]
    fn loader_loads_valid_yaml_rule() {
        let dir = tempdir().unwrap();
        let rule_file = dir.path().join("test-rule.yaml");
        let mut f = std::fs::File::create(&rule_file).unwrap();
        writeln!(
            f,
            r#"
id: TEST-001
name: Test Rule
type: security
severity: high
language: "*"
analyzer: regex
pattern: "FAKE_SECRET_[0-9]+"
message: "Test secret detected"
"#
        )
        .unwrap();

        let loader = RuleLoader::from_dir(dir.path());
        let (rules, warnings) = loader.load();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, "TEST-001");
        assert!(warnings.is_empty(), "No warnings expected: {:?}", warnings);
    }

    #[test]
    fn loader_skips_duplicate_ids() {
        let dir = tempdir().unwrap();
        for i in 0..2 {
            let rule_file = dir.path().join(format!("rule-{}.yaml", i));
            let mut f = std::fs::File::create(&rule_file).unwrap();
            writeln!(
                f,
                r#"
id: DUP-001
name: Duplicate Rule {}
type: security
severity: high
language: "*"
analyzer: regex
pattern: "DUP_[0-9]+"
message: "Duplicate test"
"#,
                i
            )
            .unwrap();
        }

        let loader = RuleLoader::from_dir(dir.path());
        let (rules, warnings) = loader.load();
        assert_eq!(rules.len(), 1, "Only first occurrence should be kept");
        assert!(warnings.iter().any(|w| w.contains("Duplicate")));
    }

    #[test]
    fn loader_skips_rule_with_invalid_regex() {
        let dir = tempdir().unwrap();
        let rule_file = dir.path().join("bad-regex.yaml");
        let mut f = std::fs::File::create(&rule_file).unwrap();
        writeln!(
            f,
            r#"
id: BAD-001
name: Bad Regex Rule
type: security
severity: high
language: "*"
analyzer: regex
pattern: "([unclosed"
message: "This rule has a broken regex"
"#
        )
        .unwrap();

        let loader = RuleLoader::from_dir(dir.path());
        let (rules, warnings) = loader.load();
        // Should fall back to defaults since no valid rules loaded
        assert!(!rules.is_empty(), "Should fall back to defaults");
        assert!(warnings
            .iter()
            .any(|w| w.contains("Invalid regex") || w.contains("No valid")));
    }

    #[test]
    fn loader_skips_rule_missing_required_fields() {
        let dir = tempdir().unwrap();
        let rule_file = dir.path().join("incomplete.yaml");
        let mut f = std::fs::File::create(&rule_file).unwrap();
        // Missing 'id' field
        writeln!(
            f,
            r#"
name: Missing ID Rule
type: security
severity: high
language: "*"
analyzer: regex
pattern: "test"
message: "test"
"#
        )
        .unwrap();

        let loader = RuleLoader::from_dir(dir.path());
        let (rules, warnings) = loader.load();
        assert!(!rules.is_empty(), "Should fall back to defaults");
        assert!(warnings
            .iter()
            .any(|w| w.contains("Validation") || w.contains("No valid")));
    }
}
