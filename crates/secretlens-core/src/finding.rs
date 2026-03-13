use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// The canonical Finding type — protocol-compatible with the C# engine's JSON contract.
/// Fields match the engine-protocol-v1.json schema exactly.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    /// Unique finding ID (UUID v4)
    pub id: Uuid,

    /// Path of the file in which the finding was detected
    pub file_path: String,

    /// 1-indexed line number of the finding
    pub line_number: u32,

    /// Category of finding (Security, Cost, Bug, Compliance, Privacy, Performance)
    #[serde(rename = "type")]
    pub finding_type: FindingType,

    /// Severity level
    pub severity: Severity,

    /// Short human-readable message
    pub message: String,

    /// Rule title
    pub title: String,

    /// Extended description of the rule
    pub description: String,

    /// Rule ID that triggered this finding
    pub rule_id: String,

    /// Remediation recommendations
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub recommendations: Vec<String>,

    /// Reference links (CVEs, docs, etc.)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub references: Vec<String>,

    /// Tags for filtering/categorization
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,

    /// The raw matched text (redacted before AI enrichment)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_finding_data: Option<String>,

    /// AI-enriched impact description (populated during AI enrichment step)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub impact: Option<String>,

    /// AI-enriched fix suggestion (populated during AI enrichment step)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suggested_fix: Option<String>,
}

impl Finding {
    /// Create a new finding with a fresh UUID
    pub fn new(
        file_path: impl Into<String>,
        line_number: u32,
        finding_type: FindingType,
        severity: Severity,
        message: impl Into<String>,
        title: impl Into<String>,
        description: impl Into<String>,
        rule_id: impl Into<String>,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            file_path: file_path.into(),
            line_number,
            finding_type,
            severity,
            message: message.into(),
            title: title.into(),
            description: description.into(),
            rule_id: rule_id.into(),
            recommendations: Vec::new(),
            references: Vec::new(),
            tags: Vec::new(),
            raw_finding_data: None,
            impact: None,
            suggested_fix: None,
        }
    }

    /// Deduplication key: same file + line + rule = same finding
    pub fn dedup_key(&self) -> (&str, u32, &str) {
        (&self.file_path, self.line_number, &self.rule_id)
    }
}

/// Finding category — maps to the C# "type" field enum
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FindingType {
    Security,
    Cost,
    Bug,
    Compliance,
    Privacy,
    Performance,
}

impl FindingType {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "security" => Self::Security,
            "cost" => Self::Cost,
            "bug" => Self::Bug,
            "compliance" => Self::Compliance,
            "privacy" => Self::Privacy,
            "performance" => Self::Performance,
            _ => Self::Security,
        }
    }
}

/// Severity levels
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    #[serde(rename = "info")]
    Info,
    #[serde(rename = "low")]
    Low,
    #[serde(rename = "medium")]
    Medium,
    #[serde(rename = "high")]
    High,
    #[serde(rename = "critical")]
    Critical,
}

impl Severity {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "critical" => Self::Critical,
            "high" => Self::High,
            "medium" => Self::Medium,
            "low" => Self::Low,
            "info" => Self::Info,
            _ => Self::Medium,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finding_dedup_key_is_stable() {
        let f = Finding::new(
            "src/main.py",
            42,
            FindingType::Security,
            Severity::Critical,
            "test msg",
            "Test",
            "Test desc",
            "SEC-001",
        );
        assert_eq!(f.dedup_key(), ("src/main.py", 42, "SEC-001"));
    }

    #[test]
    fn severity_ordering() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Medium > Severity::Low);
        assert!(Severity::Low > Severity::Info);
    }

    #[test]
    fn finding_serializes_without_null_fields() {
        let f = Finding::new(
            "a.py",
            1,
            FindingType::Security,
            Severity::High,
            "msg",
            "title",
            "desc",
            "R-001",
        );
        let json = serde_json::to_string(&f).unwrap();
        assert!(!json.contains("impact"));
        assert!(!json.contains("suggestedFix"));
        assert!(!json.contains("rawFindingData"));
    }
}
