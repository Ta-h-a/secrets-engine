use crate::finding::Finding;
use serde::{Deserialize, Serialize};

/// A file submitted for analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileChange {
    /// File path (relative or absolute)
    pub file_path: String,

    /// Full file content as a UTF-8 string
    pub content: String,
}

impl FileChange {
    /// Auto-detect the language from the file extension
    pub fn language(&self) -> &str {
        let ext = std::path::Path::new(&self.file_path)
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("");
        match ext.to_lowercase().as_str() {
            "py" => "python",
            "js" | "mjs" | "cjs" => "javascript",
            "ts" | "tsx" => "typescript",
            "rs" => "rust",
            "go" => "go",
            "java" => "java",
            "cs" => "csharp",
            "rb" => "ruby",
            "php" => "php",
            "sh" | "bash" => "shell",
            "yaml" | "yml" => "yaml",
            "json" => "json",
            "env" => "env",
            _ => "unknown",
        }
    }

    /// Whether this file is too large to analyze (>200KB by default)
    pub fn is_too_large(&self, max_bytes: usize) -> bool {
        self.content.len() > max_bytes
    }

    /// Build a line-offset lookup table for fast O(log n) line number lookup.
    /// Returns a Vec of byte offsets where each entry is the start of that line (0-indexed).
    pub fn build_line_table(&self) -> Vec<usize> {
        let mut table = vec![0usize];
        for (i, ch) in self.content.char_indices() {
            if ch == '\n' {
                table.push(i + 1);
            }
        }
        table
    }
}

/// AI provider configuration passed per-request
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AiProviderConfig {
    /// "local", "cloud", or "none"
    pub provider: String,

    /// Optional override endpoint URL
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
}

impl Default for AiProviderConfig {
    fn default() -> Self {
        Self {
            provider: "none".to_string(),
            endpoint: None,
        }
    }
}

/// Output format for CLI
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutputFormat {
    /// Default: human-readable colored text
    Text,
    /// Machine-readable JSON
    Json,
    /// SARIF 2.1.0 for CI/CD and GitHub Advanced Security
    Sarif,
}

// ─── Protocol types (stdin/stdout JSON protocol) ─────────────────────────────

/// Incoming request on the stdin/stdout protocol
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProtocolRequest {
    /// "analyze" or "resolve"
    pub command: String,

    /// Raw JSON payload — deserialized based on `command`
    pub payload: serde_json::Value,
}

/// Outgoing response on the stdin/stdout protocol
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProtocolResponse {
    /// "success" or "error"
    pub status: String,

    /// Response payload — AnalyzeResult, ResolveResult, or ErrorResult
    pub payload: serde_json::Value,
}

impl ProtocolResponse {
    pub fn success(payload: impl Serialize) -> Self {
        Self {
            status: "success".to_string(),
            payload: serde_json::to_value(payload).unwrap_or(serde_json::Value::Null),
        }
    }

    pub fn error(message: impl Into<String>) -> Self {
        let msg = message.into();
        Self {
            status: "error".to_string(),
            payload: serde_json::json!({ "errorMessage": msg }),
        }
    }
}

/// Payload for the "analyze" command
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AnalyzePayload {
    /// Files to analyze
    pub files: Vec<FileChange>,

    /// AI provider configuration
    #[serde(default)]
    pub ai_provider_config: AiProviderConfig,
}

/// Result of an "analyze" command
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AnalyzeResult {
    pub findings: Vec<Finding>,
}

/// Payload for the "resolve" command
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResolvePayload {
    /// The finding to resolve
    pub finding_to_resolve: Finding,

    /// Full content of the file containing the finding
    pub file_content: String,

    /// AI provider configuration
    #[serde(default)]
    pub ai_provider_config: AiProviderConfig,
}

/// Result of a "resolve" command
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResolveResult {
    pub file_path: String,
    pub updated_content: String,
}

/// Error result
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ErrorResult {
    pub error_message: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_change_language_detection() {
        let f = |path: &str| FileChange {
            file_path: path.to_string(),
            content: String::new(),
        };
        assert_eq!(f("main.py").language(), "python");
        assert_eq!(f("app.js").language(), "javascript");
        assert_eq!(f("app.ts").language(), "typescript");
        assert_eq!(f("main.rs").language(), "rust");
        assert_eq!(f("Main.java").language(), "java");
        assert_eq!(f("config.yaml").language(), "yaml");
        assert_eq!(f("noext").language(), "unknown");
    }

    #[test]
    fn line_table_is_correct() {
        let f = FileChange {
            file_path: "test.py".to_string(),
            content: "line1\nline2\nline3".to_string(),
        };
        let table = f.build_line_table();
        assert_eq!(table, vec![0, 6, 12]);
    }

    #[test]
    fn protocol_response_success_roundtrip() {
        let r = ProtocolResponse::success(serde_json::json!({"findings": []}));
        assert_eq!(r.status, "success");
    }

    #[test]
    fn protocol_response_error() {
        let r = ProtocolResponse::error("something went wrong");
        assert_eq!(r.status, "error");
        assert_eq!(r.payload["errorMessage"], "something went wrong");
    }
}
