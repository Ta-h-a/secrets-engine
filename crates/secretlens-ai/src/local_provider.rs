use crate::error::AiError;
use crate::provider::{AiProvider, EnrichmentRequest, EnrichmentResponse};
use async_trait::async_trait;
use tracing::{debug, warn};

/// Ollama-based local AI provider.
///
/// Sends enrichment requests to a local Ollama instance.
/// Default endpoint: http://localhost:11434
pub struct LocalModelProvider {
    endpoint: String,
    client: reqwest::Client,
}

impl LocalModelProvider {
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            client: reqwest::Client::new(),
        }
    }
}

#[async_trait]
impl AiProvider for LocalModelProvider {
    async fn enrich(
        &self,
        request: EnrichmentRequest,
    ) -> Result<Option<EnrichmentResponse>, AiError> {
        let prompt = build_prompt(&request);

        let body = serde_json::json!({
            "model": "llama3",
            "prompt": prompt,
            "stream": false
        });

        let url = format!("{}/api/generate", self.endpoint);
        debug!("Sending enrichment request to Ollama at {}", url);

        let resp = self
            .client
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|e| AiError::Http(e.to_string()))?;

        if !resp.status().is_success() {
            let status = resp.status();
            warn!("Ollama returned HTTP {}", status);
            return Ok(None);
        }

        let json: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| AiError::Deserialize(e.to_string()))?;

        let response_text = json
            .get("response")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let (impact, suggested_fix) = split_ollama_response(&response_text);

        Ok(Some(EnrichmentResponse {
            impact,
            suggested_fix,
        }))
    }

    fn name(&self) -> &str {
        "local-ollama"
    }
}

fn build_prompt(req: &EnrichmentRequest) -> String {
    format!(
        "You are a security expert. A code scanner found the following issue:\n\
        Rule: {}\n\
        Message: {}\n\
        Code snippet:\n```\n{}\n```\n\n\
        Provide:\n\
        1. IMPACT: A 1-2 sentence description of the security impact.\n\
        2. FIX: A concrete, actionable fix in 1-3 sentences.\n\
        Keep both sections short and technical.",
        req.finding.rule_id, req.finding.message, req.code_snippet
    )
}

fn split_ollama_response(text: &str) -> (String, String) {
    let impact = extract_section(text, "IMPACT:");
    let fix = extract_section(text, "FIX:");
    (impact, fix)
}

fn extract_section(text: &str, label: &str) -> String {
    if let Some(start) = text.find(label) {
        let after = &text[start + label.len()..];
        // Take until the next section label or end
        let end = after.find('\n').unwrap_or(after.len());
        after[..end].trim().to_string()
    } else {
        text.trim().to_string()
    }
}
