use crate::error::AiError;
use crate::provider::{AiProvider, EnrichmentRequest, EnrichmentResponse};
use async_trait::async_trait;
use tracing::{debug, warn};

/// Cloud AI provider (OpenAI-compatible API).
pub struct CloudProvider {
    endpoint: String,
    client: reqwest::Client,
}

impl CloudProvider {
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            client: reqwest::Client::new(),
        }
    }
}

#[async_trait]
impl AiProvider for CloudProvider {
    async fn enrich(
        &self,
        request: EnrichmentRequest,
    ) -> Result<Option<EnrichmentResponse>, AiError> {
        let prompt = format!(
            "You are a security expert. A code scanner found:\nRule: {}\nMessage: {}\nCode:\n```\n{}\n```\n\n\
            Provide:\n1. IMPACT: 1-2 sentences on the security impact.\n2. FIX: Concrete fix in 1-3 sentences.",
            request.finding.rule_id, request.finding.message, request.code_snippet
        );

        let url = format!("{}/chat/completions", self.endpoint);
        debug!("Sending enrichment request to cloud endpoint {}", url);

        let body = serde_json::json!({
            "model": "gpt-4o-mini",
            "messages": [
                { "role": "system", "content": "You are a precise security code reviewer." },
                { "role": "user", "content": prompt }
            ],
            "max_tokens": 300,
            "temperature": 0.2
        });

        let resp = self
            .client
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|e| AiError::Http(e.to_string()))?;

        if !resp.status().is_success() {
            let status = resp.status();
            warn!("Cloud AI returned HTTP {}", status);
            return Ok(None);
        }

        let json: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| AiError::Deserialize(e.to_string()))?;

        let content = json
            .pointer("/choices/0/message/content")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let (impact, suggested_fix) = parse_enrichment_response(&content);

        Ok(Some(EnrichmentResponse {
            impact,
            suggested_fix,
        }))
    }

    fn name(&self) -> &str {
        "cloud-openai"
    }
}

fn parse_enrichment_response(text: &str) -> (String, String) {
    let impact = extract_section(text, "IMPACT:");
    let fix = extract_section(text, "FIX:");
    (impact, fix)
}

fn extract_section(text: &str, label: &str) -> String {
    if let Some(start) = text.find(label) {
        let after = &text[start + label.len()..];
        let end = after
            .find('\n')
            .unwrap_or(after.len());
        after[..end].trim().to_string()
    } else {
        text.trim().to_string()
    }
}
