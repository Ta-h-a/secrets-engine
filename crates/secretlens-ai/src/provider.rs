use crate::error::AiError;
use async_trait::async_trait;
use secretlens_core::Finding;

/// Request sent to an AI provider for enrichment
#[derive(Debug, Clone)]
pub struct EnrichmentRequest {
    /// The finding to enrich
    pub finding: Finding,
    /// Redacted snippet of code around the finding
    pub code_snippet: String,
}

/// Response from an AI provider
#[derive(Debug, Clone)]
pub struct EnrichmentResponse {
    /// AI-generated impact description
    pub impact: String,
    /// AI-generated fix suggestion
    pub suggested_fix: String,
}

/// Pluggable AI provider trait — implemented by NullProvider, LocalModelProvider, CloudProvider.
#[async_trait]
pub trait AiProvider: Send + Sync {
    /// Enrich a finding with AI-generated impact + fix description.
    /// Returns Ok(None) if enrichment is not available or not desired.
    async fn enrich(
        &self,
        request: EnrichmentRequest,
    ) -> Result<Option<EnrichmentResponse>, AiError>;

    /// Human-readable name of this provider (for logging)
    fn name(&self) -> &str;
}
