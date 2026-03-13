use crate::error::AiError;
use crate::provider::{AiProvider, EnrichmentRequest, EnrichmentResponse};
use async_trait::async_trait;

/// A no-op provider — skips AI enrichment entirely.
/// Used as the default when no AI provider is configured.
pub struct NullProvider;

#[async_trait]
impl AiProvider for NullProvider {
    async fn enrich(
        &self,
        _request: EnrichmentRequest,
    ) -> Result<Option<EnrichmentResponse>, AiError> {
        Ok(None)
    }

    fn name(&self) -> &str {
        "null"
    }
}
