pub mod error;
pub mod provider;
pub mod null_provider;
pub mod local_provider;
pub mod cloud_provider;

pub use error::AiError;
pub use provider::{AiProvider, EnrichmentRequest, EnrichmentResponse};
pub use null_provider::NullProvider;
pub use local_provider::LocalModelProvider;
pub use cloud_provider::CloudProvider;

/// Build an AI provider from configuration.
pub fn build_provider(kind: &str, endpoint: Option<String>) -> Box<dyn AiProvider + Send + Sync> {
    match kind {
        "local" => Box::new(LocalModelProvider::new(
            endpoint.unwrap_or_else(|| "http://localhost:11434".to_string()),
        )),
        "cloud" => Box::new(CloudProvider::new(
            endpoint.unwrap_or_else(|| "https://api.openai.com/v1".to_string()),
        )),
        _ => Box::new(NullProvider),
    }
}
