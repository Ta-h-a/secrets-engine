use thiserror::Error;

#[derive(Debug, Error)]
pub enum AiError {
    #[error("HTTP request failed: {0}")]
    Http(String),

    #[error("Response deserialization failed: {0}")]
    Deserialize(String),

    #[error("AI provider not configured")]
    NotConfigured,
}
