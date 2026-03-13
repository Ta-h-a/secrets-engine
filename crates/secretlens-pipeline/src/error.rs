use thiserror::Error;

#[derive(Debug, Error)]
pub enum PipelineError {
    #[error("Analyzer error: {0}")]
    Analyzer(String),

    #[error("AI enrichment error: {0}")]
    AiEnrichment(String),

    #[error("File too large: '{path}' exceeds {max_bytes} bytes")]
    FileTooLarge { path: String, max_bytes: usize },
}
