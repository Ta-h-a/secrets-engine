use thiserror::Error;

#[derive(Debug, Error)]
pub enum RulesError {
    #[error("Failed to read rules directory '{path}': {source}")]
    DirectoryRead {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("Failed to parse rule file '{file}': {message}")]
    ParseError { file: String, message: String },

    #[error("Rule validation failed for '{id}': {message}")]
    ValidationError { id: String, message: String },

    #[error("Duplicate rule ID '{id}' found in '{file}' (already loaded from '{original}')")]
    DuplicateId {
        id: String,
        file: String,
        original: String,
    },

    #[error("Invalid regex pattern in rule '{id}': {message}")]
    InvalidPattern { id: String, message: String },
}
