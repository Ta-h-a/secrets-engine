use thiserror::Error;

#[derive(Debug, Error)]
pub enum HttpError {
    #[error("Bind failed on {addr}: {source}")]
    Bind {
        addr: String,
        #[source]
        source: std::io::Error,
    },

    #[error("Forward to rotation engine failed: {0}")]
    RotationForward(String),

    #[error("Request deserialization failed: {0}")]
    Deserialize(String),
}
