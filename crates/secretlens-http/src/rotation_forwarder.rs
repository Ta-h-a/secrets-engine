use serde::{Deserialize, Serialize};
use tracing::warn;

/// Request body for `POST /forward-to-rotation`
#[derive(Debug, Deserialize)]
pub struct RotationForwardRequest {
    pub iam_user: String,
    pub access_key_id: String,
    pub incident_id: String,
    pub risk_level: String,
}

/// Forwards an AWS key finding to the code-guard rotation engine.
///
/// code-guard endpoint: POST /api/v1/rotate
/// Body: { "iam_user", "access_key_id", "incident_id", "risk_level" }
pub struct RotationForwarder {
    endpoint: String,
    client: reqwest::Client,
}

impl RotationForwarder {
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            client: reqwest::Client::new(),
        }
    }

    pub async fn forward(
        &self,
        req: &RotationForwardRequest,
    ) -> Result<serde_json::Value, String> {
        let url = format!("{}/api/v1/rotate", self.endpoint);

        let body = serde_json::json!({
            "iam_user": req.iam_user,
            "access_key_id": req.access_key_id,
            "incident_id": req.incident_id,
            "risk_level": req.risk_level,
        });

        let resp = self
            .client
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("HTTP error forwarding to rotation engine: {}", e))?;

        if !resp.status().is_success() {
            let status = resp.status();
            warn!("Rotation engine returned HTTP {}", status);
            return Err(format!("Rotation engine returned HTTP {}", status));
        }

        let json = resp
            .json::<serde_json::Value>()
            .await
            .map_err(|e| format!("Failed to deserialize rotation response: {}", e))?;

        Ok(json)
    }
}
