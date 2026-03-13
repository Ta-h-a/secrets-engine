use crate::rotation_forwarder::{RotationForwardRequest, RotationForwarder};
use axum::{
    extract::{Extension, Json},
    http::StatusCode,
    response::IntoResponse,
};
use secretlens_core::{AnalyzePayload, AnalyzeResult, ResolvePayload, ResolveResult};
use secretlens_pipeline::AnalysisPipeline;
use secretlens_rules::RuleLoader;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;
use tracing::{error, info};

// ─── Shared state ─────────────────────────────────────────────────────────────

pub struct AppState {
    pub pipeline: AnalysisPipeline,
    pub rotation_endpoint: String,
}

// ─── GET /health ──────────────────────────────────────────────────────────────

pub async fn health() -> impl IntoResponse {
    Json(json!({
        "status": "ok",
        "service": "secretlens",
        "version": env!("CARGO_PKG_VERSION")
    }))
}

// ─── POST /analyze ────────────────────────────────────────────────────────────

pub async fn analyze(
    Extension(state): Extension<Arc<AppState>>,
    Json(payload): Json<AnalyzePayload>,
) -> impl IntoResponse {
    info!("POST /analyze: {} file(s)", payload.files.len());

    let findings = state.pipeline.run(&payload.files);
    let result = AnalyzeResult { findings };

    (StatusCode::OK, Json(json!({ "status": "success", "payload": result })))
}

// ─── POST /resolve ────────────────────────────────────────────────────────────

pub async fn resolve(
    Extension(state): Extension<Arc<AppState>>,
    Json(payload): Json<ResolvePayload>,
) -> impl IntoResponse {
    info!("POST /resolve: finding {}", payload.finding_to_resolve.id);

    // Resolve = return a stub updated_content for now.
    // The Electron app applies the fix based on suggested_fix; this endpoint
    // confirms the finding was received and echoes back the file path.
    let result = ResolveResult {
        file_path: payload.finding_to_resolve.file_path.clone(),
        updated_content: payload.file_content.clone(),
    };

    (StatusCode::OK, Json(json!({ "status": "success", "payload": result })))
}

// ─── POST /forward-to-rotation ────────────────────────────────────────────────

pub async fn forward_to_rotation(
    Extension(state): Extension<Arc<AppState>>,
    Json(req): Json<RotationForwardRequest>,
) -> impl IntoResponse {
    info!(
        "POST /forward-to-rotation: key {} for user {}",
        req.access_key_id, req.iam_user
    );

    let forwarder = RotationForwarder::new(state.rotation_endpoint.clone());

    match forwarder.forward(&req).await {
        Ok(response) => (
            StatusCode::OK,
            Json(json!({ "status": "success", "payload": response })),
        ),
        Err(e) => {
            error!("Rotation forward failed: {}", e);
            (
                StatusCode::BAD_GATEWAY,
                Json(json!({ "status": "error", "payload": { "errorMessage": e } })),
            )
        }
    }
}
