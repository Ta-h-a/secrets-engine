use crate::error::HttpError;
use crate::routes::{analyze, forward_to_rotation, health, resolve, AppState};
use axum::{routing::get, routing::post, Extension, Router};
use secretlens_pipeline::AnalysisPipeline;
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tracing::info;

/// The SecretLens HTTP server.
pub struct HttpServer {
    pub bind_addr: SocketAddr,
    pub rotation_endpoint: String,
    pub pipeline: AnalysisPipeline,
}

impl HttpServer {
    pub fn new(
        bind_addr: SocketAddr,
        rotation_endpoint: impl Into<String>,
        pipeline: AnalysisPipeline,
    ) -> Self {
        Self {
            bind_addr,
            rotation_endpoint: rotation_endpoint.into(),
            pipeline,
        }
    }

    /// Start the HTTP server and block until shutdown.
    pub async fn run(self) -> Result<(), HttpError> {
        let state = Arc::new(AppState {
            pipeline: self.pipeline,
            rotation_endpoint: self.rotation_endpoint,
        });

        let app = Router::new()
            .route("/health", get(health))
            .route("/analyze", post(analyze))
            .route("/resolve", post(resolve))
            .route("/forward-to-rotation", post(forward_to_rotation))
            .layer(Extension(state))
            .layer(CorsLayer::permissive())
            .layer(TraceLayer::new_for_http());

        let addr = self.bind_addr;
        info!("SecretLens HTTP server listening on http://{}", addr);

        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .map_err(|e| HttpError::Bind {
                addr: addr.to_string(),
                source: e,
            })?;

        axum::serve(listener, app).await.map_err(|e| HttpError::Bind {
            addr: addr.to_string(),
            source: e,
        })?;

        Ok(())
    }
}
