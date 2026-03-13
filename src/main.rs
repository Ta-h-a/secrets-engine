use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use secretlens_core::{AnalyzePayload, AnalyzeResult, ProtocolRequest, ProtocolResponse};
use secretlens_pipeline::{sarif, AnalysisPipeline};
use secretlens_rules::RuleLoader;
use std::io::{self, BufRead, Write};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process;
use tracing::{error, info, warn};
use tracing_subscriber::{fmt, EnvFilter};

// ─── CLI definition ───────────────────────────────────────────────────────────

/// SecretLens — high-performance secret & vulnerability detection engine
#[derive(Parser, Debug)]
#[command(
    name = "secretlens",
    version,
    about = "Secret detection engine with pipe and HTTP server modes"
)]
struct Cli {
    /// Operating mode
    #[arg(long, default_value = "pipe")]
    mode: Mode,

    /// Path to rules directory (defaults to ./rules/ relative to binary)
    #[arg(long, env = "SECRETLENS_RULES_DIR")]
    rules_dir: Option<PathBuf>,

    /// Output format (text, json, sarif) — only used in pipe mode
    #[arg(long, default_value = "json")]
    format: OutputFormat,

    /// HTTP server bind address (only used in serve mode)
    #[arg(long, default_value = "0.0.0.0:8080")]
    bind: SocketAddr,

    /// code-guard rotation engine endpoint (only used in serve mode)
    #[arg(
        long,
        default_value = "http://localhost:8000",
        env = "CODEGUARD_ENDPOINT"
    )]
    rotation_endpoint: String,

    /// Log level (off, error, warn, info, debug, trace)
    #[arg(long, default_value = "warn", env = "RUST_LOG")]
    log_level: String,
}

#[derive(Clone, Debug, ValueEnum)]
enum Mode {
    /// Stdin/stdout JSON protocol — drop-in replacement for C# engine
    Pipe,
    /// Axum HTTP server
    Serve,
}

#[derive(Clone, Debug, ValueEnum)]
enum OutputFormat {
    /// Machine-readable JSON (default, matches protocol)
    Json,
    /// Human-readable colored text
    Text,
    /// SARIF 2.1.0 for CI/CD
    Sarif,
}

// ─── Entry point ─────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    init_logging(&cli.log_level);

    // Resolve rules directory — relative to binary if not specified
    let rules_dir = cli.rules_dir.unwrap_or_else(|| {
        // Walk up from binary location to find rules/
        let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("."));
        let parent = exe.parent().unwrap_or(std::path::Path::new("."));
        // Try binary-adjacent, then current-working-dir-adjacent
        let candidate = parent.join("rules");
        if candidate.exists() {
            candidate
        } else {
            PathBuf::from("rules")
        }
    });

    let (rules, warnings) = RuleLoader::from_dir(&rules_dir).load();
    for w in &warnings {
        warn!("{}", w);
    }
    info!("Loaded {} rule(s) from '{}'", rules.len(), rules_dir.display());

    match cli.mode {
        Mode::Pipe => {
            let exit_code = run_pipe_mode(rules, cli.format);
            process::exit(exit_code);
        }
        Mode::Serve => {
            let pipeline = AnalysisPipeline::new(rules);
            if let Err(e) = run_serve_mode(pipeline, cli.bind, cli.rotation_endpoint).await {
                error!("HTTP server error: {}", e);
                process::exit(2);
            }
        }
    }
}

// ─── Pipe mode ────────────────────────────────────────────────────────────────

/// Exit codes:
///   0 — success, no findings
///   1 — success, findings present
///   2 — engine error
fn run_pipe_mode(rules: Vec<secretlens_core::Rule>, format: OutputFormat) -> i32 {
    let pipeline = AnalysisPipeline::new(rules);
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());

    let mut had_findings = false;
    let mut had_error = false;

    for line_result in stdin.lock().lines() {
        let line = match line_result {
            Ok(l) => l,
            Err(e) => {
                let resp = ProtocolResponse::error(format!("Failed to read stdin: {}", e));
                write_response(&mut out, &resp);
                had_error = true;
                continue;
            }
        };

        let line = line.trim().to_string();
        if line.is_empty() {
            continue;
        }

        let request: ProtocolRequest = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                let resp = ProtocolResponse::error(format!("Invalid request JSON: {}", e));
                write_response(&mut out, &resp);
                had_error = true;
                continue;
            }
        };

        match request.command.as_str() {
            "analyze" => {
                let payload: AnalyzePayload = match serde_json::from_value(request.payload) {
                    Ok(p) => p,
                    Err(e) => {
                        let resp =
                            ProtocolResponse::error(format!("Invalid analyze payload: {}", e));
                        write_response(&mut out, &resp);
                        had_error = true;
                        continue;
                    }
                };

                let findings = pipeline.run(&payload.files);

                if !findings.is_empty() {
                    had_findings = true;
                }

                match format {
                    OutputFormat::Sarif => {
                        let sarif_doc =
                            sarif::to_sarif(&findings, env!("CARGO_PKG_VERSION"));
                        let resp = ProtocolResponse::success(sarif_doc);
                        write_response(&mut out, &resp);
                    }
                    OutputFormat::Text => {
                        print_text_findings(&findings, &mut out);
                        let resp = ProtocolResponse::success(AnalyzeResult {
                            findings: findings.clone(),
                        });
                        // In text mode, findings are already printed; still write JSON to stdout
                        // for protocol compatibility (host reads the JSON line)
                        write_response(&mut out, &resp);
                    }
                    OutputFormat::Json => {
                        let resp =
                            ProtocolResponse::success(AnalyzeResult { findings });
                        write_response(&mut out, &resp);
                    }
                }
            }

            "resolve" => {
                let payload: secretlens_core::ResolvePayload =
                    match serde_json::from_value(request.payload) {
                        Ok(p) => p,
                        Err(e) => {
                            let resp = ProtocolResponse::error(format!(
                                "Invalid resolve payload: {}",
                                e
                            ));
                            write_response(&mut out, &resp);
                            had_error = true;
                            continue;
                        }
                    };

                // Resolve: return the file content unchanged — the Electron app applies fixes
                let result = secretlens_core::ResolveResult {
                    file_path: payload.finding_to_resolve.file_path.clone(),
                    updated_content: payload.file_content.clone(),
                };
                let resp = ProtocolResponse::success(result);
                write_response(&mut out, &resp);
            }

            unknown => {
                let resp = ProtocolResponse::error(format!("Unknown command: '{}'", unknown));
                write_response(&mut out, &resp);
                had_error = true;
            }
        }
    }

    if had_error {
        2
    } else if had_findings {
        1
    } else {
        0
    }
}

fn write_response(out: &mut impl Write, resp: &ProtocolResponse) {
    match serde_json::to_string(resp) {
        Ok(json) => {
            let _ = writeln!(out, "{}", json);
            let _ = out.flush();
        }
        Err(e) => {
            let _ = writeln!(out, "{{\"status\":\"error\",\"payload\":{{\"errorMessage\":\"Serialization failed: {}\"}}}}",
                e.to_string().replace('"', "\\\"")
            );
            let _ = out.flush();
        }
    }
}

fn print_text_findings(findings: &[secretlens_core::Finding], out: &mut impl Write) {
    if findings.is_empty() {
        let _ = writeln!(out, "No findings.");
        return;
    }
    let _ = writeln!(out, "\n{} finding(s):\n", findings.len());
    for f in findings {
        let _ = writeln!(
            out,
            "  [{:?}] {} — {}:{}",
            f.severity, f.rule_id, f.file_path, f.line_number
        );
        let _ = writeln!(out, "    {}", f.message);
        if let Some(impact) = &f.impact {
            let _ = writeln!(out, "    Impact: {}", impact);
        }
        let _ = writeln!(out);
    }
}

// ─── Serve mode ──────────────────────────────────────────────────────────────

async fn run_serve_mode(
    pipeline: AnalysisPipeline,
    bind: SocketAddr,
    rotation_endpoint: String,
) -> Result<()> {
    let server = secretlens_http::HttpServer::new(bind, rotation_endpoint, pipeline);
    server.run().await.context("HTTP server failed")
}

// ─── Logging ─────────────────────────────────────────────────────────────────

fn init_logging(level: &str) {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(level));

    // Always write logs to stderr so that stdout stays clean for the
    // JSON pipe protocol (and for any other structured output mode).
    fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_thread_ids(false)
        .with_writer(std::io::stderr)
        .compact()
        .init();
}
