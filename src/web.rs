// Local web UI (axum).
//
// Binds on 127.0.0.1:<WEB_PORT> by default -- ONLY the operator
// of the machine can manage the node. If you need remote access,
// put it behind nginx/Caddy with HTTP auth and TLS; the seed-
// exchange wire protocol is separately encrypted and authenticated,
// but the management UI is intentionally not exposed to the world.
//
// Endpoints:
//   GET  /                  -> index.html (dashboard)
//   GET  /static/*          -> assets
//   GET  /api/status        -> node status + public host setting
//   POST /api/public_host   -> set public host/IP for self-advertising
//   GET  /api/nodes         -> full list of known seeds
//   DELETE /api/nodes/:pid  -> forget a peer
//   POST /api/connect       -> contact a remote seed, verify, exchange
//   GET  /api/activity      -> recent events

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    routing::{delete, get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;

use crate::state::{now_secs, AppState};

const INDEX_HTML: &str = include_str!("../static/index.html");
const APP_CSS: &str = include_str!("../static/style.css");
const APP_JS: &str = include_str!("../static/app.js");

pub async fn run(state: Arc<AppState>, bind: String) -> anyhow::Result<()> {
    let app = Router::new()
        .route("/", get(index))
        .route("/static/style.css", get(css))
        .route("/static/app.js", get(js))
        .route("/api/status", get(api_status))
        .route("/api/public_host", post(api_set_public_host))
        .route("/api/nodes", get(api_nodes))
        .route("/api/nodes/:pid", delete(api_remove_node))
        .route("/api/connect", post(api_connect))
        .route("/api/activity", get(api_activity))
        .with_state(state);

    let addr: SocketAddr = bind.parse()?;
    let listener = TcpListener::bind(addr).await?;
    tracing::info!(%addr, "web UI listening");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn index() -> Html<&'static str> {
    Html(INDEX_HTML)
}

async fn css() -> Response {
    ([("content-type", "text/css; charset=utf-8")], APP_CSS).into_response()
}

async fn js() -> Response {
    ([("content-type", "application/javascript; charset=utf-8")], APP_JS)
        .into_response()
}

#[derive(Serialize)]
struct StatusResponse {
    peer_id_b58: String,
    libp2p_port: u16,
    seed_port: u16,
    known_nodes: usize,
    public_host: String,
    started_at: u64,
    now: u64,
}

async fn api_status(State(state): State<Arc<AppState>>) -> Json<StatusResponse> {
    Json(StatusResponse {
        peer_id_b58: state.my_peer_id_b58.clone(),
        libp2p_port: state.libp2p_port,
        seed_port: state.seed_port,
        known_nodes: state.store.len().await,
        public_host: state.public_host.read().await.clone(),
        started_at: state.started_at,
        now: now_secs(),
    })
}

#[derive(Deserialize)]
struct SetPublicHostBody {
    host: String,
}

async fn api_set_public_host(
    State(state): State<Arc<AppState>>,
    Json(body): Json<SetPublicHostBody>,
) -> Json<serde_json::Value> {
    let host = body.host.trim().to_string();
    *state.public_host.write().await = host.clone();
    state.log("config", format!("public_host set to '{host}'")).await;
    Json(serde_json::json!({ "ok": true, "public_host": host }))
}

async fn api_nodes(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let nodes = state.store.all().await;
    Json(serde_json::json!({ "nodes": nodes }))
}

async fn api_remove_node(
    State(state): State<Arc<AppState>>,
    Path(pid): Path<String>,
) -> Json<serde_json::Value> {
    let ok = state.store.remove(&pid).await;
    state.log("nodes", format!("remove {pid}: {ok}")).await;
    Json(serde_json::json!({ "ok": ok }))
}

#[derive(Deserialize)]
struct ConnectBody {
    host: String,
    port: Option<u16>,
}

#[derive(Serialize)]
struct ConnectResponse {
    ok: bool,
    peer_id_b58: Option<String>,
    agent: Option<String>,
    received: Option<usize>,
    added: Option<usize>,
    sent: Option<usize>,
    error: Option<String>,
}

async fn api_connect(
    State(state): State<Arc<AppState>>,
    Json(body): Json<ConnectBody>,
) -> (StatusCode, Json<ConnectResponse>) {
    let raw = body.host.trim().to_string();
    if raw.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ConnectResponse {
                ok: false,
                peer_id_b58: None,
                agent: None,
                received: None,
                added: None,
                sent: None,
                error: Some("host is empty".into()),
            }),
        );
    }

    let (host, port) = split_host_port(&raw, body.port.unwrap_or(state.seed_port));

    let public_host = {
        let g = state.public_host.read().await;
        g.clone()
    };

    match crate::seed_client::contact(state.clone(), &host, port, &public_host).await {
        Ok(rep) => {
            state
                .log(
                    "connect",
                    format!(
                        "{host}:{port} peer={} agent={} recv={} added={} sent={}",
                        rep.peer_id_b58, rep.agent, rep.received, rep.added, rep.sent
                    ),
                )
                .await;
            (
                StatusCode::OK,
                Json(ConnectResponse {
                    ok: true,
                    peer_id_b58: Some(rep.peer_id_b58),
                    agent: Some(rep.agent),
                    received: Some(rep.received),
                    added: Some(rep.added),
                    sent: Some(rep.sent),
                    error: None,
                }),
            )
        }
        Err(e) => {
            let msg = format!("{e:#}");
            state
                .log("connect-fail", format!("{host}:{port} -- {msg}"))
                .await;
            (
                StatusCode::OK,
                Json(ConnectResponse {
                    ok: false,
                    peer_id_b58: None,
                    agent: None,
                    received: None,
                    added: None,
                    sent: None,
                    error: Some(msg),
                }),
            )
        }
    }
}

async fn api_activity(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    let g = state.activity.read().await;
    let mut items: Vec<_> = g.iter().cloned().collect();
    items.reverse();
    Json(serde_json::json!({ "items": items }))
}

fn split_host_port(raw: &str, default_port: u16) -> (String, u16) {
    // Support "ip:port", "[ipv6]:port", "host:port", or just "ip/host".
    let s = raw.trim();
    if let Some(rest) = s.strip_prefix('[') {
        if let Some((h, p)) = rest.split_once("]:") {
            if let Ok(port) = p.parse::<u16>() {
                return (h.to_string(), port);
            }
        }
        // "[ipv6]" without port
        if let Some(h) = rest.strip_suffix(']') {
            return (h.to_string(), default_port);
        }
    }
    // Detect a single ':' that splits host and port (skip if looks like
    // multiple colons == IPv6 literal without brackets).
    let colon_count = s.matches(':').count();
    if colon_count == 1 {
        if let Some((h, p)) = s.split_once(':') {
            if let Ok(port) = p.parse::<u16>() {
                return (h.to_string(), port);
            }
        }
    }
    (s.to_string(), default_port)
}
