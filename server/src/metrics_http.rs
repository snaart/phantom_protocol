//! Minimal Prometheus `/metrics` endpoint.
//!
//! Exposes [`PhantomListener::metrics_prometheus_text`] as a plain
//! HTTP/1.1 text-exposition response. Anything else is a 404.
//!
//! Implementation notes:
//!
//! - One connection per request — sufficient for Prometheus scrapers
//!   that open + close per scrape.
//! - No TLS — this endpoint is intended for an internal scrape network
//!   (sidecar, kube-internal Service, or a `127.0.0.1` bind).
//!   Operators that need TLS terminate it at an ingress / sidecar.
//! - No body limits / keep-alive tuning — the request body is
//!   discarded immediately and the response is tiny.

use anyhow::Result;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use phantom_core::api::listener::PhantomListener;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;

const PROMETHEUS_CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

pub async fn serve(addr: SocketAddr, listener: Arc<PhantomListener>) -> Result<()> {
    let tcp = TcpListener::bind(addr).await?;
    tracing::info!(addr = %addr, "metrics HTTP listener bound");

    loop {
        let (stream, peer) = match tcp.accept().await {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(error = %e, "metrics accept failed");
                continue;
            }
        };
        let io = TokioIo::new(stream);
        let listener = listener.clone();
        tokio::spawn(async move {
            let svc = service_fn(move |req: Request<hyper::body::Incoming>| {
                let listener = listener.clone();
                async move { Ok::<_, std::convert::Infallible>(route(req, listener)) }
            });
            if let Err(e) = http1::Builder::new()
                .keep_alive(false)
                .serve_connection(io, svc)
                .await
            {
                tracing::debug!(peer = %peer, error = %e, "metrics conn finished with error");
            }
        });
    }
}

fn route(
    req: Request<hyper::body::Incoming>,
    listener: Arc<PhantomListener>,
) -> Response<Full<Bytes>> {
    if req.method() == hyper::Method::GET && req.uri().path() == "/metrics" {
        let body = listener.metrics_prometheus_text();
        Response::builder()
            .status(StatusCode::OK)
            .header(hyper::header::CONTENT_TYPE, PROMETHEUS_CONTENT_TYPE)
            .body(Full::new(Bytes::from(body)))
            .unwrap_or_else(|_| {
                Response::new(Full::new(Bytes::from_static(b"metrics build failed\n")))
            })
    } else {
        Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Full::new(Bytes::from_static(b"not found\n")))
            .unwrap_or_else(|_| Response::new(Full::new(Bytes::from_static(b"not found\n"))))
    }
}
