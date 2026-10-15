//! `tangra-notes --healthcheck -config <path>`: exits 0 when the admin
//! listener answers `GET /readyz` with 200. The release image has no
//! `wget`/`curl`, so the compose healthcheck runs the binary itself (the
//! deployer's image runs `wget -qO- http://127.0.0.1:9690/readyz`). Only a
//! loopback admin listener is plain HTTP; that is the only kind it checks.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Probes `http://<admin_addr>/readyz` (Go `:port` means loopback here).
pub async fn probe(admin_addr: &str) -> Result<(), String> {
    let addr = match admin_addr.strip_prefix(':') {
        Some(port) => format!("127.0.0.1:{port}"),
        None => admin_addr.to_owned(),
    };
    let fut = async {
        let mut s = tokio::net::TcpStream::connect(&addr)
            .await
            .map_err(|e| format!("{addr}: {e}"))?;
        s.write_all(format!("GET /readyz HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n").as_bytes())
            .await
            .map_err(|e| e.to_string())?;
        let mut buf = Vec::new();
        s.read_to_end(&mut buf).await.map_err(|e| e.to_string())?;
        let head = String::from_utf8_lossy(&buf);
        let status = head.lines().next().unwrap_or_default().to_owned();
        if status.split_whitespace().nth(1) == Some("200") {
            Ok(())
        } else {
            Err(format!("readyz: {status}"))
        }
    };
    tokio::time::timeout(Duration::from_secs(3), fut)
        .await
        .map_err(|_| "readyz: timeout".to_owned())?
}
