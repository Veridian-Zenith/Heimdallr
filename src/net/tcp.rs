// SPDX-License-Identifier: OSL-3.0
// Copyright (c) 2026 Veridian Zenith

//! TCP listener — length-prefixed framing `RFC 7766` §6.2, pipelined answers.
//!
//! When `proxy.enable = true`, each accepted connection is peeked for a
//! PROXY protocol v1/v2 header. The header is stripped and the real client
//! address is used for the DNS request.
//!
//! When `proxy.enable = false` (default), hickory-server's built-in TCP
//! listener is used directly via `register_listener`.

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{Context, Result};
use futures::StreamExt;
use hickory_server::net::BufDnsStreamHandle;
use hickory_server::net::runtime::TokioTime;
use hickory_server::net::xfer::Protocol;
use hickory_server::server::RequestHandler;
use hickory_server::server::{Request, ResponseHandle};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::{debug, error, info, warn};

use crate::net::handler::SharedHandler;
use crate::net::proxy;

const MAX_DNS_MESSAGE: usize = 65535;
const PEEK_SIZE: usize = 16;

pub async fn run_tcp_listener(
    listener: TcpListener,
    handler: SharedHandler,
    proxy_enabled: bool,
    proxy_allow: &[String],
) -> Result<()> {
    info!(
        "tcp: listening on {} (proxy={})",
        listener.local_addr()?,
        proxy_enabled
    );

    loop {
        let (stream, peer) = tokio::select! {
            result = listener.accept() => match result {
                Ok(v) => v,
                Err(e) => {
                    error!("tcp: accept error: {e}");
                    continue;
                }
            },
        };

        let handler = handler.clone();
        let proxy_allow = proxy_allow.to_vec();

        tokio::spawn(async move {
            if let Err(e) =
                handle_connection(stream, peer, handler, proxy_enabled, &proxy_allow).await
            {
                debug!("tcp: connection {peer} ended: {e:#}");
            }
        });
    }
}

async fn handle_connection(
    mut stream: tokio::net::TcpStream,
    peer: SocketAddr,
    handler: SharedHandler,
    proxy_enabled: bool,
    proxy_allow: &[String],
) -> Result<()> {
    let src_addr = resolve_src_addr(&mut stream, peer, proxy_enabled, proxy_allow).await?;

    loop {
        let len_bytes = match read_exact_timeout(&mut stream, 2).await {
            Ok(b) => b,
            Err(_) => return Ok(()),
        };

        let msg_len = u16::from_be_bytes([len_bytes[0], len_bytes[1]]) as usize;
        if msg_len == 0 || msg_len > MAX_DNS_MESSAGE {
            warn!("tcp: invalid DNS message length {msg_len} from {src_addr}");
            return Ok(());
        }

        let msg_bytes = match read_exact_timeout(&mut stream, msg_len).await {
            Ok(b) => b,
            Err(_) => return Ok(()),
        };

        if let Err(e) = handle_dns_query(&mut stream, msg_bytes, src_addr, handler.clone()).await {
            debug!("tcp: query from {src_addr} failed: {e:#}");
        }
    }
}

async fn resolve_src_addr(
    stream: &mut tokio::net::TcpStream,
    peer: SocketAddr,
    proxy_enabled: bool,
    proxy_allow: &[String],
) -> Result<SocketAddr> {
    if !proxy_enabled {
        return Ok(peer);
    }

    let mut peek_buf = [0u8; PEEK_SIZE];
    let n = stream.peek(&mut peek_buf).await?;
    if n < 6 {
        return Ok(peer);
    }

    match proxy::parse_proxy_header(&peek_buf[..n]) {
        Ok(Some(info)) => {
            if !proxy_allow.is_empty() {
                let src_str = info.source.ip().to_string();
                if !proxy_allow.iter().any(|a| a == &src_str) {
                    anyhow::bail!("tcp: proxy source {} not in allow list", info.source);
                }
            }

            let header_len = match info.version {
                proxy::ProxyVersion::V1 => peek_buf[..n]
                    .windows(2)
                    .position(|w| w == b"\r\n")
                    .map(|p| p + 2)
                    .unwrap_or(0),
                proxy::ProxyVersion::V2 => {
                    if n >= 16 {
                        let addr_len = u16::from_be_bytes([peek_buf[14], peek_buf[15]]) as usize;
                        16 + addr_len
                    } else {
                        0
                    }
                }
            };

            if header_len > 0 {
                let mut discard = vec![0u8; header_len];
                stream.read_exact(&mut discard).await?;
            }

            info!("tcp: PROXY {} → {}", info.source, peer);
            Ok(info.source)
        }
        Ok(None) => Ok(peer),
        Err(e) => {
            anyhow::bail!("tcp: bad PROXY header from {peer}: {e}");
        }
    }
}

async fn read_exact_timeout(stream: &mut tokio::net::TcpStream, n: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; n];
    tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut buf))
        .await
        .context("tcp: read timeout")?
        .context("tcp: read error")?;
    Ok(buf)
}

async fn handle_dns_query(
    stream: &mut tokio::net::TcpStream,
    msg_bytes: Vec<u8>,
    src_addr: SocketAddr,
    handler: SharedHandler,
) -> Result<()> {
    let request =
        Request::from_bytes(msg_bytes, src_addr, Protocol::Tcp).context("parse DNS TCP message")?;

    let (buf_handle, mut stream_receiver) = BufDnsStreamHandle::new(src_addr);
    let resp_handle = ResponseHandle::new(src_addr, buf_handle, Protocol::Tcp);

    handler
        .handle_request::<_, TokioTime>(&request, resp_handle)
        .await;

    while let Some(msg) = stream_receiver.next().await {
        let data = msg.bytes();
        let len = data.len() as u16;
        stream.write_all(&len.to_be_bytes()).await?;
        stream.write_all(data).await?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn max_dns_message_valid() {
        assert_eq!(MAX_DNS_MESSAGE, 65535);
    }
}
