//! UDP listener — `tokio::net::UdpSocket` + 512-1232 buf, forwards to `Core` `hickory`.

use anyhow::{Context, Result};
use std::{net::SocketAddr, sync::Arc};
use tokio::net::UdpSocket;
use tracing::{debug, error, warn};

use crate::{
    config::Config,
    core::{cache::Cache, filter::Filter, resolver::Resolver},
};

pub struct UdpListener {
    pub addr: SocketAddr,
    pub resolver: Arc<Resolver>,
    pub cache: Arc<Cache>,
    pub filter: Arc<Filter>,
    pub cfg: Config,
}

impl UdpListener {
    pub async fn bind(
        cfg: Config,
        resolver: Arc<Resolver>,
        cache: Arc<Cache>,
        filter: Arc<Filter>,
        addr: String,
    ) -> Result<Self> {
        let sock = addr.parse::<SocketAddr>().context("bad udp listen addr")?;
        Ok(Self {
            addr: sock,
            resolver,
            cache,
            filter,
            cfg,
        })
    }

    pub async fn run(self) -> Result<()> {
        let sock = UdpSocket::bind(self.addr)
            .await
            .with_context(|| format!("bind udp {}", self.addr))?;
        debug!("udp listening on {}", self.addr);
        let mut buf = vec![0u8; 4096];
        let sock = Arc::new(sock);
        loop {
            let (len, peer) = match sock.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(e) => {
                    warn!("udp recv err: {e}");
                    continue;
                }
            };
            let data = buf[..len].to_vec();
            let sock = sock.clone();
            let resolver = self.resolver.clone();
            let cache = self.cache.clone();
            let filter = self.filter.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_query(sock, peer, data, resolver, cache, filter).await {
                    error!("udp handle {peer} err: {e:#}");
                }
            });
        }
    }
}

async fn handle_query(
    sock: Arc<UdpSocket>,
    peer: SocketAddr,
    data: Vec<u8>,
    resolver: Arc<Resolver>,
    _cache: Arc<Cache>,
    filter: Arc<Filter>,
) -> Result<()> {
    use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
    use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};

    let req = Message::from_bytes(&data).context("parse query")?;
    let query = req.queries().first().cloned();
    let (qname, qtype) = match query {
        Some(q) => (q.name().to_string(), q.query_type()),
        None => {
            let mut resp = Message::new();
            resp.set_id(req.id());
            resp.set_message_type(MessageType::Response);
            resp.set_op_code(OpCode::Query);
            resp.set_response_code(ResponseCode::FormErr);
            let bytes = resp.to_bytes()?;
            sock.send_to(&bytes, peer).await?;
            return Ok(());
        }
    };

    // Filter gate — M6 regex per-client (stub now checks exact qname)
    let client_ip = peer.ip();
    if filter.is_blocked(&qname, client_ip) {
        let mut resp = Message::new();
        resp.set_id(req.id());
        resp.set_message_type(MessageType::Response);
        resp.set_op_code(OpCode::Query);
        resp.set_response_code(ResponseCode::NXDomain);
        let bytes = resp.to_bytes()?;
        sock.send_to(&bytes, peer).await?;
        return Ok(());
    }

    // Forward via hickory-resolver (latency concurrency handled there)
    let name = qname.trim_end_matches('.').to_string();
    let lookup = resolver.inner().lookup(name.clone(), qtype).await;
    let mut resp = Message::new();
    resp.set_id(req.id());
    resp.set_message_type(MessageType::Response);
    resp.set_op_code(OpCode::Query);
    resp.set_recursion_available(true);
    resp.add_query(hickory_proto::op::Query::query(
        hickory_proto::rr::Name::from_utf8(&name)
            .unwrap_or_else(|_| hickory_proto::rr::Name::root()),
        qtype,
    ));

    match lookup {
        Ok(l) => {
            for r in l.record_iter() {
                resp.add_answer(r.clone());
            }
        }
        Err(e) => {
            debug!("resolver miss {qname} {qtype:?}: {e}");
            resp.set_response_code(ResponseCode::ServFail);
        }
    }

    let bytes = resp.to_bytes()?;
    sock.send_to(&bytes, peer).await?;
    Ok(())
}
