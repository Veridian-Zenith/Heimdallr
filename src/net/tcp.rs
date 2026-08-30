// SPDX-License-Identifier: OSL-3.0
// Copyright (c) 2026 Veridian Zenith

//! TCP listener — length-prefixed framing `RFC 7766` §6.2, pipelined answers.

#![allow(dead_code)]

use anyhow::Result;
use tracing::debug;

pub struct TcpListener {
    pub addr: String,
}

impl TcpListener {
    pub fn new(addr: impl Into<String>) -> Self {
        Self { addr: addr.into() }
    }

    pub async fn run(self) -> Result<()> {
        debug!("tcp listen on {}", self.addr);
        // TODO M1: TcpListener bind, 2-byte len prefix, out-of-order answers per §7
        Ok(())
    }
}
