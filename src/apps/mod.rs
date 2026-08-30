//! Apps — WASM-sandboxed `DnsApp` trait (`ROADMAP.md:M5-M9`).
//! Replaces `DnsServer/Apps/*/` `C#` `dnsApp.config` per-app `csproj`; never `C#` direct.

#![allow(dead_code)]

pub trait DnsApp: Send + Sync {
    fn name(&self) -> &'static str;
    fn handle_query(&self, _qname: &str) -> Option<Vec<u8>> {
        None
    }
}

// Future: wasmtime host, app registry (like Apps/apps2.json)
pub struct AppRegistry {
    apps: Vec<Box<dyn DnsApp>>,
}

impl AppRegistry {
    pub fn new() -> Self {
        Self { apps: vec![] }
    }

    pub fn register(&mut self, app: Box<dyn DnsApp>) {
        self.apps.push(app);
    }
}

impl Default for AppRegistry {
    fn default() -> Self {
        Self::new()
    }
}
