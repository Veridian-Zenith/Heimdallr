// SPDX-License-Identifier: OSL-3.0
// Copyright (c) 2026 Veridian Zenith

//! Performance benchmarks for Heimdallr Cache and Resolver.

use criterion::{Criterion, criterion_group, criterion_main};
use std::collections::HashMap;
use std::hint::black_box;
use std::sync::Arc;
use tokio::sync::RwLock;

// Mock structures to avoid dependency issues during benchmark setup
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct CacheKey {
    pub qname: String,
    pub qtype: u16,
}

pub struct CacheEntry {
    pub response_bytes: Vec<u8>,
}

pub struct Cache {
    entries: HashMap<CacheKey, CacheEntry>,
}

impl Cache {
    pub fn lookup(&self, key: &CacheKey) -> Option<&CacheEntry> {
        self.entries.get(key)
    }
}

fn bench_cache_lookup(c: &mut Criterion) {
    let mut entries = HashMap::new();
    let key = CacheKey {
        qname: "example.com".into(),
        qtype: 1,
    };
    entries.insert(
        key.clone(),
        CacheEntry {
            response_bytes: vec![0; 256],
        },
    );
    let cache = Arc::new(RwLock::new(Cache { entries }));

    c.bench_function("cache_lookup_hit", |b| {
        b.iter(|| {
            let c_lock = cache.blocking_read();
            let _ = c_lock.lookup(black_box(&key));
        })
    });
}

criterion_group!(benches, bench_cache_lookup);
criterion_main!(benches);
