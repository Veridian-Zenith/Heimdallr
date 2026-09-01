// SPDX-License-Identifier: OSL-3.0
// Copyright (c) 2026 Veridian Zenith

//! Performance benchmarks for Heimdallr Cache and PROXY protocol parser.

use criterion::{Criterion, criterion_group, criterion_main};
use std::collections::HashMap;
use std::hint::black_box;

// ── Mock cache (mirrors src/core/cache API without importing the binary crate) ─

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
struct CacheKey {
    qname: String,
    qtype: u16,
}

struct CacheEntry {
    #[allow(dead_code)]
    response_bytes: Vec<u8>,
}

struct Cache {
    entries: HashMap<CacheKey, CacheEntry>,
}

impl Cache {
    fn lookup(&self, key: &CacheKey) -> Option<&CacheEntry> {
        self.entries.get(key)
    }

    fn insert(&mut self, key: CacheKey, response_bytes: Vec<u8>) {
        self.entries.insert(key, CacheEntry { response_bytes });
    }
}

// ── Mock PROXY protocol parser (mirrors src/net/proxy logic) ─

const V2_SIGNATURE: &[u8] = b"\r\n\r\n\0\r\nQUIT\n";

fn mock_parse_proxy_v1(header: &[u8]) -> Option<[u8; 4]> {
    if !header.starts_with(b"PROXY TCP4 ") {
        return None;
    }
    let rest = &header[11..];
    let _first_space = rest.iter().position(|&b| b == b' ')?;
    let ip_bytes: [u8; 4] = [rest[0], rest[1], rest[2], rest[3]];
    Some(ip_bytes)
}

fn mock_parse_proxy_v2(header: &[u8]) -> bool {
    header.starts_with(V2_SIGNATURE)
}

// ── Benchmarks ──

fn bench_cache_lookup_hit(c: &mut Criterion) {
    let mut entries = HashMap::new();
    let key = CacheKey {
        qname: "example.com.".into(),
        qtype: 1,
    };
    entries.insert(
        key.clone(),
        CacheEntry {
            response_bytes: vec![0; 256],
        },
    );
    let cache = Cache { entries };

    c.bench_function("cache_lookup_hit", |b| {
        b.iter(|| {
            let _ = cache.lookup(black_box(&key));
        })
    });
}

fn bench_cache_lookup_miss(c: &mut Criterion) {
    let cache = Cache {
        entries: HashMap::new(),
    };
    let key = CacheKey {
        qname: "miss.example.com.".into(),
        qtype: 1,
    };

    c.bench_function("cache_lookup_miss", |b| {
        b.iter(|| {
            let _ = cache.lookup(black_box(&key));
        })
    });
}

fn bench_cache_insert(c: &mut Criterion) {
    let mut cache = Cache {
        entries: HashMap::with_capacity(10_000),
    };
    let mut i = 0u32;

    c.bench_function("cache_insert_256b", |b| {
        b.iter(|| {
            let key = CacheKey {
                qname: format!("bench{i}.example.com."),
                qtype: 1,
            };
            cache.insert(key, vec![0u8; 256]);
            i = i.wrapping_add(1);
        })
    });
}

fn bench_proxy_v1_tcp4(c: &mut Criterion) {
    let header = b"PROXY TCP4 192.168.1.100 10.0.0.1 12345 53\r\n";
    c.bench_function("proxy_v1_tcp4_parse", |b| {
        b.iter(|| {
            let _ = mock_parse_proxy_v1(black_box(header));
        })
    });
}

fn bench_proxy_v2_tcp4(c: &mut Criterion) {
    let mut buf = Vec::new();
    buf.extend_from_slice(V2_SIGNATURE);
    buf.push(0x20);
    buf.push(0x10);
    buf.extend_from_slice(&12u16.to_be_bytes());
    buf.extend_from_slice(&[10, 0, 0, 1]);
    buf.extend_from_slice(&[192, 168, 1, 1]);
    buf.extend_from_slice(&443u16.to_be_bytes());
    buf.extend_from_slice(&80u16.to_be_bytes());

    c.bench_function("proxy_v2_tcp4_parse", |b| {
        b.iter(|| {
            let _ = mock_parse_proxy_v2(black_box(&buf));
        })
    });
}

fn bench_cache_large_value(c: &mut Criterion) {
    let mut entries = HashMap::new();
    let key = CacheKey {
        qname: "large.example.com.".into(),
        qtype: 28,
    };
    entries.insert(
        key.clone(),
        CacheEntry {
            response_bytes: vec![0; 4096],
        },
    );
    let cache = Cache { entries };

    c.bench_function("cache_lookup_large_4k", |b| {
        b.iter(|| {
            let _ = cache.lookup(black_box(&key));
        })
    });
}

criterion_group!(
    benches,
    bench_cache_lookup_hit,
    bench_cache_lookup_miss,
    bench_cache_insert,
    bench_proxy_v1_tcp4,
    bench_proxy_v2_tcp4,
    bench_cache_large_value,
);
criterion_main!(benches);
