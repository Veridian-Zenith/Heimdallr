//! LRU + TTL, serve-stale, prefetch (`ROADMAP.md:M1,M6`), persistent `cache.bin`.

#![allow(dead_code)]

#[derive(Default)]
pub struct Cache {
    // TODO M1: lru::LruCache<CacheKey, CachedResponse> + ttl wheel
}

impl Cache {
    pub fn new() -> Self {
        Self::default()
    }
}
