// SPDX-License-Identifier: OSL-3.0
// Copyright (c) 2026 Veridian Zenith

//! LRU + TTL cache with serve-stale and prefetch hint.
//!
//! M1: In-memory response cache for recursive resolution.
//! M6: Persistent `cache.bin` serialization.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Cache key: (qname lowercase, qtype, optional client-subnet scope for ECS M5.7).
#[derive(Debug, Clone, Hash, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct CacheKey {
    pub qname: String,
    pub qtype: u16,
    /// M5.7: optional client subnet (address, source_prefix) for ECS cache partitioning.
    /// `None` means "no ECS" (default). When ECS is enabled, the upstream
    /// `scope_prefix` is used as the discriminator (RFC 7871 §7.1.3).
    pub client_subnet: Option<(std::net::IpAddr, u8)>,
}

/// A single cached response entry.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct CacheEntry {
    /// Raw DNS response wire bytes (full message including header).
    pub response_bytes: Vec<u8>,
    /// When this entry was inserted.
    pub inserted_at: Instant,
    /// Original TTL from the shortest TTL record in the answer.
    pub original_ttl: Duration,
    /// How many times this entry has been served from cache.
    pub hit_count: u64,
    /// Last time this entry was served.
    pub last_access: Instant,
}

impl CacheEntry {
    /// Time until this entry expires (may be zero = expired).
    fn ttl_remaining(&self) -> Duration {
        let elapsed = self.inserted_at.elapsed();
        if elapsed >= self.original_ttl {
            Duration::ZERO
        } else {
            self.original_ttl - elapsed
        }
    }

    /// True if the TTL has expired.
    pub fn is_expired(&self) -> bool {
        self.ttl_remaining() == Duration::ZERO
    }

    /// True if stale (expired but within serve-stale window).
    pub fn is_stale(&self, stale_window: Duration) -> bool {
        self.is_expired() && self.inserted_at.elapsed() <= self.original_ttl + stale_window
    }
}

/// Configuration for the DNS response cache.
#[derive(Debug, Clone)]
pub struct CacheConfig {
    /// Maximum number of entries.
    pub size: usize,
    /// How long to serve stale entries after TTL expiry.
    pub serve_stale: Duration,
    /// Prefetch when TTL < prefetch_threshold * query_count (0 = disabled).
    pub prefetch: u32,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            size: 50_000,
            serve_stale: Duration::from_secs(30),
            prefetch: 2,
        }
    }
}

/// LRU + TTL DNS response cache.
pub struct Cache {
    config: CacheConfig,
    entries: HashMap<CacheKey, CacheEntry>,
    /// Access order for LRU eviction.
    access_order: Vec<CacheKey>,
    /// Total hits since creation.
    hits: u64,
    /// Total misses since creation.
    misses: u64,
}

impl Cache {
    pub fn new(config: CacheConfig) -> Self {
        let size = config.size;
        Self {
            config,
            entries: HashMap::with_capacity(size),
            access_order: Vec::with_capacity(size),
            hits: 0,
            misses: 0,
        }
    }

    /// Look up a cached response. Returns (response_bytes, is_stale, hit_count) if found.
    pub fn lookup(&mut self, key: &CacheKey) -> Option<(Vec<u8>, bool, u64)> {
        let entry = self.entries.get(key)?;
        let stale = entry.is_stale(self.config.serve_stale);
        self.hits += 1;
        let entry = self.entries.get_mut(key)?;
        entry.hit_count += 1;
        entry.last_access = Instant::now();
        let bytes = entry.response_bytes.clone();
        let hits = entry.hit_count;
        Some((bytes, stale, hits))
    }

    /// Check if a specific key is expired.
    pub fn is_expired(&self, key: &CacheKey) -> bool {
        match self.entries.get(key) {
            Some(entry) => entry.is_expired(),
            None => true,
        }
    }

    /// Insert or update a cached response.
    pub fn insert(&mut self, key: CacheKey, response_bytes: Vec<u8>, original_ttl: Duration) {
        // Evict if at capacity
        while self.entries.len() >= self.config.size {
            self.evict_lru();
        }

        let now = Instant::now();
        let entry = CacheEntry {
            response_bytes,
            inserted_at: now,
            original_ttl,
            hit_count: 0,
            last_access: now,
        };

        // Remove old entry if exists (reset access order)
        if self.entries.contains_key(&key) {
            self.access_order.retain(|k| k != &key);
        }

        self.entries.insert(key.clone(), entry);
        self.access_order.push(key);
    }

    /// Evict the least recently used entry.
    fn evict_lru(&mut self) {
        if let Some(oldest_key) = self.access_order.first().cloned() {
            self.entries.remove(&oldest_key);
            self.access_order.remove(0);
        }
    }

    /// Remove expired entries.
    pub fn reap_expired(&mut self) {
        let stale_window = self.config.serve_stale;
        let expired: Vec<CacheKey> = self
            .entries
            .iter()
            .filter(|(_, e)| e.is_expired() && !e.is_stale(stale_window))
            .map(|(k, _)| k.clone())
            .collect();
        for key in &expired {
            self.entries.remove(key);
            self.access_order.retain(|k| k != key);
        }
    }

    /// Number of entries currently in cache.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True if cache is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Total cache hits since creation.
    pub fn hits(&self) -> u64 {
        self.hits
    }

    /// Total cache misses since creation.
    pub fn misses(&self) -> u64 {
        self.misses
    }

    /// Increment miss counter (call when upstream lookup succeeds but wasn't cached).
    pub fn record_miss(&mut self) {
        self.misses += 1;
    }

    /// Check if a key should trigger prefetch (TTL < prefetch_threshold * hit_count).
    pub fn should_prefetch(&self, key: &CacheKey) -> bool {
        if self.config.prefetch == 0 {
            return false;
        }
        match self.entries.get(key) {
            Some(entry) => {
                let remaining = entry.ttl_remaining();
                let threshold = Duration::from_secs(self.config.prefetch as u64 * entry.hit_count);
                remaining < threshold
            }
            None => false,
        }
    }

    /// M6.3: Save cache to binary file at `path`.
    pub fn save_to_file(&self, path: &str) -> std::io::Result<()> {
        let snapshot: Vec<(CacheKey, Vec<u8>, u64, u64)> = self
            .entries
            .iter()
            .map(|(k, e)| {
                (
                    k.clone(),
                    e.response_bytes.clone(),
                    e.original_ttl.as_secs(),
                    e.hit_count,
                )
            })
            .collect();
        let encoded = serde_json::to_string(&snapshot)
            .map_err(|e| std::io::Error::other(format!("serde_json: {e}")))?;
        std::fs::write(path, encoded)
    }

    /// M6.3: Load cache from binary file at `path`.
    #[allow(clippy::type_complexity)]
    pub fn load_from_file(path: &str) -> std::io::Result<Self> {
        let text = std::fs::read_to_string(path)?;
        let snapshot: Vec<(CacheKey, Vec<u8>, u64, u64)> = serde_json::from_str(&text)
            .map_err(|e| std::io::Error::other(format!("serde_json: {e}")))?;
        let mut cache = Self::new(CacheConfig {
            size: snapshot.len().max(100),
            serve_stale: Duration::from_secs(30),
            prefetch: 0,
        });
        for (key, response_bytes, ttl_sec, hit_count) in snapshot {
            let k = key.clone();
            cache.insert(key, response_bytes, Duration::from_secs(ttl_sec));
            // Restore hit count (approximate, since insert resets it)
            if let Some(entry) = cache.entries.get_mut(&k) {
                entry.hit_count = hit_count;
            }
        }
        Ok(cache)
    }

    /// Clear all entries.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.access_order.clear();
        self.hits = 0;
        self.misses = 0;
    }
}

/// Thread-safe cache wrapper.
pub type SharedCache = Arc<RwLock<Cache>>;

/// Create a new shared cache with default config.
pub fn new_shared_cache(config: CacheConfig) -> SharedCache {
    Arc::new(RwLock::new(Cache::new(config)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config(size: usize) -> CacheConfig {
        CacheConfig {
            size,
            serve_stale: Duration::from_millis(100),
            prefetch: 2,
        }
    }

    #[test]
    fn insert_and_lookup() {
        let mut cache = Cache::new(test_config(10));
        let key = CacheKey {
            qname: "example.com".into(),
            qtype: 1,
            client_subnet: None,
        };
        cache.insert(key.clone(), vec![1, 2, 3], Duration::from_secs(60));
        let (bytes, stale, hits) = cache.lookup(&key).unwrap();
        assert_eq!(bytes, vec![1, 2, 3]);
        assert!(!stale);
        assert_eq!(hits, 1);
    }

    #[test]
    fn hit_counter_increments() {
        let mut cache = Cache::new(test_config(10));
        let key = CacheKey {
            qname: "example.com".into(),
            qtype: 1,
            client_subnet: None,
        };
        cache.insert(key.clone(), vec![1, 2, 3], Duration::from_secs(60));

        cache.lookup(&key);
        cache.lookup(&key);
        let (_, _, hits) = cache.lookup(&key).unwrap();
        assert_eq!(hits, 3);
        assert_eq!(cache.hits(), 3);
    }

    #[test]
    fn miss_counter() {
        let mut cache = Cache::new(test_config(10));
        let key = CacheKey {
            qname: "example.com".into(),
            qtype: 1,
            client_subnet: None,
        };
        assert!(cache.lookup(&key).is_none());
        cache.record_miss();
        assert_eq!(cache.misses(), 1);
    }

    #[test]
    fn lru_eviction() {
        let mut cache = Cache::new(test_config(3));
        for i in 0..5 {
            let key = CacheKey {
                client_subnet: None,
                qname: format!("host{i}.com"),
                qtype: 1,
            };
            cache.insert(key, vec![i as u8], Duration::from_secs(60));
        }
        assert_eq!(cache.len(), 3);
        // First two entries should be evicted
        assert!(
            cache
                .lookup(&CacheKey {
                    qname: "host0.com".into(),
                    qtype: 1,
                    client_subnet: None,
                })
                .is_none()
        );
        assert!(
            cache
                .lookup(&CacheKey {
                    qname: "host1.com".into(),
                    qtype: 1,
                    client_subnet: None,
                })
                .is_none()
        );
        // Last three should still be there
        assert!(
            cache
                .lookup(&CacheKey {
                    qname: "host2.com".into(),
                    qtype: 1,
                    client_subnet: None,
                })
                .is_some()
        );
    }

    #[test]
    fn expiry_and_serve_stale() {
        let mut cache = Cache::new(CacheConfig {
            size: 10,
            serve_stale: Duration::from_millis(200),
            prefetch: 0,
        });
        let key = CacheKey {
            qname: "example.com".into(),
            qtype: 1,
            client_subnet: None,
        };
        // Insert with very short TTL
        cache.insert(key.clone(), vec![1, 2, 3], Duration::from_millis(50));

        // Should be fresh immediately after insert
        assert!(!cache.is_expired(&key));

        // Wait for TTL to expire
        std::thread::sleep(Duration::from_millis(80));
        assert!(cache.is_expired(&key));
    }

    #[test]
    fn reap_expired_removes_old_entries() {
        let mut cache = Cache::new(CacheConfig {
            size: 10,
            serve_stale: Duration::from_millis(50),
            prefetch: 0,
        });
        let key = CacheKey {
            qname: "example.com".into(),
            qtype: 1,
            client_subnet: None,
        };
        cache.insert(key.clone(), vec![1, 2, 3], Duration::from_millis(10));
        std::thread::sleep(Duration::from_millis(80));
        cache.reap_expired();
        assert!(cache.is_empty());
    }

    #[test]
    fn prefetch_hint() {
        let mut cache = Cache::new(CacheConfig {
            size: 10,
            serve_stale: Duration::from_secs(30),
            prefetch: 2,
        });
        let key = CacheKey {
            qname: "example.com".into(),
            qtype: 1,
            client_subnet: None,
        };
        cache.insert(key.clone(), vec![1, 2, 3], Duration::from_secs(60));
        // No hits yet, so threshold = 2 * 0 = 0, but TTL is 60s
        assert!(!cache.should_prefetch(&key));

        // Hit it a few times
        for _ in 0..10 {
            cache.lookup(&key);
        }
        // Now threshold = 2 * 10 = 20s, but TTL is still ~60s
        assert!(!cache.should_prefetch(&key));
    }

    #[test]
    fn clear_resets_all() {
        let mut cache = Cache::new(test_config(10));
        let key = CacheKey {
            qname: "example.com".into(),
            qtype: 1,
            client_subnet: None,
        };
        cache.insert(key.clone(), vec![1, 2, 3], Duration::from_secs(60));
        cache.lookup(&key);
        cache.record_miss();
        cache.clear();
        assert!(cache.is_empty());
        assert_eq!(cache.hits(), 0);
        assert_eq!(cache.misses(), 0);
    }

    #[test]
    fn update_existing_key() {
        let mut cache = Cache::new(test_config(10));
        let key = CacheKey {
            qname: "example.com".into(),
            qtype: 1,
            client_subnet: None,
        };
        cache.insert(key.clone(), vec![1], Duration::from_secs(60));
        cache.insert(key.clone(), vec![2], Duration::from_secs(60));
        let (bytes, _, _) = cache.lookup(&key).unwrap();
        assert_eq!(bytes, vec![2]);
        assert_eq!(cache.len(), 1);
    }

    // ── Cache fuzz: rapid insert/lookup/evict cycles ──

    /// Deterministic pseudo-random byte from a seed (xorshift32).
    fn fuzz_byte(seed: &mut u32) -> u8 {
        *seed ^= *seed << 13;
        *seed ^= *seed >> 17;
        *seed ^= *seed << 5;
        *seed as u8
    }

    /// Fuzz: random insert/lookup/evict — no panics, no corruption.
    #[test]
    fn cache_fuzz_insert_lookup_evict() {
        let mut cache = Cache::new(CacheConfig {
            size: 64,
            serve_stale: Duration::from_millis(50),
            prefetch: 0,
        });
        let mut seed: u32 = 0xDEAD_BEEF;

        for i in 0..2000 {
            let key = CacheKey {
                client_subnet: None,
                qname: format!("fuzz{}.example.com", fuzz_byte(&mut seed) as u16 % 100),
                qtype: fuzz_byte(&mut seed) as u16,
            };
            let ttl_ms = 10 + (fuzz_byte(&mut seed) as u64 % 200);
            let data: Vec<u8> = (0..fuzz_byte(&mut seed) as usize % 64)
                .map(|_| fuzz_byte(&mut seed))
                .collect();

            // Interleave insert, lookup, reap, clear based on seed
            let op = fuzz_byte(&mut seed) % 8;
            match op {
                0..=3 => {
                    cache.insert(key, data, Duration::from_millis(ttl_ms));
                }
                4..=5 => {
                    let _ = cache.lookup(&key);
                }
                6 => {
                    cache.reap_expired();
                }
                7 if i % 500 == 0 => {
                    cache.clear();
                }
                _ => {}
            }

            // Invariant: len <= size
            assert!(
                cache.len() <= 64,
                "fuzz iteration {i}: cache.len()={} > 64",
                cache.len()
            );
        }
    }

    /// Fuzz: concurrent-style insert/lookup with shared cache (single-threaded).
    #[test]
    fn cache_fuzz_rapid_hits() {
        let mut cache = Cache::new(CacheConfig {
            size: 32,
            serve_stale: Duration::from_secs(1),
            prefetch: 2,
        });

        // Insert one entry, then hit it 1000 times — no corruption
        let key = CacheKey {
            qname: "fuzz-target.example.com".into(),
            qtype: 1,
            client_subnet: None,
        };
        cache.insert(key.clone(), vec![42; 256], Duration::from_secs(60));

        for _ in 0..1000 {
            let result = cache.lookup(&key);
            assert!(result.is_some(), "entry disappeared during rapid hits");
            let (_, _, hits) = result.unwrap();
            assert!(hits > 0);
        }

        // should_prefetch should eventually trigger with enough hits
        assert!(cache.should_prefetch(&key));
    }

    /// Fuzz: TTL edge cases — zero TTL, very large TTL, negative-ish values.
    #[test]
    fn cache_fuzz_ttl_edge_cases() {
        let mut cache = Cache::new(test_config(10));
        let key_zero = CacheKey {
            qname: "zero-ttl.example.com".into(),
            qtype: 1,
            client_subnet: None,
        };
        let key_max = CacheKey {
            qname: "max-ttl.example.com".into(),
            qtype: 1,
            client_subnet: None,
        };

        // Zero TTL — should be immediately expired
        cache.insert(key_zero.clone(), vec![1], Duration::ZERO);
        assert!(cache.is_expired(&key_zero));

        // Very large TTL — should not expire
        cache.insert(key_max.clone(), vec![2], Duration::from_secs(u64::MAX / 2));
        assert!(!cache.is_expired(&key_max));

        // Lookup on zero-TTL entry — should still return data (serve from cache)
        let result = cache.lookup(&key_zero);
        assert!(result.is_some());
    }
}
