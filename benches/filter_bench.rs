// SPDX-License-Identifier: OSL-3.0
// Copyright (c) 2026 Veridian Zenith

//! M6.1/M6.2 benchmarks: blocklist load, regex match, meta-list expand.

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use heimdallr::core::filter::Blocklist;
use std::io::Write;

fn bench_blocklist_load_hosts(c: &mut Criterion) {
    let content = "0.0.0.0 ads.example.com\n0.0.0.0 tracker.example.net\n";
    c.bench_function("blocklist_load_hosts_2_entries", |b| {
        b.iter(|| {
            let mut bl = Blocklist::new();
            bl.parse_hosts(black_box(content));
        })
    });
}

fn bench_blocklist_is_blocked_hit(c: &mut Criterion) {
    let mut bl = Blocklist::new();
    bl.parse_hosts("0.0.0.0 example.com\n");
    c.bench_function("blocklist_is_blocked_hit", |b| {
        b.iter(|| {
            let _ = bl.is_blocked(black_box("ads.example.com"));
        })
    });
}

fn bench_blocklist_is_blocked_miss(c: &mut Criterion) {
    let bl = Blocklist::new();
    c.bench_function("blocklist_is_blocked_miss", |b| {
        b.iter(|| {
            let _ = bl.is_blocked(black_box("allowed.example.com"));
        })
    });
}

fn bench_meta_list_expand_local(c: &mut Criterion) {
    use std::io::Write;
    let hosts = tempfile::NamedTempFile::new().unwrap();
    hosts
        .as_file_mut()
        .write_all(b"0.0.0.0 meta.test\n")
        .unwrap();
    let meta_text = format!("# meta\n{}\n", hosts.path().display());
    let meta_file = tempfile::NamedTempFile::new().unwrap();
    meta_file
        .as_file_mut()
        .write_all(meta_text.as_bytes())
        .unwrap();
    c.bench_function("meta_list_expand_local", |b| {
        b.iter(|| {
            let bl = Blocklist::load_sources(&[meta_file.path().to_string_lossy().into()]);
            assert!(bl.is_blocked("meta.test"));
        })
    });
}

criterion_group!(
    benches,
    bench_blocklist_load_hosts_2_entries,
    bench_blocklist_is_blocked_hit,
    bench_blocklist_is_blocked_miss,
    bench_meta_list_expand_local,
);
criterion_main!(benches);
