use std::process::Command;

fn main() {
    // M-0.4 Hard guard: OpenSSL/BoringSSL/aws-lc-rs/aws-lc-sys are BANNED.
    // The CI gate (`.github/workflows/ci.yml`) greps `cargo tree` for these
    // names. This `build.rs` enforces the same rule at compile time so any
    // dependency that tries to pull them in fails the build immediately
    // rather than silently linking a non-ring/botan crypto provider.
    let forbidden = [
        "aws-lc-rs",
        "aws-lc-sys",
        "openssl",
        "openssl-probe",
        "openssl-sys",
        "bssl",
    ];

    let out = Command::new("cargo")
        .args(["tree", "--prefix", "none"])
        .output()
        .expect("failed to run cargo tree");

    let tree = String::from_utf8_lossy(&out.stdout);
    for needle in &forbidden {
        if tree.lines().any(|l| l.contains(needle)) {
            panic!(
                "banned crypto dependency detected: `{needle}` found in `cargo tree`. \
                 Heimdallr must build with pure `ring` + `botan` only (no OpenSSL/BoringSSL/aws-lc-rs). \
                 Remove the offending dependency or replace it with a ring-based implementation."
            );
        }
    }
    println!("cargo:rerun-if-changed=Cargo.lock");
    println!("cargo:rerun-if-changed=Cargo.toml");
}
