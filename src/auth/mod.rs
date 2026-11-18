// SPDX-License-Identifier: OSL-3.0
// Copyright (c) 2026 Veridian Zenith

//! Auth — M7.1+M7.2 RBAC with two token types + password hashing + TOTP:
//!
//! - **API tokens**: Static, long-lived tokens stored as SHA-256 hashes in
//!   config. Full permissions based on the account's roles. Generated once
//!   and shown to the user (like AWS secret keys — never stored in plaintext).
//!
//! - **Session tokens**: HMAC-SHA256 signed, 15-minute expiry, read-only
//!   (`dns_reader` role only). Obtained via login with password + optional TOTP.
//!
//! - **Password hashing**: argon2id (RFC 9106) via the `argon2` crate.
//! - **TOTP 2FA**: RFC 6238 via the `totp-rs` crate (SHA1, 6 digits, 30s step).
//!
//! Crypto: `ring::digest::SHA256` for API token hashing,
//! `ring::hmac::HMAC_SHA256` for session token signing,
//! `argon2` for password hashing, `totp-rs` for TOTP.
//! All original code — no Technitium `auth` derivation.

use ring::digest;
use ring::hmac;
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Default session token lifetime: 15 minutes.
pub const SESSION_EXPIRY: Duration = Duration::from_secs(15 * 60);

// ── Token scope ──────────────────────────────────────────────────────────────

/// Access scope for a token. Controls what operations the token can perform.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TokenScope {
    /// Read-only access (zone listing, query, metrics).
    #[default]
    ReadOnly,
    /// Full access (config changes, record CRUD, zone management).
    Full,
}

impl TokenScope {
    /// Check if this scope can perform the required operation.
    pub fn allows(&self, required: TokenScope) -> bool {
        matches!(
            (self, required),
            (TokenScope::Full, _) | (TokenScope::ReadOnly, TokenScope::ReadOnly)
        )
    }
}

// ── Password hashing (argon2id) ─────────────────────────────────────────────

/// Hash a plaintext password with argon2id.
/// Returns the PHC-encoded hash string (includes salt, params, and hash).
pub fn hash_password(plain: &str) -> Result<String, argon2::password_hash::Error> {
    use argon2::{Argon2, PasswordHasher};
    let hash = Argon2::default().hash_password(plain.as_bytes())?;
    Ok(hash.to_string())
}

/// Verify a plaintext password against an argon2id PHC hash.
pub fn verify_password(plain: &str, phc_hash: &str) -> bool {
    use argon2::{Argon2, password_hash::PasswordVerifier};
    let Ok(parsed) = argon2::password_hash::phc::PasswordHash::new(phc_hash) else {
        return false;
    };
    Argon2::default()
        .verify_password(plain.as_bytes(), &parsed)
        .is_ok()
}

// ── TOTP (RFC 6238) ─────────────────────────────────────────────────────────

/// TOTP configuration stored per-user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotpConfig {
    /// Base32-encoded secret (shown to user once during setup).
    pub secret: String,
    /// Issuer name (e.g. "Heimdallr").
    #[serde(default = "default_totp_issuer")]
    pub issuer: String,
    /// Account name (username).
    pub account_name: String,
}

fn default_totp_issuer() -> String {
    "Heimdallr".into()
}

/// Generate a new TOTP secret (20 bytes, base32-encoded).
pub fn generate_totp_secret() -> String {
    use totp_rs::Secret;
    let secret = Secret::generate();
    secret.to_base32()
}

/// Build a TOTP object from a secret string.
fn build_totp(secret: &str, issuer: &str, account: &str) -> Option<totp_rs::Totp> {
    use totp_rs::{Builder, Secret};
    let secret_bytes = Secret::try_from_base32(secret).ok()?;
    Builder::new()
        .with_secret(secret_bytes)
        .with_issuer(Some(issuer.to_string()))
        .with_account_name(account.to_string())
        .build()
        .ok()
}

/// Verify a TOTP code against a secret. Returns true if valid.
pub fn verify_totp(secret: &str, issuer: &str, account: &str, code: &str) -> bool {
    let Some(totp) = build_totp(secret, issuer, account) else {
        return false;
    };
    totp.check_current(code).is_some()
}

/// Generate the current TOTP code.
pub fn generate_totp_code(secret: &str, issuer: &str, account: &str) -> Option<String> {
    let totp = build_totp(secret, issuer, account)?;
    let token = totp.generate_current();
    Some(format!("{}", token))
}

/// Build an otpauth:// URI for QR code generation.
pub fn totp_uri(secret: &str, issuer: &str, account: &str) -> Option<String> {
    use totp_rs::{Builder, Secret};
    let secret_bytes = Secret::try_from_base32(secret).ok()?;
    let totp = Builder::new()
        .with_secret(secret_bytes)
        .with_issuer(Some(issuer.to_string()))
        .with_account_name(account.to_string())
        .build()
        .ok()?;
    totp.to_url().ok()
}

// ── API token hashing ───────────────────────────────────────────────────────

/// Hash a raw API token with SHA-256 for secure storage.
/// Returns the hex-encoded hash.
pub fn hash_api_token(raw_token: &str) -> String {
    let digest = digest::digest(&digest::SHA256, raw_token.as_bytes());
    hex_encode(digest.as_ref())
}

/// Verify a raw API token against a stored SHA-256 hash.
pub fn verify_api_token(raw_token: &str, stored_hash: &str) -> bool {
    let computed = hash_api_token(raw_token);
    constant_time_eq(computed.as_bytes(), stored_hash.as_bytes())
}

/// Constant-time comparison to prevent timing attacks.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    // XOR all bytes; result is 0 only if all bytes match.
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Generate a new random API token (32 bytes, base64-encoded).
/// Returns (raw_token, hashed_token). The raw token is shown once;
/// only the hash is stored in config.
pub fn generate_api_token() -> (String, String) {
    use ring::rand::SecureRandom;
    let rng = ring::rand::SystemRandom::new();
    let mut bytes = [0u8; 32];
    rng.fill(&mut bytes).expect("generate api token");
    let raw = base64_encode(&bytes);
    let hashed = hash_api_token(&raw);
    (raw, hashed)
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

// ── HMAC signing key ────────────────────────────────────────────────────────

/// HMAC signing key for session tokens (derived from `auth.token_secret`).
pub struct TokenKey {
    key: hmac::Key,
}

impl TokenKey {
    /// Derive an HMAC-SHA256 key from the secret string.
    pub fn from_secret(secret: &str) -> Self {
        let key = hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes());
        Self { key }
    }

    /// Sign a message and return the tag as base64.
    pub fn sign(&self, message: &str) -> String {
        let tag = hmac::sign(&self.key, message.as_bytes());
        base64_encode(tag.as_ref())
    }

    /// Verify a signature against a message. Returns true if valid.
    pub fn verify(&self, message: &str, signature: &str) -> bool {
        let Ok(decoded) = base64_decode(signature) else {
            return false;
        };
        hmac::verify(&self.key, message.as_bytes(), &decoded).is_ok()
    }
}

// ── Auth session ─────────────────────────────────────────────────────────────

/// Auth session — represents an authenticated user with roles and scope.
#[derive(Debug, Clone)]
pub struct AuthSession {
    pub user: String,
    pub roles: Vec<String>,
    pub scope: TokenScope,
}

impl AuthSession {
    /// Create a read-only session (for session tokens).
    pub fn read_only(user: String) -> Self {
        Self {
            user,
            roles: vec!["dns_reader".into()],
            scope: TokenScope::ReadOnly,
        }
    }

    /// Create a session with explicit roles and scope (for API tokens).
    pub fn with_roles(user: String, roles: Vec<String>, scope: TokenScope) -> Self {
        Self { user, roles, scope }
    }

    /// Check if the session has a given role.
    pub fn has_role(&self, role: &str) -> bool {
        self.roles.iter().any(|r| r == role)
    }

    /// Check if the session has the required scope.
    pub fn has_scope(&self, required: TokenScope) -> bool {
        self.scope.allows(required)
    }

    /// Check if the session is authorized for a runtime toggle (requires `dns_admin`).
    pub fn is_authorized_for_toggle(&self, required_role: &str) -> bool {
        self.has_role(required_role) && self.has_scope(TokenScope::Full)
    }

    /// Produce an HMAC-signed session token. Format: `payload.signature`.
    /// `expires` is epoch seconds; 0 means no expiry (for API tokens, though
    /// API tokens use static bearer auth, not HMAC).
    pub fn to_token(&self, key: &TokenKey, expires: u64) -> String {
        let payload = format!(
            "{}:{}:{}:{}",
            self.user,
            self.roles.join(","),
            self.scope as u8,
            expires
        );
        let sig = key.sign(&payload);
        format!("{}.{}", payload, sig)
    }

    /// Validate a session token and return the session. Returns `None` if:
    /// - token format is invalid
    /// - signature verification fails
    /// - token has expired (if expiry > 0)
    pub fn from_token(token: &str, key: &TokenKey) -> Option<Self> {
        let (payload, sig) = token.split_once('.')?;
        if !key.verify(payload, sig) {
            return None;
        }
        let mut parts = payload.splitn(4, ':');
        let user = parts.next()?.to_string();
        let roles_str = parts.next()?;
        let scope_val: u8 = parts.next()?.parse().ok()?;
        let expires: u64 = parts.next()?.parse().ok()?;

        if expires > 0 {
            let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
            if now > expires {
                return None;
            }
        }

        let roles: Vec<String> = if roles_str.is_empty() {
            vec![]
        } else {
            roles_str.split(',').map(String::from).collect()
        };
        let scope = match scope_val {
            0 => TokenScope::ReadOnly,
            1 => TokenScope::Full,
            _ => return None,
        };

        Some(Self { user, roles, scope })
    }
}

// ── Base64 (minimal, no dependency) ──────────────────────────────────────────

fn base64_encode(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[((triple >> 18) & 0x3F) as usize] as char);
        out.push(TABLE[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            out.push(TABLE[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(TABLE[(triple & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

fn base64_decode(s: &str) -> Result<Vec<u8>, ()> {
    let s = s.trim_end_matches('=');
    let mut buf = Vec::with_capacity(s.len() * 3 / 4);
    let mut bits: u32 = 0;
    let mut nbits: u32 = 0;
    for &c in s.as_bytes() {
        let val = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return Err(()),
        };
        bits = (bits << 6) | val as u32;
        nbits += 6;
        if nbits >= 8 {
            nbits -= 8;
            buf.push((bits >> nbits) as u8);
            bits &= (1 << nbits) - 1;
        }
    }
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> TokenKey {
        TokenKey::from_secret("test-secret-key-for-m7")
    }

    // ── Password hashing tests ───────────────────────────────────────

    #[test]
    fn password_hash_and_verify() {
        let hash = hash_password("correct-horse-battery-staple").unwrap();
        assert!(verify_password("correct-horse-battery-staple", &hash));
        assert!(!verify_password("wrong-password", &hash));
    }

    #[test]
    fn password_hash_different_each_time() {
        let h1 = hash_password("same-password").unwrap();
        let h2 = hash_password("same-password").unwrap();
        // Different salts → different hashes
        assert_ne!(h1, h2);
        // But both verify
        assert!(verify_password("same-password", &h1));
        assert!(verify_password("same-password", &h2));
    }

    #[test]
    fn password_verify_invalid_hash() {
        assert!(!verify_password("password", "not-a-valid-hash"));
        assert!(!verify_password("password", ""));
    }

    // ── TOTP tests ───────────────────────────────────────────────────

    #[test]
    fn totp_secret_generation() {
        let secret = generate_totp_secret();
        assert!(!secret.is_empty());
        // Should be valid base32
        // Base32 (RFC 4648): A-Z and 2-7
        assert!(
            secret
                .chars()
                .all(|c| ('A'..='Z').contains(&c) || ('2'..='7').contains(&c))
        );
    }

    #[test]
    fn totp_roundtrip() {
        let secret = generate_totp_secret();
        let code = generate_totp_code(&secret, "Heimdallr", "admin").unwrap();
        assert_eq!(code.len(), 6);
        assert!(code.chars().all(|c| c.is_ascii_digit()));
        assert!(verify_totp(&secret, "Heimdallr", "admin", &code));
    }

    #[test]
    fn totp_wrong_code_rejected() {
        let secret = generate_totp_secret();
        assert!(!verify_totp(&secret, "Heimdallr", "admin", "000000"));
        assert!(!verify_totp(&secret, "Heimdallr", "admin", "123456"));
    }

    #[test]
    fn totp_wrong_secret_rejected() {
        let secret1 = generate_totp_secret();
        let secret2 = generate_totp_secret();
        let code = generate_totp_code(&secret1, "Heimdallr", "admin").unwrap();
        assert!(!verify_totp(&secret2, "Heimdallr", "admin", &code));
    }

    #[test]
    fn totp_uri_format() {
        let secret = generate_totp_secret();
        let uri = totp_uri(&secret, "Heimdallr", "admin").unwrap();
        assert!(uri.starts_with("otpauth://totp/"));
        assert!(uri.contains("Heimdallr"));
        assert!(uri.contains("admin"));
    }

    // ── API token tests ──────────────────────────────────────────────

    #[test]
    fn api_token_hash_and_verify() {
        let (raw, hashed) = generate_api_token();
        assert!(verify_api_token(&raw, &hashed));
        assert!(!verify_api_token("wrong-token", &hashed));
    }

    #[test]
    fn api_token_constant_time() {
        // Verify that different-length inputs don't panic
        let (_, hashed) = generate_api_token();
        assert!(!verify_api_token("", &hashed));
        assert!(!verify_api_token("short", &hashed));
        assert!(!verify_api_token(&"x".repeat(1000), &hashed));
    }

    #[test]
    fn api_token_deterministic_hash() {
        let hash1 = hash_api_token("test-token-123");
        let hash2 = hash_api_token("test-token-123");
        assert_eq!(hash1, hash2);
    }

    // ── Session token tests ──────────────────────────────────────────

    #[test]
    fn session_roundtrip() {
        let key = test_key();
        let session = AuthSession::with_roles(
            "admin".into(),
            vec!["dns_reader".into(), "dns_admin".into()],
            TokenScope::Full,
        );
        let token = session.to_token(&key, 0);
        let recovered = AuthSession::from_token(&token, &key).unwrap();
        assert_eq!(recovered.user, "admin");
        assert!(recovered.has_role("dns_admin"));
        assert!(recovered.has_scope(TokenScope::Full));
    }

    #[test]
    fn session_read_only_scope() {
        let key = test_key();
        let session = AuthSession::read_only("viewer".into());
        let token = session.to_token(&key, 0);
        let recovered = AuthSession::from_token(&token, &key).unwrap();
        assert_eq!(recovered.scope, TokenScope::ReadOnly);
        assert!(!recovered.has_scope(TokenScope::Full));
    }

    #[test]
    fn session_expired_rejected() {
        let key = test_key();
        let session = AuthSession::read_only("admin".into());
        let token = session.to_token(&key, 1);
        assert!(AuthSession::from_token(&token, &key).is_none());
    }

    #[test]
    fn session_wrong_key_rejected() {
        let key1 = TokenKey::from_secret("secret-1");
        let key2 = TokenKey::from_secret("secret-2");
        let session = AuthSession::read_only("admin".into());
        let token = session.to_token(&key1, 0);
        assert!(AuthSession::from_token(&token, &key2).is_none());
    }

    #[test]
    fn session_tampered_rejected() {
        let key = test_key();
        let session = AuthSession::read_only("admin".into());
        let mut token = session.to_token(&key, 0);
        if let Some(pos) = token.find('.') {
            token.replace_range(..pos, "attacker:evil:1:9999999999");
        }
        assert!(AuthSession::from_token(&token, &key).is_none());
    }

    #[test]
    fn session_invalid_format() {
        let key = test_key();
        assert!(AuthSession::from_token("no-signature", &key).is_none());
        assert!(AuthSession::from_token("", &key).is_none());
        assert!(AuthSession::from_token(".", &key).is_none());
    }

    // ── Scope tests ──────────────────────────────────────────────────

    #[test]
    fn scope_full_allows_read() {
        assert!(TokenScope::Full.allows(TokenScope::ReadOnly));
        assert!(TokenScope::Full.allows(TokenScope::Full));
    }

    #[test]
    fn scope_readonly_only_allows_read() {
        assert!(TokenScope::ReadOnly.allows(TokenScope::ReadOnly));
        assert!(!TokenScope::ReadOnly.allows(TokenScope::Full));
    }

    #[test]
    fn rbac_dns_admin_requires_full_scope() {
        let session = AuthSession::with_roles(
            "admin".into(),
            vec!["dns_admin".into()],
            TokenScope::ReadOnly,
        );
        // Has the role but wrong scope
        assert!(!session.is_authorized_for_toggle("dns_admin"));

        let session =
            AuthSession::with_roles("admin".into(), vec!["dns_admin".into()], TokenScope::Full);
        assert!(session.is_authorized_for_toggle("dns_admin"));
    }

    // ── Base64 tests ─────────────────────────────────────────────────

    #[test]
    fn base64_roundtrip() {
        let data = b"Hello, world! This is a test of base64.";
        let encoded = base64_encode(data);
        let decoded = base64_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn base64_empty() {
        let encoded = base64_encode(b"");
        let decoded = base64_decode(&encoded).unwrap();
        assert!(decoded.is_empty());
    }
}
