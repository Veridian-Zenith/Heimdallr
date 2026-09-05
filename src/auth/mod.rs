// SPDX-License-Identifier: OSL-3.0
// Copyright (c) 2026 Veridian Zenith

//! Auth — M7.2 RBAC + TOTP + OIDC stub. Original interface; no C# /
//! Technitium `auth` derivation. Uses `axum` `State` for session gate.

#[derive(Debug, Clone, Default)]
pub struct AuthConfig {
    pub enabled: bool,
    pub rbac_roles: Vec<String>,
    pub totp_issuer: String,
    pub oidc_provider: Option<String>,
}

pub struct AuthSession {
    pub user: String,
    pub roles: Vec<String>,
    pub totp_verified: bool,
    pub oidc_token: Option<String>,
}

impl AuthSession {
    pub fn new(user: String) -> Self {
        Self {
            user,
            roles: vec!["dns_reader".into()],
            totp_verified: false,
            oidc_token: None,
        }
    }
    pub fn has_role(&self, role: &str) -> bool {
        self.roles.contains(&role.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn auth_session_default_roles() {
        let session = AuthSession::new("operator".into());
        assert!(session.has_role("dns_reader"));
        assert!(!session.has_role("dns_admin"));
    }
}
