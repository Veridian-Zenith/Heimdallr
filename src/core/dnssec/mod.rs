// SPDX-License-Identifier: OSL-3.0
// Copyright (c) 2026 Veridian Zenith

//! DNSSEC validation/signing — `ring` default, `botan` optional.
//! `hickory-proto:dnssec-ring` covers `RSA`/`ECDSA`/`EdDSA` + `NSEC`/`NSEC3`; `botan-crypto` alt for HSM/agility.

pub mod keygen;

pub trait DnssecProvider: Send + Sync {
    fn name(&self) -> &'static str;
}

pub struct RingProvider;
impl DnssecProvider for RingProvider {
    fn name(&self) -> &'static str {
        "ring"
    }
}

#[cfg(feature = "botan-crypto")]
pub struct BotanProvider;
#[cfg(feature = "botan-crypto")]
impl DnssecProvider for BotanProvider {
    fn name(&self) -> &'static str {
        "botan"
    }
}

pub fn provider_for(name: &str) -> Box<dyn DnssecProvider> {
    #[cfg(feature = "botan-crypto")]
    if name == "botan" {
        return Box::new(BotanProvider);
    }
    let _ = name;
    Box::new(RingProvider)
}
