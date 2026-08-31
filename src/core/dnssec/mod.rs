// SPDX-License-Identifier: OSL-3.0
// Copyright (c) 2026 Veridian Zenith

//! DNSSEC validation/signing — `ring` default, `botan` for HSM/DNSSEC agility.
//! `hickory-proto:dnssec-ring` covers `RSA`/`ECDSA`/`EdDSA` + `NSEC`/`NSEC3`.
//! Botan provides alternate crypto backend for DoT/DoH/DoQ TLS and future HSM support.

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

pub struct BotanProvider;
impl DnssecProvider for BotanProvider {
    fn name(&self) -> &'static str {
        "botan"
    }
}

pub fn provider_for(name: &str) -> Box<dyn DnssecProvider> {
    if name == "botan" {
        return Box::new(BotanProvider);
    }
    Box::new(RingProvider)
}
