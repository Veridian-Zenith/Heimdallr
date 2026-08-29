//! Primary/Secondary/Stub/Conditional zones, `AXFR`/`IXFR`/`NOTIFY`, catalog `9432` (`M2`).

#[derive(Debug, Clone, Copy)]
pub enum ZoneKind {
    Primary,
    Secondary,
    Stub,
    Conditional,
    Forwarder,
}

pub struct Zone {
    pub name: String,
    pub kind: ZoneKind,
}
