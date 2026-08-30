//! Recursive behaviors — `QNAME` min `9156`, `0x20` randomization, `ECS` `7871`.

#![allow(dead_code)]

#[derive(Debug, Clone, Copy)]
pub struct RecOptions {
    pub qname_minimization: bool,
    pub case_randomization: bool,
    pub ecs: bool,
}

impl Default for RecOptions {
    fn default() -> Self {
        Self {
            qname_minimization: true,
            case_randomization: false,
            ecs: false,
        }
    }
}
