#![allow(warnings)]
use ark_std::rand::{thread_rng, Rng};
use log::info;
use rand::seq::index::sample;
use env_logger;

#[allow(warnings)]
pub mod thbgn;

pub const NUM_RECIPIENTS: usize = 10_000;
pub const NUM_PERIODS: usize = 10;
pub const NUM_SHOW_UP: usize = 9_000;
pub const DECRYPTION_THRESHOLD: usize = NUM_RECIPIENTS / 5;
pub const MIN_ENTITLEMENT: usize = 1;
pub const MAX_ENTITLEMENT: usize = 5;
pub const CONTACT_INFO_LEN: usize = 10;
pub const TOTAL_SHOWUP_ENTITLEMENT: usize = 20_000;
pub const TOTAL_ENTITLEMENT: usize = 18_000;
pub const TAG_BYTELEN: usize = 16; // 128 bits

const PROB_IN_GROUP: f64 = 0.10;