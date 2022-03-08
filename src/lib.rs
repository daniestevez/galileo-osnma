#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]

#[cfg(feature = "galmon")]
pub mod galmon;
