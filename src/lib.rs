//! # Galileo OSNMA
//!
//! galileo-osnma is a Rust implementation of the Galileo OSNMA (Open Service
//! Navigation Message Authentication) protocol. This protocol is used by the
//! Galileo GNSS to sign cryptographically the navigation message data
//! transmitted by its satellites, in order to prevent spoofing. Briefly
//! speaking, galileo-osnma can process the navigation message data and OSNMA
//! cryptographic data and check all the cryptographic signatures against the
//! ECDSA public key, in order to check the authenticity of the navigation data.
//!
//! This library provides an [`Osnma`] struct that implements the OSNMA
//! authentication as a black box. A user can feed data from INAV pages into
//! [`Osnma`] and then request authenticated navigation data.
//!
//! Additionally, lower level functionalities of the OSNMA protocol are
//! accessible in case finer control is needed.
//!
//! ## Logging
//!
//! The galileo-osnma crate makes extensive use of the
//! [log](https://docs.rs/log/latest/log/) crate to log events related to the
//! processing of the messages and the cryptographic functions.

#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]

pub mod bitfields;
pub mod dsm;
#[cfg(feature = "galmon")]
pub mod galmon;
mod gst;
pub use gst::{Gst, Tow, Wn};
pub mod mack;
pub mod navmessage;
mod osnma;
pub use osnma::Osnma;
pub mod storage;
pub mod subframe;
pub mod tesla;
pub mod types;
pub mod validation;
