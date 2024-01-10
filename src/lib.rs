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
//! [`Osnma`] and then request authenticated navigation data.  Additionally,
//! lower level functionalities of the OSNMA protocol are accessible in case
//! finer control is needed.
//!
//! This crate does not depend on `std` and can be used in small embedded
//! microcontrollers. An example of this is given in the
//! [osnma-longan-nano](https://github.com/daniestevez/galileo-osnma/tree/main/osnma-longan-nano)
//! crate.
//!
//! ## Logging
//!
//! The galileo-osnma crate makes extensive use of the
//! [log](https://docs.rs/log/latest/log/) crate to log events related to the
//! processing of the messages and the cryptographic functions.
//!
//! ## Galmon integration
//!
//! When this crate is built with the `galmon` feature, a `galmon` module is
//! available, which can be used to read data using the [Galmon transport
//! protocol](https://github.com/berthubert/galmon#internals). The reader can
//! be used to obtain INAV frames and OSNMA data from the
//! [Galmon](https://github.com/berthubert/galmon) tools, such as `ubxtool`.
//!
//! An example of this functionality is given in
//! [galmon-osnma](https://github.com/daniestevez/galileo-osnma/tree/main/galmon-osnma). This
//! is a binary tool that reads data from the standard input using the Galmon
//! transport protocol, and runs it through the [`Osnma`] black box, logging all
//! the events that happen. See the
//! [quick start instructions](https://github.com/daniestevez/galileo-osnma#quick-start-using-galmon)
//! about how to use this tool.
//!
//! ## Features
//!
//! When built with the default features, the crate does not require
//! `std`. Additionally, the crate supports the following features:
//! * `galmon`. This enables support for reading the Galmon transport protocol
//!    and requires `std`.

#![warn(missing_docs)]
#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]

pub mod bitfields;
pub mod dsm;
#[cfg(feature = "galmon")]
pub mod galmon;
mod gst;
pub use gst::{Gst, Tow, Wn};
pub mod mack;
pub mod maclt;
pub mod merkle_tree;
pub mod navmessage;
mod osnma;
pub use osnma::Osnma;
pub mod storage;
pub mod subframe;
mod svn;
pub use svn::{Svn, SvnError};
pub mod tesla;
pub mod types;
pub use types::{InavBand, VerifyingKey};
pub mod validation;
