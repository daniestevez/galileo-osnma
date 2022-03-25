//! Validation status.
//!
//! This module contains types that can be used to take advantage of Rust's type
//! system to mark the validation status of objects such as TESLA keys and MACK
//! messages. It can be used to prevent at the type-checking level misuses such
//! as attempting to validate a TESLA chain key using any other TESLA chain key
//! that has not being traced back to the ECDSA public key via cryptographic checks.
//!
//! Types that use validation status have a type parameter that is intended to
//! hold either the [`Validated`] or [`NotValidated`] types. Generally, the
//! objects are first created with a `NotValidated` parameter, and as a result
//! of some cryptographic checks (potentially involving other `Validated` objects),
//! they are transformed into objects with a `Validated` parameter.

/// Validated status.
///
/// This type represents that the object holding it has successfully gone
/// through all the required cryptographic validations.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub struct Validated {}

/// Not validated status.
///
/// This type represents that the object holding it has not yet gone through all
/// the required cryptographic validations.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub struct NotValidated {}
