//! OSNMA storage definitions.
//!
//! The trait [`StaticStorage`] in this module is used to define the sizes of
//! some of the data that is allocated by [`Osnma`](crate::Osnma). This can be
//! used to reduce the memory footprint, at the cost of processing less
//! satellites in parallel or not processing Slow MAC.
//!
//! The number of SVNs (satellites) in the Galileo constellation is 36, but
//! a receiver will typically track at most 8 to 12 satellites at a time.
//! Storage space can be saved by limiting the information stored to only
//! that of 8 or 12 satellites.
//!
//! Slow MAC requires authenticating the data transmitted 10 subframes
//! (300 seconds) ago, so an additional history of data for 10 subframes needs
//! to be stored if Slow MAC is used. By limiting the history stored and not
//! using Slow MAC, space can be saved.
//!
//! A [`StaticStorage`] trait is used to define types that indicate the size of
//! the storage. In general, these types should be zero-sized. Two types are provided:
//! [`FullStorage`], which gives the largest reasonable storage, and [`SmallStorage`],
//! which is a much smaller size that can be used in memory constrained applications.
//! Users can define additional storage sizes by implementing the [`StaticStorage`]
//! trait on their own types.

use generic_array::ArrayLength;

/// Auxiliary trait for generic array sizes.
///
/// This is a trait that has as supertraits all the traits required to use an
/// [`Unsigned`](typenum::marker_traits::Unsigned) type from `typenum` as an
/// array length for the generic arrays used in the storage. Its main purpose is
/// to simplify trait bounds. A blanket implementation is used to derive this
/// trait for the appriate types.
pub trait StaticStorageTypenum:
    typenum::marker_traits::Unsigned
    + core::fmt::Debug
    + core::cmp::PartialEq
    + core::cmp::Eq
    + ArrayLength
{
}

/// Blanket implementation for [`StaticStorageTypenum`].
///
/// This implements the [`StaticStorageTypenum`] trait for all the types that
/// have the required traits.
impl<T> StaticStorageTypenum for T where
    T: typenum::marker_traits::Unsigned
        + core::fmt::Debug
        + core::cmp::PartialEq
        + core::cmp::Eq
        + ArrayLength
{
}

/// Trait defining static storage sizes.
///
/// A type that implements this trait defines the sizes for the static
/// storage used for OSNMA data. In general, unsigned integers from the
/// `typenum` crate should be used anywhere a `StaticStorageTypenum` is
/// needed.
///
/// There is some consistency that must be ensured between the different
/// sizes. If a type does not follow these consistency rules, users of that
/// type may panic or give wrong results.
pub trait StaticStorage {
    /// The number of satellites to store in parallel.
    ///
    /// This should be 36 (or [`NUM_SVNS`](crate::types::NUM_SVNS)) to store
    /// data for the full constellation, and a value around 8 to 12 to store
    /// data only for the satellites in view.
    const NUM_SATS: usize;
    /// Number of navigation message subframes to store.
    ///
    /// Several navigation messages are stored as a history of past data.
    /// The value used here should usually be one more than the value of
    /// `MackDepth`, because tags in the MACK message refer to navigation
    /// data transmitted in the previous subframe.
    type NavMessageDepth: StaticStorageTypenum;
    /// Product of `NUM_SATS` and `NavMessageDepth`.
    ///
    /// This type should always equal the product of `NUM_SATS` and
    /// `NavMessageDepth`.
    type NavMessageDepthSats: StaticStorageTypenum;
    /// Number of MACK message subframes to store.
    ///
    /// Several MACK messages are stored as a history of past data. In order to
    /// process Slow MAC, the value of this type should be at least 12, because
    /// it is necessary to store the current subframe, the previous subframe
    /// (whose tags correspond to the key in the current subframe), plus the
    /// 10 previous subframes to account for the Slow MAC delay. If Slow MAC
    /// processing is not needed, then this value can be as small as 2.
    type MackDepth: StaticStorageTypenum;
    /// Product of `NUM_SATS` and `MackDepth`.
    ///
    /// This type should always equal the product of `NUM_SATS` and `MackDepth`.
    type MackDepthSats: StaticStorageTypenum;
}

/// Storage size for 36 satellites and Slow MAC.
///
/// This is the largest storage size that it makes sense to have.
/// It has a history of 13 subframes of navigation messages in order
/// to process Slow MAC, and stores 36 satellites in parallel.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub struct FullStorage {}

impl StaticStorage for FullStorage {
    const NUM_SATS: usize = 36;
    type NavMessageDepth = typenum::U13;
    type NavMessageDepthSats = typenum::U468;
    type MackDepth = typenum::U12;
    type MackDepthSats = typenum::U432;
}

/// Storage size for 12 satellites without Slow MAC.
///
/// This is an example of a reduced storage size that can be used in a platform
/// with constrained memory. It stores a history of only 3 subframes of
/// navigation messages, so it cannot process Slow MAC, and only stores 12
/// satellites in parallel.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub struct SmallStorage {}

impl StaticStorage for SmallStorage {
    const NUM_SATS: usize = 12;
    type NavMessageDepth = typenum::U3;
    type NavMessageDepthSats = typenum::U36;
    type MackDepth = typenum::U2;
    type MackDepthSats = typenum::U24;
}
