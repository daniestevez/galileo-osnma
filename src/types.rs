use crate::mack::Mack;
use crate::navmessage::{CedAndStatus, TimingParameters};
use crate::Gst;
use generic_array::ArrayLength;

pub const HKROOT_SECTION_BYTES: usize = 1;
pub const MACK_SECTION_BYTES: usize = 4;
pub type HkrootSection = [u8; HKROOT_SECTION_BYTES];
pub type MackSection = [u8; MACK_SECTION_BYTES];

pub type OsnmaDataMessage = [u8; HKROOT_SECTION_BYTES + MACK_SECTION_BYTES];

const WORDS_PER_SUBFRAME: usize = 15;
pub const HKROOT_MESSAGE_BYTES: usize = HKROOT_SECTION_BYTES * WORDS_PER_SUBFRAME;
pub const MACK_MESSAGE_BYTES: usize = MACK_SECTION_BYTES * WORDS_PER_SUBFRAME;
pub type HkrootMessage = [u8; HKROOT_MESSAGE_BYTES];
pub type MackMessage = [u8; MACK_MESSAGE_BYTES];

pub const DSM_BLOCK_BYTES: usize = 13;
pub type DsmBlock = [u8; DSM_BLOCK_BYTES];

pub type BitSlice = bitvec::slice::BitSlice<u8, bitvec::order::Msb0>;

pub const INAV_WORD_BYTES: usize = 16;
pub type InavWord = [u8; INAV_WORD_BYTES];

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub struct Validated {}
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub struct NotValidated {}

pub const NUM_SVNS: usize = 36;

pub trait StaticStorageTypenum:
    typenum::marker_traits::Unsigned
    + core::fmt::Debug
    + core::cmp::PartialEq
    + core::cmp::Eq
    + ArrayLength<CedAndStatus>
    + ArrayLength<TimingParameters>
    + ArrayLength<Option<Gst>>
    + ArrayLength<Option<Mack>>
{
}

impl<T> StaticStorageTypenum for T where
    T: typenum::marker_traits::Unsigned
        + core::fmt::Debug
        + core::cmp::PartialEq
        + core::cmp::Eq
        + ArrayLength<CedAndStatus>
        + ArrayLength<TimingParameters>
        + ArrayLength<Option<Gst>>
        + ArrayLength<Option<Mack>>
{
}

pub trait StaticStorage {
    const NUM_SATS: usize;
    // Number of subframes to store.
    // This should usually be 1 more than the DEPTH of the MackStorage, because tags
    // in the MACK refer to the previous subframe.
    type NavMessageDepth: StaticStorageTypenum;
    type NavMessageDepthSats: StaticStorageTypenum;
    // Number of subframes to store.
    // For full storage this is 12 because we need to store the current subframe,
    // the previous subframe because its tags correspond to the
    // key in the current subframe, and also the 10 previous subframes
    // to this to acccount for Slow MAC.
    type MackDepth: StaticStorageTypenum;
    type MackDepthSats: StaticStorageTypenum;
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub struct FullStorage {}

impl StaticStorage for FullStorage {
    const NUM_SATS: usize = 36;
    type NavMessageDepth = typenum::U13;
    type NavMessageDepthSats = typenum::U468;
    type MackDepth = typenum::U12;
    type MackDepthSats = typenum::U432;
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub struct SmallStorage {}

impl StaticStorage for SmallStorage {
    const NUM_SATS: usize = 12;
    type NavMessageDepth = typenum::U3;
    type NavMessageDepthSats = typenum::U36;
    type MackDepth = typenum::U2;
    type MackDepthSats = typenum::U24;
}
