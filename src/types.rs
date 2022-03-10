pub type Wn = u16;
pub type Tow = u32; // Time of week in seconds
pub type Towh = u8; // Time of week in hours

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct Gst {
    pub wn: Wn,
    pub tow: Tow,
}

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
