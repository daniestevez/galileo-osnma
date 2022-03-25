//! Types used in galileo_osnma.
//!
//! This module contains some types that are used throughout the galileo_osnma
//! crate.

/// Size in bytes of the HKROOT section of an OSNMA message.
pub const HKROOT_SECTION_BYTES: usize = 1;
/// Size in bytes of the MACK section of an OSNMA message.
pub const MACK_SECTION_BYTES: usize = 4;
/// HKROOT section of an OSNMA message.
///
/// The HKROOT section corresponds to the first 8 bits of the
/// OSNMA data message. See Figure 2 in the
/// [OSNMA ICD](https://www.gsc-europa.eu/sites/default/files/sites/all/files/Galileo_OSNMA_User_ICD_for_Test_Phase_v1.0.pdf).
pub type HkrootSection = [u8; HKROOT_SECTION_BYTES];
/// MACK section of an OSNMA message.
///
/// The MACK section corresponds to the last 32 bits of the
/// OSNMA data message. See Figure 2 in the
/// [OSNMA ICD](https://www.gsc-europa.eu/sites/default/files/sites/all/files/Galileo_OSNMA_User_ICD_for_Test_Phase_v1.0.pdf).
pub type MackSection = [u8; MACK_SECTION_BYTES];

/// OSNMA data message.
///
/// The OSNMA data message corresponds to 40 bits that are carrier in one of the
/// reserved fields of the INAV pages. See Figure 1 in the
/// [OSNMA ICD](https://www.gsc-europa.eu/sites/default/files/sites/all/files/Galileo_OSNMA_User_ICD_for_Test_Phase_v1.0.pdf).
pub type OsnmaDataMessage = [u8; HKROOT_SECTION_BYTES + MACK_SECTION_BYTES];

const WORDS_PER_SUBFRAME: usize = 15;
/// Number of bytes in an HKROOT message.
pub const HKROOT_MESSAGE_BYTES: usize = HKROOT_SECTION_BYTES * WORDS_PER_SUBFRAME;
/// Number of bytes in a MACK message.
pub const MACK_MESSAGE_BYTES: usize = MACK_SECTION_BYTES * WORDS_PER_SUBFRAME;
/// HKROOT message.
///
/// The HKROOT message is composed by 15 HKROOT sections. See Figure 3 in the
/// [OSNMA ICD](https://www.gsc-europa.eu/sites/default/files/sites/all/files/Galileo_OSNMA_User_ICD_for_Test_Phase_v1.0.pdf).
pub type HkrootMessage = [u8; HKROOT_MESSAGE_BYTES];
/// MACK message.
///
/// The MACK message is composed by 15 MACK sections. See Figure 8 in the
/// [OSNMA ICD](https://www.gsc-europa.eu/sites/default/files/sites/all/files/Galileo_OSNMA_User_ICD_for_Test_Phase_v1.0.pdf).
pub type MackMessage = [u8; MACK_MESSAGE_BYTES];

/// Size of a DSM block in bytes.
pub const DSM_BLOCK_BYTES: usize = 13;
/// DSM block.
///
/// A DSM block corresponds to the HKROOT message minus the NMA header and the
/// DSM header. See Figure 3 in the
/// [OSNMA ICD](https://www.gsc-europa.eu/sites/default/files/sites/all/files/Galileo_OSNMA_User_ICD_for_Test_Phase_v1.0.pdf).
pub type DsmBlock = [u8; DSM_BLOCK_BYTES];

/// A slice of bits.
///
/// A [`BitSlice`](bitvec::slice::BitSlice) from the `bitvec` crate used to
/// represent binary data whose length is not a multiple of 8 bytes or which is
/// not byte aligned within its containing message.
///
/// In the Galileo documentation, the most significant bit of the first byte of
/// the data is numbered as bit 0, so we use the [`Msb0`](bitvec::order::Msb0)
/// ordering.
pub type BitSlice = bitvec::slice::BitSlice<u8, bitvec::order::Msb0>;

/// Number of bytes in an INAV word.
pub const INAV_WORD_BYTES: usize = 16;
/// INAV word.
///
/// An INAV word contains the 128 bits (16 bytes) as defined in
/// Section 4.3.5 of the
/// [Galileo OS SIS ICD](https://www.gsc-europa.eu/sites/default/files/sites/all/files/Galileo_OS_SIS_ICD_v2.0.pdf).
pub type InavWord = [u8; INAV_WORD_BYTES];

/// The number of SVNs in the Galileo constellation.
pub const NUM_SVNS: usize = 36;

/// The time of week given in hours, as an 8 bit integer.
///
/// This is used in the DSM-KROOT message.
pub type Towh = u8;
