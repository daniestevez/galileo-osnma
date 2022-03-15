pub type Wn = u16;
pub type Tow = u32; // Time of week in seconds
pub type Towh = u8; // Time of week in hours

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct Gst {
    pub wn: Wn,
    pub tow: Tow,
}

impl Gst {
    pub fn add_seconds(&self, seconds: i32) -> Self {
        let secs_in_week = 24 * 3600 * 7;
        let weeks = seconds / secs_in_week;
        let seconds = seconds - weeks * secs_in_week;
        let mut tow = i32::try_from(self.tow).unwrap() + seconds;
        let mut wn = self.wn + u16::try_from(weeks).unwrap();
        if tow < 0 {
            wn -= 1;
            tow += secs_in_week;
        } else if tow >= secs_in_week {
            wn += 1;
            tow -= secs_in_week;
        };
        assert!((0..secs_in_week).contains(&tow));
        Gst {
            tow: tow.try_into().unwrap(),
            wn,
        }
    }
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

pub const INAV_WORD_BYTES: usize = 16;
pub type InavWord = [u8; INAV_WORD_BYTES];

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub struct Validated {}
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub struct NotValidated {}

pub const NUM_SVNS: usize = 36;
