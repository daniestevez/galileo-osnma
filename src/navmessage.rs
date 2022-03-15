use crate::types::{BitSlice, InavWord, NUM_SVNS};
use bitvec::prelude::*;

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct CollectNavMessage {
    ced_and_status: [CedAndStatus; NUM_SVNS],
    timing_parameters: TimingParameters,
}

impl CollectNavMessage {
    pub fn new() -> CollectNavMessage {
        CollectNavMessage {
            ced_and_status: [CedAndStatus::new(); NUM_SVNS],
            timing_parameters: TimingParameters::new(),
        }
    }

    fn check_svn(svn: usize) {
        assert!((1..=NUM_SVNS).contains(&svn));
    }

    pub fn feed(&mut self, word: &InavWord, svn: usize) {
        log::trace!("feeding INAV word = {:02x?} for svn = E{:02}", word, svn);
        Self::check_svn(svn);
        let svn_idx = svn - 1;
        self.ced_and_status[svn_idx].feed(word);
        self.timing_parameters.feed(word);
    }

    pub fn ced_and_status(&self, svn: usize) -> Option<&BitSlice> {
        Self::check_svn(svn);
        let item = &self.ced_and_status[svn - 1];
        if item.all_valid() {
            Some(&item.bits()[..549])
        } else {
            None
        }
    }

    pub fn timing_parameters(&self) -> Option<&BitSlice> {
        if self.timing_parameters.all_valid() {
            Some(&self.timing_parameters.bits()[..372])
        } else {
            None
        }
    }
}

impl Default for CollectNavMessage {
    fn default() -> CollectNavMessage {
        CollectNavMessage::new()
    }
}

pub const CED_AND_STATUS_BYTES: usize = 69;
const CED_AND_STATUS_WORDS: usize = 5;

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
struct CedAndStatus {
    data: [u8; CED_AND_STATUS_BYTES],
    valid: [bool; CED_AND_STATUS_WORDS],
}

pub const TIMING_PARAMETERS_BYTES: usize = 21;
const TIMING_PARAMETERS_WORDS: usize = 2;

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
struct TimingParameters {
    data: [u8; TIMING_PARAMETERS_BYTES],
    valid: [bool; TIMING_PARAMETERS_WORDS],
}

macro_rules! impl_common {
    ($s: ident, $data_size: expr, $num_words: expr) => {
        impl $s {
            fn new() -> $s {
                $s {
                    data: [0; $data_size],
                    valid: [false; $num_words],
                }
            }

            fn bits(&self) -> &BitSlice {
                BitSlice::from_slice(&self.data)
            }

            fn bits_as_mut(&mut self) -> &mut BitSlice {
                BitSlice::from_slice_mut(&mut self.data)
            }

            fn all_valid(&self) -> bool {
                self.valid.iter().all(|&x| x)
            }
        }
    };
}

impl_common!(CedAndStatus, CED_AND_STATUS_BYTES, CED_AND_STATUS_WORDS);
impl_common!(
    TimingParameters,
    TIMING_PARAMETERS_BYTES,
    TIMING_PARAMETERS_WORDS
);

impl CedAndStatus {
    fn feed(&mut self, word: &InavWord) {
        let word = BitSlice::from_slice(word);
        let word_type = word[..6].load_be::<u8>();
        let iodnav = word[6..16].load_be::<u16>();
        if (1..=5).contains(&word_type) {
            Self::log_word(word_type);
        }
        match word_type {
            1 => {
                self.bits_as_mut()[..120].copy_from_bitslice(&word[6..126]);
                self.valid[0] = true;
                self.new_iodnav(iodnav);
                assert!(self.valid[0]);
            }
            2 => {
                self.bits_as_mut()[120..240].copy_from_bitslice(&word[6..126]);
                self.valid[1] = true;
                self.new_iodnav(iodnav);
                assert!(self.valid[1]);
            }
            3 => {
                self.bits_as_mut()[240..362].copy_from_bitslice(&word[6..128]);
                self.valid[2] = true;
                self.new_iodnav(iodnav);
                assert!(self.valid[2]);
            }
            4 => {
                self.bits_as_mut()[362..482].copy_from_bitslice(&word[6..126]);
                self.valid[3] = true;
                self.new_iodnav(iodnav);
                assert!(self.valid[3]);
            }
            5 => {
                self.bits_as_mut()[482..549].copy_from_bitslice(&word[6..73]);
                self.valid[4] = true;
            }
            _ => (),
        };
        log::trace!(
            "CedAndStatus has the following valid words: {:?}",
            self.valid
        );
    }

    fn log_word(word_type: u8) {
        log::trace!("CedAndStatus storing INAV word type {}", word_type);
    }

    // Invalidate all the words having an IODNAV different from
    // the new IODNAV we have received.
    fn new_iodnav(&mut self, iodnav: u16) {
        log::trace!("received word with IODNAV {}", iodnav);
        let old_iodnav = self.bits()[..10].load_be::<u16>();
        if self.valid[0] && old_iodnav != iodnav {
            self.valid[0] = false;
            Self::log_erased(iodnav, old_iodnav, 1);
        }
        let old_iodnav = self.bits()[120..130].load_be::<u16>();
        if self.valid[1] && old_iodnav != iodnav {
            self.valid[1] = false;
            Self::log_erased(iodnav, old_iodnav, 2);
        }
        let old_iodnav = self.bits()[240..250].load_be::<u16>();
        if self.valid[2] && old_iodnav != iodnav {
            self.valid[2] = false;
            Self::log_erased(iodnav, old_iodnav, 3);
        }
        let old_iodnav = self.bits()[362..372].load_be::<u16>();
        if self.valid[3] && old_iodnav != iodnav {
            self.valid[4] = false;
            Self::log_erased(iodnav, old_iodnav, 4);
        }
    }

    fn log_erased(new_iodnav: u16, old_iodnav: u16, word: u8) {
        log::trace!(
            "erased word {} due to having old IODNAV {} (new IODNAV is {})",
            word,
            old_iodnav,
            new_iodnav
        );
    }
}

impl TimingParameters {
    fn feed(&mut self, word: &InavWord) {
        let word = BitSlice::from_slice(word);
        let word_type = word[..6].load_be::<u8>();
        match word_type {
            6 => {
                Self::log_word(word_type);
                // Note that the TOW field will be removed in a new version
                // of the ICD, so this will need to be updated.
                self.bits_as_mut()[..119].copy_from_bitslice(&word[6..125]);
                self.valid[0] = true;
            }
            10 => {
                Self::log_word(word_type);
                self.bits_as_mut()[119..161].copy_from_bitslice(&word[86..128]);
                self.valid[1] = true;
            }
            _ => (),
        }
        log::trace!(
            "TimingParameters has the following valid words: {:?}",
            self.valid
        );
    }

    fn log_word(word_type: u8) {
        log::trace!("TimingParameters storing INAV word type {}", word_type);
    }
}
