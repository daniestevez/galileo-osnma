use crate::gst::Gst;
use crate::types::{BitSlice, InavWord, NUM_SVNS};
use bitvec::prelude::*;

// Number of subframes to store.
// This should usually be 1 more than the DEPTH of the MackStorage, because tags
// in the MACK refer to the previous subframe.
const DEPTH: usize = 13;

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct CollectNavMessage {
    ced_and_status: [[CedAndStatus; NUM_SVNS]; DEPTH],
    timing_parameters: [TimingParameters; DEPTH],
    gsts: [Option<Gst>; DEPTH],
    write_pointer: usize,
}

impl CollectNavMessage {
    pub fn new() -> CollectNavMessage {
        CollectNavMessage {
            ced_and_status: [[CedAndStatus::new(); NUM_SVNS]; DEPTH],
            timing_parameters: [TimingParameters::new(); DEPTH],
            gsts: [None; DEPTH],
            write_pointer: 0,
        }
    }

    fn check_svn(svn: usize) {
        assert!((1..=NUM_SVNS).contains(&svn));
    }

    pub fn feed(&mut self, word: &InavWord, svn: usize, gst: Gst) {
        log::trace!(
            "feeding INAV word = {:02x?} for svn = E{:02} GST {:?}",
            word,
            svn,
            gst
        );
        Self::check_svn(svn);
        let gst = gst.gst_subframe();
        self.adjust_write_pointer(gst);
        let svn_idx = svn - 1;
        self.ced_and_status[self.write_pointer][svn_idx].feed(word);
        self.timing_parameters[self.write_pointer].feed(word, svn);
    }

    fn adjust_write_pointer(&mut self, gst: Gst) {
        // If write pointer points to a valid GST which is distinct
        // from the current, we advance the write pointer and copy
        // the old CED and status to the new write pointer location.
        // We mark the copy as stale.
        // The timing parameters are not copied. Since all the satellites
        // transmit this information, it is very likely that in this subframe
        // we are able to gather the two required words.
        if let Some(g) = self.gsts[self.write_pointer] {
            if g != gst {
                log::trace!(
                    "got a new GST {:?} (current GST is {:?}); \
                     advancing write pointer",
                    gst,
                    g
                );
                let new_pointer = (self.write_pointer + 1) % DEPTH;
                self.ced_and_status[new_pointer] = self.ced_and_status[self.write_pointer];
                self.timing_parameters[new_pointer].valid = [false; TIMING_PARAMETERS_WORDS];
                self.write_pointer = new_pointer;
                self.mark_stale();
            }
        }
        self.gsts[self.write_pointer] = Some(gst);
    }

    fn mark_stale(&mut self) {
        for ced in self.ced_and_status[self.write_pointer].iter_mut() {
            ced.stale = true;
        }
    }

    pub fn ced_and_status(&self, svn: usize, gst: Gst) -> Option<&BitSlice> {
        Self::check_svn(svn);
        let item = &self.ced_and_status[self.find_gst(gst)?][svn - 1];
        if !item.stale && item.all_valid() {
            Some(&item.bits()[..549])
        } else {
            None
        }
    }

    pub fn timing_parameters(&self, gst: Gst) -> Option<&BitSlice> {
        let item = &self.timing_parameters[self.find_gst(gst)?];
        if item.all_valid() {
            Some(&item.bits()[..161])
        } else {
            None
        }
    }

    fn find_gst(&self, gst: Gst) -> Option<usize> {
        assert!(gst.is_subframe());
        self.gsts
            .iter()
            .enumerate()
            .find_map(|(j, &g)| if g == Some(gst) { Some(j) } else { None })
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
    stale: bool,
}

pub const TIMING_PARAMETERS_BYTES: usize = 21;
const TIMING_PARAMETERS_WORDS: usize = 2;

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
struct TimingParameters {
    data: [u8; TIMING_PARAMETERS_BYTES],
    valid: [bool; TIMING_PARAMETERS_WORDS],
}

macro_rules! impl_common {
    ($s: ident, $data_size: expr, $num_words: expr, $($id: ident <= $val: expr),*) => {
        impl $s {
            fn new() -> $s {
                $s {
                    data: [0; $data_size],
                    valid: [false; $num_words],
                    $($id: $val),*
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

impl_common!(
    CedAndStatus,
    CED_AND_STATUS_BYTES,
    CED_AND_STATUS_WORDS,
    stale <= true
);
impl_common!(
    TimingParameters,
    TIMING_PARAMETERS_BYTES,
    TIMING_PARAMETERS_WORDS,
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
                self.stale = false;
                self.valid[0] = true;
                self.new_iodnav(iodnav);
                assert!(self.valid[0]);
            }
            2 => {
                self.bits_as_mut()[120..240].copy_from_bitslice(&word[6..126]);
                self.stale = false;
                self.valid[1] = true;
                self.new_iodnav(iodnav);
                assert!(self.valid[1]);
            }
            3 => {
                self.bits_as_mut()[240..362].copy_from_bitslice(&word[6..128]);
                self.stale = false;
                self.valid[2] = true;
                self.new_iodnav(iodnav);
                assert!(self.valid[2]);
            }
            4 => {
                self.bits_as_mut()[362..482].copy_from_bitslice(&word[6..126]);
                self.stale = false;
                self.valid[3] = true;
                self.new_iodnav(iodnav);
                assert!(self.valid[3]);
            }
            5 => {
                self.bits_as_mut()[482..549].copy_from_bitslice(&word[6..73]);
                self.stale = false;
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
    fn feed(&mut self, word: &InavWord, svn: usize) {
        let word = BitSlice::from_slice(word);
        let word_type = word[..6].load_be::<u8>();
        match word_type {
            6 => {
                if !self.valid[0] {
                    Self::log_word(word_type);
                    // Note that the TOW field will be removed in a new version
                    // of the ICD, so this will need to be updated.
                    self.bits_as_mut()[..119].copy_from_bitslice(&word[6..125]);
                    self.valid[0] = true;
                } else {
                    Self::check_mismatch(word_type, svn, &self.bits()[..119], &word[6..125]);
                }
            }
            10 => {
                if !self.valid[1] {
                    Self::log_word(word_type);
                    self.bits_as_mut()[119..161].copy_from_bitslice(&word[86..128]);
                    self.valid[1] = true;
                } else {
                    Self::check_mismatch(word_type, svn, &self.bits()[119..161], &word[86..128]);
                }
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

    fn check_mismatch(word_type: u8, svn: usize, stored: &BitSlice, received: &BitSlice) {
        if stored != received {
            log::warn!(
                "received word {} from E{:02} doesn't match word stored for the same subframe\
                        (received = {:?}, stored = {:?}",
                word_type,
                svn,
                received,
                stored
            );
        }
    }
}
