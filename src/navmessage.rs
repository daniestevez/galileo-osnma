use crate::bitfields::{Adkd, Mack};
use crate::gst::Gst;
use crate::tesla::Key;
use crate::types::{BitSlice, InavWord, Validated, NUM_SVNS};
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
                self.timing_parameters[new_pointer].reset();
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

    fn ced_and_status_as_mut(&mut self, svn: usize, gst: Gst) -> Option<&mut CedAndStatus> {
        Self::check_svn(svn);
        let item = &mut self.ced_and_status[self.find_gst(gst)?][svn - 1];
        if !item.stale && item.all_valid() {
            Some(item)
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

    fn timing_parameters_as_mut(&mut self, gst: Gst) -> Option<&mut TimingParameters> {
        let item = &mut self.timing_parameters[self.find_gst(gst)?];
        if item.all_valid() {
            Some(item)
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

    pub fn process_mack(
        &mut self,
        mack: Mack<Validated>,
        key: &Key<Validated>,
        prna: usize,
        gst_mack: Gst,
    ) {
        let prna_u8 = u8::try_from(prna).unwrap();
        let gst_navmessage = gst_mack.add_seconds(-30);
        if let Some(navdata) = self.ced_and_status_as_mut(prna, gst_navmessage) {
            // Try to validate tag0
            Self::validate_tag(
                &key,
                mack.tag0(),
                Adkd::InavCed,
                gst_mack,
                prna_u8,
                prna_u8,
                0,
                navdata,
            );
        }

        // Try to validate InavCed and InavTiming tags
        for j in 1..mack.num_tags() {
            let tag = mack.tag_and_info(j);
            let prnd = match u8::try_from(tag.prnd()) {
                Ok(p) => p,
                Err(_) => {
                    log::error!("could not obtain PRND from tag {:?}", tag);
                    continue;
                }
            };
            if let Some(navdata) = match tag.adkd() {
                Adkd::InavCed => self
                    .ced_and_status_as_mut(prnd.into(), gst_navmessage)
                    .map(|x| {
                        let y: &mut dyn AuthBits = x;
                        y
                    }),
                Adkd::InavTiming => self.timing_parameters_as_mut(gst_navmessage).map(|x| {
                    let y: &mut dyn AuthBits = x;
                    y
                }),
                Adkd::SlowMac => {
                    // Slow MAC is not processed here, because the key doesn't
                    // have the appropriate extra delay
                    None
                }
                Adkd::Reserved => {
                    log::error!("reserved ADKD in tag {:?}", tag);
                    None
                }
            } {
                let prnd = if tag.adkd() == Adkd::InavTiming {
                    prna_u8
                } else {
                    prnd
                };
                Self::validate_tag(
                    &key,
                    tag.tag(),
                    tag.adkd(),
                    gst_mack,
                    prnd,
                    prna_u8,
                    j,
                    navdata,
                );
            }
        }
    }

    pub fn process_mack_slowmac(
        &mut self,
        mack: Mack<Validated>,
        key: &Key<Validated>,
        prna: usize,
        gst_mack: Gst,
    ) {
        let gst_navmessage = gst_mack.add_seconds(-30);
        let prna_u8 = u8::try_from(prna).unwrap();
        for j in 1..mack.num_tags() {
            let tag = mack.tag_and_info(j);
            if tag.adkd() != Adkd::SlowMac {
                continue;
            }
            let prnd = match u8::try_from(tag.prnd()) {
                Ok(p) => p,
                Err(_) => {
                    log::error!("could not obtain PRND from tag {:?}", tag);
                    continue;
                }
            };
            if let Some(navdata) = self.ced_and_status_as_mut(prnd.into(), gst_navmessage) {
                Self::validate_tag(
                    &key,
                    tag.tag(),
                    tag.adkd(),
                    gst_mack,
                    prnd,
                    prna_u8,
                    j,
                    navdata,
                );
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn validate_tag(
        key: &Key<Validated>,
        tag: &BitSlice,
        adkd: Adkd,
        gst_tag: Gst,
        prnd: u8,
        prna: u8,
        tag_idx: usize,
        navdata: &mut dyn AuthBits,
    ) -> bool {
        let ctr = (tag_idx + 1).try_into().unwrap();
        let ret = match tag_idx {
            0 => key.validate_tag0(tag, gst_tag, prna, navdata.message_bits()),
            _ => key.validate_tag(tag, gst_tag, prnd, prna, ctr, navdata.message_bits()),
        };
        if ret {
            log::info!(
                "E{:02} {:?} at {:?} tag{} correct (auth by E{:02})",
                prnd,
                adkd,
                gst_tag,
                tag_idx,
                prna
            );
            navdata.add_authbits(tag);
        } else {
            log::error!(
                "E{:02} {:?} at {:?} tag{} wrong (auth by E{:02})",
                prnd,
                adkd,
                gst_tag,
                tag_idx,
                prna
            );
        }
        ret
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
    authbits: u16,
}

pub const TIMING_PARAMETERS_BYTES: usize = 21;
const TIMING_PARAMETERS_WORDS: usize = 2;

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
struct TimingParameters {
    data: [u8; TIMING_PARAMETERS_BYTES],
    valid: [bool; TIMING_PARAMETERS_WORDS],
    authbits: u16,
}

trait AuthBits {
    fn message_bits(&self) -> &BitSlice;
    fn add_authbits(&mut self, tag: &BitSlice);
}

macro_rules! impl_common {
    ($s: ident, $data_size: expr, $num_words: expr, $num_bits: expr,
     $($id: ident <= $val: expr),*) => {
        impl $s {
            fn new() -> $s {
                $s {
                    data: [0; $data_size],
                    valid: [false; $num_words],
                    authbits: 0,
                    $($id: $val),*
                }
            }

            // This is required because CedAndStatus::reset is never called
            #[allow(dead_code)]
            fn reset(&mut self) {
                self.valid = [false; $num_words];
                self.authbits = 0;
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

        impl AuthBits for $s {
            fn message_bits(&self) -> &BitSlice {
                &self.bits()[..$num_bits]
            }

            fn add_authbits(&mut self, tag: &BitSlice) {
                self.authbits = self.authbits.saturating_add(tag.len().try_into().unwrap());
            }
        }
    };
}

impl_common!(
    CedAndStatus,
    CED_AND_STATUS_BYTES,
    CED_AND_STATUS_WORDS,
    549,
    stale <= true
);
impl_common!(
    TimingParameters,
    TIMING_PARAMETERS_BYTES,
    TIMING_PARAMETERS_WORDS,
    161,
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
            1 => self.try_copy(0..120, &word[6..126], 0, Some(iodnav)),
            2 => self.try_copy(120..240, &word[6..126], 1, Some(iodnav)),
            3 => self.try_copy(240..362, &word[6..128], 2, Some(iodnav)),
            4 => self.try_copy(362..482, &word[6..126], 3, Some(iodnav)),
            5 => self.try_copy(482..549, &word[6..73], 4, None),
            _ => (),
        };
        log::trace!(
            "CedAndStatus has the following valid words: {:?}",
            self.valid
        );
    }

    fn try_copy(
        &mut self,
        dest_range: core::ops::Range<usize>,
        source: &BitSlice,
        idx: usize,
        iodnav: Option<u16>,
    ) {
        // We mark as not stale regardless of whether we need
        // overwrite with new data or whether the new data is
        // equal to the old.
        self.stale = false;
        let dest = &mut self.bits_as_mut()[dest_range];
        if dest != source {
            dest.copy_from_bitslice(source);
            self.authbits = 0;
            self.valid[idx] = true;
            if let Some(iodnav) = iodnav {
                self.new_iodnav(iodnav);
                assert!(self.valid[idx]);
            }
        }
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
