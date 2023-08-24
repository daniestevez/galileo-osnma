//! Navigation message storage and handling.
//!
//! This module contains the [`CollectNavMessage`] struct, which is used to
//! classify and store navigation message data. This is used internally by
//! the [`Osnma`](crate::Osnma) black box, but it can also be used directly
//! if finer control is needed.

use crate::bitfields::{Adkd, Mack};
use crate::storage::StaticStorage;
use crate::tesla::Key;
use crate::types::{BitSlice, InavBand, InavWord};
use crate::validation::Validated;
use crate::{Gst, Svn};
use bitvec::prelude::*;
use generic_array::GenericArray;
use typenum::Unsigned;

// Minimum equivalent tag for authentication. Currently defined as 80 bits
const MIN_AUTHBITS: u16 = 80;

/// Navigation message store.
///
/// This struct is used to store and classify the navigation message data, and
/// to authenticate it using MACK tags and their corresponding TESLA keys.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct CollectNavMessage<S: StaticStorage> {
    ced_and_status: GenericArray<CedAndStatus, S::NavMessageDepthSats>,
    timing_parameters: GenericArray<TimingParameters, S::NavMessageDepthSats>,
    gsts: GenericArray<Option<Gst>, S::NavMessageDepth>,
    write_pointer: usize,
}

/// Authenticated navigation message data.
///
/// Gives access to some piece of navigation message data that has been
/// successfully authenticated with OSNMA. This struct refers to data
/// that is owned by a [`CollectNavMessage`].
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct NavMessageData<'a> {
    data: &'a BitSlice,
    authbits: u16,
    gst: Gst,
}

impl<'a> NavMessageData<'a> {
    /// Returns the navigation data as a `BitSlice`.
    pub fn data(&'_ self) -> &'a BitSlice {
        self.data
    }

    /// Returns the number of authentication bits corresponding to this data.
    ///
    /// This indicates the sum of the length in bits of all the tags that have
    /// authenticated this message.
    pub fn authbits(&self) -> u16 {
        self.authbits
    }

    /// Returns the GST that corresponds to this navigation data.
    ///
    /// The GST is defined as the starting GST of the subframe where this
    /// navigation data was transmitted.
    pub fn gst(&self) -> Gst {
        self.gst
    }
}

impl<S: StaticStorage> CollectNavMessage<S> {
    /// Constructs a new, empty navigation message storage.
    pub fn new() -> CollectNavMessage<S> {
        CollectNavMessage {
            ced_and_status: GenericArray::default(),
            timing_parameters: GenericArray::default(),
            gsts: GenericArray::default(),
            write_pointer: 0,
        }
    }

    /// Feed an INAV word into the navigation message storage.
    ///
    /// The `svn` parameter corresponds to the SVN of the satellite transmitting
    /// the INAV word. This should be obtained from the PRN used for tracking.
    ///
    /// The `gst` parameter gives the GST at the start of the INAV page transmission.
    ///
    /// The `band` parameter indicates the band in which the INAV word was received.
    pub fn feed(&mut self, word: &InavWord, svn: Svn, gst: Gst, band: InavBand) {
        log::trace!(
            "feeding INAV word = {:02x?} for {} GST {:?}",
            word,
            svn,
            gst
        );
        let gst = gst.gst_subframe();
        self.adjust_write_pointer(gst);

        // CED
        //
        // Search for best location to place this SVN
        let ced = self
            .current_ced_as_mut()
            .iter_mut()
            .max_by_key(|x| match x.svn {
                Some(s) if s == svn => u16::from(u8::MAX) + 2,
                None => u16::from(u8::MAX) + 1,
                _ => u16::from(x.max_age()),
            })
            .unwrap();
        log::trace!(
            "selected CED store with SVN {:?} and age {}",
            ced.svn,
            ced.max_age()
        );
        ced.feed(word, svn);

        // Timing parameters
        //
        // Search for best location to place this SVN
        let timing_parameters = self
            .current_timing_parameters_as_mut()
            .iter_mut()
            .max_by_key(|x| match x.svn {
                Some(s) if s == svn => u16::from(u8::MAX) + 2,
                None => u16::from(u8::MAX) + 1,
                _ => u16::from(x.max_age()),
            })
            .unwrap();
        log::trace!(
            "selected timing parameters store with SVN {:?} and age {}",
            timing_parameters.svn,
            timing_parameters.max_age(),
        );
        timing_parameters.feed(word, svn, band);
    }

    fn adjust_write_pointer(&mut self, gst: Gst) {
        // If write pointer points to a valid GST which is distinct from the
        // current, we advance the write pointer and copy the old CED and status
        // and timing parameters to the new write pointer location. We increase
        // the stale counter of the copy.
        if let Some(g) = self.gsts[self.write_pointer] {
            if g != gst {
                log::trace!(
                    "got a new GST {:?} (current GST is {:?}); \
                     advancing write pointer",
                    gst,
                    g
                );
                let new_pointer = (self.write_pointer + 1) % S::NavMessageDepth::USIZE;
                self.ced_and_status.copy_within(
                    self.write_pointer * S::NUM_SATS..(self.write_pointer + 1) * S::NUM_SATS,
                    new_pointer * S::NUM_SATS,
                );
                self.timing_parameters.copy_within(
                    self.write_pointer * S::NUM_SATS..(self.write_pointer + 1) * S::NUM_SATS,
                    new_pointer * S::NUM_SATS,
                );
                self.write_pointer = new_pointer;
                self.increase_age();
                if log::log_enabled!(log::Level::Debug) {
                    log::debug!("advanced write pointer to {:?}", gst);
                    log::debug!("CedAndStatus contents:");
                    for elem in self.ced_and_status
                        [self.write_pointer * S::NUM_SATS..(self.write_pointer + 1) * S::NUM_SATS]
                        .iter()
                    {
                        log::debug!(
                            "SVN {:?}: age {:?} authbits {}",
                            elem.svn,
                            elem.age,
                            elem.authbits
                        );
                    }
                    log::debug!("TimingParameters contents:");
                    for elem in self.timing_parameters
                        [self.write_pointer * S::NUM_SATS..(self.write_pointer + 1) * S::NUM_SATS]
                        .iter()
                    {
                        log::debug!(
                            "SVN {:?}: age {:?} authbits {}",
                            elem.svn,
                            elem.age,
                            elem.authbits
                        );
                    }
                }
            }
        }
        self.gsts[self.write_pointer] = Some(gst);
    }

    fn current_ced_as_mut(&mut self) -> &mut [CedAndStatus] {
        &mut self.ced_and_status
            [self.write_pointer * S::NUM_SATS..(self.write_pointer + 1) * S::NUM_SATS]
    }

    fn current_timing_parameters_as_mut(&mut self) -> &mut [TimingParameters] {
        &mut self.timing_parameters
            [self.write_pointer * S::NUM_SATS..(self.write_pointer + 1) * S::NUM_SATS]
    }

    fn increase_age(&mut self) {
        for ced in self.current_ced_as_mut().iter_mut() {
            for age in ced.age.iter_mut() {
                *age = age.saturating_add(1);
            }
        }
        for timing_parameters in self.current_timing_parameters_as_mut().iter_mut() {
            for age in timing_parameters.age.iter_mut() {
                *age = age.saturating_add(1);
            }
        }
    }

    /// Try to get authenticated CED and health status data for a satellite.
    ///
    /// This will try to retrieve the most recent authenticated CED and health
    /// status data (ADKD=0 and 12) for the satellite with SVN `svn` that is
    /// available in the OSNMA storage. If the storage does not contain any
    /// authenticated CED and health status data for this SVN, this returns
    /// `None`.
    pub fn get_ced_and_status(&self, svn: Svn) -> Option<NavMessageData> {
        // Search in order of decreasing Gst
        for j in 0..S::NavMessageDepth::USIZE {
            let gst_idx =
                (S::NavMessageDepth::USIZE + self.write_pointer - j) % S::NavMessageDepth::USIZE;
            for item in
                self.ced_and_status[gst_idx * S::NUM_SATS..(gst_idx + 1) * S::NUM_SATS].iter()
            {
                if item.svn == Some(svn) && item.authbits >= MIN_AUTHBITS {
                    return Some(NavMessageData {
                        data: item.message_bits(),
                        authbits: item.authbits,
                        gst: self.gsts[gst_idx].unwrap(),
                    });
                }
            }
        }
        None
    }

    /// Try to get authenticated timing parameters for a satellite.
    ///
    /// This will try to retrieve the most recent timing parameters data
    /// (ADKD=4) for the satellite with SNV`svn` that is available in the OSNMA
    /// storage. If the storage does not contain any authenticated timing
    /// parameters data for this SVN, this returns `None`.
    pub fn get_timing_parameters(&self, svn: Svn) -> Option<NavMessageData> {
        // Search in order of decreasing Gst
        for j in 0..S::NavMessageDepth::USIZE {
            let gst_idx =
                (S::NavMessageDepth::USIZE + self.write_pointer - j) % S::NavMessageDepth::USIZE;
            for item in
                self.timing_parameters[gst_idx * S::NUM_SATS..(gst_idx + 1) * S::NUM_SATS].iter()
            {
                if item.svn == Some(svn) && item.authbits >= MIN_AUTHBITS {
                    return Some(NavMessageData {
                        data: item.message_bits(),
                        authbits: item.authbits,
                        gst: self.gsts[gst_idx].unwrap(),
                    });
                }
            }
        }
        None
    }

    fn find_ced_and_status(&mut self, svn: Svn, gst: Gst) -> Option<&CedAndStatus> {
        let gst_idx = self.find_gst(gst)?;
        self.ced_and_status[gst_idx * S::NUM_SATS..(gst_idx + 1) * S::NUM_SATS]
            .iter()
            .find(|item| item.svn == Some(svn))
    }

    fn find_timing_parameters(&mut self, svn: Svn, gst: Gst) -> Option<&TimingParameters> {
        let gst_idx = self.find_gst(gst)?;
        self.timing_parameters[gst_idx * S::NUM_SATS..(gst_idx + 1) * S::NUM_SATS]
            .iter()
            .find(|item| item.svn == Some(svn))
    }

    fn ced_and_status_iter_authbits_mut(&mut self) -> impl Iterator<Item = &mut dyn AuthBits> {
        self.ced_and_status.iter_mut().map(|x| {
            let y: &mut dyn AuthBits = x;
            y
        })
    }

    fn timing_parameters_iter_authbits_mut(&mut self) -> impl Iterator<Item = &mut dyn AuthBits> {
        self.timing_parameters.iter_mut().map(|x| {
            let y: &mut dyn AuthBits = x;
            y
        })
    }

    fn find_gst(&self, gst: Gst) -> Option<usize> {
        assert!(gst.is_subframe());
        self.gsts
            .iter()
            .enumerate()
            .find_map(|(j, &g)| if g == Some(gst) { Some(j) } else { None })
    }

    /// Process a MACK message.
    ///
    /// This processes a MACK message, authenticating stored navigation data as
    /// possible. The `key` should be the TESLA key with which the tags in the
    /// MACK message `mack` have been generated (recall that this key is
    /// transmitted in the next subframe with respect to the MACK message). The
    /// `prna` is the authenticating PRN, which is the SVN that has transmitted
    /// the MACK message. The `gst_mack` parameter should be the GST
    /// corresponding to the start of the subframe when the MACK message was
    /// transmitted.
    ///
    /// This function ignores the ADKD=12 (Slow MAC) tags in the MACK message,
    /// since they do not correspond to `key`.
    pub fn process_mack(
        &mut self,
        mack: Mack<Validated>,
        key: &Key<Validated>,
        prna: Svn,
        gst_mack: Gst,
    ) {
        log::info!("{} tag0 at {:?} COP = {}", prna, gst_mack, mack.cop());
        let gst_navmessage = gst_mack.add_seconds(-30);
        if mack.cop() == 0 {
            log::warn!("COP = 0 validation not implemented");
        } else if let Some(&navdata) = self.find_ced_and_status(prna, gst_navmessage) {
            if navdata.max_age().saturating_add(1) <= mack.cop() {
                // Try to validate tag0
                Self::validate_tag(
                    key,
                    mack.tag0(),
                    Adkd::InavCed,
                    gst_mack,
                    u8::from(prna),
                    prna,
                    0,
                    &navdata,
                    self.ced_and_status_iter_authbits_mut(),
                );
            }
        }

        // Try to validate InavCed and InavTiming tags
        for j in 1..mack.num_tags() {
            let tag = mack.tag_and_info(j);
            log::info!(
                "{} tag{} {:?} at {:?} COP = {} PRND = {:?}",
                prna,
                j,
                tag.adkd(),
                gst_mack,
                tag.cop(),
                tag.prnd()
            );
            if tag.cop() == 0 {
                log::warn!("COP = 0 validation not implemented");
                continue;
            }
            let prnd = match u8::try_from(tag.prnd()) {
                Ok(p) => p,
                Err(_) => {
                    log::error!("could not obtain PRND from tag {:?}", tag);
                    continue;
                }
            };
            match tag.adkd() {
                Adkd::InavCed => match Svn::try_from(prnd) {
                    Ok(prnd_svn) => {
                        if let Some(&navdata) = self.find_ced_and_status(prnd_svn, gst_navmessage) {
                            if navdata.max_age().saturating_add(1) <= tag.cop() {
                                Self::validate_tag(
                                    key,
                                    tag.tag(),
                                    tag.adkd(),
                                    gst_mack,
                                    prnd,
                                    prna,
                                    j,
                                    &navdata,
                                    self.ced_and_status_iter_authbits_mut(),
                                );
                            }
                        }
                    }
                    Err(_) => {
                        log::error!("invalid PRND {:?} for ADKD {:?}", tag.prnd(), tag.adkd());
                    }
                },
                Adkd::InavTiming => match Svn::try_from(prnd) {
                    Ok(prnd_svn) => {
                        if let Some(&navdata) =
                            self.find_timing_parameters(prnd_svn, gst_navmessage)
                        {
                            if navdata.max_age().saturating_add(1) <= tag.cop() {
                                Self::validate_tag(
                                    key,
                                    tag.tag(),
                                    tag.adkd(),
                                    gst_mack,
                                    prnd,
                                    prna,
                                    j,
                                    &navdata,
                                    self.timing_parameters_iter_authbits_mut(),
                                );
                            }
                        }
                    }
                    Err(_) => {
                        log::error!("invalid PRND {:?} for ADKD {:?}", tag.prnd(), tag.adkd());
                    }
                },
                Adkd::SlowMac => {
                    // Slow MAC is not processed here, because the key doesn't
                    // have the appropriate extra delay
                }
                Adkd::Reserved => {
                    log::error!("reserved ADKD in tag {:?}", tag);
                }
            }
        }
    }

    /// Process the Slow MAC (ADKD=12) tags in a MACK message.
    ///
    /// This processes a MACK message, authenticating stored navigation data as
    /// possible using the Slow MAC tags. The `key` should be the TESLA key with
    /// which the Slow MAC tags in the MACK message `mack` have been generated
    /// (recall that this key is transmitted 11 subframes after the MACK
    /// message). The `prna` is the authenticating PRN, which is the SVN that
    /// has transmitted the MACK message. The `gst_mack` parameter should be the
    /// GST corresponding to the start of the subframe when the MACK message was
    /// transmitted.
    ///
    /// This function ignores all the other tags in the MACK message, since they
    /// do not correspond to `key`.
    pub fn process_mack_slowmac(
        &mut self,
        mack: Mack<Validated>,
        key: &Key<Validated>,
        prna: Svn,
        gst_mack: Gst,
    ) {
        let gst_navmessage = gst_mack.add_seconds(-30);
        for j in 1..mack.num_tags() {
            let tag = mack.tag_and_info(j);
            if tag.adkd() != Adkd::SlowMac {
                continue;
            }
            if tag.cop() == 0 {
                log::warn!("COP = 0 validation not implemented");
            }
            let prnd = match u8::try_from(tag.prnd()) {
                Ok(p) => p,
                Err(_) => {
                    log::error!("could not obtain PRND from tag {:?}", tag);
                    continue;
                }
            };
            let prnd_svn = match Svn::try_from(prnd) {
                Ok(s) => s,
                Err(_) => {
                    log::error!("invalid PRND {:?} for Slow MAC tag {:?}", tag.prnd(), tag);
                    continue;
                }
            };
            if let Some(&navdata) = self.find_ced_and_status(prnd_svn, gst_navmessage) {
                if navdata.max_age().saturating_add(1) <= tag.cop() {
                    Self::validate_tag(
                        key,
                        tag.tag(),
                        tag.adkd(),
                        gst_mack,
                        prnd,
                        prna,
                        j,
                        &navdata,
                        self.ced_and_status_iter_authbits_mut(),
                    );
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn validate_tag<'a>(
        key: &Key<Validated>,
        tag: &BitSlice,
        adkd: Adkd,
        gst_tag: Gst,
        prnd: u8,
        prna: Svn,
        tag_idx: usize,
        navdata: &dyn AuthBits,
        to_add_authbits: impl Iterator<Item = &'a mut dyn AuthBits>,
    ) -> bool {
        let ctr = (tag_idx + 1).try_into().unwrap();
        let ret = match tag_idx {
            0 => key.validate_tag0(tag, gst_tag, prna, navdata.message_bits()),
            _ => key.validate_tag(tag, gst_tag, prnd, prna, ctr, navdata.message_bits()),
        };
        if ret {
            log::info!(
                "E{:02} {:?} at {:?} tag{} correct (auth by {})",
                prnd,
                adkd,
                gst_tag,
                tag_idx,
                prna
            );
            for to_add in to_add_authbits {
                if navdata.svn() == to_add.svn() && navdata.message_bits() == to_add.message_bits()
                {
                    to_add.add_authbits(tag);
                }
            }
        } else {
            log::error!(
                "E{:02} {:?} at {:?} tag{} wrong (auth by {})",
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

impl<S: StaticStorage> Default for CollectNavMessage<S> {
    fn default() -> CollectNavMessage<S> {
        CollectNavMessage::new()
    }
}

const CED_AND_STATUS_BYTES: usize = 69;
const CED_AND_STATUS_WORDS: usize = 5;

#[doc(hidden)]
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
// This is pub only because it appears in the definition of StaticStorageTypenum
pub struct CedAndStatus {
    data: [u8; CED_AND_STATUS_BYTES],
    age: [u8; CED_AND_STATUS_WORDS],
    svn: Option<Svn>,
    authbits: u16,
}

const TIMING_PARAMETERS_BYTES: usize = 18;
const TIMING_PARAMETERS_WORDS: usize = 2;

#[doc(hidden)]
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
// This is pub only because it appears in the definition of StaticStorageTypenum
pub struct TimingParameters {
    data: [u8; TIMING_PARAMETERS_BYTES],
    age: [u8; TIMING_PARAMETERS_WORDS],
    svn: Option<Svn>,
    authbits: u16,
}

trait AuthBits {
    fn svn(&self) -> Option<Svn>;
    fn message_bits(&self) -> &BitSlice;
    fn add_authbits(&mut self, tag: &BitSlice);
}

macro_rules! impl_common {
    ($s:ident, $data_size:expr, $num_words:expr, $num_bits:expr) => {
        impl $s {
            fn new() -> $s {
                $s {
                    data: [0; $data_size],
                    age: [u8::MAX; $num_words],
                    authbits: 0,
                    svn: None,
                }
            }

            fn reset(&mut self) {
                self.age.fill(u8::MAX);
                self.authbits = 0;
                self.svn = None;
            }

            fn bits(&self) -> &BitSlice {
                BitSlice::from_slice(&self.data)
            }

            fn bits_as_mut(&mut self) -> &mut BitSlice {
                BitSlice::from_slice_mut(&mut self.data)
            }

            fn max_age(&self) -> u8 {
                self.age.iter().copied().max().unwrap()
            }

            fn copy_word(
                &mut self,
                dest_range: core::ops::Range<usize>,
                source: &BitSlice,
                idx: usize,
            ) {
                self.age[idx] = 0;
                let dest = &mut self.bits_as_mut()[dest_range];
                if dest != source {
                    dest.copy_from_bitslice(source);
                    self.authbits = 0;
                }
            }

            fn log_word(&self, word_type: u8) {
                log::trace!(
                    concat!(stringify!($s), " storing INAV word type {} for {}"),
                    self.svn.unwrap(),
                    word_type
                );
            }

            fn log_age(&self) {
                log::trace!(
                    concat!(stringify!($s), " for {} age: {:?}"),
                    self.svn.unwrap(),
                    &self.age
                );
            }
        }

        impl AuthBits for $s {
            fn svn(&self) -> Option<Svn> {
                self.svn
            }

            fn message_bits(&self) -> &BitSlice {
                &self.bits()[..$num_bits]
            }

            fn add_authbits(&mut self, tag: &BitSlice) {
                self.authbits = self.authbits.saturating_add(tag.len().try_into().unwrap());
            }
        }

        impl Default for $s {
            fn default() -> Self {
                Self::new()
            }
        }
    };
}

impl_common!(
    CedAndStatus,
    CED_AND_STATUS_BYTES,
    CED_AND_STATUS_WORDS,
    549
);
impl_common!(
    TimingParameters,
    TIMING_PARAMETERS_BYTES,
    TIMING_PARAMETERS_WORDS,
    141
);

impl CedAndStatus {
    fn feed(&mut self, word: &InavWord, svn: Svn) {
        match self.svn {
            Some(s) if s == svn => (),
            None => self.svn = Some(svn),
            _ => {
                self.reset();
                self.svn = Some(svn);
            }
        };

        let word = BitSlice::from_slice(word);
        let word_type = word[..6].load_be::<u8>();
        if (1..=5).contains(&word_type) {
            self.log_word(word_type);
        }
        match word_type {
            1 => self.copy_word(0..120, &word[6..126], 0),
            2 => self.copy_word(120..240, &word[6..126], 1),
            3 => self.copy_word(240..362, &word[6..128], 2),
            4 => self.copy_word(362..482, &word[6..126], 3),
            5 => self.copy_word(482..549, &word[6..73], 4),
            _ => (),
        };
        self.log_age();
    }
}

impl TimingParameters {
    fn feed(&mut self, word: &InavWord, svn: Svn, band: InavBand) {
        match self.svn {
            Some(s) if s == svn => (),
            None => self.svn = Some(svn),
            _ => {
                self.reset();
                self.svn = Some(svn);
            }
        };

        let word = BitSlice::from_slice(word);
        let word_type = word[..6].load_be::<u8>();
        match (word_type, band) {
            (6, InavBand::E1B) => {
                self.log_word(word_type);
                self.copy_word(0..99, &word[6..105], 0);
            }
            (10, InavBand::E1B) => {
                self.log_word(word_type);
                self.copy_word(99..141, &word[86..128], 1);
            }
            _ => (),
        }
        self.log_age();
    }
}
