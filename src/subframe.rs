//! Subframe collection.
//!
//! This module contains the [`CollectSubframe`] struct, which is used to
//! collect all the OSNMA data messages in a particular subframe in order to
//! recompose the HKROOT and MACK messages of that subframe.
//!
//! The data for the 36 satellites in the Galileo constellation is collected in
//! parallel.

use crate::types::{
    HkrootMessage, HkrootSection, MackMessage, MackSection, OsnmaDataMessage, HKROOT_MESSAGE_BYTES,
    HKROOT_SECTION_BYTES, MACK_MESSAGE_BYTES, MACK_SECTION_BYTES, NUM_SVNS,
};
use crate::{Gst, Svn, Tow, Wn};

const WORDS_PER_SUBFRAME: u8 = 15;
const SECONDS_PER_SUBFRAME: Tow = 30;

/// Subframe collector.
///
/// This struct collects HKROOT and MACK sections from the OSNMA data in INAV
/// words and produces the complete HKROOT and MACK messages transmitted in that
/// subframe.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct CollectSubframe {
    hkroot: [HkrootMessage; NUM_SVNS],
    mack: [MackMessage; NUM_SVNS],
    num_valid: [u8; NUM_SVNS],
    wn: Wn,
    subframe: Tow,
}

impl CollectSubframe {
    /// Constructs a new, empty subframe collector.
    pub fn new() -> CollectSubframe {
        CollectSubframe {
            hkroot: [[0; HKROOT_MESSAGE_BYTES]; NUM_SVNS],
            mack: [[0; MACK_MESSAGE_BYTES]; NUM_SVNS],
            num_valid: [0; NUM_SVNS],
            wn: 0,
            subframe: 0,
        }
    }

    /// Feed a new OSNMA data message into the subframe collector.
    ///
    /// If this data message completes the HKROOT and MACK message, the
    /// corresponding messages, together with the GST at the start of the
    /// subframe are returned. Otherwise, this returns `None`.
    ///
    /// The `svn` parameter corresponds to the SVN of the satellite transmitting
    /// the INAV word. This should be obtained from the PRN used for tracking.
    ///
    /// The `gst` parameter gives the GST at the start of the INAV page
    /// transmission. It the `gst` corresponds to a new subframe, the data for
    /// the old subframe is discarded, and collection of data for a new subframe
    /// begins. This assumes that the OSNMA data for different satellites is fed
    /// in chronological order.
    pub fn feed(
        &mut self,
        osnma_data: &OsnmaDataMessage,
        svn: Svn,
        gst: Gst,
    ) -> Option<(&HkrootMessage, &MackMessage, Gst)> {
        let hkroot_section: HkrootSection = osnma_data[..HKROOT_SECTION_BYTES].try_into().unwrap();
        let mack_section: MackSection = osnma_data[HKROOT_SECTION_BYTES..].try_into().unwrap();
        let word_num = (gst.tow() / 2) % Tow::from(WORDS_PER_SUBFRAME);
        log::trace!(
            "feeding hkroot = {:02x?}, mack = {:02x?} for {} (GST = {:?}, word number = {})",
            hkroot_section,
            mack_section,
            svn,
            gst,
            word_num
        );
        let subframe = gst.tow() / SECONDS_PER_SUBFRAME;
        if gst.wn() != self.wn || subframe != self.subframe {
            log::debug!("valid sections per SVN: {:?}", &self.num_valid);
            log::info!("starting collection of new subframe (GST {:?})", gst);
            self.wn = gst.wn();
            self.subframe = subframe;
            for s in 0..NUM_SVNS {
                self.num_valid[s] = 0;
            }
        }
        let svn_idx = usize::from(svn) - 1;
        if word_num != u32::from(self.num_valid[svn_idx]) {
            log::trace!(
                "there are missing words for {} (GST {:?}), \
                 word number = {}, valid words = {}",
                svn,
                gst,
                word_num,
                self.num_valid[svn_idx]
            );
            return None;
        }
        let valid = usize::from(self.num_valid[svn_idx]);
        let hkroot_idx = valid * HKROOT_SECTION_BYTES;
        let mack_idx = valid * MACK_SECTION_BYTES;
        self.hkroot[svn_idx][hkroot_idx..hkroot_idx + HKROOT_SECTION_BYTES]
            .copy_from_slice(&hkroot_section);
        self.mack[svn_idx][mack_idx..mack_idx + MACK_SECTION_BYTES].copy_from_slice(&mack_section);
        self.num_valid[svn_idx] += 1;
        if self.num_valid[svn_idx] == WORDS_PER_SUBFRAME {
            log::trace!(
                "completed collection for {} (GST {:?})\n\
                 hkroot = {:02x?}\nmack = {:02x?}",
                svn,
                gst,
                self.hkroot[svn_idx],
                self.mack[svn_idx],
            );
            Some((
                &self.hkroot[svn_idx],
                &self.mack[svn_idx],
                Gst::new(self.wn, self.subframe * SECONDS_PER_SUBFRAME),
            ))
        } else {
            None
        }
    }
}

impl Default for CollectSubframe {
    fn default() -> CollectSubframe {
        CollectSubframe::new()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn collect() {
        // This test starts delivering data for a CollectSubframe for a single
        // satellite at some point already inside a subframe. Then it continues
        // until one full subframe is delivered. The test checks the return value
        // of CollectSubframe::feed every time it is called.
        //
        // The data that is supplied as part of the HKROOT section and MACK
        // section is different each time, so that we can check that the data
        // has been assembled correctly into the HKROOT and MACK messages.
        let svn = Svn::try_from(1).unwrap();
        let wn = 1234;
        let mut collector = CollectSubframe::new();

        // Start delivering data 5 seconds into the subframe
        let delta = 5;
        let tow0 = 123 * SECONDS_PER_SUBFRAME + delta;
        let tow1 = tow0 + (SECONDS_PER_SUBFRAME) - delta;
        let mut counter = 0;
        const N: usize = HKROOT_SECTION_BYTES + MACK_SECTION_BYTES;
        for tow in (tow0..tow1).step_by(2) {
            let mut data = [counter; N];
            data[0] ^= 0xff;
            assert!(collector.feed(&data, svn, Gst::new(wn, tow)).is_none());
            counter += 1;
        }
        let counter0 = counter;
        // Now we start a new subframe
        let tow2 = tow1 + SECONDS_PER_SUBFRAME;
        for tow in (tow1..tow2).step_by(2) {
            let mut data = [counter; N];
            data[0] ^= 0xff;
            let ret = collector.feed(&data, svn, Gst::new(wn, tow));
            counter += 1;
            if tow != tow2 - 2 {
                assert!(ret.is_none())
            } else {
                let mut expected_hkroot = Vec::new();
                let mut expected_mack = Vec::new();
                for j in 0..WORDS_PER_SUBFRAME {
                    let a = counter0 + j;
                    expected_hkroot.extend_from_slice(&[a ^ 0xff; HKROOT_SECTION_BYTES]);
                    expected_mack.extend_from_slice(&[a; MACK_SECTION_BYTES]);
                }
                let expected_hkroot: HkrootMessage = expected_hkroot[..].try_into().unwrap();
                let expected_mack: MackMessage = expected_mack[..].try_into().unwrap();
                let expected = Some((&expected_hkroot, &expected_mack, Gst::new(wn, tow1)));
                assert_eq!(ret, expected);
            }
        }
    }
}
