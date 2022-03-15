use crate::types::{
    Gst, HkrootMessage, HkrootSection, MackMessage, MackSection, OsnmaDataMessage, Tow, Wn,
    HKROOT_MESSAGE_BYTES, HKROOT_SECTION_BYTES, MACK_MESSAGE_BYTES, MACK_SECTION_BYTES, NUM_SVNS,
};

const WORDS_PER_SUBFRAME: u8 = 15;
const SECONDS_PER_SUBFRAME: Tow = 30;

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct CollectSubframe {
    hkroot: [HkrootMessage; NUM_SVNS],
    mack: [MackMessage; NUM_SVNS],
    num_valid: [u8; NUM_SVNS],
    wn: Wn,
    subframe: Tow,
}

impl CollectSubframe {
    pub fn new() -> CollectSubframe {
        CollectSubframe {
            hkroot: [[0; HKROOT_MESSAGE_BYTES]; NUM_SVNS],
            mack: [[0; MACK_MESSAGE_BYTES]; NUM_SVNS],
            num_valid: [0; NUM_SVNS],
            wn: 0,
            subframe: 0,
        }
    }

    pub fn feed(
        &mut self,
        osnma_data: &OsnmaDataMessage,
        wn: Wn,
        tow: Tow,
        svn: usize,
    ) -> Option<(&HkrootMessage, &MackMessage, Gst)> {
        let hkroot_section: HkrootSection = osnma_data[..HKROOT_SECTION_BYTES].try_into().unwrap();
        let mack_section: MackSection = osnma_data[HKROOT_SECTION_BYTES..].try_into().unwrap();
        let word_num = (tow / 2) % Tow::from(WORDS_PER_SUBFRAME);
        log::trace!(
            "feeding hkroot = {:02x?}, mack = {:02x?} for svn = E{:02} (wn = {}, tow = {}, word number = {})",
            hkroot_section,
            mack_section,
            svn,
            wn,
            tow,
            word_num
        );
        let subframe = tow / SECONDS_PER_SUBFRAME;
        if wn != self.wn || subframe != self.subframe {
            log::info!(
                "starting collection of new subframe (wn = {}, tow = {})",
                wn,
                tow
            );
            self.wn = wn;
            self.subframe = subframe;
            for s in 0..NUM_SVNS {
                self.num_valid[s] = 0;
            }
        }
        let svn_idx = svn - 1;
        if word_num != u32::from(self.num_valid[svn_idx]) {
            log::trace!(
                "there are missing words for svn = E{:02} (wn = {}, tow = {}), \
                 word number = {}, valid words = {}",
                svn,
                wn,
                tow,
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
                "completed collection for svn = E{:02} (wn = {}, tow = {})\n\
                 hkroot = {:02x?}\nmack = {:02x?}",
                svn,
                wn,
                tow,
                self.hkroot[svn_idx],
                self.mack[svn_idx],
            );
            Some((
                &self.hkroot[svn_idx],
                &self.mack[svn_idx],
                Gst {
                    wn: self.wn,
                    tow: self.subframe * SECONDS_PER_SUBFRAME,
                },
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
        let svn = 1;
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
            assert!(collector.feed(&data, wn, tow, svn).is_none());
            counter += 1;
        }
        let counter0 = counter;
        // Now we start a new subframe
        let tow2 = tow1 + SECONDS_PER_SUBFRAME;
        for tow in (tow1..tow2).step_by(2) {
            let mut data = [counter; N];
            data[0] ^= 0xff;
            let ret = collector.feed(&data, wn, tow, svn);
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
                let expected = Some((&expected_hkroot, &expected_mack, Gst { wn, tow: tow1 }));
                assert_eq!(ret, expected);
            }
        }
    }
}
