use crate::types::{
    HkrootMessage, HkrootSection, MackMessage, MackSection, OsnmaDataMessage, Tow, Wn,
    HKROOT_MESSAGE_BYTES, HKROOT_SECTION_BYTES, MACK_MESSAGE_BYTES, MACK_SECTION_BYTES,
};

const WORDS_PER_SUBFRAME: u8 = 15;
const SECONDS_PER_SUBFRAME: Tow = 30;
const SVNS: usize = 36;

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct CollectSubframe {
    hkroot: [HkrootMessage; SVNS],
    mack: [MackMessage; SVNS],
    num_valid: [u8; SVNS],
    wn: Wn,
    subframe: Tow,
}

impl CollectSubframe {
    pub fn new() -> CollectSubframe {
        CollectSubframe {
            hkroot: [[0; HKROOT_MESSAGE_BYTES]; SVNS],
            mack: [[0; MACK_MESSAGE_BYTES]; SVNS],
            num_valid: [0; SVNS],
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
    ) -> Option<(&HkrootMessage, &MackMessage)> {
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
            for s in 0..SVNS {
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
            Some((&self.hkroot[svn_idx], &self.mack[svn_idx]))
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
