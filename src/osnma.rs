use crate::bitfields::{Adkd, DsmHeader, DsmKroot, Mack, NmaHeader};
use crate::dsm::CollectDsm;
use crate::gst::Gst;
use crate::mack::MackStorage;
use crate::navmessage::CollectNavMessage;
use crate::subframe::CollectSubframe;
use crate::tesla::Key;
use crate::types::{
    BitSlice, HkrootMessage, InavWord, MackMessage, OsnmaDataMessage, Validated, NUM_SVNS,
};

use core::cmp::Ordering;
use p256::ecdsa::VerifyingKey;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Osnma {
    subframe: CollectSubframe,
    data: OsnmaDsm,
}

// These structures exist only in order to avoid double mutable
// borrows of Osnma because we take references from CollectSubframe
// and CollectDsm
#[derive(Debug, Clone, PartialEq, Eq)]
struct OsnmaDsm {
    dsm: CollectDsm,
    data: OsnmaData,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct OsnmaData {
    navmessage: CollectNavMessage,
    mack: MackStorage,
    pubkey: VerifyingKey,
    key: Option<Key<Validated>>,
}

impl Osnma {
    pub fn from_pubkey(pubkey: VerifyingKey) -> Osnma {
        Osnma {
            subframe: CollectSubframe::new(),
            data: OsnmaDsm {
                dsm: CollectDsm::new(),
                data: OsnmaData {
                    navmessage: CollectNavMessage::new(),
                    mack: MackStorage::new(),
                    pubkey,
                    key: None,
                },
            },
        }
    }

    pub fn feed_inav(&mut self, word: &InavWord, svn: usize, gst: Gst) {
        self.data.data.navmessage.feed(word, svn, gst);
    }

    pub fn feed_osnma(&mut self, osnma: &OsnmaDataMessage, svn: usize, gst: Gst) {
        if osnma.iter().all(|&x| x == 0) {
            // No OSNMA data
            return;
        }
        if let Some((hkroot, mack, subframe_gst)) = self.subframe.feed(osnma, svn, gst) {
            self.data.process_subframe(hkroot, mack, svn, subframe_gst);
        }
    }
}

impl OsnmaDsm {
    fn process_subframe(
        &mut self,
        hkroot: &HkrootMessage,
        mack: &MackMessage,
        svn: usize,
        gst: Gst,
    ) {
        self.data.mack.store(mack, svn, gst);

        let nma_header = &hkroot[..1].try_into().unwrap();
        let nma_header = NmaHeader(nma_header);
        let dsm_header = &hkroot[1..2].try_into().unwrap();
        let dsm_header = DsmHeader(dsm_header);
        let dsm_block = &hkroot[2..].try_into().unwrap();
        if let Some(dsm) = self.dsm.feed(dsm_header, dsm_block) {
            self.data.process_dsm(dsm, nma_header);
        }

        self.data.validate_key(mack, gst);
    }
}

impl OsnmaData {
    fn process_dsm(&mut self, dsm: &[u8], nma_header: NmaHeader) {
        // TODO: handle DSM-PKR
        let dsm_kroot = DsmKroot(dsm);
        match Key::from_dsm_kroot(nma_header, dsm_kroot, &self.pubkey) {
            Ok(key) => {
                log::info!("verified KROOT");
                if self.key.is_none() {
                    self.key = Some(key);
                    log::info!("initializing TESLA key to {:?}", key);
                }
            }
            Err(e) => log::error!("could not verify KROOT: {:?}", e),
        }
    }

    fn validate_key(&mut self, mack: &MackMessage, gst: Gst) {
        let current_key = match self.key {
            Some(k) => k,
            None => {
                log::info!("no valid TESLA key yet. unable to validate MACK key");
                return;
            }
        };
        let mack = Mack::new(
            mack,
            current_key.chain().key_size_bits(),
            current_key.chain().tag_size_bits(),
        );
        let new_key = Key::from_bitslice(mack.key(), gst, current_key.chain());
        match current_key.gst_subframe().cmp(&new_key.gst_subframe()) {
            Ordering::Equal => {
                // we already have this key; nothing to do
            }
            Ordering::Greater => {
                log::warn!(
                    "got a key in MACK which is older than our current valid key\
                            MACK key = {:?}, current valid key = {:?}",
                    new_key,
                    current_key
                );
            }
            Ordering::Less => {
                // attempt to validate the new key
                match current_key.validate_key(&new_key) {
                    Ok(new_valid_key) => {
                        log::info!(
                            "new TESLA key {:?} successfully validated by {:?}",
                            new_valid_key,
                            current_key
                        );
                        self.key = Some(new_valid_key);
                        self.process_tags();
                    }
                    Err(e) => log::error!(
                        "could not validate TESLA key {:?} using {:?}: {:?}",
                        new_key,
                        current_key,
                        e
                    ),
                }
            }
        }
    }

    fn process_tags(&mut self) {
        let current_key = match self.key {
            Some(k) => k,
            None => {
                log::info!("no valid TESLA key yet. unable to validate MACK tags");
                return;
            }
        };
        let gst_tags = current_key.gst_subframe().add_seconds(-30);
        let gst_navmessage = gst_tags.add_seconds(-30);
        for svn in 1..=NUM_SVNS {
            let svn_u8 = u8::try_from(svn).unwrap();
            if let Some(mack) = self.mack.get(svn, gst_tags) {
                let mack = Mack::new(
                    mack,
                    current_key.chain().key_size_bits(),
                    current_key.chain().tag_size_bits(),
                );
                // Try to validate tag0
                if let Some(navdata) = self.navmessage.ced_and_status(svn, gst_navmessage) {
                    Self::validate_tag(
                        &current_key,
                        mack.tag0(),
                        Adkd::InavCed,
                        gst_tags,
                        svn_u8,
                        svn_u8,
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
                        Adkd::InavCed => {
                            self.navmessage.ced_and_status(prnd.into(), gst_navmessage)
                        }
                        Adkd::InavTiming => self.navmessage.timing_parameters(gst_navmessage),
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
                            svn_u8
                        } else {
                            prnd
                        };
                        Self::validate_tag(
                            &current_key,
                            tag.tag(),
                            tag.adkd(),
                            gst_tags,
                            prnd,
                            svn_u8,
                            j,
                            navdata,
                        );
                    }
                }
            }

            // Try to validate Slow MAC
            // This needs fetching a tag which is 300 seconds older than for
            // the other ADKDs
            let gst_tag_slowmac = gst_tags.add_seconds(-300);
            if let Some(mack) = self.mack.get(svn, gst_tag_slowmac) {
                let mack = Mack::new(
                    mack,
                    current_key.chain().key_size_bits(),
                    current_key.chain().tag_size_bits(),
                );
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
                    if let Some(navdata) = self
                        .navmessage
                        .ced_and_status(prnd.into(), gst_navmessage.add_seconds(-300))
                    {
                        Self::validate_tag(
                            &current_key,
                            tag.tag(),
                            tag.adkd(),
                            gst_tag_slowmac,
                            prnd,
                            svn_u8,
                            j,
                            navdata,
                        );
                    }
                }
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
        navdata: &BitSlice,
    ) -> bool {
        let ctr = (tag_idx + 1).try_into().unwrap();
        let ret = match tag_idx {
            0 => key.validate_tag0(tag, gst_tag, prna, navdata),
            _ => key.validate_tag(tag, gst_tag, prnd, prna, ctr, navdata),
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
