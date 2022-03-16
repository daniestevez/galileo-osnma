use crate::bitfields::{DsmHeader, DsmKroot, Mack, NmaHeader};
use crate::dsm::CollectDsm;
use crate::gst::Gst;
use crate::mack::MackStorage;
use crate::navmessage::CollectNavMessage;
use crate::subframe::CollectSubframe;
use crate::tesla::Key;
use crate::types::{HkrootMessage, InavWord, MackMessage, OsnmaDataMessage, Validated, NUM_SVNS};

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
                ()
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
            if let (Some(mack), Some(adkd0)) = (
                self.mack.get(svn, gst_tags).map(|m| {
                    Mack::new(
                        m,
                        current_key.chain().key_size_bits(),
                        current_key.chain().tag_size_bits(),
                    )
                }),
                self.navmessage.ced_and_status(svn, gst_navmessage),
            ) {
                let svn_u8 = u8::try_from(svn).unwrap();
                if current_key.validate_tag0(mack.tag0(), gst_tags, svn_u8, adkd0) {
                    log::info!("E{:02} {:?} tag0 correct", svn, gst_tags);
                } else {
                    log::error!("E{:02} {:?} tag0 wrong", svn, gst_tags);
                }
            }
        }
    }
}
