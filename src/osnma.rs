use crate::bitfields::{DsmHeader, DsmKroot, Mack, NmaHeader};
use crate::dsm::CollectDsm;
use crate::gst::Gst;
use crate::mack::MackStorage;
use crate::navmessage::{CollectNavMessage, NavMessageData};
use crate::subframe::CollectSubframe;
use crate::tesla::Key;
use crate::types::{
    HkrootMessage, InavWord, MackMessage, NotValidated, OsnmaDataMessage, Validated, NUM_SVNS,
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
    only_slowmac: bool,
}

impl Osnma {
    pub fn from_pubkey(pubkey: VerifyingKey, only_slowmac: bool) -> Osnma {
        Osnma {
            subframe: CollectSubframe::new(),
            data: OsnmaDsm {
                dsm: CollectDsm::new(),
                data: OsnmaData {
                    navmessage: CollectNavMessage::new(),
                    mack: MackStorage::new(),
                    pubkey,
                    key: None,
                    only_slowmac,
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

    pub fn get_ced_and_status(&self, svn: usize) -> Option<NavMessageData> {
        self.data.data.navmessage.get_ced_and_status(svn)
    }

    pub fn get_timing_parameters(&self) -> Option<NavMessageData> {
        self.data.data.navmessage.get_timing_parameters()
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
        let gst_mack = current_key.gst_subframe().add_seconds(-30);
        let gst_slowmac = gst_mack.add_seconds(-300);
        // Re-generate the key that was used for the MACSEQ of the
        // Slow MAC MACK
        let slowmac_key = current_key.derive(10);
        for svn in 1..=NUM_SVNS {
            let svn_u8 = u8::try_from(svn).unwrap();
            if !self.only_slowmac {
                if let Some(mack) = self.mack.get(svn, gst_mack) {
                    let mack = Mack::new(
                        mack,
                        current_key.chain().key_size_bits(),
                        current_key.chain().tag_size_bits(),
                    );
                    if let Some(mack) = Self::validate_mack(mack, &current_key, svn_u8, gst_mack) {
                        self.navmessage
                            .process_mack(mack, &current_key, svn, gst_mack);
                    };
                }
            }

            // Try to validate Slow MAC
            // This needs fetching a tag which is 300 seconds older than for
            // the other ADKDs
            if let Some(mack) = self.mack.get(svn, gst_slowmac) {
                let mack = Mack::new(
                    mack,
                    current_key.chain().key_size_bits(),
                    current_key.chain().tag_size_bits(),
                );
                // Note that slowmac_key is used for validation of the MACK, while
                // current_key is used for validation of the Slow MAC tags it contains.
                if let Some(mack) = Self::validate_mack(mack, &slowmac_key, svn_u8, gst_slowmac) {
                    self.navmessage
                        .process_mack_slowmac(mack, &current_key, svn, gst_slowmac);
                }
            }
        }
    }

    fn validate_mack<'a>(
        mack: Mack<'a, NotValidated>,
        key: &Key<Validated>,
        prna: u8,
        gst_mack: Gst,
    ) -> Option<Mack<'a, Validated>> {
        match mack.validate(key, prna.into(), gst_mack) {
            Err(e) => {
                log::error!("error validating MACK {:?}: {:?}", mack, e);
                None
            }
            Ok(m) => Some(m),
        }
    }
}
