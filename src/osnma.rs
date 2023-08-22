use crate::bitfields::{DsmHeader, DsmKroot, Mack, NmaHeader};
use crate::dsm::CollectDsm;
use crate::mack::MackStorage;
use crate::navmessage::{CollectNavMessage, NavMessageData};
use crate::storage::StaticStorage;
use crate::subframe::CollectSubframe;
use crate::tesla::Key;
use crate::types::{HkrootMessage, InavBand, InavWord, MackMessage, OsnmaDataMessage};
use crate::validation::{NotValidated, Validated};
use crate::{Gst, Svn};

use core::cmp::Ordering;
use p256::ecdsa::VerifyingKey;

/// OSNMA "black box" processing.
///
/// The [`Osnma`] struct gives a way to process OSNMA data using a "black box"
/// approach. INAV words and OSNMA data retrieved from the E1B and E5b signals
/// is fed by the user into `Osnma`, and at any point the user can request
/// `Osnma` to give the most recent authenticated navigation data (provided that
/// it is available).
///
/// # Examples
///
/// ```
/// use galileo_osnma::{Gst, InavBand, Osnma, Svn};
/// use galileo_osnma::storage::FullStorage;
/// use p256::ecdsa::VerifyingKey;
///
/// // Typically, the ECDSA public key should be obtained from
/// // a file. Here a statically defined dummy key is used for
/// // the sake of the example.
/// let pubkey = [3, 154, 36, 205, 5, 122, 110, 166, 187, 238, 33,
///               117, 116, 91, 202, 57, 34, 72, 200, 202, 10, 169,
///               253, 225, 1, 233, 82, 99, 133, 255, 241, 114, 218];
/// let pubkey = VerifyingKey::from_sec1_bytes(&pubkey).unwrap();
///
/// // Create OSNMA black box using full storage (36 satellites and
/// // large enough history for Slow MAC)
/// let only_slowmac = false; // process "fast" MAC as well as Slow MAC
/// let mut osnma = Osnma::<FullStorage>::from_pubkey(pubkey, only_slowmac);
///
/// // Feed some INAV and OSNMA data. Data full of zeros is used here.
/// let svn = Svn::try_from(12).unwrap(); // E12
/// let gst = Gst::new(1177, 175767); // WN 1177, TOW 175767
/// let band = InavBand::E1B;
/// let inav = [0; 16];
/// let osnma_data = [0; 5];
/// osnma.feed_inav(&inav, svn, gst, band);
/// osnma.feed_osnma(&osnma_data, svn, gst);
///
/// // Try to retrieve authenticated data
/// // ADKD=0 and 12, CED and health status for a satellite
/// let ced = osnma.get_ced_and_status(svn);
/// // ADKD=4, Galileo constellation timing parameters
/// let timing = osnma.get_timing_parameters();
/// ```
///
/// # Storage size
///
/// The size of the internal storage used to hold navigation data and MACK
/// messages is defined by the [`StaticStorage`] type parameter `S`. See the
/// [storage](crate::storage) module for a description of how the storage size
/// is defined.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Osnma<S: StaticStorage> {
    subframe: CollectSubframe,
    data: OsnmaDsm<S>,
}

// These structures exist only in order to avoid double mutable
// borrows of Osnma because we take references from CollectSubframe
// and CollectDsm
#[derive(Debug, Clone, PartialEq, Eq)]
struct OsnmaDsm<S: StaticStorage> {
    dsm: CollectDsm,
    data: OsnmaData<S>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct OsnmaData<S: StaticStorage> {
    navmessage: CollectNavMessage<S>,
    mack: MackStorage<S>,
    pubkey: VerifyingKey,
    key: Option<Key<Validated>>,
    only_slowmac: bool,
}

impl<S: StaticStorage> Osnma<S> {
    /// Constructs a new OSNMA black box using an ECDSA P-256 public key.
    ///
    /// The OSNMA black box will hold the public key `pubkey` and use it to
    /// try to authenticate the TESLA root key. The public key cannot be changed
    /// after construction.
    ///
    /// If `only_slowmac` is `true`, only ADKD=12 (Slow MAC) will be processed.
    /// This should be used by receivers which have a larger time uncertainty.
    /// (See Annex 3 in the
    /// [OSNMA Receiver Guidelines](https://www.gsc-europa.eu/sites/default/files/sites/all/files/Galileo_OSNMA_Receiver_Guidelines_for_Test_Phase_v1.0.pdf)).
    pub fn from_pubkey(pubkey: VerifyingKey, only_slowmac: bool) -> Osnma<S> {
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

    /// Feed an INAV word into the OSNMA black box.
    ///
    /// The black box will store the navigation data in the INAV word for later
    /// usage.
    ///
    /// The `svn` parameter corresponds to the SVN of the satellite transmitting
    /// the INAV word. This should be obtained from the PRN used for tracking.
    ///
    /// The `gst` parameter gives the GST at the start of the INAV page transmission.
    ///
    /// The `band` parameter indicates the band in which the INAV word was received.
    pub fn feed_inav(&mut self, word: &InavWord, svn: Svn, gst: Gst, band: InavBand) {
        self.data.data.navmessage.feed(word, svn, gst, band);
    }

    /// Feed the OSNMA data message from an INAV page into the OSNMA black box.
    ///
    /// The black box will store the data and potentially trigger any new
    /// cryptographic checks that this data makes possible.
    ///
    /// The `svn` parameter corresponds to the SVN of the satellite transmitting
    /// the INAV word. This should be obtained from the PRN used for tracking.
    ///
    /// The `gst` parameter gives the GST at the start of the INAV page transmission.
    pub fn feed_osnma(&mut self, osnma: &OsnmaDataMessage, svn: Svn, gst: Gst) {
        if osnma.iter().all(|&x| x == 0) {
            // No OSNMA data
            return;
        }
        if let Some((hkroot, mack, subframe_gst)) = self.subframe.feed(osnma, svn, gst) {
            self.data.process_subframe(hkroot, mack, svn, subframe_gst);
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
        self.data.data.navmessage.get_ced_and_status(svn)
    }

    /// Try to get authenticated timing parameters for a satellite.
    ///
    /// This will try to retrieve the most recent authenticated timing
    /// parameters data (ADKD=4) for the satellite with SVN `svn` that is
    /// available in the OSNMA storage. If the storage does not contain any
    /// authenticated timing parameters data for this SVN, this returns `None`.
    pub fn get_timing_parameters(&self, svn: Svn) -> Option<NavMessageData> {
        self.data.data.navmessage.get_timing_parameters(svn)
    }
}

impl<S: StaticStorage> OsnmaDsm<S> {
    fn process_subframe(&mut self, hkroot: &HkrootMessage, mack: &MackMessage, svn: Svn, gst: Gst) {
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

impl<S: StaticStorage> OsnmaData<S> {
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
        for svn in Svn::iter() {
            if !self.only_slowmac {
                if let Some(mack) = self.mack.get(svn, gst_mack) {
                    let mack = Mack::new(
                        mack,
                        current_key.chain().key_size_bits(),
                        current_key.chain().tag_size_bits(),
                    );
                    if let Some(mack) = Self::validate_mack(mack, &current_key, svn, gst_mack) {
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
                if let Some(mack) = Self::validate_mack(mack, &slowmac_key, svn, gst_slowmac) {
                    self.navmessage
                        .process_mack_slowmac(mack, &current_key, svn, gst_slowmac);
                }
            }
        }
    }

    fn validate_mack<'a>(
        mack: Mack<'a, NotValidated>,
        key: &Key<Validated>,
        prna: Svn,
        gst_mack: Gst,
    ) -> Option<Mack<'a, Validated>> {
        match mack.validate(key, prna, gst_mack) {
            Err(e) => {
                log::error!("error validating MACK {:?}: {:?}", mack, e);
                None
            }
            Ok(m) => Some(m),
        }
    }
}
