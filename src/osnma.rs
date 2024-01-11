use crate::bitfields::{DsmHeader, DsmKroot, DsmPkr, DsmType, Mack, NmaHeader};
use crate::dsm::{CollectDsm, Dsm};
use crate::mack::MackStorage;
use crate::merkle_tree::MerkleTree;
use crate::navmessage::{CollectNavMessage, NavMessageData};
use crate::storage::StaticStorage;
use crate::subframe::CollectSubframe;
use crate::tesla::Key;
use crate::types::{HkrootMessage, InavBand, InavWord, MackMessage, OsnmaDataMessage};
use crate::validation::{NotValidated, Validated};
use crate::{Gst, MerkleTreeNode, PublicKey, Svn};

use core::cmp::Ordering;

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
/// use galileo_osnma::{Gst, InavBand, Osnma, PublicKey, Svn};
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
/// let public_key_id = 0;
/// let pubkey = PublicKey::from_p256(pubkey, public_key_id);
/// // Force the public key to be valid. Only do this if the key
/// // has been loaded from a trustworthy source.
/// let pubkey = pubkey.force_valid();
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
/// let timing = osnma.get_timing_parameters(svn);
/// ```
///
/// # Storage size
///
/// The size of the internal storage used to hold navigation data and MACK
/// messages is defined by the [`StaticStorage`] type parameter `S`. See the
/// [storage](crate::storage) module for a description of how the storage size
/// is defined.
#[derive(Debug, Clone)]
pub struct Osnma<S: StaticStorage> {
    subframe: CollectSubframe,
    data: OsnmaDsm<S>,
}

// These structures exist only in order to avoid double mutable
// borrows of Osnma because we take references from CollectSubframe
// and CollectDsm
#[derive(Debug, Clone)]
struct OsnmaDsm<S: StaticStorage> {
    dsm: CollectDsm,
    data: OsnmaData<S>,
}

#[derive(Debug, Clone)]
struct OsnmaData<S: StaticStorage> {
    navmessage: CollectNavMessage<S>,
    mack: MackStorage<S>,
    merkle_tree: Option<MerkleTree>,
    pubkey: PubkeyStore,
    key: KeyStore,
    only_slowmac: bool,
}

#[derive(Debug, Clone)]
struct PubkeyStore {
    current: Option<PublicKey<Validated>>,
    next: Option<PublicKey<Validated>>,
}

// The KeyStore can hold up to two keys: the TESLA key for the current chain in
// force, and an additional KROOT for a chain that will become in force in the
// future.
#[derive(Debug, Clone)]
struct KeyStore {
    keys: [Option<Key<Validated>>; 2],
    in_force: Option<bool>,
}

impl<S: StaticStorage> Osnma<S> {
    fn new(
        merkle_tree_root: Option<MerkleTreeNode>,
        pubkey: Option<PublicKey<Validated>>,
        only_slowmac: bool,
    ) -> Osnma<S> {
        Osnma {
            subframe: CollectSubframe::new(),
            data: OsnmaDsm {
                dsm: CollectDsm::new(),
                data: OsnmaData {
                    navmessage: CollectNavMessage::new(),
                    mack: MackStorage::new(),
                    merkle_tree: merkle_tree_root.map(MerkleTree::new),
                    pubkey: pubkey
                        .map_or_else(PubkeyStore::empty, PubkeyStore::from_current_pubkey),
                    key: KeyStore::empty(),
                    only_slowmac,
                },
            },
        }
    }

    /// Constructs a new OSNMA black box using the Merkle tree root.
    ///
    /// An optional ECDSA public key can be passed in addition to the Merkle
    /// tree root. If the ECDSA public key is not passed, the OSNMA black box
    /// will need to obtain the public key from a DSM-PKR message. These
    /// messages are broadcast only every 6 hours.
    ///
    /// If `only_slowmac` is `true`, only ADKD=12 (Slow MAC) will be processed.
    /// This should be used by receivers which have a larger time uncertainty.
    /// (See Annex 3 in the
    /// [OSNMA Receiver Guidelines](https://www.gsc-europa.eu/sites/default/files/sites/all/files/Galileo_OSNMA_Receiver_Guidelines_for_Test_Phase_v1.0.pdf)).
    pub fn from_merkle_tree(
        merkle_tree_root: MerkleTreeNode,
        pubkey: Option<PublicKey<Validated>>,
        only_slowmac: bool,
    ) -> Osnma<S> {
        Osnma::new(Some(merkle_tree_root), pubkey, only_slowmac)
    }

    /// Constructs a new OSNMA black box using only an ECDSA public key.
    ///
    /// This function is similar to [`Osnma::from_merkle_tree`], but the Merkle
    /// tree root is not loaded. Therefore, DSM-PKR verification will not be
    /// done, and only the provided ECDSA public key will be used.
    ///
    /// The OSNMA black box will hold the public key `pubkey` and use it to
    /// try to authenticate the TESLA root key. The public key cannot be changed
    /// after construction.
    ///
    /// If `only_slowmac` is `true`, only ADKD=12 (Slow MAC) will be processed.
    /// This should be used by receivers which have a larger time uncertainty.
    /// (See Annex 3 in the
    /// [OSNMA Receiver Guidelines](https://www.gsc-europa.eu/sites/default/files/sites/all/files/Galileo_OSNMA_Receiver_Guidelines_for_Test_Phase_v1.0.pdf)).
    pub fn from_pubkey(pubkey: PublicKey<Validated>, only_slowmac: bool) -> Osnma<S> {
        Osnma::new(None, Some(pubkey), only_slowmac)
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

        let nma_header = NmaHeader::new(hkroot[0]);
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
    fn process_dsm(&mut self, dsm: Dsm, nma_header: NmaHeader<NotValidated>) {
        match dsm.dsm_type() {
            DsmType::Kroot => self.process_dsm_kroot(DsmKroot(dsm.data()), nma_header),
            DsmType::Pkr => self.process_dsm_pkr(DsmPkr(dsm.data())),
        }
    }

    fn process_dsm_kroot(&mut self, dsm_kroot: DsmKroot, nma_header: NmaHeader<NotValidated>) {
        let pkid = dsm_kroot.public_key_id();
        let Some(pubkey) = self.pubkey.applicable_pubkey(pkid) else {
            return;
        };
        match Key::from_dsm_kroot(nma_header, dsm_kroot, pubkey) {
            Ok((key, nma_header)) => {
                log::info!("verified KROOT with public key id {pkid}");
                log::info!("current NMA header: {nma_header:?}");
                self.pubkey.make_pkid_current(pkid);
                self.key.store_kroot(key, nma_header);
            }
            Err(e) => log::error!("could not verify KROOT: {:?}", e),
        }
    }

    fn process_dsm_pkr(&mut self, dsm_pkr: DsmPkr) {
        let Some(merkle_tree) = &self.merkle_tree else {
            log::error!("could not verify public key because Merkle tree is not loaded");
            return;
        };
        match merkle_tree.validate_pkr(dsm_pkr) {
            Ok(pubkey) => {
                log::info!("verified public key in DSM-PKR: {dsm_pkr:?}");
                self.pubkey.store_new_pubkey(pubkey);
            }
            Err(e) => log::error!("could not verify public key: {e:?}"),
        }
    }

    fn validate_key(&mut self, mack: &MackMessage, gst: Gst) {
        let Some(current_key) = self.key.current_key() else {
            log::info!("no valid TESLA key for the chain in force. unable to validate MACK key");
            return;
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
                        self.process_tags(&new_valid_key);
                        self.key.store_key(new_valid_key);
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

    fn process_tags(&mut self, current_key: &Key<Validated>) {
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
                    if let Some(mack) = Self::validate_mack(mack, current_key, svn, gst_mack) {
                        self.navmessage
                            .process_mack(mack, current_key, svn, gst_mack);
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
                        .process_mack_slowmac(mack, current_key, svn, gst_slowmac);
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

impl PubkeyStore {
    fn empty() -> PubkeyStore {
        PubkeyStore {
            current: None,
            next: None,
        }
    }

    fn from_current_pubkey(current_key: PublicKey<Validated>) -> PubkeyStore {
        PubkeyStore {
            current: Some(current_key),
            next: None,
        }
    }

    fn check_consistency(&self) {
        // consistency check: if next is Some, current must also be Some
        assert!(self.next.is_none() || self.current.is_some());
    }

    fn applicable_pubkey(&self, pkid: u8) -> Option<&PublicKey<Validated>> {
        self.check_consistency();
        match (&self.current, &self.next) {
            (Some(k), _) if k.public_key_id() == pkid => Some(k),
            (_, Some(k)) if k.public_key_id() == pkid => {
                log::info!("selecting next public key to authenticate KROOT");
                Some(k)
            }
            (Some(_), _) => {
                log::error!(
                    "could not verify KROOT because public key with id {pkid} is not available"
                );
                None
            }
            (None, _) => {
                log::error!("could not verify KROOT because no public key is available");
                None
            }
        }
    }

    fn make_pkid_current(&mut self, pkid: u8) {
        self.check_consistency();
        if self.current.as_ref().map(|k| k.public_key_id()) == Some(pkid) {
            // pkid is already current
            return;
        }
        if self.next.as_ref().map(|k| k.public_key_id()) == Some(pkid) {
            // consistency check: the PKID of self.current should be smaller
            // (and self.current cannot be None)
            assert!(self.current.as_ref().unwrap().public_key_id() < pkid);
            self.current.replace(self.next.take().unwrap());
            return;
        }
        // this should not be reached, because the KROOT has been authenticated
        // with one of the keys in the store
        panic!("inconsistent PubkeyStore state");
    }

    fn store_new_pubkey(&mut self, pubkey: PublicKey<Validated>) {
        self.check_consistency();
        let new_pkid = pubkey.public_key_id();
        if let Some(current) = &self.current {
            let curr_pkid = current.public_key_id();
            if new_pkid < curr_pkid {
                log::error!("received public key with id {new_pkid} smaller than current id {curr_pkid}; discarding");
            }
            if let Some(next) = &self.next {
                let next_pkid = next.public_key_id();
                match new_pkid.cmp(&next_pkid) {
                    Ordering::Less => log::error!(
                        "received public key with id {new_pkid} smaller than \
                         the next id {next_pkid}; discarding"
                    ),
                    Ordering::Greater => {
                        log::warn!(
                            "received public key with id {new_pkid} greater than \
                             the next id {next_pkid}; overwriting"
                        );
                        self.next = Some(pubkey);
                    }
                    Ordering::Equal => {
                        // the same key is already stored; do nothing
                    }
                }
            } else {
                self.next = Some(pubkey);
            }
        } else {
            // no keys are stored at this moment
            self.current = Some(pubkey);
        }
    }
}

impl KeyStore {
    fn empty() -> KeyStore {
        KeyStore {
            keys: [None; 2],
            in_force: None,
        }
    }

    fn store_kroot(&mut self, key: Key<Validated>, nma_header: NmaHeader<Validated>) {
        let kid = key.chain().chain_id();
        let cid = nma_header.chain_id();
        match (&self.keys[0], &self.keys[1]) {
            (Some(k), _) if k.chain().chain_id() == kid => {
                // do nothing; we already have a key for the same chain
            }
            (_, Some(k)) if k.chain().chain_id() == kid => {
                // do nothing; we already have a key for the same chain
            }
            // there is one slot vacant to place the key
            (None, _) => {
                log::info!("storing KROOT {key:?} in slot 0 (vacant)");
                self.keys[0] = Some(key);
            }
            (_, None) => {
                log::info!("storing KROOT {key:?} in slot 1 (vacant)");
                self.keys[1] = Some(key);
            }
            (Some(k0), Some(_)) => {
                // both slots are occupied; do not overwrite the slot for the
                // current chain
                if k0.chain().chain_id() == cid {
                    log::info!("overwriting slot 1 with KROOT {key:?}");
                    self.keys[1] = Some(key);
                } else {
                    log::info!("overwriting slot 0 with KROOT {key:?}");
                    self.keys[0] = Some(key);
                }
            }
        }
        // update self.in_force
        match (&self.keys[0], &self.keys[1]) {
            (Some(k), _) if k.chain().chain_id() == cid => self.in_force = Some(false),
            (_, Some(k)) if k.chain().chain_id() == cid => self.in_force = Some(true),
            _ => self.in_force = None,
        }
    }

    fn store_key(&mut self, key: Key<Validated>) {
        let id = key.chain().chain_id();
        match (&self.keys[0], &self.keys[1]) {
            (Some(k), _) if k.chain().chain_id() == id => self.keys[0] = Some(key),
            (_, Some(k)) if k.chain().chain_id() == id => self.keys[1] = Some(key),
            _ => {
                // This should not happen, because the TESLA key 'key' was
                // validated with one of the keys stored here, so it must belong
                // to the same chain.
                unreachable!();
            }
        }
    }

    fn current_key(&self) -> Option<&Key<Validated>> {
        self.in_force
            .and_then(|v| self.keys[usize::from(v)].as_ref())
    }
}
