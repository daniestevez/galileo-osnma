//! TESLA keys and chain parameters.
//!
//! This module contains the [`Chain`] struct, that holds the parameters of a
//! TESLA chain, and the [`Key`] struct, which contains a TESLA key and a copy
//! of a `Chain` with the parameters of the corresponding chain. Keys can be
//! used to validate other keys transmitted at later GSTs, and to validate MACK
//! messages and authenticate the navigation data using the tags in a MACK message.

use crate::bitfields::{
    self, DsmKroot, EcdsaFunction, Mack, NmaHeader, NmaStatus, Prnd, TagAndInfo,
};
use crate::maclt::{get_flx_indices, get_maclt_entry, AuthObject, MacLTError, MacLTSlot};
use crate::types::{BitSlice, VerifyingKey, NUM_SVNS};
use crate::validation::{NotValidated, Validated};
use crate::{Gst, PublicKey, Svn, Tow};
use aes::Aes128;
use bitvec::prelude::*;
use cmac::Cmac;
use core::fmt;
use crypto_common::generic_array::GenericArray;
use hmac::{Hmac, Mac};
use sha2::{
    digest::{FixedOutput, Output, OutputSizeUser, Update},
    Digest, Sha256,
};
use sha3::Sha3_256;

const MAX_KEY_BYTES: usize = 32;

/// TESLA chain parameters.
///
/// This struct stores the parameters of a TESLA chain. It is typically
/// constructed from a DSK-KROOT message using [`Chain::from_dsm_kroot`].
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct Chain {
    status: ChainStatus,
    id: u8,
    // TODO: decide if CPKS needs to be included here (and how)
    hash_function: HashFunction,
    mac_function: MacFunction,
    key_size_bytes: usize,
    tag_size_bits: usize,
    maclt: u8,
    alpha: u64,
}

/// Chain status.
///
/// This gives the chain status for a valid TESLA chain. This roughly
/// corresponds to the NMA status [`NmaStatus`],
/// but "don't use" and "reserved" are not considered valid statuses for a TESLA
/// chain.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum ChainStatus {
    /// Test (corresponds to NMAS = 1).
    Test,
    /// Operational (corresponds to NMAS = 2).
    Operational,
}

/// Hash function.
///
/// This gives the hash function used by the TESLA chain. Its values correspond
/// to those of [`bitfields::HashFunction`],
/// minus the reserved value.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum HashFunction {
    /// SHA-256.
    Sha256,
    /// SHA3-256.
    Sha3_256,
}

/// MAC function.
///
/// This gives the MAC function used by the TESLA chain. Its values correspond
/// to those of [`bitfields::MacFunction`],
/// minus the reserved value.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum MacFunction {
    /// HMAC-SHA-256.
    HmacSha256,
    /// CMAC-AES.
    CmacAes,
}

impl Chain {
    /// Extract the chain parameters from a DSM-KROOT message.
    ///
    /// The corresponding NMA header needs to be given, in order to extract the
    /// [`ChainStatus`] from the NMA status field.
    ///
    /// If all the values in the DSM-KROOT message are acceptable a `Chain` is
    /// returned. Otherwise, this returns an error indicating the problem.
    pub fn from_dsm_kroot(nma_header: NmaHeader, dsm_kroot: DsmKroot) -> Result<Chain, ChainError> {
        let status = match nma_header.nma_status() {
            NmaStatus::Test => ChainStatus::Test,
            NmaStatus::Operational => ChainStatus::Operational,
            NmaStatus::DontUse => return Err(ChainError::NmaDontUse),
            NmaStatus::Reserved => return Err(ChainError::ReservedField),
        };
        let hash_function = match dsm_kroot.hash_function() {
            bitfields::HashFunction::Sha256 => HashFunction::Sha256,
            bitfields::HashFunction::Sha3_256 => HashFunction::Sha3_256,
            bitfields::HashFunction::Reserved => return Err(ChainError::ReservedField),
        };
        let mac_function = match dsm_kroot.mac_function() {
            bitfields::MacFunction::HmacSha256 => MacFunction::HmacSha256,
            bitfields::MacFunction::CmacAes => MacFunction::CmacAes,
            bitfields::MacFunction::Reserved => return Err(ChainError::ReservedField),
        };
        let key_size_bytes = match dsm_kroot.key_size() {
            Some(s) => {
                assert!(s % 8 == 0);
                s / 8
            }
            None => return Err(ChainError::ReservedField),
        };
        let tag_size_bits = dsm_kroot.tag_size().ok_or(ChainError::ReservedField)?;
        Ok(Chain {
            status,
            id: nma_header.chain_id(),
            hash_function,
            mac_function,
            key_size_bytes,
            tag_size_bits,
            maclt: dsm_kroot.mac_lookup_table(),
            alpha: dsm_kroot.alpha(),
        })
    }

    /// Gives the status of the TESLA chain.
    pub fn chain_status(&self) -> ChainStatus {
        self.status
    }

    /// Gives the chain ID of the TESLA chain.
    pub fn chain_id(&self) -> u8 {
        self.id
    }

    /// Gives the hash function used by the TESLA chain.
    pub fn hash_function(&self) -> HashFunction {
        self.hash_function
    }

    /// Gives the MAC function used by the TESLA chain.
    pub fn mac_function(&self) -> MacFunction {
        self.mac_function
    }

    /// Gives the size of the TESLA keys in bytes.
    ///
    /// Note that all the possible TESLA key sizes are an integer number of
    /// bytes.
    pub fn key_size_bytes(&self) -> usize {
        self.key_size_bytes
    }

    /// Gives the size of the TESLA keys in bits.
    pub fn key_size_bits(&self) -> usize {
        self.key_size_bytes() * 8
    }

    /// Gives the size of the tags in bits.
    ///
    /// Note that there are some possible tag sizes which are not an integer
    /// number of bytes.
    pub fn tag_size_bits(&self) -> usize {
        self.tag_size_bits
    }

    /// Gives the value of the MAC look-up table field.
    pub fn mac_lookup_table(&self) -> u8 {
        self.maclt
    }

    /// Gives the value of the chain random parameter alpha.
    pub fn alpha(&self) -> u64 {
        self.alpha
    }

    /// Try to validate the ADKD field of a Tag-Info section.
    ///
    /// This checks the ADKD against the MAC look-up table as described in Annex
    /// C of the
    /// [OSNMA SIS ICD v1.1](https://www.gsc-europa.eu/sites/default/files/sites/all/files/Galileo_OSNMA_SIS_ICD_v1.1.pdf).
    /// If the ADKD field is correct, this returns `Ok(())`. Otherwise, this
    /// returns an error indicating what property is not satisfied.
    ///
    /// The `num_tag` parameter gives the index of the Tag-Info field. This is
    /// the same index that is used in
    /// [`Mack::tag_and_info`](crate::bitfields::Mack::tag_and_info). The first
    /// Tag-Info field in a MACK message has `num_tag = 1`. The `prna` parameter
    /// indicates the SVN of the satellite that transmitted the tag, and
    /// `gst_tag` is the GST at the start of the subframe when the tag was
    /// transmitted.
    ///
    /// # Panics
    ///
    /// Panics if `num_tag` is zero.
    pub fn validate_adkd<V>(
        &self,
        num_tag: usize,
        tag: TagAndInfo<V>,
        prna: Svn,
        gst_tag: Gst,
    ) -> Result<(), AdkdCheckError> {
        // Half of the GST minute
        let msg = usize::try_from((gst_tag.tow() / 30) % 2).unwrap();
        match get_maclt_entry(self.maclt, msg, num_tag)? {
            MacLTSlot::Fixed { adkd, object } => {
                if tag.adkd() != adkd {
                    Err(AdkdCheckError::WrongAdkd)
                } else if let Prnd::GalileoSvid(prnd) = tag.prnd() {
                    if object == AuthObject::SelfAuth && prnd != prna.into() {
                        Err(AdkdCheckError::WrongPrnd)
                    } else if (1..=NUM_SVNS).contains(&prnd.into()) {
                        Ok(())
                    } else {
                        Err(AdkdCheckError::WrongPrnd)
                    }
                } else {
                    // tag.prnd() is not a Galileo SVID
                    Err(AdkdCheckError::WrongPrnd)
                }
            }
            MacLTSlot::Flex => {
                // Any tag is valid for a flex slot
                Ok(())
            }
        }
    }
}

/// Errors produced during the extraction of the chain parameters.
///
/// This gives the errors that can happen during the extraction of the TESLA
/// chain parameters from the DSM-KROOT message.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum ChainError {
    /// One of the fields holding information about the TESLA chain has a
    /// reserved value.
    ReservedField,
    /// The NMA status is set to "don't use".
    NmaDontUse,
}

impl fmt::Display for ChainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ChainError::ReservedField => "reserved value present in some field".fmt(f),
            ChainError::NmaDontUse => "NMA status is \"don't use\"".fmt(f),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ChainError {}

/// Errors produced during the validation of an ADKD field.
///
/// This gives the errors that can happen during the validation of an ADKD field
/// using [`Chain::validate_adkd`].
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum AdkdCheckError {
    /// MAC Look-up Table error.
    MacLTError(MacLTError),
    /// The ADKD does not match the value indicated in the corresponding MAC
    /// look-up table entry.
    WrongAdkd,
    /// The PRND field does not match the value indicated in the corresponding
    /// MAC look-up table entry.
    WrongPrnd,
}

impl fmt::Display for AdkdCheckError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AdkdCheckError::MacLTError(err) => err.fmt(f),
            AdkdCheckError::WrongAdkd => "ADKD does not match MAC look-up table entry".fmt(f),
            AdkdCheckError::WrongPrnd => "PRND field does not match MAC look-up table entry".fmt(f),
        }
    }
}

impl From<MacLTError> for AdkdCheckError {
    fn from(value: MacLTError) -> AdkdCheckError {
        AdkdCheckError::MacLTError(value)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for AdkdCheckError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            AdkdCheckError::MacLTError(err) => Some(err),
            _ => None,
        }
    }
}

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
enum HashDigest {
    Sha256(Sha256),
    Sha3_256(Sha3_256),
}

impl HashDigest {
    fn new(hash_function: HashFunction) -> HashDigest {
        match hash_function {
            HashFunction::Sha256 => HashDigest::Sha256(Sha256::new()),
            HashFunction::Sha3_256 => HashDigest::Sha3_256(Sha3_256::new()),
        }
    }
}

impl Update for HashDigest {
    fn update(&mut self, data: &[u8]) {
        match self {
            HashDigest::Sha256(d) => Update::update(d, data),
            HashDigest::Sha3_256(d) => Update::update(d, data),
        }
    }
}

impl OutputSizeUser for HashDigest {
    type OutputSize = <Sha256 as OutputSizeUser>::OutputSize;
}

impl FixedOutput for HashDigest {
    fn finalize_into(self, out: &mut Output<Self>) {
        match self {
            HashDigest::Sha256(d) => FixedOutput::finalize_into(d, out),
            HashDigest::Sha3_256(d) => FixedOutput::finalize_into(d, out),
        }
    }
}

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
enum MacDigest {
    HmacSha256(Hmac<Sha256>),
    CmacAes(Cmac<Aes128>),
}

impl MacDigest {
    fn new_from_slice(
        mac_function: MacFunction,
        key: &[u8],
    ) -> Result<MacDigest, hmac::digest::InvalidLength> {
        Ok(match mac_function {
            MacFunction::HmacSha256 => MacDigest::HmacSha256(Mac::new_from_slice(key)?),
            MacFunction::CmacAes => MacDigest::CmacAes(Mac::new_from_slice(key)?),
        })
    }
}

impl Update for MacDigest {
    fn update(&mut self, data: &[u8]) {
        match self {
            MacDigest::HmacSha256(d) => Update::update(d, data),
            MacDigest::CmacAes(d) => Update::update(d, data),
        }
    }
}

impl OutputSizeUser for MacDigest {
    type OutputSize = <Hmac<Sha256> as OutputSizeUser>::OutputSize;
}

impl FixedOutput for MacDigest {
    fn finalize_into(self, out: &mut Output<Self>) {
        match self {
            MacDigest::HmacSha256(d) => FixedOutput::finalize_into(d, out),
            MacDigest::CmacAes(d) => {
                // Out is a 256-bit GenericArray. CMAC AES-128 output is
                // 128-bit. We write to the first 128 bits of the output GenericArray.
                FixedOutput::finalize_into(d, GenericArray::from_mut_slice(&mut out[..16]));
            }
        }
    }
}

/// TESLA key.
///
/// This struct holds a TESLA key, its corresponding GST (the GST at the start
/// of the subframe when the key was transmitted in a MACK message), and the
/// corresponding chain parameters.
///
/// The `V` type parameter is used to indicate the validation status of the
/// key. A TESLA key is considered valid if it has been traced back to the ECDSA
/// public key using the DSM-KROOT signature and TELA key derivations.  See
/// [validation](crate::validation) for a description of validation type
/// parameters.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct Key<V> {
    data: [u8; MAX_KEY_BYTES],
    chain: Chain,
    gst_subframe: Gst,
    _validated: V,
}

/// Errors produced during the validation of a TESLA key.
///
/// This gives the errors that can happen during the validation of TESLA key
/// using another, already validated TESLA key, and [`Key::validate_key`].
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum ValidationError {
    /// The key obtained via one-way function applications differs from the
    /// expected key.
    WrongOneWayFunction,
    /// Both keys belong to chains with different IDs.
    DifferentChain,
    /// The GST of the key that whose validation is attempted is not later than
    /// the GST of the key that is used for the validation.
    DoesNotFollow,
    /// The distance between the GSTs of both keys is large enough that the
    /// number of derivations to get from one to the other exceeds a certain threshold.
    ///
    /// The threshold is currently set to 3000 derivations, which corresponds to
    /// a maximum GST difference of 25 hours.
    TooManyDerivations,
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ValidationError::WrongOneWayFunction => "derived key does not match".fmt(f),
            ValidationError::DifferentChain => "keys belong to different chains".fmt(f),
            ValidationError::DoesNotFollow => "key is older than validating key".fmt(f),
            ValidationError::TooManyDerivations => "time difference between keys too large".fmt(f),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ValidationError {}

impl<V> Key<V> {
    /// Gives the GST at the start of the subframe when the key was transmitted.
    pub fn gst_subframe(&self) -> Gst {
        self.gst_subframe
    }

    fn check_gst(gst: Gst) {
        assert!(gst.is_subframe());
    }

    /// Gives the chain parameters of the chain that the key belongs to.
    pub fn chain(&self) -> &Chain {
        &self.chain
    }

    fn store_gst(buffer: &mut [u8], gst: Gst) {
        let bits = BitSlice::from_slice_mut(buffer);
        bits[0..12].store_be(gst.wn());
        bits[12..32].store_be(gst.tow());
    }
}

impl Key<NotValidated> {
    /// Constructs a new key from a [`BitSlice`].
    ///
    /// This creates a new `Key` by copying the key data from a `BitSlice`. The
    /// `gst` parameter should give the GST at the start of the subframe when
    /// the key was transmitted. The key is marked as `NotValidated`.
    ///
    /// # Panics
    ///
    /// Panics if `slice.len()` does not match the key size indicated in `chain`.
    pub fn from_bitslice(slice: &BitSlice, gst: Gst, chain: &Chain) -> Key<NotValidated> {
        Self::check_gst(gst);
        let mut data = [0; MAX_KEY_BYTES];
        BitSlice::from_slice_mut(&mut data)[..chain.key_size_bytes * 8].copy_from_bitslice(slice);
        Key {
            data,
            chain: *chain,
            gst_subframe: gst,
            _validated: NotValidated {},
        }
    }

    /// Constructs a new key from a slice of bytes.
    ///
    /// This creates a new `Key` by copying the key data from a `&[u8]`. The
    /// `gst` parameter should give the GST at the start of the subframe when
    /// the key was transmitted. The key is marked as `NotValidated`.
    ///
    /// # Panics
    ///
    /// Panics if `slice.len()` does not match the key size indicated in `chain`.
    pub fn from_slice(slice: &[u8], gst: Gst, chain: &Chain) -> Key<NotValidated> {
        Self::check_gst(gst);
        let mut data = [0; MAX_KEY_BYTES];
        data[..chain.key_size_bytes].copy_from_slice(slice);
        Key {
            data,
            chain: *chain,
            gst_subframe: gst,
            _validated: NotValidated {},
        }
    }
}

impl<V> Key<V> {
    fn force_valid(self) -> Key<Validated> {
        Key {
            data: self.data,
            chain: self.chain,
            gst_subframe: self.gst_subframe,
            _validated: Validated {},
        }
    }
}

impl Key<Validated> {
    /// Extracts the TESLA root key from the DSM-KROOT.
    ///
    /// This checks the ECDSA signature of the DSM-KROOT message and constructs
    /// a validated TESLA root key that is marked with the `Validated` type
    /// parameter.
    ///
    /// The chain parameters and the GST of the key are extracted from the
    /// DSM-KROOT message and from the NMA header given in the `nma_header`
    /// parameter.
    ///
    /// If validation using the public key `pubkey` and
    /// the corresponding check signature method of [`DsmKroot`]
    /// is correct, as well as the contents of the DSM-KROOT padding, which are
    /// also checked using [`DsmKroot::check_padding`], the TESLA root key is
    /// returned. Otherwise, this returns an error that indicates what
    /// validation property was not satisfied.
    pub fn from_dsm_kroot(
        nma_header: NmaHeader,
        dsm_kroot: DsmKroot,
        pubkey: &PublicKey<Validated>,
    ) -> Result<Key<Validated>, KrootValidationError> {
        let chain = Chain::from_dsm_kroot(nma_header, dsm_kroot)
            .map_err(KrootValidationError::WrongDsmKrootChain)?;
        if !dsm_kroot.check_padding(nma_header) {
            return Err(KrootValidationError::WrongDsmKrootPadding);
        }
        match (pubkey.verifying_key(), dsm_kroot.ecdsa_function()) {
            (VerifyingKey::P256(pubkey), EcdsaFunction::P256Sha256) => {
                if !dsm_kroot.check_signature_p256(nma_header, pubkey) {
                    return Err(KrootValidationError::WrongEcdsa);
                }
            }
            #[cfg(feature = "p521")]
            (VerifyingKey::P521(pubkey), EcdsaFunction::P521Sha512) => {
                if !dsm_kroot.check_signature_p521(nma_header, pubkey) {
                    return Err(KrootValidationError::WrongEcdsa);
                }
            }
            _ => return Err(KrootValidationError::WrongEcdsaKeyType),
        }
        let wn = dsm_kroot.kroot_wn();
        let tow = Tow::from(dsm_kroot.kroot_towh()) * 3600;
        let gst = Gst::new(wn, tow);
        Self::check_gst(gst);
        let gst = gst.add_seconds(-30);
        Ok(Key::from_slice(dsm_kroot.kroot(), gst, &chain).force_valid())
    }
}

/// Errors produced during the extraction of a TESLA root key from a DSM-KROOT
/// message.
///
/// This gives the errors that can happen during the extraction of the TESLA
/// root key using [`Key::from_dsm_kroot`].
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum KrootValidationError {
    /// A valid chain could not be extracted from the DSM-KROOT message.
    ///
    /// See [`ChainError`].
    WrongDsmKrootChain(ChainError),
    /// The check of the padding of the DSM-KROOT message was not successful.
    WrongDsmKrootPadding,
    /// The check of the ECDSA signature of the DSM-KROOT message was not
    /// successful.
    WrongEcdsa,
    /// The type of the ECDSA key does not match the ECDSA algorithm used in the
    /// DSM-KROOT message.
    WrongEcdsaKeyType,
}

impl fmt::Display for KrootValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KrootValidationError::WrongDsmKrootChain(e) => {
                write!(f, "invalid chain in DSM-KROOT ({})", e)
            }
            KrootValidationError::WrongDsmKrootPadding => "incorrect padding in DSM-KROOT".fmt(f),
            KrootValidationError::WrongEcdsa => "invalid ECDSA signature in DSM-KROOT".fmt(f),
            KrootValidationError::WrongEcdsaKeyType => {
                "ECDSA key type does not match DSM-KROOT".fmt(f)
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for KrootValidationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            KrootValidationError::WrongDsmKrootChain(e) => Some(e),
            KrootValidationError::WrongDsmKrootPadding
            | KrootValidationError::WrongEcdsa
            | KrootValidationError::WrongEcdsaKeyType => None,
        }
    }
}

impl<V: Clone> Key<V> {
    /// Computes the one-way function of a TESLA key.
    ///
    /// This gives the key corresponding to the previous subframe in the TESLA
    /// chain. The validation status of the returned key is inherited from the
    /// validation status of `self`.
    pub fn one_way_function(&self) -> Key<V> {
        let mut hash = self.hash_digest();
        let size = self.chain.key_size_bytes;
        hash.update(&self.data[..size]);
        let mut gst = [0; 4];
        let previous_subframe = self.gst_subframe.add_seconds(-30);
        Self::store_gst(&mut gst, previous_subframe);
        hash.update(&gst);
        hash.update(&self.chain.alpha.to_be_bytes()[2..]);
        let mut hash_out = GenericArray::default();
        hash.finalize_into(&mut hash_out);
        let mut new_key = [0; MAX_KEY_BYTES];
        new_key[..size].copy_from_slice(&hash_out[..size]);
        Key {
            data: new_key,
            chain: self.chain,
            gst_subframe: previous_subframe,
            _validated: self._validated.clone(),
        }
    }

    fn hash_digest(&self) -> HashDigest {
        HashDigest::new(self.chain.hash_function)
    }

    /// Derives a TESLA key by applying the one-way function `num_derivations` times.
    ///
    /// This gives the TESLA key that comes `num_derivations` subframes earlier
    /// in the TESLA chain. The validation status of the returned key is
    /// inherited from the validation status of `self`.
    pub fn derive(&self, num_derivations: usize) -> Key<V> {
        let mut derived_key = self.clone();
        for _ in 0..num_derivations {
            derived_key = derived_key.one_way_function();
        }
        derived_key
    }
}

impl Key<Validated> {
    /// Tries to validate a TESLA key.
    ///
    /// If `self` precedes `other` in the TESLA chain, and `self` is already
    /// validated, this tries to validate `other`. A copy of `other` with its
    /// validation type parameter set to `Validated` is returned if the
    /// validation is successful. Otherwise, this returns an error indicating
    /// what validation property was not satisfied.
    ///
    /// This uses the algorithm described in Section 6.4 in the
    /// [OSNMA SIS ICD v1.1](https://www.gsc-europa.eu/sites/default/files/sites/all/files/Galileo_OSNMA_SIS_ICD_v1.1.pdf).
    pub fn validate_key<V: Clone>(
        &self,
        other: &Key<V>,
    ) -> Result<Key<Validated>, ValidationError> {
        if self.chain != other.chain {
            return Err(ValidationError::DifferentChain);
        }
        if self.gst_subframe >= other.gst_subframe {
            return Err(ValidationError::DoesNotFollow);
        }
        let derivations = i32::from(other.gst_subframe.wn() - self.gst_subframe.wn())
            * (7 * 24 * 3600 / 30)
            + (i32::try_from(other.gst_subframe.tow()).unwrap()
                - i32::try_from(self.gst_subframe.tow()).unwrap())
                / 30;
        assert!(derivations >= 1);
        // Set an arbitrary limit to the number of derivations.
        // This is chosen to be slightly greater than 1 day.
        if derivations > 3000 {
            return Err(ValidationError::TooManyDerivations);
        }
        let derived_key = other.derive(derivations.try_into().unwrap());
        assert!(derived_key.gst_subframe == self.gst_subframe);
        let size = self.chain.key_size_bytes;
        if derived_key.data[..size] == self.data[..size] {
            Ok(other.clone().force_valid())
        } else {
            Err(ValidationError::WrongOneWayFunction)
        }
    }

    /// Tries to validate a tag and its corresponding navigation data.
    ///
    /// The algorithm in Section 6.7 of the
    /// [OSNMA SIS ICD v1.1](https://www.gsc-europa.eu/sites/default/files/sites/all/files/Galileo_OSNMA_SIS_ICD_v1.1.pdf).
    /// Is used to attempt to validate a tag and its corresponding navigation data.
    ///
    /// The `tag_gst` parameter should give the GST at the start of the subframe
    /// when the `tag` was transmitted. The `prnd` and `prna` parameters are
    /// according to Section 6.7 in the ICD. The `ctr` parameter is the index of
    /// the tag, where the first tag in a MACK message has `ctr = 1`. Note that
    /// [`Key::validate_tag0`] should be used to validate the tag0 in a MACK
    /// message instead of this function.
    ///
    /// Note that the navigation data `navdata` must correspond to the previous
    /// subframe of the tag, and the key `self` must correspond to the next
    /// subframe of the tag, except when tag is a Slow MAC key (in this case the
    /// difference between the GSTs of the key and the tag should be 11
    /// subframes).
    ///
    ///
    /// This returns `true` if the validation was succesful. Otherwise, it
    /// returns `false`.
    pub fn validate_tag(
        &self,
        tag: &BitSlice,
        tag_gst: Gst,
        prnd: u8,
        prna: Svn,
        ctr: u8,
        navdata: &BitSlice,
    ) -> bool {
        let mut mac = self.mac_digest();
        mac.update(&[prnd]);
        self.update_common_tag_message(&mut mac, tag_gst, prna, ctr, navdata);
        self.check_common(mac, tag)
    }

    /// Tries to validate a tag0 and its corresponding navigation data.
    ///
    /// The algorithm in Section 6.7 of the
    /// [OSNMA SIS ICD v1.1](https://www.gsc-europa.eu/sites/default/files/sites/all/files/Galileo_OSNMA_SIS_ICD_v1.1.pdf).
    /// Is used to attempt to validate a tag and its corresponding navigation data.
    ///
    /// The `tag_gst` parameter should give the GST at the start of the subframe
    /// when the `tag` was transmitted. The `prna` parameter corresponds to the
    /// SVN of the satellite that transmitted the tag0.
    ///
    /// Note that the navigation data `navdata` must correspond to the previous
    /// subframe of the tag0, and the key `self` must correspond to the next
    /// subframe of the tag0.
    ///
    /// This returns `true` if the validation was succesful. Otherwise, it
    /// returns `false`.
    pub fn validate_tag0(
        &self,
        tag0: &BitSlice,
        tag_gst: Gst,
        prna: Svn,
        navdata: &BitSlice,
    ) -> bool {
        let mut mac = self.mac_digest();
        self.update_common_tag_message(&mut mac, tag_gst, prna, 1, navdata);
        self.check_common(mac, tag0)
    }

    fn mac_digest(&self) -> MacDigest {
        let key = &self.data[..self.chain.key_size_bytes];
        MacDigest::new_from_slice(self.chain.mac_function, key).unwrap()
    }

    fn update_common_tag_message(
        &self,
        mac: &mut MacDigest,
        gst: Gst,
        prna: Svn,
        ctr: u8,
        navdata: &BitSlice,
    ) {
        // This is large enough to fit all the message for ADKD=0 and 12
        // (which have the largest navdata size, equal to 549 bits)
        const MAX_NAVDATA_SIZE: usize = 69;
        const FIXED_SIZE: usize = 6;
        const BUFF_SIZE: usize = FIXED_SIZE + MAX_NAVDATA_SIZE;
        let mut buffer = [0u8; BUFF_SIZE];
        buffer[0] = u8::from(prna);
        Self::store_gst(&mut buffer[1..5], gst);
        buffer[5] = ctr;
        let remaining_bits = BitSlice::from_slice_mut(&mut buffer[6..]);
        const STATUS_BITS: usize = 2;
        remaining_bits[..STATUS_BITS].store_be(match self.chain.status {
            ChainStatus::Test => 1,
            ChainStatus::Operational => 2,
        });
        remaining_bits[STATUS_BITS..STATUS_BITS + navdata.len()].copy_from_bitslice(navdata);
        let message_bytes = FIXED_SIZE + (STATUS_BITS + navdata.len() + 7) / 8;
        mac.update(&buffer[..message_bytes]);
    }

    fn check_common(&self, mac: MacDigest, tag: &BitSlice) -> bool {
        let mut mac_out = GenericArray::default();
        mac.finalize_into(&mut mac_out);
        let computed = &BitSlice::from_slice(&mac_out)[..tag.len()];
        computed == tag
    }

    /// Tries to validate the MACSEQ field in a MACK message.
    ///
    /// The algorithm in Section 6.6 of the
    /// [OSNMA SIS ICD v1.1](https://www.gsc-europa.eu/sites/default/files/sites/all/files/Galileo_OSNMA_SIS_ICD_v1.1.pdf).
    /// Is used to attempt to validate the contents of the MACSEQ field in the MACK
    /// message.
    ///
    /// The `prna` parameter corresponds to the SVN of the satellite that
    /// transmitted the MACK message, and `gst_mack` gives the GST at the start
    /// of the subframe when the MACK message was transmitted.
    ///
    /// Note that the key `self` must correspond to the next subframe of the
    /// MACK message.
    ///
    /// The function returns `Ok` if the validation was successful, and an error
    /// otherwise.
    pub fn validate_macseq<V: Clone>(
        &self,
        mack: &Mack<V>,
        prna: Svn,
        gst_mack: Gst,
    ) -> Result<(), MacseqCheckError> {
        let mut mac = self.mac_digest();
        let mut buffer = [0u8; FIXED_SIZE];
        const TAG_INFO_SIZE: usize = 2; // size of tag-info in bytes
        const FIXED_SIZE: usize = 5; // size in bytes required for PRN_A and GST_SF
        buffer[0] = prna.into();
        Self::store_gst(&mut buffer[1..5], gst_mack);
        mac.update(&buffer);
        // update MAC with FLX tag-info's
        let msg = usize::try_from((gst_mack.tow() / 30) % 2).unwrap(); // Half of the GST minute
        let maclt = self.chain().mac_lookup_table();
        for idx in get_flx_indices(maclt, msg)? {
            let tag_and_info = mack.tag_and_info(idx);
            let dest = BitSlice::from_slice_mut(&mut buffer[..TAG_INFO_SIZE]);
            dest.copy_from_bitslice(tag_and_info.tag_info());
            mac.update(&buffer[..TAG_INFO_SIZE]);
        }
        let mut mac_out = GenericArray::default();
        mac.finalize_into(&mut mac_out);
        const MACSEQ_BITS: usize = 12;
        let computed = &BitSlice::from_slice(&mac_out)[..MACSEQ_BITS];

        let mut macseq_buffer = [0u8; 2];
        let macseq_bits = &mut BitSlice::from_slice_mut(&mut macseq_buffer)[..MACSEQ_BITS];
        macseq_bits.store_be::<u16>(mack.macseq());
        if computed == macseq_bits {
            Ok(())
        } else {
            Err(MacseqCheckError::WrongMacseq)
        }
    }
}

/// Errors produced during the validation of a MACSEQ field.
///
/// This gives the errors that can happen during the validation of a MACSEQ field
/// using [`Key::validate_macseq`].
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum MacseqCheckError {
    /// MAC Look-up Table error.
    MacLTError(MacLTError),
    /// The calculated MACSEQ does not match the one in the MACK.
    WrongMacseq,
}

impl fmt::Display for MacseqCheckError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MacseqCheckError::MacLTError(err) => err.fmt(f),
            MacseqCheckError::WrongMacseq => "MACSEQ field is wrong".fmt(f),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for MacseqCheckError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            MacseqCheckError::MacLTError(err) => Some(err),
            _ => None,
        }
    }
}

impl From<MacLTError> for MacseqCheckError {
    fn from(value: MacLTError) -> MacseqCheckError {
        MacseqCheckError::MacLTError(value)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use hex_literal::hex;

    fn test_chain() -> Chain {
        // Active chain on 2022-03-07 ~09:00 UTC
        Chain {
            status: ChainStatus::Test,
            id: 1,
            hash_function: HashFunction::Sha256,
            mac_function: MacFunction::HmacSha256,
            key_size_bytes: 16,
            tag_size_bits: 40,
            maclt: 0x21,
            alpha: 0x25d3964da3a2,
        }
    }

    fn test_chain_2023() -> Chain {
        // Active chain on 2023-12-12 ~10:00 UTC
        Chain {
            status: ChainStatus::Test,
            id: 0,
            hash_function: HashFunction::Sha256,
            mac_function: MacFunction::HmacSha256,
            key_size_bytes: 16,
            tag_size_bits: 40,
            maclt: 34,
            alpha: 0xe409305bb856,
        }
    }

    #[test]
    fn one_way_function() {
        // Keys broadcast on 2022-03-07 ~9:00 UTC
        let chain = test_chain();
        let k0 = Key::from_slice(
            &hex!("42 b4 19 da 6a da 1c 0a 3d 6f 56 a5 e5 dc 59 a7"),
            Gst::new(1176, 120930),
            &chain,
        );
        let k1 = Key::from_slice(
            &hex!("95 42 aa d4 7a bf 39 ba fe 56 68 61 af e8 80 b2"),
            Gst::new(1176, 120960),
            &chain,
        );
        assert_eq!(k1.one_way_function(), k0);
    }

    #[test]
    fn validation_kroot() {
        // KROOT broadcast on 2022-03-07 ~9:00 UTC
        let chain = test_chain();
        let kroot = Key::from_slice(
            &hex!("84 1e 1d e4 d4 58 c0 e9 84 24 76 e0 04 66 6c f3"),
            Gst::new(1176, 0x21 * 3600 - 30), // towh in DSM-KROOT was 0x21
            &chain,
        );
        // Force KROOT to be valid manually
        let kroot = kroot.force_valid();
        let key = Key::from_slice(
            &hex!("42 b4 19 da 6a da 1c 0a 3d 6f 56 a5 e5 dc 59 a7"),
            Gst::new(1176, 120930),
            &chain,
        );
        assert!(kroot.validate_key(&key).is_ok());
    }

    #[test]
    fn tag0() {
        // Data corresponding to E21 on 2022-03-07 ~9:00 UTC
        let tag0 = BitSlice::from_slice(&hex!("8f 54 58 88 71"));
        let tag0_gst = Gst::new(1176, 121050);
        let prna = Svn::try_from(21).unwrap();
        let chain = test_chain();
        let key = Key::from_slice(
            &hex!("19 58 e7 76 6f b4 08 cb d6 a8 de fc e4 c7 d5 66"),
            Gst::new(1176, 121080),
            &chain,
        )
        .force_valid();
        let navdata_adkd0 = &BitSlice::from_slice(&hex!(
            "
            12 07 d0 ec 19 90 2e 00 1f e1 06 aa 04 ed 97 12
            11 f0 56 1f 49 ea ce 67 88 4d 18 57 81 9f 12 3f
            f0 37 48 93 42 c3 c2 96 c7 65 c3 83 1a c4 85 40
            01 7f fd 87 d0 fe 85 ee 31 ff f6 20 0c 68 0b fe
            48 00 50 14 00"
        ))[..549];
        assert!(key.validate_tag0(tag0, tag0_gst, prna, navdata_adkd0));
    }

    fn test_mack() -> Mack<'static, NotValidated> {
        // Data broadcast by E19 on 2022-03-07 ~9:00 UTC
        let key_size = 128;
        let tag_size = 40;
        Mack::new(
            &hex!(
                "
                7e ff 9e 16 a5 dd f0 04 f0 3c 9b 6b 1b 07 4d 49
                2e dd 67 0b 02 60 ef 9b 83 36 13 c0 94 a8 72 a7
                f6 12 05 8f 2e f7 63 24 0e c5 ca 40 0f ad f1 12
                47 9f 05 44 9a 25 d8 2e 80 c8 00 00"
            ),
            key_size,
            tag_size,
        )
    }

    fn test_mack_2023() -> Mack<'static, NotValidated> {
        // Data broadcast by E03 on 2023-12-12 ~10:00 UTC
        let key_size = 128;
        let tag_size = 40;
        Mack::new(
            &hex!(
                "
                88 36 af a3 5b eb b1 32 bf 2f 08 e9 24 0f 0a d4
                c0 4f a2 08 0f 1d 02 fb 7f 53 03 c1 d4 a6 c5 3b
                4a 05 0f 82 b1 53 4c fe 08 cf b3 2c df 02 5f 50
                cf 39 04 d2 78 26 30 39 10 bf 00 00"
            ),
            key_size,
            tag_size,
        )
    }

    fn test_key() -> Key<NotValidated> {
        Key::from_slice(
            &hex!("19 58 e7 76 6f b4 08 cb d6 a8 de fc e4 c7 d5 66"),
            Gst::new(1176, 121080),
            &test_chain(),
        )
    }

    fn test_key_2023() -> Key<NotValidated> {
        Key::from_slice(
            &hex!("33 4f d3 e5 68 c0 4e 2a 44 db a7 8a 03 01 c3 4a"),
            Gst::new(1268, 208920),
            &test_chain_2023(),
        )
    }

    #[test]
    fn adkd() {
        // This does not include FLX entries
        let mack = test_mack();
        let prna = Svn::try_from(19).unwrap();
        for j in 1..mack.num_tags() {
            assert!(test_chain()
                .validate_adkd(j, mack.tag_and_info(j), prna, Gst::new(1176, 121050))
                .is_ok());
        }
    }

    #[test]
    fn adkd_2023() {
        // This includes FLX entries
        let mack = test_mack_2023();
        let prna = Svn::try_from(3).unwrap();
        for j in 1..mack.num_tags() {
            assert!(test_chain()
                .validate_adkd(j, mack.tag_and_info(j), prna, Gst::new(1268, 208890))
                .is_ok());
        }
    }

    #[test]
    fn macseq() {
        // This does not include FLX entries
        let key = test_key().force_valid();
        let mack = test_mack();
        let prna = Svn::try_from(19).unwrap();
        assert_eq!(
            key.validate_macseq(&mack, prna, Gst::new(1176, 121050)),
            Ok(())
        );
    }

    #[test]
    fn macseq_2023() {
        // This includes FLX entries
        let key = test_key_2023().force_valid();
        let mack = test_mack_2023();
        let prna = Svn::try_from(3).unwrap();
        assert_eq!(
            key.validate_macseq(&mack, prna, Gst::new(1268, 208890)),
            Ok(())
        );
    }
}
