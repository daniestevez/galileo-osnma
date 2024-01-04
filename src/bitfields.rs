//! Message bit fields.
//!
//! This module contains structures that give acccess to each of the fields in
//! the messages used by OSNMA. As a general rule, the structures are a wrapper
//! over a `&[u8]` or `&[u8; N]`.

use crate::tesla::{AdkdCheckError, Key, MacseqCheckError};
use crate::types::{BitSlice, MackMessage, Towh, MACK_MESSAGE_BYTES};
use crate::validation::{NotValidated, Validated};
use crate::{Gst, Svn, Wn};
use bitvec::prelude::*;
use core::fmt;
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use sha2::{Digest, Sha256};

/// NMA header.
///
/// The NMA header found in the first byte of an HKROOT message.
/// See Figure 4 in the
/// [OSNMA ICD](https://www.gsc-europa.eu/sites/default/files/sites/all/files/Galileo_OSNMA_User_ICD_for_Test_Phase_v1.0.pdf).
#[derive(Copy, Clone, Eq, PartialEq, Hash)]
pub struct NmaHeader<'a>(
    /// Reference to an array containing the 1-byte header data.
    pub &'a [u8; 1],
);

/// Status of the NMA chain.
///
/// This represents the values of the NMAS field of the [`NmaHeader`]
/// as defined in Section 3.1.1 of the
/// [OSNMA ICD](https://www.gsc-europa.eu/sites/default/files/sites/all/files/Galileo_OSNMA_User_ICD_for_Test_Phase_v1.0.pdf).
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum NmaStatus {
    /// Reserved value (NMAS = 0),
    Reserved,
    /// Test (NMAS = 1),
    Test,
    /// Operational (NMAS = 2).
    Operational,
    /// Don't use (NMAS = 3).
    DontUse,
}

/// Chain and Public Key status.
///
/// This represents the valus of the CPKS field of the [`NmaHeader`]
/// as defined in Section 3.1.3 of the
/// [OSNMA ICD](https://www.gsc-europa.eu/sites/default/files/sites/all/files/Galileo_OSNMA_User_ICD_for_Test_Phase_v1.0.pdf).
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum ChainAndPubkeyStatus {
    /// Reserved value (CPKS = 0).
    Reserved,
    /// Nominal (CPKS = 1).
    Nominal,
    /// End of chain (EOC) (CPKS = 2).
    EndOfChain,
    /// Chain revoked (CREV) (CPKS = 3).
    ChainRevoked,
    /// New public key (NPK) (CPKS = 4).
    NewPublicKey,
    /// Public key revoked (PKREV) (CPKS = 5).
    PublicKeyRevoked,
    /// New Merkle tree (NMT) (CPKS = 6).
    NewMerkleTree,
    /// Alert Message (AM) (CPKS = 7)
    AlertMessage,
}

impl<'a> NmaHeader<'a> {
    fn bits(&self) -> &BitSlice {
        BitSlice::from_slice(self.0)
    }

    /// Gives the value of the NMAS (NMA status) field.
    pub fn nma_status(&self) -> NmaStatus {
        match self.bits()[..2].load_be::<u8>() {
            0 => NmaStatus::Reserved,
            1 => NmaStatus::Test,
            2 => NmaStatus::Operational,
            3 => NmaStatus::DontUse,
            _ => unreachable!(),
        }
    }

    /// Gives the value of the CID (chain ID) field.
    pub fn chain_id(&self) -> u8 {
        self.bits()[2..4].load_be::<u8>()
    }

    /// Gives the value of the CPKS (chain and public key status) field.
    pub fn chain_and_pubkey_status(&self) -> ChainAndPubkeyStatus {
        match self.bits()[4..7].load_be::<u8>() {
            0 => ChainAndPubkeyStatus::Reserved,
            1 => ChainAndPubkeyStatus::Nominal,
            2 => ChainAndPubkeyStatus::EndOfChain,
            3 => ChainAndPubkeyStatus::ChainRevoked,
            4 => ChainAndPubkeyStatus::NewPublicKey,
            5 => ChainAndPubkeyStatus::PublicKeyRevoked,
            6 => ChainAndPubkeyStatus::NewMerkleTree,
            7 => ChainAndPubkeyStatus::AlertMessage,
            8.. => unreachable!(), // we are only reading 3 bits
        }
    }
}

impl fmt::Debug for NmaHeader<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NmaHeader")
            .field("nma_status", &self.nma_status())
            .field("chain_id", &self.chain_id())
            .field("chain_and_pubkey_status", &self.chain_and_pubkey_status())
            .finish()
    }
}

/// DSM header.
///
/// The DSM header found in the second byte of an HKROOT message.
/// See Figure 5 in the
/// [OSNMA ICD](https://www.gsc-europa.eu/sites/default/files/sites/all/files/Galileo_OSNMA_User_ICD_for_Test_Phase_v1.0.pdf).
#[derive(Copy, Clone, Eq, PartialEq, Hash)]
pub struct DsmHeader<'a>(
    /// Reference to an array containing the 1-byte header data.
    pub &'a [u8; 1],
);

/// Type of the DSM message.
///
/// This is derived from the DSM ID field according to Section 3.2.1.1 in the
/// [OSNMA ICD](https://www.gsc-europa.eu/sites/default/files/sites/all/files/Galileo_OSNMA_User_ICD_for_Test_Phase_v1.0.pdf).
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum DsmType {
    /// DSM-KROOT.
    ///
    /// This message is used to transmit the TESLA root key. It corresponds to
    /// DSM IDs 0 to 11.
    Kroot,
    /// DSM-PKR.
    ///
    /// This message is used to transmit a new ECDSA public key. It corresponds
    /// to DSM IDs 12 to 15.
    Pkr,
}

impl<'a> DsmHeader<'a> {
    fn bits(&self) -> &BitSlice {
        BitSlice::from_slice(self.0)
    }

    /// Gives the value of the DSM ID field.
    pub fn dsm_id(&self) -> u8 {
        self.bits()[..4].load_be()
    }

    /// Gives the value of the DSM block ID field.
    pub fn dsm_block_id(&self) -> u8 {
        self.bits()[4..8].load_be()
    }

    /// Gives the type of DSM message, according to the DSM ID field.
    pub fn dsm_type(&self) -> DsmType {
        if self.dsm_id() >= 12 {
            DsmType::Pkr
        } else {
            DsmType::Kroot
        }
    }
}

impl fmt::Debug for DsmHeader<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DsmHeader")
            .field("dsm_id", &self.dsm_id())
            .field("dsm_block_id", &self.dsm_block_id())
            .finish()
    }
}

/// DSM-KROOT message.
///
/// The DSM-KROOT message, as defined in Figure 7 of the
/// [OSNMA ICD](https://www.gsc-europa.eu/sites/default/files/sites/all/files/Galileo_OSNMA_User_ICD_for_Test_Phase_v1.0.pdf).
#[derive(Copy, Clone, Eq, PartialEq, Hash)]
pub struct DsmKroot<'a>(
    /// Reference to a slice containing the DSM-KROOT message data.
    ///
    /// # Panics
    ///
    /// This slice should be long enough to contain the full DSM-KROOT
    /// message. Otherwise the methods of `DsmKroot` may panic.
    pub &'a [u8],
);

/// Hash function.
///
/// This represents the values of the Hash Function (HF) field of the DSM-KROOT
/// message. See Table 8 in the
/// [OSNMA ICD](https://www.gsc-europa.eu/sites/default/files/sites/all/files/Galileo_OSNMA_User_ICD_for_Test_Phase_v1.0.pdf).
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum HashFunction {
    /// SHA-256 (HF = 0).
    Sha256,
    /// SHA3-256 (HF = 2).
    Sha3_256,
    /// Reserved value (HF = 1, 3).
    Reserved,
}

/// MAC function.
///
/// This represents the values of the MAC Function (MF) field of the DSM-KROOT
/// message. See Table 9 in the
/// [OSNMA ICD](https://www.gsc-europa.eu/sites/default/files/sites/all/files/Galileo_OSNMA_User_ICD_for_Test_Phase_v1.0.pdf).
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum MacFunction {
    /// HMAC-SHA-256 (MF = 0).
    HmacSha256,
    /// CMAC-AES (MF = 1).
    CmacAes,
    /// Reserved value (MF = 2, 3).
    Reserved,
}

/// ECDSA function.
///
/// This represents the key types available for ECDSA signatures. See Table 15
/// in the
/// [OSNMA ICD](https://www.gsc-europa.eu/sites/default/files/sites/all/files/Galileo_OSNMA_User_ICD_for_Test_Phase_v1.0.pdf).
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum EcdsaFunction {
    /// ECDSA P-256/SHA-256.
    P256Sha256,
    /// ECDSA P-521/SHA-512
    P521Sha512,
}

impl<'a> DsmKroot<'a> {
    fn bits(&self) -> &BitSlice {
        BitSlice::from_slice(self.0)
    }

    /// Gives the number of DSM-KROOT blocks.
    ///
    /// The number is computed according to the value of the NB_DK field and
    /// Table 7 in the
    /// [OSNMA ICD](https://www.gsc-europa.eu/sites/default/files/sites/all/files/Galileo_OSNMA_User_ICD_for_Test_Phase_v1.0.pdf).
    ///
    /// If the NB_DK field contains a reserved value, `None` is returned.
    pub fn number_of_blocks(&self) -> Option<usize> {
        match self.bits()[..4].load_be::<u8>() {
            1 => Some(7),
            2 => Some(8),
            3 => Some(9),
            4 => Some(10),
            5 => Some(11),
            6 => Some(12),
            7 => Some(13),
            8 => Some(14),
            _ => None, // reserved value
        }
    }

    /// Gives the value of the PKID (public key ID) field.
    pub fn public_key_id(&self) -> u8 {
        self.bits()[4..8].load_be::<u8>()
    }

    /// Gives the value of the CIDKR (KROOT chain ID) field.
    pub fn kroot_chain_id(&self) -> u8 {
        self.bits()[8..10].load_be::<u8>()
    }

    /// Gives the value of the hash function field.
    pub fn hash_function(&self) -> HashFunction {
        match self.bits()[12..14].load_be::<u8>() {
            0 => HashFunction::Sha256,
            2 => HashFunction::Sha3_256,
            _ => HashFunction::Reserved,
        }
    }

    /// Gives the value of the MAC function field.
    pub fn mac_function(&self) -> MacFunction {
        match self.bits()[14..16].load_be::<u8>() {
            0 => MacFunction::HmacSha256,
            1 => MacFunction::CmacAes,
            _ => MacFunction::Reserved,
        }
    }

    /// Gives the TESLA key size in bits.
    ///
    /// The size is computed according to the value of the KS field and
    /// Table 10 in the
    /// [OSNMA ICD](https://www.gsc-europa.eu/sites/default/files/sites/all/files/Galileo_OSNMA_User_ICD_for_Test_Phase_v1.0.pdf).
    ///
    /// If the KS field contains a reserved value, `None` is returned.
    pub fn key_size(&self) -> Option<usize> {
        // note that all the key sizes are a multiple of 8 bits
        let size = match self.bits()[16..20].load_be::<u8>() {
            0 => Some(96),
            1 => Some(104),
            2 => Some(112),
            3 => Some(120),
            4 => Some(128),
            5 => Some(160),
            6 => Some(192),
            7 => Some(224),
            8 => Some(256),
            _ => None,
        };
        if let Some(s) = size {
            debug_assert!(s % 8 == 0);
        }
        size
    }

    /// Gives the MAC tag size in bits.
    ///
    /// The size is computed according to the value of the TS field and
    /// Table 11 in the
    /// [OSNMA ICD](https://www.gsc-europa.eu/sites/default/files/sites/all/files/Galileo_OSNMA_User_ICD_for_Test_Phase_v1.0.pdf).
    ///
    /// If the TS field contains a reserved value, `None` is returned.
    pub fn tag_size(&self) -> Option<usize> {
        match self.bits()[20..24].load_be::<u8>() {
            5 => Some(20),
            6 => Some(24),
            7 => Some(28),
            8 => Some(32),
            9 => Some(40),
            _ => None,
        }
    }

    /// Gives the value of the MACLT (MAC look-up table) field.
    pub fn mac_lookup_table(&self) -> u8 {
        self.bits()[24..32].load_be()
    }

    /// Gives the KROOT week number.
    ///
    /// This is the value of the WNK field.
    pub fn kroot_wn(&self) -> Wn {
        self.bits()[36..48].load_be()
    }

    /// Gives the KROOT time of week in hours.
    ///
    /// This is the value of the TOWHK field.
    pub fn kroot_towh(&self) -> Towh {
        self.bits()[48..56].load_be()
    }

    /// Gives the value of the random pattern alpha.
    ///
    /// The random pattern alpha is a 48-bit value. Here it is given in a `u64`.
    pub fn alpha(&self) -> u64 {
        self.bits()[56..104].load_be()
    }

    /// Returns a slice reference to the KROOT in the DSM-KROOT message.
    ///
    /// This is the contents of the KROOT field. The length of the returned slice
    /// depends on the TESLA key size.
    ///
    /// # Panics
    ///
    /// Panics if the key size field in the DSM-KROOT message contains a reserved
    /// value.
    pub fn kroot(&self) -> &[u8] {
        let size = self
            .key_size()
            .expect("attempted to extract kroot of DSM with reserved key size");
        let size_bytes = size / 8;
        &self.0[13..13 + size_bytes]
    }

    /// Returns the ECDSA function used by this DSM-KROOT message.
    ///
    /// The ECDSA function is guessed from the size of the ECDSA signature
    /// in the message.
    ///
    /// # Panics
    ///
    /// Panics if the ECDSA function cannot be guessed because the size of
    /// the signature is neither 512 bits (for P-256) nor 1056 bits (for P-521).
    pub fn ecdsa_function(&self) -> EcdsaFunction {
        // Although the ICD is not clear about this, we can guess the
        // ECDSA function in use from the size of the DSM-KROOT
        let total_len = self.0.len();
        let fixed_len = 13;
        let kroot_len = self.kroot().len();
        let remaining_len = total_len - fixed_len - kroot_len;
        let b = 13; // block size
        let p256_bytes = 64; // 512 bits
        let p521_bytes = 132; // 1056 bits
        let p256_padding = (b - (kroot_len + p256_bytes) % b) % b;
        let p521_padding = (b - (kroot_len + p521_bytes) % b) % b;
        if remaining_len == p256_bytes + p256_padding {
            EcdsaFunction::P256Sha256
        } else if remaining_len == p521_bytes + p521_padding {
            EcdsaFunction::P521Sha512
        } else {
            panic!(
                "failed to guess ECDSA function with DSM-KROOT total len = {}\
                    and kroot len = {}",
                total_len, kroot_len
            );
        }
    }

    /// Returns a slice reference to the ECDSA signature in the DSM-KROOT message.
    ///
    /// This is the contents of the digital signature (DS) field. The length of
    /// the returned slice depend on the ECDSA function in use.
    ///
    /// # Panics
    ///
    /// Panics if the ECDSA function cannot be guessed because the size of
    /// the signature is neither 512 bits (for P-256) nor 1056 bits (for P-521).
    pub fn digital_signature(&self) -> &[u8] {
        let size = match self.ecdsa_function() {
            EcdsaFunction::P256Sha256 => 64,
            EcdsaFunction::P521Sha512 => 132,
        };
        let start = 13 + self.kroot().len();
        &self.0[start..start + size]
    }

    /// Gives the contents of the DSM-KROOT padding (P_DK) field.
    pub fn padding(&self) -> &[u8] {
        let start = 13 + self.kroot().len() + self.digital_signature().len();
        &self.0[start..]
    }

    // message for digital signature verification
    fn signature_message(&self, nma_header: NmaHeader) -> ([u8; 209], usize) {
        let mut m = [0; 209];
        m[0] = nma_header.0[0];
        let end = 13 + self.kroot().len();
        // we skip the NB_DK and PKID fields in self.0
        m[1..end].copy_from_slice(&self.0[1..end]);
        (m, end)
    }

    /// Checks the contents of the padding field.
    ///
    /// The contents are checked according to Eq. 7 in the
    /// [OSNMA ICD](https://www.gsc-europa.eu/sites/default/files/sites/all/files/Galileo_OSNMA_User_ICD_for_Test_Phase_v1.0.pdf).
    ///
    /// If the contents are correct, this returns `true`. Otherwise, this
    /// returns `false`.
    pub fn check_padding(&self, nma_header: NmaHeader) -> bool {
        // maximum size is 209 bytes for the message and 132 bytes for
        // the P521Sha512 signature
        let mut buff = [0_u8; 209 + 132];
        let (message, size) = self.signature_message(nma_header);
        let message = &message[..size];
        let a = message.len();
        buff[..a].copy_from_slice(message);
        let signature = self.digital_signature();
        let b = a + signature.len();
        buff[a..b].copy_from_slice(signature);
        let mut hash = Sha256::new();
        hash.update(&buff[..b]);
        let hash = hash.finalize();
        let padding = self.padding();
        let truncated = &hash[..padding.len()];
        truncated == padding
    }

    /// Checks the ECDSA signature.
    ///
    /// This verifies that the ECDSA signature of the DSM-KROOT message is
    /// correct. The algorithm in Section 6.3 of the
    /// [OSNMA ICD](https://www.gsc-europa.eu/sites/default/files/sites/all/files/Galileo_OSNMA_User_ICD_for_Test_Phase_v1.0.pdf)
    /// is followed.
    ///
    /// Only P-256 signatures are supported.
    ///
    /// # Panics
    ///
    /// Panics if the ECDSA signature cannot be serialized.
    ///
    pub fn check_signature(&self, nma_header: NmaHeader, pubkey: &VerifyingKey) -> bool {
        let (message, size) = self.signature_message(nma_header);
        let message = &message[..size];
        let signature = Signature::from_bytes(self.digital_signature().into())
            .expect("error serializing ECDSA signature");
        pubkey.verify(message, &signature).is_ok()
    }
}

impl fmt::Debug for DsmKroot<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DsmKroot")
            .field("number_of_blocks", &self.number_of_blocks())
            .field("public_key_id", &self.public_key_id())
            .field("kroot_chain_id", &self.kroot_chain_id())
            .field("hash_function", &self.hash_function())
            .field("mac_function", &self.mac_function())
            .field("key_size", &self.key_size())
            .field("tag_size", &self.tag_size())
            .field("mac_loopkup_table", &self.mac_lookup_table())
            .field("kroot_wn", &self.kroot_wn())
            .field("kroot_towh", &self.kroot_towh())
            .field("alpha", &self.alpha())
            .field("kroot", &self.kroot())
            .field("digital_signature", &self.digital_signature())
            .field("padding", &self.padding())
            .finish()
    }
}

/// MACK message.
///
/// The MACK message, as defined in Figure 8 of the
/// [OSNMA ICD](https://www.gsc-europa.eu/sites/default/files/sites/all/files/Galileo_OSNMA_User_ICD_for_Test_Phase_v1.0.pdf).
///
/// This is one of the few structs in [bitfields](crate::bitfields) that is not
/// a simple wrapper around a slice. The reason is that to interpret the MACK
/// message, it is necessary to know the key and tag sizes, so `Mack` holds
/// these values as well.
///
/// The `V` type parameter is used to indicate the validation status of the MACK
/// message. Validation of a MACK message corresponds to checking its MACSEQ
/// field and that its ADKDs match the corresponding look-up table. See
/// [validation](crate::validation) for a description of validation type
/// parameters.
#[derive(Copy, Clone, Eq, PartialEq, Hash)]
pub struct Mack<'a, V> {
    data: &'a BitSlice,
    key_size: usize,
    tag_size: usize,
    _validated: V,
}

impl<'a> Mack<'a, NotValidated> {
    /// Constructs a new MACK message.
    ///
    /// The `data` should be a reference to an array containing the 60 bytes of
    /// the MACK message. The `key_size` in bits and `tag_size` in bits should
    /// be taken from the parameters of the current TESLA chain. The MACK
    /// message is marked as [`NotValidated`].
    pub fn new(data: &MackMessage, key_size: usize, tag_size: usize) -> Mack<NotValidated> {
        Mack {
            data: BitSlice::from_slice(data),
            key_size,
            tag_size,
            _validated: NotValidated {},
        }
    }
}

impl<'a, V> Mack<'a, V> {
    /// Gives the key size in bits corresponding to the MACK message.
    ///
    /// This returns the value that has been given in [`Mack::new`].
    pub fn key_size(&self) -> usize {
        self.key_size
    }

    /// Gives the key size in bits corresponding to the MACK message.
    ///
    /// This returns the value that has been given in [`Mack::new`].
    pub fn tag_size(&self) -> usize {
        self.tag_size
    }

    /// Gives the tag0 field contained in the MACK header of the MACK message.
    ///
    /// See Figure 9 in the
    /// [OSNMA ICD](https://www.gsc-europa.eu/sites/default/files/sites/all/files/Galileo_OSNMA_User_ICD_for_Test_Phase_v1.0.pdf).
    pub fn tag0(&self) -> &BitSlice {
        &self.data[..self.tag_size()]
    }

    /// Gives the value of the MACSEQ field contained in the MACK header of the MACK message.
    ///
    /// See Figure 9 in the
    /// [OSNMA ICD](https://www.gsc-europa.eu/sites/default/files/sites/all/files/Galileo_OSNMA_User_ICD_for_Test_Phase_v1.0.pdf).
    /// The MACSEQ is a 12-bit integer, which is returned as a `u16`.
    pub fn macseq(&self) -> u16 {
        let macseq_size = 12;
        self.data[self.tag_size()..self.tag_size() + macseq_size].load_be::<u16>()
    }

    /// Gives the value of the COP field contained in the MACK header of the MACK message.
    ///
    /// See Figure 9 in the [OSNMA ICD](https://www.gsc-europa.eu/sites/default/files/sites/all/files/Galileo_OSNMA_SIS_ICD_v1.0.pdf).
    /// The COP is a 4-bit integer, which is returned as a `u8`.
    pub fn cop(&self) -> u8 {
        let macseq_size = 12;
        let cop_offset = self.tag_size() + macseq_size;
        let cop_size = 4;
        self.data[cop_offset..cop_offset + cop_size].load_be::<u8>()
    }

    /// Returns the number of tags in the MACK message.
    ///
    /// The number of tags is computed according to the tag size.
    pub fn num_tags(&self) -> usize {
        (8 * MACK_MESSAGE_BYTES - self.key_size()) / (self.tag_size() + 16)
    }

    /// Gives the Key field of the MACK message.
    ///
    /// This fields contains a TESLA key. See Figure 8 in the
    /// [OSNMA ICD](https://www.gsc-europa.eu/sites/default/files/sites/all/files/Galileo_OSNMA_User_ICD_for_Test_Phase_v1.0.pdf).
    pub fn key(&self) -> &BitSlice {
        let start = (self.tag_size() + 16) * self.num_tags();
        &self.data[start..start + self.key_size()]
    }
}

/// MACK validation error
///
/// This enum lists the possible errors that can happen when a MACK message
/// validation using [`Mack::validate`] is attempted.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum MackValidationError {
    /// The MACSEQ field could not be verified.
    ///
    /// The MACSEQ field is checked using the algorithm in Section 6.6 of the
    /// [OSNMA ICD](https://www.gsc-europa.eu/sites/default/files/sites/all/files/Galileo_OSNMA_User_ICD_for_Test_Phase_v1.0.pdf).
    MacseqError(MacseqCheckError),
    /// One of the ADKD fields is not correct.
    WrongAdkd {
        /// The index of the first tag whose ADKD is not correct.
        tag_index: usize,
        /// The reason why the ADKD field is not correct.
        error: AdkdCheckError,
    },
}

impl fmt::Display for MackValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MackValidationError::MacseqError(err) => err.fmt(f),
            MackValidationError::WrongAdkd { tag_index, error } => {
                write!(f, "incorrect ADKD field at tag {} ({})", tag_index, error)
            }
        }
    }
}

impl From<MacseqCheckError> for MackValidationError {
    fn from(value: MacseqCheckError) -> MackValidationError {
        MackValidationError::MacseqError(value)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for MackValidationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            MackValidationError::MacseqError(err) => Some(err),
            MackValidationError::WrongAdkd { error, .. } => Some(error),
        }
    }
}

impl<'a, V: Clone> Mack<'a, V> {
    /// Gives an object representing one of the Tag-Info sections in the MACK message.
    ///
    /// The Tag-Info section is defined in Figure 11 of the [OSNMA
    /// ICD](https://www.gsc-europa.eu/sites/default/files/sites/all/files/Galileo_OSNMA_User_ICD_for_Test_Phase_v1.0.pdf).
    /// The parameter `n` corresponds to the index of the Tag-Info in the MACK
    /// message. The first Tag-Info has `n = 1`, since `n = 0` would correspond
    /// to the Tag0 field, which does not have an associated info field and is
    /// obtained with [`Mack::tag0`].
    ///
    /// The validation status of the Tag-Info is inherited from the validation
    /// status of the MACK message. There is no way to validate Tag-Info
    /// sections once they have been separated from the MACK message. If a
    /// validated Tag-Info is needed, the whole MACK message should be validated
    /// first using [`Mack::validate`] before calling [`Mack::tag_and_info`].
    ///
    /// # Panics
    ///
    /// Panics if `n` is not between 1 and `self.num_tags() - 1`.
    pub fn tag_and_info(&self, n: usize) -> TagAndInfo<'_, V> {
        assert!(0 < n && n < self.num_tags());
        let size = self.tag_size() + 16;
        TagAndInfo {
            data: &self.data[size * n..size * (n + 1)],
            _validated: self._validated.clone(),
        }
    }

    /// Try to validate the MACK message.
    ///
    /// Given the TESLA `key` transmitted on the next subframe, this will
    /// attempt to validate the MACSEQ field and the ADKD fields of the MACK
    /// message. The MACSEQ field is checked using the algorithm in Section 6.6
    /// of the
    /// [OSNMA ICD](https://www.gsc-europa.eu/sites/default/files/sites/all/files/Galileo_OSNMA_User_ICD_for_Test_Phase_v1.0.pdf).
    /// The sequence of ADKD fields is checked against the MAC look-up table
    /// using the chain parameters held by the TESLA key.
    ///
    /// The parameter `prna` should be the SVN of the satellite that transmitted
    /// this MACK message, and `gst_mack` corresponds to the GST at the start of
    /// the subframe in which the MACK message was transmitted. The `maclt`
    /// parameter indicates the active MAC Look-up Table id. It is used to
    /// determine which tags are flexible.
    ///
    /// If the validation is successful, this returns a copy of `self` with the
    /// validation type parameter `V` set to `Validated`. Otherwise, an error
    /// indicating which check was not satisfied is returned.
    pub fn validate(
        &self,
        key: &'_ Key<Validated>,
        prna: Svn,
        gst_mack: Gst,
    ) -> Result<Mack<'a, Validated>, MackValidationError> {
        key.validate_macseq(self, prna, gst_mack)?;

        for j in 1..self.num_tags() {
            let tag = self.tag_and_info(j);
            if let Err(e) = key.chain().validate_adkd(j, tag, prna, gst_mack) {
                return Err(MackValidationError::WrongAdkd {
                    tag_index: j,
                    error: e,
                });
            }
        }
        Ok(Mack {
            data: self.data,
            key_size: self.key_size,
            tag_size: self.tag_size,
            _validated: Validated {},
        })
    }
}

impl<V: fmt::Debug + Clone> fmt::Debug for Mack<'_, V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut dbg = f.debug_struct("Mack");
        dbg.field("tag0", &self.tag0())
            .field("macseq", &self.macseq());
        for tag in 1..self.num_tags() {
            dbg.field("tag", &self.tag_and_info(tag));
        }
        dbg.field("key", &self.key())
            .field("_validated", &self._validated)
            .finish()
    }
}

/// Tag-Info section.
///
/// The Tag-Info section is defined in Figure 11 of the
/// [OSNMA ICD](https://www.gsc-europa.eu/sites/default/files/sites/all/files/Galileo_OSNMA_User_ICD_for_Test_Phase_v1.0.pdf).
/// A Tag-Info field is obtained from a MACK message with [`Mack::tag_and_info`].
#[derive(Copy, Clone, Eq, PartialEq, Hash)]
pub struct TagAndInfo<'a, V> {
    data: &'a BitSlice,
    _validated: V,
}

/// PRND (PRN of the satellite transmitting the authenticated data).
///
/// This represents the values of the PRND field in a Tag-Info section, as
/// described in Table 12 in the
/// [OSNMA ICD](https://www.gsc-europa.eu/sites/default/files/sites/all/files/Galileo_OSNMA_User_ICD_for_Test_Phase_v1.0.pdf).
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum Prnd {
    /// Galileo SVID (PRND = 1 - 36).
    GalileoSvid(
        /// The Galileo SVID value (between 1 and 36).
        u8,
    ),
    /// Galileo constellation-related information (PRND = 255).
    GalileoConstellation,
    /// Reserved value (any other value of the PRND field).
    Reserved,
}

impl TryFrom<Prnd> for u8 {
    type Error = ();
    fn try_from(value: Prnd) -> Result<u8, ()> {
        match value {
            Prnd::GalileoSvid(svid) => Ok(svid),
            Prnd::GalileoConstellation => Ok(255),
            Prnd::Reserved => Err(()),
        }
    }
}

/// ADKD (Authentication Data and Key Delay).
///
/// Represents the values of the ADKD (Authentication Data and Key Delay) field,
/// as defined in Table 14 in the
/// [OSNMA ICD](https://www.gsc-europa.eu/sites/default/files/sites/all/files/Galileo_OSNMA_User_ICD_for_Test_Phase_v1.0.pdf).
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum Adkd {
    /// Galileo I/NAV ephemeris, clock and status (ADKD = 0).
    InavCed,
    /// Galileo I/NAV timing parameters (ADKD = 4).
    InavTiming,
    /// Slow MAC. Galileo I/NAV ephemeris, clock and status (ADKD = 12).
    SlowMac,
    /// Reserved value (any other ADKD value).
    Reserved,
}

impl<'a, V> TagAndInfo<'a, V> {
    /// Gives the tag field.
    pub fn tag(&self) -> &BitSlice {
        &self.data[..self.data.len() - 16]
    }

    /// Returns the tag-info section as a [`BitSlice`].
    ///
    /// The methods below return individual fields of the tag-info section.
    pub fn tag_info(&self) -> &BitSlice {
        &self.data[self.data.len() - 16..]
    }

    /// Gives the value of the PRND field in the Tag-Info section.
    pub fn prnd(&self) -> Prnd {
        let len = self.data.len();
        match self.data[len - 16..len - 8].load_be::<u8>() {
            n @ 1..=36 => Prnd::GalileoSvid(n),
            255 => Prnd::GalileoConstellation,
            _ => Prnd::Reserved,
        }
    }

    /// Gives the value of the ADKD field in the Tag-Info section.
    pub fn adkd(&self) -> Adkd {
        let len = self.data.len();
        match self.data[len - 8..len - 4].load_be::<u8>() {
            0 => Adkd::InavCed,
            4 => Adkd::InavTiming,
            12 => Adkd::SlowMac,
            _ => Adkd::Reserved,
        }
    }

    /// Gives the value of the COP field in the Tag-Info section.
    ///
    /// The COP is a 4-bit integer, which is returned as a `u8`.
    pub fn cop(&self) -> u8 {
        let len = self.data.len();
        self.data[len - 4..].load_be::<u8>()
    }
}

impl<V: fmt::Debug> fmt::Debug for TagAndInfo<'_, V> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TagAndInfo")
            .field("tag", &self.tag())
            .field("prnd", &self.prnd())
            .field("adkd", &self.adkd())
            .field("_validated", &self._validated)
            .finish()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn nma_header() {
        let header = [0x52]; // NMA header broadcast on 2022-03-07
        let nma_header = NmaHeader(&header);
        assert_eq!(nma_header.nma_status(), NmaStatus::Test);
        assert_eq!(nma_header.chain_id(), 1);
        assert_eq!(
            nma_header.chain_and_pubkey_status(),
            ChainAndPubkeyStatus::Nominal
        );
    }

    #[test]
    fn dsm_header() {
        let header = [0x17];
        let dsm_header = DsmHeader(&header);
        assert_eq!(dsm_header.dsm_id(), 1);
        assert_eq!(dsm_header.dsm_block_id(), 7);
        assert_eq!(dsm_header.dsm_type(), DsmType::Kroot);
    }

    #[test]
    fn dsm_kroot() {
        // DSM-KROOT broadcast on 2022-03-07 9:00 UTC
        let dsm = hex!(
            "
            22 50 49 21 04 98 21 25 d3 96 4d a3 a2 84 1e 1d
            e4 d4 58 c0 e9 84 24 76 e0 04 66 6c f3 79 58 de
            28 51 97 a2 63 53 f1 a4 c6 6d 7e 3d 29 18 53 ba
            5a 13 c9 c3 48 4a 26 77 70 11 2a 13 38 3e a5 2d
            3a 01 9d 5b 6e 1d d1 87 b9 45 3c df 06 ca 7f 34
            ea 14 97 52 5a af 18 f1 f9 f1 fc cb 12 29 89 77
            35 c0 21 b0 41 73 93 b5"
        );
        let dsm = DsmKroot(&dsm);
        assert_eq!(dsm.number_of_blocks(), Some(8));
        assert_eq!(dsm.public_key_id(), 2);
        assert_eq!(dsm.kroot_chain_id(), 1);
        assert_eq!(dsm.hash_function(), HashFunction::Sha256);
        assert_eq!(dsm.mac_function(), MacFunction::HmacSha256);
        assert_eq!(dsm.key_size(), Some(128));
        assert_eq!(dsm.tag_size(), Some(40));
        assert_eq!(dsm.mac_lookup_table(), 0x21);
        assert_eq!(dsm.kroot_wn(), 0x498);
        assert_eq!(dsm.kroot_towh(), 0x21);
        assert_eq!(dsm.alpha(), 0x25d3964da3a2);
        assert_eq!(
            dsm.kroot(),
            hex!("84 1e 1d e4 d4 58 c0 e9 84 24 76 e0 04 66 6c f3")
        );
        assert_eq!(dsm.ecdsa_function(), EcdsaFunction::P256Sha256);
        assert_eq!(
            dsm.digital_signature(),
            hex!(
                "79 58 de 28 51 97 a2 63 53 f1 a4 c6 6d 7e 3d 29
                 18 53 ba 5a 13 c9 c3 48 4a 26 77 70 11 2a 13 38
                 3e a5 2d 3a 01 9d 5b 6e 1d d1 87 b9 45 3c df 06
                 ca 7f 34 ea 14 97 52 5a af 18 f1 f9 f1 fc cb 12"
            )
        );
        assert_eq!(dsm.padding(), hex!("29 89 77 35 c0 21 b0 41 73 93 b5"));
        let nma_header = [0x52];
        let nma_header = NmaHeader(&nma_header);
        assert!(dsm.check_padding(nma_header));
    }

    #[test]
    fn mack() {
        // MACK broadcast on 2022-03-07 9:00 UTC
        let mack = hex!(
            "
            11 55 d3 71 f2 1f 30 a8 e4 ec e0 c0 1b 07 6d 17
            7d 64 03 12 05 d4 02 7e 77 13 15 c0 4c ca 1c 16
            99 1a 05 48 91 07 a7 f7 0e c5 42 b4 19 da 6a da
            1c 0a 3d 6f 56 a5 e5 dc 59 a7 00 00"
        );
        let key_size = 128;
        let tag_size = 40;
        let mack = Mack::new(&mack, key_size, tag_size);
        assert_eq!(mack.key_size(), key_size);
        assert_eq!(mack.tag_size(), tag_size);
        assert_eq!(mack.tag0(), BitSlice::from_slice(&hex!("11 55 d3 71 f2")));
        assert_eq!(mack.macseq(), 0x1f3);
        assert_eq!(mack.num_tags(), 6);
        assert_eq!(
            mack.tag_and_info(1).tag(),
            BitSlice::from_slice(&hex!("a8 e4 ec e0 c0"))
        );
        assert_eq!(mack.tag_and_info(1).prnd(), Prnd::GalileoSvid(0x1b));
        assert_eq!(mack.tag_and_info(1).adkd(), Adkd::InavCed);
        assert_eq!(
            mack.tag_and_info(2).tag(),
            BitSlice::from_slice(&hex!("6d 17 7d 64 03"))
        );
        assert_eq!(mack.tag_and_info(2).prnd(), Prnd::GalileoSvid(0x12));
        assert_eq!(mack.tag_and_info(2).adkd(), Adkd::InavCed);
        assert_eq!(
            mack.tag_and_info(3).tag(),
            BitSlice::from_slice(&hex!("d4 02 7e 77 13"))
        );
        assert_eq!(mack.tag_and_info(3).prnd(), Prnd::GalileoSvid(0x15));
        assert_eq!(mack.tag_and_info(3).adkd(), Adkd::SlowMac);
        assert_eq!(
            mack.tag_and_info(4).tag(),
            BitSlice::from_slice(&hex!("4c ca 1c 16 99"))
        );
        assert_eq!(mack.tag_and_info(4).prnd(), Prnd::GalileoSvid(0x1a));
        assert_eq!(mack.tag_and_info(4).adkd(), Adkd::InavCed);
        assert_eq!(
            mack.tag_and_info(5).tag(),
            BitSlice::from_slice(&hex!("48 91 07 a7 f7"))
        );
        assert_eq!(mack.tag_and_info(5).prnd(), Prnd::GalileoSvid(0x0e));
        assert_eq!(mack.tag_and_info(5).adkd(), Adkd::SlowMac);
        assert_eq!(
            mack.key(),
            BitSlice::from_slice(&hex!("42 b4 19 da 6a da 1c 0a 3d 6f 56 a5 e5 dc 59 a7"))
        );
    }
}
