//! Message bit fields.
//!
//! This module contains structures that give acccess to each of the fields in
//! the messages used by OSNMA. As a general rule, the structures are a wrapper
//! over a `&[u8]` or `&[u8; N]`.

pub use crate::tesla::NmaHeader;
use crate::tesla::{AdkdCheckError, Key, MacseqCheckError};
use crate::types::{
    BitSlice, MackMessage, MerkleTreeNode, Towh, MACK_MESSAGE_BYTES, MERKLE_TREE_NODE_BYTES,
};
use crate::validation::{NotValidated, Validated};
use crate::{Gst, Svn, Wn};
use bitvec::prelude::*;
use core::fmt;
use ecdsa::{PrimeCurve, Signature, SignatureSize};
use sha2::{Digest, Sha256};
use signature::Verifier;

/// Status of the NMA chain.
///
/// This represents the values of the NMAS field of the [`NmaHeader`]
/// as defined in Section 3.1.1 of the
/// [OSNMA SIS ICD v1.1](https://www.gsc-europa.eu/sites/default/files/sites/all/files/Galileo_OSNMA_SIS_ICD_v1.1.pdf).
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
/// [OSNMA SIS ICD v1.1](https://www.gsc-europa.eu/sites/default/files/sites/all/files/Galileo_OSNMA_SIS_ICD_v1.1.pdf).
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

/// DSM header.
///
/// The DSM header found in the second byte of an HKROOT message.
/// See Figure 5 in the
/// [OSNMA SIS ICD v1.1](https://www.gsc-europa.eu/sites/default/files/sites/all/files/Galileo_OSNMA_SIS_ICD_v1.1.pdf).
#[derive(Copy, Clone, Eq, PartialEq, Hash)]
pub struct DsmHeader<'a>(
    /// Reference to an array containing the 1-byte header data.
    pub &'a [u8; 1],
);

/// Type of the DSM message.
///
/// This is derived from the DSM ID field according to Section 3.2.1.1 in the
/// [OSNMA SIS ICD v1.1](https://www.gsc-europa.eu/sites/default/files/sites/all/files/Galileo_OSNMA_SIS_ICD_v1.1.pdf).
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

impl DsmHeader<'_> {
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

/// DSM-PKR message.
///
/// The DSM-PKR message, as defined in Figure 6 of the
/// [OSNMA SIS ICD v1.1](https://www.gsc-europa.eu/sites/default/files/sites/all/files/Galileo_OSNMA_SIS_ICD_v1.1.pdf).
#[derive(Copy, Clone, Eq, PartialEq, Hash)]
pub struct DsmPkr<'a>(
    /// Reference to a slice containing the DSM-PKR message data.
    ///
    /// # Panics
    ///
    /// This slice should be long enough to contain the full DSM-PKR
    /// message. Otherwise the methods of `DsmPkr` may panic.
    pub &'a [u8],
);

/// New Public Key Type (NPKT).
///
/// This represents the values of the New Public Key Type (NPKT) field in the
/// DSM-PKR message. See Table 5 in the
/// [OSNMA SIS ICD v1.1](https://www.gsc-europa.eu/sites/default/files/sites/all/files/Galileo_OSNMA_SIS_ICD_v1.1.pdf).
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum NewPublicKeyType {
    /// An ECDSA key, as defined by the enum [`EcdsaFunction`].
    EcdsaKey(EcdsaFunction),
    /// OSNMA Alert Message (OAM).
    OsnmaAlertMessage,
    /// Reserved value.
    Reserved,
}

impl DsmPkr<'_> {
    fn bits(&self) -> &BitSlice {
        BitSlice::from_slice(self.0)
    }

    /// Gives the number of DSM-PKR blocks.
    ///
    /// The number is computed according to the value of the NB_DP field and
    /// Table 3 in the
    /// [OSNMA SIS ICD v1.1](https://www.gsc-europa.eu/sites/default/files/sites/all/files/Galileo_OSNMA_SIS_ICD_v1.1.pdf).
    ///
    /// If the NB_DP field contains a reserved value, `None` is returned.
    pub fn number_of_blocks(&self) -> Option<usize> {
        let v = self.bits()[..4].load_be::<u8>();
        match v {
            7..=10 => Some(usize::from(v) + 6),
            _ => None, // reserved value
        }
    }

    /// Gives the value of the Message ID (MID) field.
    pub fn message_id(&self) -> u8 {
        self.bits()[4..8].load_be::<u8>()
    }

    /// Gives the value of an interemediate tree node.
    ///
    /// The DSM-PKR contains 4 256-bit intermediate tree nodes. This returns the
    /// 256-bit slice corresponding to the intermediate tree node in position
    /// `node_number` (where `node_number` can be 0, 1, 2, or 3).
    ///
    /// # Panics
    ///
    /// This function panics if `node` number is not 0, 1, 2, or 3.
    ///
    pub fn intermediate_tree_node(&self, node_number: usize) -> &MerkleTreeNode {
        assert!(node_number < 4);
        (&self.0[1 + node_number * MERKLE_TREE_NODE_BYTES
            ..1 + (node_number + 1) * MERKLE_TREE_NODE_BYTES])
            .try_into()
            .unwrap()
    }

    /// Gives the value of the New Public Key Type (NPKT) field.
    pub fn new_public_key_type(&self) -> NewPublicKeyType {
        match self.bits()[1032..1036].load_be::<u8>() {
            1 => NewPublicKeyType::EcdsaKey(EcdsaFunction::P256Sha256),
            3 => NewPublicKeyType::EcdsaKey(EcdsaFunction::P521Sha512),
            4 => NewPublicKeyType::OsnmaAlertMessage,
            _ => NewPublicKeyType::Reserved,
        }
    }

    /// Gives the value of the New Public Key ID (NPKID) field.
    pub fn new_public_key_id(&self) -> u8 {
        self.bits()[1036..1040].load_be::<u8>()
    }

    /// Gives the size of the New Public Key field in bytes.
    ///
    /// The size is computed according to the value of the NPKT field and Table 6 in the
    /// [OSNMA SIS ICD v1.1](https://www.gsc-europa.eu/sites/default/files/sites/all/files/Galileo_OSNMA_SIS_ICD_v1.1.pdf).
    /// If the NPKT field contains a reserved value, `None` is returned.
    pub fn key_size(&self) -> Option<usize> {
        match self.new_public_key_type() {
            NewPublicKeyType::EcdsaKey(EcdsaFunction::P256Sha256) => Some(264 / 8),
            NewPublicKeyType::EcdsaKey(EcdsaFunction::P521Sha512) => Some(536 / 8),
            NewPublicKeyType::OsnmaAlertMessage => {
                self.number_of_blocks().map(|n| n * (104 / 8) - 1040 / 8)
            }
            NewPublicKeyType::Reserved => None,
        }
    }

    /// Gives a slice containing the New Public Key field.
    ///
    /// If the size of the New Public Key field cannot be determined because
    /// some other fields contain reserved values, `None` is returned.
    pub fn new_public_key(&self) -> Option<&[u8]> {
        self.key_size().map(|s| &self.0[1040 / 8..1040 / 8 + s])
    }

    /// Gives a slice containing the padding field.
    ///
    /// If the size of the New Public Key field cannot be determined because
    /// some other fields contain reserved values, `None` is returned.
    pub fn padding(&self) -> Option<&[u8]> {
        if let (Some(ks), Some(nb)) = (self.key_size(), self.number_of_blocks()) {
            Some(&self.0[1040 / 8 + ks..nb * 104 / 8])
        } else {
            None
        }
    }

    /// Gives the Merkle tree leaf corresponding to this message.
    ///
    /// The tree leaf is defined in Section 6.2 of the
    /// [OSNMA SIS ICD v1.1](https://www.gsc-europa.eu/sites/default/files/sites/all/files/Galileo_OSNMA_SIS_ICD_v1.1.pdf).
    ///
    /// If the size of the New Public Key field cannot be determined because
    /// some other fields contain reserved values, `None` is returned.
    pub fn merkle_tree_leaf(&self) -> Option<&[u8]> {
        self.key_size().map(|s| &self.0[1032 / 8..1040 / 8 + s])
    }

    /// Checks the contents of the padding field.
    /// The contents are checked according to Eq. 4 in the
    /// [OSNMA SIS ICD v1.1](https://www.gsc-europa.eu/sites/default/files/sites/all/files/Galileo_OSNMA_SIS_ICD_v1.1.pdf).
    ///
    /// If the contents are correct, this returns `true`. Otherwise, this
    /// returns `false`. If `self.padding()` returns `None`, then this function
    /// returns `false`.
    pub fn check_padding(&self, merkle_tree_root: &MerkleTreeNode) -> bool {
        let Some(padding) = self.padding() else {
            return false;
        };
        if padding.is_empty() {
            // This happens for OSNMA Alert Messages: The padding is empty and
            // does not need to be checked.
            return true;
        }
        let mut hash = Sha256::new();
        hash.update(merkle_tree_root);
        // merkle_tree_leaf should not panic, because self.padding() is not None
        hash.update(self.merkle_tree_leaf().unwrap());
        let hash = hash.finalize();
        let truncated = &hash[..padding.len()];
        truncated == padding
    }
}

impl fmt::Debug for DsmPkr<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DsmPkr")
            .field("number_of_blocks", &self.number_of_blocks())
            .field("message_id", &self.message_id())
            .field("intermediate_tree_node_0", &self.intermediate_tree_node(0))
            .field("intermediate_tree_node_1", &self.intermediate_tree_node(1))
            .field("intermediate_tree_node_2", &self.intermediate_tree_node(2))
            .field("intermediate_tree_node_3", &self.intermediate_tree_node(3))
            .field("new_public_key_type", &self.new_public_key_type())
            .field("new_public_key_id", &self.new_public_key_id())
            .field("new_public_key", &self.new_public_key())
            .field("padding", &self.padding())
            .finish()
    }
}

/// DSM-KROOT message.
///
/// The DSM-KROOT message, as defined in Figure 7 of the
/// [OSNMA SIS ICD v1.1](https://www.gsc-europa.eu/sites/default/files/sites/all/files/Galileo_OSNMA_SIS_ICD_v1.1.pdf).
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
/// [OSNMA SIS ICD v1.1](https://www.gsc-europa.eu/sites/default/files/sites/all/files/Galileo_OSNMA_SIS_ICD_v1.1.pdf).
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
/// [OSNMA SIS ICD v1.1](https://www.gsc-europa.eu/sites/default/files/sites/all/files/Galileo_OSNMA_SIS_ICD_v1.1.pdf).
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
/// [OSNMA SIS ICD v1.1](https://www.gsc-europa.eu/sites/default/files/sites/all/files/Galileo_OSNMA_SIS_ICD_v1.1.pdf).
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum EcdsaFunction {
    /// ECDSA P-256/SHA-256.
    P256Sha256,
    /// ECDSA P-521/SHA-512
    P521Sha512,
}

impl DsmKroot<'_> {
    fn bits(&self) -> &BitSlice {
        BitSlice::from_slice(self.0)
    }

    /// Gives the number of DSM-KROOT blocks.
    ///
    /// The number is computed according to the value of the NB_DK field and
    /// Table 7 in the
    /// [OSNMA SIS ICD v1.1](https://www.gsc-europa.eu/sites/default/files/sites/all/files/Galileo_OSNMA_SIS_ICD_v1.1.pdf).
    ///
    /// If the NB_DK field contains a reserved value, `None` is returned.
    pub fn number_of_blocks(&self) -> Option<usize> {
        let v = self.bits()[..4].load_be::<u8>();
        match v {
            1..=8 => Some(usize::from(v) + 6),
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
    /// [OSNMA SIS ICD v1.1](https://www.gsc-europa.eu/sites/default/files/sites/all/files/Galileo_OSNMA_SIS_ICD_v1.1.pdf).
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
    /// [OSNMA SIS ICD v1.1](https://www.gsc-europa.eu/sites/default/files/sites/all/files/Galileo_OSNMA_SIS_ICD_v1.1.pdf).
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
    fn signature_message(&self, nma_header: NmaHeader<NotValidated>) -> ([u8; 209], usize) {
        let mut m = [0; 209];
        m[0] = nma_header.data();
        let end = 13 + self.kroot().len();
        // we skip the NB_DK and PKID fields in self.0
        m[1..end].copy_from_slice(&self.0[1..end]);
        (m, end)
    }

    /// Checks the contents of the padding field.
    ///
    /// The contents are checked according to Eq. 7 in the
    /// [OSNMA SIS ICD v1.1](https://www.gsc-europa.eu/sites/default/files/sites/all/files/Galileo_OSNMA_SIS_ICD_v1.1.pdf).
    ///
    /// If the contents are correct, this returns `true`. Otherwise, this
    /// returns `false`.
    pub fn check_padding(&self, nma_header: NmaHeader<NotValidated>) -> bool {
        let (message, size) = self.signature_message(nma_header);
        let message = &message[..size];
        let mut hash = Sha256::new();
        hash.update(message);
        hash.update(self.digital_signature());
        let hash = hash.finalize();
        let padding = self.padding();
        let truncated = &hash[..padding.len()];
        truncated == padding
    }

    /// Checks the P256 ECDSA signature.
    ///
    /// This verifies that the P256 ECDSA signature of the DSM-KROOT message is
    /// correct. The algorithm in Section 6.3 of the
    /// [OSNMA SIS ICD v1.1](https://www.gsc-europa.eu/sites/default/files/sites/all/files/Galileo_OSNMA_SIS_ICD_v1.1.pdf).
    /// is followed.
    ///
    /// # Panics
    ///
    /// Panics if the DSM-KROOT message does not use a P256 ECDSA signature.
    ///
    pub fn check_signature_p256(
        &self,
        nma_header: NmaHeader<NotValidated>,
        pubkey: &p256::ecdsa::VerifyingKey,
    ) -> bool {
        assert_eq!(self.ecdsa_function(), EcdsaFunction::P256Sha256);
        self.check_signature(nma_header, pubkey)
    }

    /// Checks the P512 ECDSA signature.
    ///
    /// This verifies that the P512 ECDSA signature of the DSM-KROOT message is
    /// correct. The algorithm in Section 6.3 of the
    /// [OSNMA SIS ICD v1.1](https://www.gsc-europa.eu/sites/default/files/sites/all/files/Galileo_OSNMA_SIS_ICD_v1.1.pdf).
    /// is followed.
    ///
    /// # Panics
    ///
    /// Panics if the DSM-KROOT message does not use a P512 ECDSA signature.
    ///
    #[cfg(feature = "p521")]
    pub fn check_signature_p521(
        &self,
        nma_header: NmaHeader<NotValidated>,
        pubkey: &p521::ecdsa::VerifyingKey,
    ) -> bool {
        assert_eq!(self.ecdsa_function(), EcdsaFunction::P521Sha512);
        self.check_signature(nma_header, pubkey)
    }

    // Generic function to check the ECDSA signature. This works for either:
    //
    // - VK = p256::ecdsa::VerifyingKey, C = p256::NistP256
    // - VK = p512::ecdsa::VerifyingKey, C = p521::NistP521
    //
    // The function can also be called with other type parameters, but it doesn't
    // make sense to do so.
    //
    // # Panics
    //
    // The function panics if the ECDSA signature cannot be serialized, which
    // can happen if the chosen type parameters do not match the signature
    // length in the DSM-KROOT message.
    fn check_signature<VK, C>(&self, nma_header: NmaHeader<NotValidated>, pubkey: &VK) -> bool
    where
        VK: Verifier<Signature<C>>,
        C: PrimeCurve,
        SignatureSize<C>: crypto_common::generic_array::ArrayLength<u8>,
    {
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
/// [OSNMA SIS ICD v1.1](https://www.gsc-europa.eu/sites/default/files/sites/all/files/Galileo_OSNMA_SIS_ICD_v1.1.pdf).
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

impl Mack<'_, NotValidated> {
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

impl<V> Mack<'_, V> {
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
    /// [OSNMA SIS ICD v1.1](https://www.gsc-europa.eu/sites/default/files/sites/all/files/Galileo_OSNMA_SIS_ICD_v1.1.pdf).
    pub fn tag0(&self) -> &BitSlice {
        &self.data[..self.tag_size()]
    }

    /// Gives the value of the MACSEQ field contained in the MACK header of the MACK message.
    ///
    /// See Figure 9 in the
    /// [OSNMA SIS ICD v1.1](https://www.gsc-europa.eu/sites/default/files/sites/all/files/Galileo_OSNMA_SIS_ICD_v1.1.pdf).
    /// The MACSEQ is a 12-bit integer, which is returned as a `u16`.
    pub fn macseq(&self) -> u16 {
        let macseq_size = 12;
        self.data[self.tag_size()..self.tag_size() + macseq_size].load_be::<u16>()
    }

    /// Gives the value of the COP field contained in the MACK header of the MACK message.
    ///
    /// See Figure 9 in the
    /// [OSNMA SIS ICD v1.1](https://www.gsc-europa.eu/sites/default/files/sites/all/files/Galileo_OSNMA_SIS_ICD_v1.1.pdf).
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
    /// [OSNMA SIS ICD v1.1](https://www.gsc-europa.eu/sites/default/files/sites/all/files/Galileo_OSNMA_SIS_ICD_v1.1.pdf).
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
    /// [OSNMA SIS ICD v1.1](https://www.gsc-europa.eu/sites/default/files/sites/all/files/Galileo_OSNMA_SIS_ICD_v1.1.pdf).
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

impl<V: Clone> Mack<'_, V> {
    /// Gives an object representing one of the Tag-Info sections in the MACK message.
    ///
    /// The Tag-Info section is defined in Figure 11 of the
    /// [OSNMA SIS ICD v1.1](https://www.gsc-europa.eu/sites/default/files/sites/all/files/Galileo_OSNMA_SIS_ICD_v1.1.pdf).
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
}

impl<'a, V: Clone> Mack<'a, V> {
    /// Try to validate the MACK message.
    ///
    /// Given the TESLA `key` transmitted on the next subframe, this will
    /// attempt to validate the MACSEQ field and the ADKD fields of the MACK
    /// message. The MACSEQ field is checked using the algorithm in Section 6.6
    /// of the
    /// [OSNMA SIS ICD v1.1](https://www.gsc-europa.eu/sites/default/files/sites/all/files/Galileo_OSNMA_SIS_ICD_v1.1.pdf).
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
        key: &Key<Validated>,
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
/// [OSNMA SIS ICD v1.1](https://www.gsc-europa.eu/sites/default/files/sites/all/files/Galileo_OSNMA_SIS_ICD_v1.1.pdf).
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
/// [OSNMA SIS ICD v1.1](https://www.gsc-europa.eu/sites/default/files/sites/all/files/Galileo_OSNMA_SIS_ICD_v1.1.pdf).
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
/// [OSNMA SIS ICD v1.1](https://www.gsc-europa.eu/sites/default/files/sites/all/files/Galileo_OSNMA_SIS_ICD_v1.1.pdf).
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

impl<V> TagAndInfo<'_, V> {
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
        // NMA header broadcast on 2022-03-07
        let nma_header = NmaHeader::new(0x52);
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
    fn dsm_pkr() {
        // DSM-PKR broadcast on 2023-12-12 12:00 UTC
        let dsm = hex!(
            "
            70 01 63 1b dc ed 79 d4 31 7b c2 87 0e e3 89 5b
            d5 9c f2 b6 ea 51 6f ab bf df 1d 73 96 26 14 6f
            fe 31 6f a9 28 5f 5a 1e 44 04 24 13 bd af 18 aa
            3c f6 84 72 33 97 d7 b8 32 5a ec a1 eb ca 9f 0f
            64 99 05 42 4c be 48 2a 1a 32 b0 10 64 f8 5d 0c
            36 df 03 8e 52 ce 12 8e 7e c5 f3 23 e1 65 b1 82
            a7 15 37 bd b0 10 97 2e b4 a3 b9 0b aa cd 14 94
            1e f4 0d a2 cb 2b 82 d3 78 b3 15 c0 08 de ce fd
            8e 11 03 74 a9 25 cf a0 ff 18 05 e5 c5 a5 8f db
            a3 1b f0 14 5d 5b 5b e2 f0 62 d3 f8 bb 2e e9 8f
            0f 6d b0 e8 23 c5 e7 5e 78"
        );
        let dsm = DsmPkr(&dsm);
        assert_eq!(dsm.number_of_blocks(), Some(13));
        assert_eq!(dsm.message_id(), 0);
        assert_eq!(
            dsm.intermediate_tree_node(0),
            &hex!(
                "01 63 1b dc ed 79 d4 31 7b c2 87 0e e3 89 5b d5
                 9c f2 b6 ea 51 6f ab bf df 1d 73 96 26 14 6f fe"
            )
        );
        let itn1 = hex!(
            "31 6f a9 28 5f 5a 1e 44 04 24 13 bd af 18 aa 3c
             f6 84 72 33 97 d7 b8 32 5a ec a1 eb ca 9f 0f 64"
        );
        assert_eq!(dsm.intermediate_tree_node(1), &itn1);
        let itn2 = hex!(
            "99 05 42 4c be 48 2a 1a 32 b0 10 64 f8 5d 0c 36
             df 03 8e 52 ce 12 8e 7e c5 f3 23 e1 65 b1 82 a7"
        );
        assert_eq!(dsm.intermediate_tree_node(2), &itn2);
        let itn3 = hex!(
            "15 37 bd b0 10 97 2e b4 a3 b9 0b aa cd 14 94 1e
             f4 0d a2 cb 2b 82 d3 78 b3 15 c0 08 de ce fd 8e"
        );
        assert_eq!(dsm.intermediate_tree_node(3), &itn3);
        assert_eq!(
            dsm.new_public_key_type(),
            NewPublicKeyType::EcdsaKey(EcdsaFunction::P256Sha256)
        );
        assert_eq!(dsm.new_public_key_id(), 1);
        assert_eq!(
            dsm.new_public_key(),
            Some(
                &hex!(
                    "03 74 a9 25 cf a0 ff 18 05 e5 c5 a5 8f db a3 1b
                     f0 14 5d 5b 5b e2 f0 62 d3 f8 bb 2e e9 8f 0f 6d b0"
                )[..]
            )
        );
        assert_eq!(dsm.padding(), Some(&hex!("e8 23 c5 e7 5e 78")[..]));
        // Obtained from OSNMA_MerkleTree_20231213105954_PKID_1.xml
        let merkle_tree_root =
            hex!("0E63F552C8021709043C239032EFFE941BF22C8389032F5F2701E0FBC80148B8");
        assert!(dsm.check_padding(&merkle_tree_root));

        // DSM-PKR broadcast on 2023-12-15 00:00 UTC
        let dsm = hex!(
            "
            71 e5 53 0a 33 d5 cb 60 c9 50 16 b8 ae c7 45 93
            db cd f2 71 1d 39 9e a2 48 69 17 3c a2 29 37 9a
            15 31 6f a9 28 5f 5a 1e 44 04 24 13 bd af 18 aa
            3c f6 84 72 33 97 d7 b8 32 5a ec a1 eb ca 9f 0f
            64 99 05 42 4c be 48 2a 1a 32 b0 10 64 f8 5d 0c
            36 df 03 8e 52 ce 12 8e 7e c5 f3 23 e1 65 b1 82
            a7 15 37 bd b0 10 97 2e b4 a3 b9 0b aa cd 14 94
            1e f4 0d a2 cb 2b 82 d3 78 b3 15 c0 08 de ce fd
            8e 12 03 35 78 e5 c7 11 a9 c3 bd dd 1c a4 ee 85
            f7 c5 1b 36 78 97 cb 40 b8 85 68 a0 c8 97 da 30
            ef b7 c3 24 e0 22 2c 90 80"
        );
        let dsm = DsmPkr(&dsm);
        assert_eq!(dsm.number_of_blocks(), Some(13));
        assert_eq!(dsm.message_id(), 1);
        assert_eq!(
            dsm.intermediate_tree_node(0),
            &hex!(
                "e5 53 0a 33 d5 cb 60 c9 50 16 b8 ae c7 45 93 db
                 cd f2 71 1d 39 9e a2 48 69 17 3c a2 29 37 9a 15"
            )
        );
        assert_eq!(dsm.intermediate_tree_node(1), &itn1);
        assert_eq!(dsm.intermediate_tree_node(2), &itn2);
        assert_eq!(dsm.intermediate_tree_node(3), &itn3);
        assert_eq!(
            dsm.new_public_key_type(),
            NewPublicKeyType::EcdsaKey(EcdsaFunction::P256Sha256)
        );
        assert_eq!(dsm.new_public_key_id(), 2);
        assert_eq!(
            dsm.new_public_key(),
            Some(
                &hex!(
                    "03 35 78 e5 c7 11 a9 c3 bd dd 1c a4 ee 85 f7 c5
                     1b 36 78 97 cb 40 b8 85 68 a0 c8 97 da 30 ef b7 c3"
                )[..]
            )
        );
        assert_eq!(dsm.padding(), Some(&hex!("24 e0 22 2c 90 80")[..]));
        assert!(dsm.check_padding(&merkle_tree_root));
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
        let nma_header = NmaHeader::new(0x52);
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
