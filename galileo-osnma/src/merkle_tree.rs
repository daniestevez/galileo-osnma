//! Merkle tree.
//!
//! This module contains code used to authenticate public keys against the OSNMA
//! Merkle tree.

use crate::bitfields::{DsmPkr, EcdsaFunction, NewPublicKeyType};
use crate::types::{MerkleTreeNode, VerifyingKey};
use crate::validation::{NotValidated, Validated};
use core::fmt;
use sha2::{Digest, Sha256};

/// Merkle tree.
///
/// This struct represents the OSNMA Merkle tree.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct MerkleTree {
    root: MerkleTreeNode,
}

impl MerkleTree {
    /// Creates a new Merkle tree.
    ///
    /// The value of the root of the Merkle tree is given to the constructor.
    pub fn new(root: MerkleTreeNode) -> MerkleTree {
        MerkleTree { root }
    }

    /// Validates a DSM-PKR containing a public key against this Merkle tree.
    ///
    /// This function checks that the public key in the DSM-PKR message belongs
    /// to the Merkle tree by using the intermediate tree nodes in the DSM-PKR
    /// and checking against the tree root stored in `self`.
    ///
    /// The validation algorithm is described in Section 6.2 of the
    /// [OSNMA SIS ICD v1.1](https://www.gsc-europa.eu/sites/default/files/sites/all/files/Galileo_OSNMA_SIS_ICD_v1.1.pdf).
    ///
    /// If validation is successful, the function returns the public key
    /// contained in the DSM-PRK, with its validation status set to
    /// `Validated`. Otherwise, an error is returned.
    pub fn validate_pkr(&self, dsm_pkr: DsmPkr) -> Result<PublicKey<Validated>, PkrError> {
        if !matches!(dsm_pkr.new_public_key_type(), NewPublicKeyType::EcdsaKey(_)) {
            return Err(PkrError::NoPublicKey);
        }
        self.validate(dsm_pkr)?;
        Self::pubkey_from_pkr(dsm_pkr)
    }

    /// Validates a DSM-PKR containing an Alert Message against this Merkle tree.
    ///
    /// This function checks that the public key in the DSM-PKR message belongs
    /// to the Merkle tree by using the intermediate tree nodes in the DSM-PKR
    /// and checking against the tree root stored in `self`.
    ///
    /// The validation algorithm is described in Section 6.2 of the
    /// [OSNMA SIS ICD v1.1](https://www.gsc-europa.eu/sites/default/files/sites/all/files/Galileo_OSNMA_SIS_ICD_v1.1.pdf).
    ///
    /// If validation is successful, the function returns `Ok(())`. Otherwise,
    /// an error is returned.
    pub fn validate_alert_message(&self, dsm_pkr: DsmPkr) -> Result<(), PkrError> {
        if !matches!(
            dsm_pkr.new_public_key_type(),
            NewPublicKeyType::OsnmaAlertMessage
        ) {
            return Err(PkrError::NoPublicKey);
        }
        self.validate(dsm_pkr)
    }

    fn validate(&self, dsm_pkr: DsmPkr) -> Result<(), PkrError> {
        let Some(leaf) = dsm_pkr.merkle_tree_leaf() else {
            return Err(PkrError::ReservedField);
        };
        let mut id = dsm_pkr.message_id();
        let mut node = Self::hash_leaf(leaf);
        const MERKLE_TREE_DEPTH: usize = 4;
        for j in 0..MERKLE_TREE_DEPTH {
            let is_left = id & 1 == 0;
            let itn = dsm_pkr.intermediate_tree_node(j);
            node = if is_left {
                Self::calc_node(&node, itn)
            } else {
                Self::calc_node(itn, &node)
            };
            id >>= 1;
        }
        if node == self.root {
            Ok(())
        } else {
            Err(PkrError::Invalid)
        }
    }

    fn hash_leaf(leaf: &[u8]) -> MerkleTreeNode {
        let mut hash = Sha256::new();
        hash.update(leaf);
        hash.finalize().into()
    }

    fn calc_node(left: &MerkleTreeNode, right: &MerkleTreeNode) -> MerkleTreeNode {
        let mut hash = Sha256::new();
        hash.update(left);
        hash.update(right);
        hash.finalize().into()
    }

    fn pubkey_from_pkr(dsm_pkr: DsmPkr) -> Result<PublicKey<Validated>, PkrError> {
        let key = dsm_pkr.new_public_key().unwrap();
        let key = match dsm_pkr.new_public_key_type() {
            NewPublicKeyType::EcdsaKey(EcdsaFunction::P256Sha256) => {
                p256::ecdsa::VerifyingKey::from_sec1_bytes(key)
                    .unwrap()
                    .into()
            }
            #[cfg(feature = "p521")]
            NewPublicKeyType::EcdsaKey(EcdsaFunction::P521Sha512) => {
                p521::ecdsa::VerifyingKey::from_sec1_bytes(key)
                    .unwrap()
                    .into()
            }
            #[cfg(not(feature = "p521"))]
            NewPublicKeyType::EcdsaKey(EcdsaFunction::P521Sha512) => {
                return Err(PkrError::P521NotSupported);
            }
            // if this function has been called, the PKR contains a public key
            _ => unreachable!(),
        };
        Ok(PublicKey {
            key,
            pkid: dsm_pkr.new_public_key_id(),
            _validated: Validated {},
        })
    }
}

/// Errors produced during validation of the DSM-PKR using the Merkle tree.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum PkrError {
    /// One of the fields in the DSM-PKR needed to interpret it has a reserved
    /// value.
    ReservedField,
    /// The computed Merkle tree root value does not match the pre-stored Merkle
    /// tree root.
    Invalid,
    /// The DSM-PKR does not contain a public key.
    NoPublicKey,
    /// The DSM-PKR is not an Alert Message.
    NotAlert,
    /// The DSM-PRK key is P-521, but P-521 support has not been enabled.
    #[cfg(not(feature = "p521"))]
    P521NotSupported,
}

impl fmt::Display for PkrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PkrError::ReservedField => "reserved value present in some field".fmt(f),
            PkrError::Invalid => "wrong calculated Merkle tree root".fmt(f),
            PkrError::NoPublicKey => "no public key in DSM-PKR".fmt(f),
            PkrError::NotAlert => "the DSM-PKR is not an alert message".fmt(f),
            #[cfg(not(feature = "p521"))]
            PkrError::P521NotSupported => "P-521 support disabled".fmt(f),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for PkrError {}

/// OSNMA public key.
///
/// This is an ECDSA verifying key used as public key for the verification of
/// the TESLA KROOT. The key can be either a P-256 ECDSA key or a P-521 ECDSA key
/// (if the feature `p521` is enabled).
///
/// The `V` type parameter is used to indicate the validation status of the
/// key. By default, public keys are constructed as [`NotValidated`]. A
/// [`Validated`] key can be obtained in two ways. Either by verification of a
/// DSM-PKR against the Merkle tree, or by forcing the validation of a
/// `NotValidated` key with [`PublicKey::force_valid`]. This function should
/// only be called if the key is known to be valid, because it has been verified
/// externally or loaded from a trustworthy source.
#[derive(Debug, Clone)]
pub struct PublicKey<V> {
    key: VerifyingKey,
    pkid: u8,
    _validated: V,
}

impl PublicKey<NotValidated> {
    /// Creates a new, not validated, key from a P-256 ECDSA key.
    ///
    /// The `public_key_id` parameter indicates the PKID parameter associated
    /// with this OSNMA public key.
    pub fn from_p256(
        verifying_key: p256::ecdsa::VerifyingKey,
        public_key_id: u8,
    ) -> PublicKey<NotValidated> {
        PublicKey {
            key: verifying_key.into(),
            pkid: public_key_id,
            _validated: NotValidated {},
        }
    }

    /// Creates a new, not validated, key from a P-512 ECDSA key.
    ///
    /// The `public_key_id` parameter indicates the PKID parameter associated
    /// with this OSNMA public key.
    #[cfg(feature = "p521")]
    pub fn from_p521(
        verifying_key: p521::ecdsa::VerifyingKey,
        public_key_id: u8,
    ) -> PublicKey<NotValidated> {
        PublicKey {
            key: verifying_key.into(),
            pkid: public_key_id,
            _validated: NotValidated {},
        }
    }

    /// Forces the key validation state to [`Validated`].
    ///
    /// This function should only be called if the key is known to be valid,
    /// because it has been verified externally or loaded from a trustworthy
    /// source.
    pub fn force_valid(self) -> PublicKey<Validated> {
        PublicKey {
            key: self.key,
            pkid: self.pkid,
            _validated: Validated {},
        }
    }
}

impl<V> PublicKey<V> {
    /// Gives the public key ID associated with this key.
    pub fn public_key_id(&self) -> u8 {
        self.pkid
    }
}

impl PublicKey<Validated> {
    /// Gives access to the public key.
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.key
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use hex_literal::hex;

    fn merkle_tree() -> MerkleTree {
        // Obtained from OSNMA_MerkleTree_20231213105954_PKID_1.xml
        let root = hex!("0E63F552C8021709043C239032EFFE941BF22C8389032F5F2701E0FBC80148B8");
        MerkleTree::new(root)
    }

    #[test]
    fn message_0() {
        // DSM-PKR broadcast on 2023-12-12 12:00 UTC
        let mut dsm_buf = hex!(
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
        let dsm = DsmPkr(&dsm_buf);
        let mtree = merkle_tree();
        assert!(mtree.validate_pkr(dsm).is_ok());
        // inject error
        dsm_buf[40] ^= 1;
        let dsm = DsmPkr(&dsm_buf);
        let mtree = merkle_tree();
        assert_eq!(mtree.validate_pkr(dsm).unwrap_err(), PkrError::Invalid);
    }

    #[test]
    fn message_1() {
        // DSM-PKR broadcast on 2023-12-15 00:00 UTC
        let mut dsm_buf = hex!(
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
        let dsm = DsmPkr(&dsm_buf);
        let mtree = merkle_tree();
        assert!(mtree.validate_pkr(dsm).is_ok());
        // inject error
        dsm_buf[123] ^= 1;
        let dsm = DsmPkr(&dsm_buf);
        let mtree = merkle_tree();
        assert_eq!(mtree.validate_pkr(dsm).unwrap_err(), PkrError::Invalid);
    }
}
