//! Merkle tree.
//!
//! This module contains code used to authenticate public keys against the OSNMA
//! Merkle tree.

use crate::bitfields::DsmPkr;
use crate::types::MerkleTreeNode;
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

    /// Validates a DSM-PKR against this Merkle tree.
    ///
    /// This function checks that the public key in the DSM-PKR message belongs
    /// to the Merkle tree by using the intermediate tree nodes in the DSM-PKR
    /// and checking against the tree root stored in `self`.
    ///
    /// The validation algorithm is described in Section 6.2 of the
    /// [OSNMA SIS ICD v1.1](https://www.gsc-europa.eu/sites/default/files/sites/all/files/Galileo_OSNMA_SIS_ICD_v1.1.pdf).
    ///
    /// The function returns `Ok(())` if validation is successful. Otherwise, an
    /// error is returned.
    pub fn validate_pkr(&self, dsm_pkr: DsmPkr) -> Result<(), PkrError> {
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
}

impl fmt::Display for PkrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PkrError::ReservedField => "reserved value present in some field".fmt(f),
            PkrError::Invalid => "wrong calculated Merkle tree root".fmt(f),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for PkrError {}

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
        assert_eq!(mtree.validate_pkr(dsm), Ok(()));
        // inject error
        dsm_buf[40] ^= 1;
        let dsm = DsmPkr(&dsm_buf);
        let mtree = merkle_tree();
        assert_eq!(mtree.validate_pkr(dsm), Err(PkrError::Invalid));
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
        assert_eq!(mtree.validate_pkr(dsm), Ok(()));
        // inject error
        dsm_buf[123] ^= 1;
        let dsm = DsmPkr(&dsm_buf);
        let mtree = merkle_tree();
        assert_eq!(mtree.validate_pkr(dsm), Err(PkrError::Invalid));
    }
}
