use crate::types::{Towh, Wn};
use core::fmt;
use p256::ecdsa::{
    signature::{Signature as SignatureTrait, Verifier},
    Signature, VerifyingKey,
};
use sha2::{Digest, Sha256};

#[derive(Copy, Clone, Eq, PartialEq, Hash)]
pub struct NmaHeader<'a>(pub &'a [u8; 1]);

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum NmaStatus {
    Reserved,
    Test,
    Operational,
    DontUse,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum ChainAndPubkeyStatus {
    Reserved,
    Nominal,
    EndOfChain,
    ChainRevoked,
    NewPublicKey,
    PublicKeyRevoked,
}

impl<'a> NmaHeader<'a> {
    pub fn nma_status(&self) -> NmaStatus {
        match self.value() >> 6 {
            0 => NmaStatus::Reserved,
            1 => NmaStatus::Test,
            2 => NmaStatus::Operational,
            3 => NmaStatus::DontUse,
            _ => unreachable!(),
        }
    }

    pub fn chain_id(&self) -> u8 {
        (self.value() >> 4) & 0x3
    }

    pub fn chain_and_pubkey_status(&self) -> ChainAndPubkeyStatus {
        match (self.value() >> 1) & 0x7 {
            0 | 6 | 7 => ChainAndPubkeyStatus::Reserved,
            1 => ChainAndPubkeyStatus::Nominal,
            2 => ChainAndPubkeyStatus::EndOfChain,
            3 => ChainAndPubkeyStatus::ChainRevoked,
            4 => ChainAndPubkeyStatus::NewPublicKey,
            5 => ChainAndPubkeyStatus::PublicKeyRevoked,
            _ => unreachable!(),
        }
    }

    fn value(&self) -> u8 {
        self.0[0]
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

#[derive(Copy, Clone, Eq, PartialEq, Hash)]
pub struct DsmHeader<'a>(pub &'a [u8; 1]);

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum DsmType {
    Kroot,
    Pkr,
}

impl<'a> DsmHeader<'a> {
    pub fn dsm_id(&self) -> u8 {
        self.value() >> 4
    }

    pub fn dsm_block_id(&self) -> u8 {
        self.value() & 0xf
    }

    pub fn dsm_type(&self) -> DsmType {
        if self.dsm_id() >= 12 {
            DsmType::Pkr
        } else {
            DsmType::Kroot
        }
    }

    fn value(&self) -> u8 {
        self.0[0]
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

#[derive(Copy, Clone, Eq, PartialEq, Hash)]
pub struct DsmKroot<'a>(pub &'a [u8]);

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum HashFunction {
    Sha256,
    Sha3_256,
    Reserved,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum MacFunction {
    HmacSha256,
    CmacAes,
    Reserved,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum EcdsaFunction {
    P256Sha256,
    P521Sha512,
}

impl<'a> DsmKroot<'a> {
    pub fn number_of_blocks(&self) -> Option<usize> {
        match self.0[0] >> 4 {
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

    pub fn public_key_id(&self) -> u8 {
        self.0[0] & 0xf
    }

    pub fn kroot_chain_id(&self) -> u8 {
        (self.0[1] >> 6) & 0x3
    }

    pub fn hash_function(&self) -> HashFunction {
        match (self.0[1] >> 2) & 0x3 {
            0 => HashFunction::Sha256,
            2 => HashFunction::Sha3_256,
            _ => HashFunction::Reserved,
        }
    }

    pub fn mac_function(&self) -> MacFunction {
        match self.0[1] & 0x3 {
            0 => MacFunction::HmacSha256,
            1 => MacFunction::CmacAes,
            _ => MacFunction::Reserved,
        }
    }

    pub fn key_size(&self) -> Option<usize> {
        // note that all the key sizes are a multiple of 8 bits
        let size = match self.0[2] >> 4 {
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

    pub fn tag_size(&self) -> Option<usize> {
        match self.0[2] & 0xf {
            5 => Some(20),
            6 => Some(24),
            7 => Some(28),
            8 => Some(32),
            9 => Some(40),
            _ => None,
        }
    }

    pub fn mac_lookup_table(&self) -> u8 {
        self.0[3]
    }

    pub fn kroot_wn(&self) -> Wn {
        (u16::from(self.0[4] & 0xf) << 8) | u16::from(self.0[5])
    }

    pub fn kroot_towh(&self) -> Towh {
        self.0[6]
    }

    pub fn alpha(&self) -> u64 {
        let mut value = 0_u64;
        for j in 0..6 {
            value |= u64::from(self.0[7 + j]) << (8 * (5 - j));
        }
        value
    }

    pub fn kroot(&self) -> &[u8] {
        let size = self
            .key_size()
            .expect("attempted to extract kroot of DSM with reserved key size");
        let size_bytes = size / 8;
        &self.0[13..13 + size_bytes]
    }

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

    pub fn digital_signature(&self) -> &[u8] {
        let size = match self.ecdsa_function() {
            EcdsaFunction::P256Sha256 => 64,
            EcdsaFunction::P521Sha512 => 132,
        };
        let start = 13 + self.kroot().len();
        &self.0[start..start + size]
    }

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

    // By now we only support P256
    pub fn check_signature(&self, nma_header: NmaHeader, pubkey: &VerifyingKey) -> bool {
        let (message, size) = self.signature_message(nma_header);
        let message = &message[..size];
        let signature = Signature::from_bytes(self.digital_signature())
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

#[cfg(test)]
mod test {
    use super::*;

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
}
