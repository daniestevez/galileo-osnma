use crate::types::{BitSlice, MackMessage, Towh, Wn, MACK_MESSAGE_BYTES};
use bitvec::prelude::*;
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
    fn bits(&self) -> &BitSlice {
        BitSlice::from_slice(self.0)
    }

    pub fn nma_status(&self) -> NmaStatus {
        match self.bits()[..2].load_be::<u8>() {
            0 => NmaStatus::Reserved,
            1 => NmaStatus::Test,
            2 => NmaStatus::Operational,
            3 => NmaStatus::DontUse,
            _ => unreachable!(),
        }
    }

    pub fn chain_id(&self) -> u8 {
        self.bits()[2..4].load_be::<u8>()
    }

    pub fn chain_and_pubkey_status(&self) -> ChainAndPubkeyStatus {
        match self.bits()[4..7].load_be::<u8>() {
            0 | 6 | 7 => ChainAndPubkeyStatus::Reserved,
            1 => ChainAndPubkeyStatus::Nominal,
            2 => ChainAndPubkeyStatus::EndOfChain,
            3 => ChainAndPubkeyStatus::ChainRevoked,
            4 => ChainAndPubkeyStatus::NewPublicKey,
            5 => ChainAndPubkeyStatus::PublicKeyRevoked,
            _ => unreachable!(), // we are only reading 3 bits
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

#[derive(Copy, Clone, Eq, PartialEq, Hash)]
pub struct DsmHeader<'a>(pub &'a [u8; 1]);

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum DsmType {
    Kroot,
    Pkr,
}

impl<'a> DsmHeader<'a> {
    fn bits(&self) -> &BitSlice {
        BitSlice::from_slice(self.0)
    }

    pub fn dsm_id(&self) -> u8 {
        self.bits()[..4].load_be()
    }

    pub fn dsm_block_id(&self) -> u8 {
        self.bits()[4..8].load_be()
    }

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
    fn bits(&self) -> &BitSlice {
        BitSlice::from_slice(self.0)
    }

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

    pub fn public_key_id(&self) -> u8 {
        self.bits()[4..8].load_be::<u8>()
    }

    pub fn kroot_chain_id(&self) -> u8 {
        self.bits()[8..10].load_be::<u8>()
    }

    pub fn hash_function(&self) -> HashFunction {
        match self.bits()[12..14].load_be::<u8>() {
            0 => HashFunction::Sha256,
            2 => HashFunction::Sha3_256,
            _ => HashFunction::Reserved,
        }
    }

    pub fn mac_function(&self) -> MacFunction {
        match self.bits()[14..16].load_be::<u8>() {
            0 => MacFunction::HmacSha256,
            1 => MacFunction::CmacAes,
            _ => MacFunction::Reserved,
        }
    }

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

    pub fn mac_lookup_table(&self) -> u8 {
        self.bits()[24..32].load_be()
    }

    pub fn kroot_wn(&self) -> Wn {
        self.bits()[36..48].load_be()
    }

    pub fn kroot_towh(&self) -> Towh {
        self.bits()[48..56].load_be()
    }

    pub fn alpha(&self) -> u64 {
        self.bits()[56..104].load_be()
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

#[derive(Copy, Clone, Eq, PartialEq, Hash)]
pub struct Mack<'a> {
    data: &'a BitSlice,
    key_size: usize,
    tag_size: usize,
}

impl<'a> Mack<'a> {
    pub fn new(data: &MackMessage, key_size: usize, tag_size: usize) -> Mack {
        Mack {
            data: BitSlice::from_slice(data),
            key_size,
            tag_size,
        }
    }

    pub fn key_size(&self) -> usize {
        self.key_size
    }

    pub fn tag_size(&self) -> usize {
        self.tag_size
    }

    pub fn tag0(&self) -> &BitSlice {
        &self.data[..self.tag_size()]
    }

    pub fn macseq(&self) -> u16 {
        let macseq_size = 12;
        self.data[self.tag_size()..self.tag_size() + macseq_size].load_be::<u16>()
    }

    pub fn tag_and_info(&self, n: usize) -> TagAndInfo {
        assert!(0 < n && n < self.num_tags());
        let size = self.tag_size() + 16;
        TagAndInfo {
            data: &self.data[size * n..size * (n + 1)],
        }
    }

    pub fn num_tags(&self) -> usize {
        (8 * MACK_MESSAGE_BYTES - self.key_size()) / (self.tag_size() + 16)
    }

    pub fn key(&self) -> &BitSlice {
        let start = (self.tag_size() + 16) * self.num_tags();
        &self.data[start..start + self.key_size()]
    }
}

impl fmt::Debug for Mack<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut dbg = f.debug_struct("Mack");
        dbg.field("tag0", &self.tag0())
            .field("macseq", &self.macseq());
        for tag in 1..self.num_tags() {
            dbg.field("tag", &self.tag_and_info(tag));
        }
        dbg.field("key", &self.key()).finish()
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Hash)]
pub struct TagAndInfo<'a> {
    data: &'a BitSlice,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum Prnd {
    GalileoSvid(u8),
    GalileoConstellation,
    Reserved,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum Adkd {
    InavCed,
    InavTiming,
    SlowMac,
    Reserved,
}

impl<'a> TagAndInfo<'a> {
    pub fn tag(&self) -> &BitSlice {
        &self.data[..self.data.len() - 16]
    }

    pub fn prnd(&self) -> Prnd {
        let len = self.data.len();
        match self.data[len - 16..len - 8].load_be::<u8>() {
            n @ 1..=36 => Prnd::GalileoSvid(n),
            255 => Prnd::GalileoConstellation,
            _ => Prnd::Reserved,
        }
    }

    pub fn adkd(&self) -> Adkd {
        let len = self.data.len();
        match self.data[len - 8..len - 4].load_be::<u8>() {
            0 => Adkd::InavCed,
            4 => Adkd::InavTiming,
            12 => Adkd::SlowMac,
            _ => Adkd::Reserved,
        }
    }
}

impl fmt::Debug for TagAndInfo<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TagAndInfo")
            .field("tag", &self.tag())
            .field("prnd", &self.prnd())
            .field("adkd", &self.adkd())
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
