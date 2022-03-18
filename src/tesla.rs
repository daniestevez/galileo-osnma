use crate::bitfields::{self, Adkd, DsmKroot, Mack, NmaHeader, NmaStatus, Prnd, TagAndInfo};
use crate::gst::{Gst, Tow};
use crate::types::NUM_SVNS;
use crate::types::{BitSlice, NotValidated, Validated};
use aes::Aes128;
use bitvec::prelude::*;
use cmac::Cmac;
use crypto_common::KeyInit;
use hmac::{Hmac, Mac};
use p256::ecdsa::VerifyingKey;
use sha2::{Digest, Sha256};
use sha3::Sha3_256;

const MAX_KEY_BYTES: usize = 32;

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

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum ChainStatus {
    Test,
    Operational,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum HashFunction {
    Sha256,
    Sha3_256,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum MacFunction {
    HmacSha256,
    CmacAes,
}

impl Chain {
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

    pub fn chain_status(&self) -> ChainStatus {
        self.status
    }

    pub fn chain_id(&self) -> u8 {
        self.id
    }

    pub fn hash_function(&self) -> HashFunction {
        self.hash_function
    }

    pub fn mac_function(&self) -> MacFunction {
        self.mac_function
    }

    pub fn key_size_bytes(&self) -> usize {
        self.key_size_bytes
    }

    pub fn key_size_bits(&self) -> usize {
        self.key_size_bytes() * 8
    }

    pub fn tag_size_bits(&self) -> usize {
        self.tag_size_bits
    }

    pub fn mac_lookup_table(&self) -> u8 {
        self.maclt
    }

    pub fn alpha(&self) -> u64 {
        self.alpha
    }

    pub fn check_adkd(
        &self,
        num_tag: usize,
        tag: TagAndInfo,
        prna: usize,
        gst_tag: Gst,
    ) -> Result<(), AdkdCheckError> {
        assert!(num_tag >= 1);
        // Half of the GST minute
        let column = (gst_tag.tow() / 30) % 2;
        assert!((column == 0) || (column == 1));
        let (adkd, object) = match (self.maclt, column, num_tag) {
            (27, 0, 1 | 2 | 3 | 5) => (Adkd::InavCed, AuthObject::Other),
            (27, _, 4) => (Adkd::SlowMac, AuthObject::SelfAuth),
            (27, 1, 1 | 2 | 5) => (Adkd::InavCed, AuthObject::Other),
            (27, 1, 3) => (Adkd::InavTiming, AuthObject::SelfAuth),
            (28, 0, 1 | 2 | 3 | 5 | 6 | 8 | 9) => (Adkd::InavCed, AuthObject::Other),
            (28, 0, 4) => (Adkd::InavCed, AuthObject::SelfAuth),
            (28, _, 7) => (Adkd::SlowMac, AuthObject::SelfAuth),
            (28, 1, 1 | 2 | 4 | 5 | 8 | 9) => (Adkd::InavCed, AuthObject::Other),
            (28, 1, 3) => (Adkd::InavCed, AuthObject::SelfAuth),
            (28, 1, 6) => (Adkd::InavTiming, AuthObject::SelfAuth),
            (31, 0, 1 | 2 | 4) => (Adkd::InavCed, AuthObject::Other),
            (31, _, 3) => (Adkd::SlowMac, AuthObject::SelfAuth),
            (31, 1, 1 | 2) => (Adkd::InavCed, AuthObject::Other),
            (31, 1, 4) => (Adkd::InavTiming, AuthObject::SelfAuth),
            (33, 0, 1 | 3 | 5) => (Adkd::InavCed, AuthObject::Other),
            (33, 0, 2) => (Adkd::InavTiming, AuthObject::SelfAuth),
            (33, 0, 4) => (Adkd::SlowMac, AuthObject::SelfAuth),
            (33, 1, 1 | 2 | 4) => (Adkd::InavCed, AuthObject::Other),
            (33, 1, 3) => (Adkd::SlowMac, AuthObject::SelfAuth),
            (33, 1, 5) => (Adkd::SlowMac, AuthObject::Other),
            (27 | 28 | 31 | 33, _, _) => return Err(AdkdCheckError::InvalidTagNumber),
            (_, _, _) => return Err(AdkdCheckError::InvalidMaclt),
        };
        assert!((adkd != Adkd::InavTiming) || (object == AuthObject::SelfAuth));
        if tag.adkd() != adkd {
            Err(AdkdCheckError::WrongAdkd)
        } else if adkd == Adkd::InavTiming {
            if tag.prnd() != Prnd::GalileoConstellation {
                Err(AdkdCheckError::WrongPrnd)
            } else {
                Ok(())
            }
        } else if let Prnd::GalileoSvid(prnd) = tag.prnd() {
            if object == AuthObject::SelfAuth && prnd != prna.try_into().unwrap() {
                Err(AdkdCheckError::WrongPrnd)
            } else if (1..=NUM_SVNS).contains(&prnd.into()) {
                Ok(())
            } else {
                Err(AdkdCheckError::WrongPrnd)
            }
        } else {
            unreachable!()
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum ChainError {
    ReservedField,
    NmaDontUse,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum AdkdCheckError {
    InvalidTagNumber,
    InvalidMaclt,
    WrongAdkd,
    WrongPrnd,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
enum AuthObject {
    SelfAuth,
    Other,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct Key<V> {
    data: [u8; MAX_KEY_BYTES],
    chain: Chain,
    gst_subframe: Gst,
    _validated: V,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum ValidationError {
    WrongOneWayFunction,
    DifferentChain,
    DoesNotFollow,
    TooManyDerivations,
}

impl<V> Key<V> {
    pub fn gst_subframe(&self) -> Gst {
        self.gst_subframe
    }

    fn check_gst(gst: Gst) {
        assert!(gst.is_subframe());
    }

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
    pub fn from_dsm_kroot(
        nma_header: NmaHeader,
        dsm_kroot: DsmKroot,
        pubkey: &VerifyingKey,
    ) -> Result<Key<Validated>, KrootValidationError> {
        let chain = Chain::from_dsm_kroot(nma_header, dsm_kroot)
            .map_err(|_| KrootValidationError::WrongDsmKrootChain)?;
        if !dsm_kroot.check_padding(nma_header) {
            return Err(KrootValidationError::WrongDsmKrootPadding);
        }
        if !dsm_kroot.check_signature(nma_header, pubkey) {
            return Err(KrootValidationError::WrongEcdsa);
        }
        let wn = dsm_kroot.kroot_wn();
        let tow = Tow::from(dsm_kroot.kroot_towh()) * 3600;
        let gst = Gst::new(wn, tow);
        Self::check_gst(gst);
        let gst = gst.add_seconds(-30);
        Ok(Key::from_slice(dsm_kroot.kroot(), gst, &chain).force_valid())
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum KrootValidationError {
    WrongDsmKrootChain,
    WrongDsmKrootPadding,
    WrongEcdsa,
}

impl<V: Clone> Key<V> {
    pub fn one_way_function(&self) -> Key<V> {
        // 10 bytes are needed for GST (32 bits) || alpha (48 bits)
        let mut buffer = [0; MAX_KEY_BYTES + 10];
        let size = self.chain.key_size_bytes;
        buffer[..size].copy_from_slice(&self.data[..size]);
        let previous_subframe = self.gst_subframe.add_seconds(-30);
        Self::store_gst(&mut buffer[size..size + 4], previous_subframe);
        buffer[size + 4..size + 10].copy_from_slice(&self.chain.alpha.to_be_bytes()[2..]);
        let mut new_key = [0; MAX_KEY_BYTES];
        self.hash_message(&buffer[..size + 10], &mut new_key[..size]);
        Key {
            data: new_key,
            chain: self.chain,
            gst_subframe: previous_subframe,
            _validated: self._validated.clone(),
        }
    }

    fn hash_message(&self, message: &[u8], hash_out: &mut [u8]) {
        match self.chain.hash_function {
            HashFunction::Sha256 => Self::hash_message_digest::<Sha256>(message, hash_out),
            HashFunction::Sha3_256 => Self::hash_message_digest::<Sha3_256>(message, hash_out),
        }
    }

    fn hash_message_digest<D: Digest>(message: &[u8], hash_out: &mut [u8]) {
        let mut hash = D::new();
        hash.update(message);
        let hash = hash.finalize();
        hash_out.copy_from_slice(&hash[..hash_out.len()]);
    }

    pub fn derive(&self, num_derivations: usize) -> Key<V> {
        let mut derived_key = self.clone();
        for _ in 0..num_derivations {
            derived_key = derived_key.one_way_function();
        }
        derived_key
    }
}

impl Key<Validated> {
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

    pub fn validate_tag(
        &self,
        tag: &BitSlice,
        tag_gst: Gst,
        prnd: u8,
        prna: u8,
        ctr: u8,
        navdata: &BitSlice,
    ) -> bool {
        // The buffer needs to be 1 byte larger than for tag0,
        // in order to fit PRN_D
        const BUFF_SIZE: usize = 76;
        let mut buffer = [0u8; BUFF_SIZE];
        buffer[0] = prnd;
        let num_bytes =
            1 + self.fill_common_tag_message(&mut buffer[1..], tag_gst, prna, ctr, navdata);
        self.check_tag(&buffer[..num_bytes], tag)
    }

    pub fn validate_tag0(
        &self,
        tag0: &BitSlice,
        tag_gst: Gst,
        prna: u8,
        navdata: &BitSlice,
    ) -> bool {
        // This is large enough to fit all the message for ADKD=0 and 12
        // (which have the largest navdata)
        const BUFF_SIZE: usize = 75;
        let mut buffer = [0u8; BUFF_SIZE];
        let num_bytes = self.fill_common_tag_message(&mut buffer, tag_gst, prna, 1, navdata);
        self.check_tag(&buffer[..num_bytes], tag0)
    }

    fn fill_common_tag_message(
        &self,
        buffer: &mut [u8],
        gst: Gst,
        prna: u8,
        ctr: u8,
        navdata: &BitSlice,
    ) -> usize {
        buffer[0] = prna;
        Self::store_gst(&mut buffer[1..5], gst);
        buffer[5] = ctr;
        let remaining_bits = BitSlice::from_slice_mut(&mut buffer[6..]);
        remaining_bits[..2].store_be(match self.chain.status {
            ChainStatus::Test => 1,
            ChainStatus::Operational => 2,
        });
        remaining_bits[2..2 + navdata.len()].copy_from_bitslice(navdata);
        6 + (2 + navdata.len() + 7) / 8 // number of bytes used by message
    }

    fn check_tag(&self, message: &[u8], tag: &BitSlice) -> bool {
        match self.chain.mac_function {
            MacFunction::HmacSha256 => self.check_tag_mac::<Hmac<Sha256>>(message, tag),
            MacFunction::CmacAes => self.check_tag_mac::<Cmac<Aes128>>(message, tag),
        }
    }

    fn check_tag_mac<M: Mac + KeyInit>(&self, message: &[u8], tag: &BitSlice) -> bool {
        let key = &self.data[..self.chain.key_size_bytes];
        let mut mac = <M as Mac>::new_from_slice(key).unwrap();
        mac.update(message);
        let mac = mac.finalize().into_bytes();
        let computed = &BitSlice::from_slice(&mac)[..tag.len()];
        computed == tag
    }

    pub fn check_macseq(&self, mack: Mack, prna: usize, gst_mack: Gst) -> bool {
        // No MACLTs with FLEX tags are defined currently, so FLEX
        // tags are not taken into account. This will need to be
        // updated when FLEX tags are added to the MACLTs.

        // This is large enough if there are no FLEX tags
        let mut buffer = [0u8; 5];
        buffer[0] = prna.try_into().unwrap();
        Self::store_gst(&mut buffer[1..5], gst_mack);
        let num_bytes = 5;
        let mut macseq_buffer = [0u8; 2];
        let macseq_bits = &mut BitSlice::from_slice_mut(&mut macseq_buffer)[..12];
        macseq_bits.store_be::<u16>(mack.macseq());
        self.check_tag(&buffer[..num_bytes], macseq_bits)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use hex_literal::hex;

    fn test_chain() -> Chain {
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
        let prna = 21;
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

    fn test_mack() -> Mack<'static> {
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

    fn test_key() -> Key<NotValidated> {
        Key::from_slice(
            &hex!("19 58 e7 76 6f b4 08 cb d6 a8 de fc e4 c7 d5 66"),
            Gst::new(1176, 121080),
            &test_chain(),
        )
    }

    #[test]
    fn adkd() {
        let mack = test_mack();
        let prna = 19;
        for j in 1..mack.num_tags() {
            assert!(test_chain()
                .check_adkd(j, mack.tag_and_info(j), prna, Gst::new(1176, 121050))
                .is_ok());
        }
    }

    #[test]
    fn macseq() {
        let key = test_key().force_valid();
        let mack = test_mack();
        let prna = 19;
        assert!(key.check_macseq(mack, prna, Gst::new(1176, 121050)));
    }
}
