use crate::bitfields::HashFunction;
use crate::types::{BitSlice, Gst};
use bitvec::prelude::*;
use sha2::{Digest, Sha256};
use sha3::Sha3_256;

const MAX_KEY_BYTES: usize = 32;

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct Key {
    data: [u8; MAX_KEY_BYTES],
    size: usize,
    gst_subframe: Gst,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct ChainParameters {
    pub hash: HashFunction,
    pub alpha: u64,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum ValidationError {
    WrongOneWayFunction,
    DoesNotFollow,
    TooManyDerivations,
}

impl Key {
    pub fn gst_subframe(&self) -> Gst {
        self.gst_subframe
    }

    fn check_gst(gst: Gst) {
        assert!(gst.tow % 30 == 0);
    }

    pub fn from_bitslice(slice: &BitSlice, gst: Gst) -> Key {
        Self::check_gst(gst);
        let mut data = [0; MAX_KEY_BYTES];
        let size = slice.len();
        assert!(size % 8 == 0);
        BitSlice::from_slice_mut(&mut data)[..size].copy_from_bitslice(slice);
        Key {
            data,
            size,
            gst_subframe: gst,
        }
    }

    pub fn from_slice(slice: &[u8], gst: Gst) -> Key {
        Self::check_gst(gst);
        let mut data = [0; MAX_KEY_BYTES];
        let size = slice.len();
        data[..size].copy_from_slice(slice);
        Key {
            data,
            size: 8 * size,
            gst_subframe: gst,
        }
    }

    pub fn one_way_function(&self, params: &ChainParameters) -> Key {
        // 10 bytes are needed for GST (32 bits) || alpha (48 bits)
        let mut buffer = [0; MAX_KEY_BYTES + 10];
        let size = self.size / 8;
        buffer[..size].copy_from_slice(&self.data[..size]);
        let previous_subframe = Gst {
            wn: if self.gst_subframe.tow == 0 {
                self.gst_subframe.wn - 1
            } else {
                self.gst_subframe.wn
            },
            tow: if self.gst_subframe.tow == 0 {
                7 * 24 * 3600 - 30
            } else {
                self.gst_subframe.tow - 30
            },
        };
        let gst_bits = BitSlice::from_slice_mut(&mut buffer[size..size + 4]);
        gst_bits[0..12].store_be(previous_subframe.wn);
        gst_bits[12..32].store_be(previous_subframe.tow);
        buffer[size + 4..size + 10].copy_from_slice(&params.alpha.to_be_bytes()[2..]);
        let mut new_key = [0; MAX_KEY_BYTES];
        match params.hash {
            HashFunction::Sha256 => {
                let mut hash = Sha256::new();
                hash.update(&buffer[..size + 10]);
                let hash = hash.finalize();
                new_key[..size].copy_from_slice(&hash[..size]);
            }
            HashFunction::Sha3_256 => {
                let mut hash = Sha3_256::new();
                hash.update(&buffer[..size + 10]);
                let hash = hash.finalize();
                new_key[..size].copy_from_slice(&hash[..size]);
            }
            HashFunction::Reserved => {
                panic!(
                    "attempted to compute one-way-function using\
                        a reserved value for the hash function parameter"
                );
            }
        };
        Key {
            data: new_key,
            size: self.size,
            gst_subframe: previous_subframe,
        }
    }

    pub fn validate(&self, other: &Key, params: &ChainParameters) -> Result<(), ValidationError> {
        if self.gst_subframe.wn > other.gst_subframe.wn
            || (self.gst_subframe.tow == other.gst_subframe.tow
                && self.gst_subframe.tow >= other.gst_subframe.tow)
        {
            return Err(ValidationError::DoesNotFollow);
        }
        let derivations = i32::from(other.gst_subframe.wn - self.gst_subframe.wn)
            * (7 * 24 * 3600 / 30)
            + (i32::try_from(other.gst_subframe.tow).unwrap()
                - i32::try_from(self.gst_subframe.tow).unwrap())
                / 30;
        assert!(derivations >= 1);
        // Set an arbitrary limit to the number of derivations.
        // This is chosen to be slightly greater than 1 day.
        if derivations > 3000 {
            return Err(ValidationError::TooManyDerivations);
        }
        let mut derived_key = *other;
        for _ in 0..derivations {
            derived_key = derived_key.one_way_function(params);
        }
        assert!(derived_key.gst_subframe == self.gst_subframe);
        if derived_key == *self {
            Ok(())
        } else {
            Err(ValidationError::WrongOneWayFunction)
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn one_way_function() {
        // Keys broadcast on 2022-03-07 ~9:00 UTC
        let k0 = Key::from_slice(
            &hex!("42 b4 19 da 6a da 1c 0a 3d 6f 56 a5 e5 dc 59 a7"),
            Gst {
                wn: 1176,
                tow: 120930,
            },
        );
        let k1 = Key::from_slice(
            &hex!("95 42 aa d4 7a bf 39 ba fe 56 68 61 af e8 80 b2"),
            Gst {
                wn: 1176,
                tow: 120960,
            },
        );
        let chain = ChainParameters {
            hash: HashFunction::Sha256,
            alpha: 0x25d3964da3a2,
        };
        assert_eq!(k1.one_way_function(&chain), k0);
    }

    #[test]
    fn validation_kroot() {
        // KROOT broadcast on 2022-03-07 ~9:00 UTC
        let kroot = Key::from_slice(
            &hex!("84 1e 1d e4 d4 58 c0 e9 84 24 76 e0 04 66 6c f3"),
            Gst {
                wn: 1176,
                tow: 0x21 * 3600 - 30, // towh in DSM-KROOT was 0x21
            },
        );
        let key = Key::from_slice(
            &hex!("42 b4 19 da 6a da 1c 0a 3d 6f 56 a5 e5 dc 59 a7"),
            Gst {
                wn: 1176,
                tow: 120930,
            },
        );
        let chain = ChainParameters {
            hash: HashFunction::Sha256,
            alpha: 0x25d3964da3a2,
        };
        assert!(kroot.validate(&key, &chain).is_ok());
    }
}
