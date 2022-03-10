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

impl Key {
    pub fn gst_subframe(&self) -> Gst {
        self.gst_subframe
    }

    pub fn from_bitslice(slice: &BitSlice, gst: Gst) -> Key {
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
}
