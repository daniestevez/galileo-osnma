//! DSM message collection.
//!
//! This module contains the [`CollectDsm`] struct, which is used to collect all
//! the DSM blocks of a DSM message and recompose the message.

use crate::bitfields::{DsmHeader, DsmType};
use crate::types::{DsmBlock, DSM_BLOCK_BYTES};

const MAX_DSM_BLOCKS: usize = 16;
const MAX_DSM_BYTES: usize = MAX_DSM_BLOCKS * DSM_BLOCK_BYTES;

/// DSM message.
///
/// This struct represents a DSM message. It does not own the storage of the DSM
/// data. It is borrowed from the internal storage of the [`CollectDsm`] that
/// produced it.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct Dsm<'a> {
    id: u8,
    data: &'a [u8],
}

impl Dsm<'_> {
    /// Gives the DSM ID of the DSM.
    pub fn id(&self) -> u8 {
        self.id
    }

    /// Returns a slice containing the data of the DSM.
    pub fn data(&self) -> &[u8] {
        self.data
    }
}

/// DSM message collector.
///
/// This struct collects DSM blocks and produces a complete DSM message when all
/// the blocks of the message have been collected. Only one DSM message at a
/// time can be collected.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct CollectDsm {
    dsm: [u8; MAX_DSM_BYTES],
    block_valid: [bool; MAX_DSM_BLOCKS],
    done: bool,
    dsm_type: Option<DsmType>,
    dsm_id: u8,
}

impl CollectDsm {
    /// Constructs a new, empty DSM collector.
    pub fn new() -> CollectDsm {
        CollectDsm {
            dsm: [0; MAX_DSM_BYTES],
            block_valid: [false; MAX_DSM_BLOCKS],
            done: false,
            dsm_type: None,
            dsm_id: 0,
        }
    }

    fn reset(&mut self) {
        self.block_valid = [false; MAX_DSM_BLOCKS];
        self.done = false;
    }

    /// Feed a new block into the DSM collector.
    ///
    /// If this block completes the DSM message, the recomposed message will be
    /// returned. Otherwise, this returns `None`. The DSM message is represented
    /// as a slice of bytes, owned by the `CollectDsm`.
    ///
    /// The `header` parameter contains the DSM header of the block, and the
    /// `block` parameter contains the 13-byte DSM block.
    ///
    /// If the block fed corresponds to a new DSM ID, the old data is discarded
    /// and the collection for the new DSM begins.
    pub fn feed(&mut self, header: DsmHeader, block: &DsmBlock) -> Option<Dsm> {
        log::trace!("feeding header = {:?}, block = {:02x?}", header, block);
        if header.dsm_id() != self.dsm_id || self.dsm_type.is_none() {
            log::info!(
                "new DSM id = {} (had id = {}). resetting",
                header.dsm_id(),
                self.dsm_id
            );
            self.reset();
            self.dsm_id = header.dsm_id();
            self.dsm_type = Some(header.dsm_type());
        }
        // cannot panic, since the above ensures that self.dsm_type is
        // not None
        let dsm_type = self.dsm_type.unwrap();
        if self.done {
            log::trace!("current DSM is complete. nothing to do");
            return None;
        }
        self.store_block(header.dsm_block_id(), block);
        if let Some(size) = self.done_and_size(dsm_type) {
            log::info!(
                "completed DSM with id = {}, size = {} bytes",
                self.dsm_id,
                size
            );
            let dsm = &self.dsm[..size];
            log::trace!("DSM contents {:02x?}", dsm);
            self.done = true;
            Some(Dsm {
                id: self.dsm_id,
                data: dsm,
            })
        } else {
            None
        }
    }

    fn store_block(&mut self, block_id: u8, block: &DsmBlock) {
        let block_id = usize::from(block_id);
        let idx = block_id * DSM_BLOCK_BYTES;
        let section = &mut self.dsm[idx..idx + DSM_BLOCK_BYTES];
        if self.block_valid[block_id] {
            if section != block {
                log::error!(
                    "block {} already stored, but its contents differ\
                             stored = {:02x?}, just received = {:02x?}",
                    block_id,
                    section,
                    block
                );
            } else {
                log::trace!("block {} already stored", block_id);
            }
        } else {
            section.copy_from_slice(block);
            self.block_valid[block_id] = true;
            log::trace!("stored block {}", block_id);
        }
    }

    fn done_and_size(&self, dsm_type: DsmType) -> Option<usize> {
        if !self.block_valid[0] {
            log::trace!("first block not yet present. DSM size unknown");
            return None;
        }
        // If first block is present, we can read the NB field
        let nb = self.dsm[0] >> 4;
        if let Some(n) = Self::number_of_blocks(dsm_type, nb) {
            let missing = self.block_valid[..n].iter().filter(|&x| !x).count();
            log::trace!("DSM size = {} blocks. missing {} blocks", n, missing);
            if missing == 0 {
                Some(n * DSM_BLOCK_BYTES)
            } else {
                None
            }
        } else {
            // An invalid DSM with a reserved value as NB can never
            // be complete. It will be cancelled once a new DSM id
            // arrives.
            None
        }
    }

    fn number_of_blocks(dsm_type: DsmType, nb: u8) -> Option<usize> {
        let a = match dsm_type {
            DsmType::Pkr => {
                match nb {
                    7 => Some(13),
                    8 => Some(14),
                    9 => Some(15),
                    10 => Some(16),
                    _ => None, // reserved value
                }
            }
            DsmType::Kroot => {
                // TODO: use DsmKroot::number_of_blocks instead of this
                match nb {
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
        };
        if a.is_none() {
            log::error!("reserved NB value {} for dsm_type = {:?}", nb, dsm_type);
        }
        a
    }
}

impl Default for CollectDsm {
    fn default() -> CollectDsm {
        CollectDsm::new()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn collect_dsm() {
        // HKROOT messages broadcast on 2022-03-07 ~9:00 UTC
        let hkroots = [
            hex!("52 25 01 9d 5b 6e 1d d1 87 b9 45 3c df 06 ca"),
            hex!("52 23 a4 c6 6d 7e 3d 29 18 53 ba 5a 13 c9 c3"),
            hex!("52 27 cb 12 29 89 77 35 c0 21 b0 41 73 93 b5"),
            hex!("52 26 7f 34 ea 14 97 52 5a af 18 f1 f9 f1 fc"),
            hex!("52 24 48 4a 26 77 70 11 2a 13 38 3e a5 2d 3a"),
            hex!("52 20 22 50 49 21 04 98 21 25 d3 96 4d a3 a2"),
            hex!("52 27 cb 12 29 89 77 35 c0 21 b0 41 73 93 b5"),
            hex!("52 25 01 9d 5b 6e 1d d1 87 b9 45 3c df 06 ca"),
            hex!("52 20 22 50 49 21 04 98 21 25 d3 96 4d a3 a2"),
            hex!("52 20 22 50 49 21 04 98 21 25 d3 96 4d a3 a2"),
            hex!("52 26 7f 34 ea 14 97 52 5a af 18 f1 f9 f1 fc"),
            hex!("52 21 84 1e 1d e4 d4 58 c0 e9 84 24 76 e0 04"),
            hex!("52 27 cb 12 29 89 77 35 c0 21 b0 41 73 93 b5"),
            hex!("52 22 66 6c f3 79 58 de 28 51 97 a2 63 53 f1"),
        ];
        let mut collect = CollectDsm::new();

        for (j, hkroot) in hkroots.iter().enumerate() {
            let ret = collect.feed(
                DsmHeader(hkroot[1..2].try_into().unwrap()),
                hkroot[2..].try_into().unwrap(),
            );
            if j != hkroots.len() - 1 {
                assert!(ret.is_none());
                assert!(!collect.done);
            } else {
                let dsm = ret.unwrap();
                assert_eq!(dsm.id(), 2);
                assert_eq!(
                    dsm.data(),
                    &hex!(
                        "22 50 49 21 04 98 21 25 d3 96 4d a3 a2 84 1e 1d
                         e4 d4 58 c0 e9 84 24 76 e0 04 66 6c f3 79 58 de
                         28 51 97 a2 63 53 f1 a4 c6 6d 7e 3d 29 18 53 ba
                         5a 13 c9 c3 48 4a 26 77 70 11 2a 13 38 3e a5 2d
                         3a 01 9d 5b 6e 1d d1 87 b9 45 3c df 06 ca 7f 34
                         ea 14 97 52 5a af 18 f1 f9 f1 fc cb 12 29 89 77
                         35 c0 21 b0 41 73 93 b5"
                    )[..]
                );
                assert!(collect.done);
            }
        }
    }
}
