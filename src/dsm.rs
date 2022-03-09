use crate::bitfields::{DsmHeader, DsmType};
use crate::types::{DsmBlock, DSM_BLOCK_BYTES};

const MAX_DSM_BLOCKS: usize = 16;
const MAX_DSM_BYTES: usize = MAX_DSM_BLOCKS * DSM_BLOCK_BYTES;

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct CollectDsm {
    dsm: [u8; MAX_DSM_BYTES],
    block_valid: [bool; MAX_DSM_BLOCKS],
    done: bool,
    dsm_type: Option<DsmType>,
    dsm_id: u8,
}

impl CollectDsm {
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

    pub fn feed(&mut self, header: DsmHeader, block: &DsmBlock) -> Option<&[u8]> {
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
            Some(dsm)
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
