use crate::gst::Gst;
use crate::types::{MackMessage, StaticStorage, NUM_SVNS};
use core::num::NonZeroU8;
use generic_array::GenericArray;
use typenum::Unsigned;

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct MackStorage<S: StaticStorage> {
    macks: GenericArray<Option<Mack>, S::MackDepthSats>,
    gsts: GenericArray<Option<Gst>, S::MackDepth>,
    write_pointer: usize,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct Mack {
    message: MackMessage,
    svn: NonZeroU8,
}

impl<S: StaticStorage> MackStorage<S> {
    pub fn new() -> MackStorage<S> {
        MackStorage {
            macks: GenericArray::default(),
            gsts: GenericArray::default(),
            write_pointer: 0,
        }
    }

    fn check_svn(svn: usize) {
        assert!((1..=NUM_SVNS).contains(&svn));
    }

    pub fn store(&mut self, mack: &MackMessage, svn: usize, gst: Gst) {
        Self::check_svn(svn);
        self.adjust_write_pointer(gst);
        for location in self.current_macks_as_mut().iter_mut() {
            if location.is_none() {
                log::trace!(
                    "storing MACK {:02x?} for E{:02} and GST {:?}",
                    mack,
                    svn,
                    gst
                );
                let svn_u8 = NonZeroU8::new(svn.try_into().unwrap()).unwrap();
                *location = Some(Mack {
                    message: *mack,
                    svn: svn_u8,
                });
                return;
            }
        }
        log::warn!(
            "no room to store MACK {:02x?} for E{:02} and GST {:?}",
            mack,
            svn,
            gst
        );
    }

    fn current_macks_as_mut(&mut self) -> &mut [Option<Mack>] {
        &mut self.macks[self.write_pointer * S::NUM_SATS..(self.write_pointer + 1) * S::NUM_SATS]
    }

    fn adjust_write_pointer(&mut self, gst: Gst) {
        // If write pointer points to a valid GST which is distinct
        // from the current, we advance the write pointer and erase
        // everything at the new write pointer location.
        if let Some(g) = self.gsts[self.write_pointer] {
            if g != gst {
                log::trace!(
                    "got a new GST {:?} (current GST is {:?}); \
                             advancing write pointer",
                    gst,
                    g
                );
                self.write_pointer = (self.write_pointer + 1) % S::MackDepth::USIZE;
                self.current_macks_as_mut().fill(None);
            }
        }
        self.gsts[self.write_pointer] = Some(gst);
    }

    pub fn get(&self, svn: usize, gst: Gst) -> Option<&MackMessage> {
        Self::check_svn(svn);
        let gst_idx =
            self.gsts
                .iter()
                .enumerate()
                .find_map(|(j, &g)| if g == Some(gst) { Some(j) } else { None })?;
        let svn_u8 = NonZeroU8::new(svn.try_into().unwrap()).unwrap();
        self.macks[gst_idx * S::NUM_SATS..(gst_idx + 1) * S::NUM_SATS]
            .iter()
            .find_map(|x| match x {
                Some(Mack { svn, message }) if *svn == svn_u8 => Some(message),
                _ => None,
            })
    }
}

impl<S: StaticStorage> Default for MackStorage<S> {
    fn default() -> MackStorage<S> {
        MackStorage::new()
    }
}
