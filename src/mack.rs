//! MACK message storage.
//!
//! This module contains [`MackStorage`], which is used to classify and store
//! MACK messages until their corresponding TESLA keys are received.

use crate::gst::Gst;
use crate::storage::StaticStorage;
use crate::types::MackMessage;
use crate::Svn;
use generic_array::GenericArray;
use typenum::Unsigned;

/// MACK message store.
///
/// This struct is a container that stores a history of MACK messages, so that
/// they can be used when the TESLA keys corresponding to their tags become
/// available. The storage size is statically allocated, and as new messages are
/// stored, the older ones are deleted.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct MackStorage<S: StaticStorage> {
    macks: GenericArray<Option<Mack>, S::MackDepthSats>,
    gsts: GenericArray<Option<Gst>, S::MackDepth>,
    write_pointer: usize,
}

#[doc(hidden)]
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
// This is pub only because it appears in the definition of StaticStorageTypenum
pub struct Mack {
    message: MackMessage,
    svn: Svn,
}

impl<S: StaticStorage> MackStorage<S> {
    /// Creates a new, empty store of MACK messages.
    pub fn new() -> MackStorage<S> {
        MackStorage {
            macks: GenericArray::default(),
            gsts: GenericArray::default(),
            write_pointer: 0,
        }
    }

    /// Store a MACK message.
    ///
    /// This will store the MACK message, potentially erasing the oldest messages
    /// if new storage space is needed.
    ///
    /// The `svn` parameter corresponds to the SVN of the satellite transmitting
    /// the MACK message. This should be obtained from the PRN used for
    /// tracking.
    ///
    /// The `gst` parameter gives the GST at the start of the subframe when the
    /// MACK message was transmitted.
    pub fn store(&mut self, mack: &MackMessage, svn: Svn, gst: Gst) {
        self.adjust_write_pointer(gst);
        for location in self.current_macks_as_mut().iter_mut() {
            if location.is_none() {
                log::trace!("storing MACK {:02x?} for {} and GST {:?}", mack, svn, gst);
                *location = Some(Mack {
                    message: *mack,
                    svn,
                });
                return;
            }
        }
        log::warn!(
            "no room to store MACK {:02x?} for {} and GST {:?}",
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

    /// Try to retrieve a MACK message.
    ///
    /// This will return a the MACK message for a particular SVN and timestamp if
    /// it is available in the storage. If the MACK message is not available, this
    /// returns `None`.
    ///
    /// The `svn` parameter corresponds to the SVN of the satellite transmitting
    /// the MACK message. This should be obtained from the PRN used for
    /// tracking.
    ///
    /// The `gst` parameter refers to the GST at the start of the subframe when the
    /// MACK message was transmitted.
    pub fn get(&self, svn: Svn, gst: Gst) -> Option<&MackMessage> {
        let gst_idx =
            self.gsts
                .iter()
                .enumerate()
                .find_map(|(j, &g)| if g == Some(gst) { Some(j) } else { None })?;
        self.macks[gst_idx * S::NUM_SATS..(gst_idx + 1) * S::NUM_SATS]
            .iter()
            .find_map(|x| match x {
                Some(Mack { svn: s, message }) if *s == svn => Some(message),
                _ => None,
            })
    }
}

impl<S: StaticStorage> Default for MackStorage<S> {
    fn default() -> MackStorage<S> {
        MackStorage::new()
    }
}
