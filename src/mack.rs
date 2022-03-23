use crate::gst::Gst;
use crate::types::{MackMessage, StaticStorage, NUM_SVNS};
use generic_array::GenericArray;
use typenum::Unsigned;

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct MackStorage<S: StaticStorage> {
    macks: GenericArray<[Option<MackMessage>; NUM_SVNS], S::MackDepth>,
    gsts: GenericArray<Option<Gst>, S::MackDepth>,
    write_pointer: usize,
}

impl<S: StaticStorage> MackStorage<S> {
    pub fn new() -> MackStorage<S> {
        let n = S::MackDepth::to_usize();
        let macks =
            GenericArray::from_exact_iter(core::iter::repeat([None; NUM_SVNS]).take(n)).unwrap();
        let gsts = GenericArray::from_exact_iter(core::iter::repeat(None).take(n)).unwrap();
        MackStorage {
            macks,
            gsts,
            write_pointer: 0,
        }
    }

    fn check_svn(svn: usize) {
        assert!((1..=NUM_SVNS).contains(&svn));
    }

    pub fn store(&mut self, mack: &MackMessage, svn: usize, gst: Gst) {
        Self::check_svn(svn);
        self.adjust_write_pointer(gst);
        log::trace!(
            "storing MACK {:02x?} for E{:02} and GST {:?}",
            mack,
            svn,
            gst
        );
        self.macks[self.write_pointer][svn - 1] = Some(*mack);
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
                self.macks[self.write_pointer] = [None; NUM_SVNS];
            }
        }
        self.gsts[self.write_pointer] = Some(gst);
    }

    pub fn get(&self, svn: usize, gst: Gst) -> Option<&MackMessage> {
        Self::check_svn(svn);
        let idx =
            self.gsts
                .iter()
                .enumerate()
                .find_map(|(j, &g)| if g == Some(gst) { Some(j) } else { None })?;
        self.macks[idx][svn - 1].as_ref()
    }
}

impl<S: StaticStorage> Default for MackStorage<S> {
    fn default() -> MackStorage<S> {
        MackStorage::new()
    }
}
