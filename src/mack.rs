use crate::types::{Gst, MackMessage, NUM_SVNS};

// Number of subframes to store.
// This is 12 because we need to store the current subframe,
// the previous subframe because its tags correspond to the
// key in the current subframe, and also the 10 previous subframes
// to this to acccount for Slow MAC.
const DEPTH: usize = 12;

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct MackStorage {
    macks: [[Option<MackMessage>; NUM_SVNS]; DEPTH],
    gsts: [Option<Gst>; DEPTH],
    write_pointer: usize,
}

impl MackStorage {
    pub fn new() -> MackStorage {
        MackStorage {
            macks: [[None; NUM_SVNS]; DEPTH],
            gsts: [None; DEPTH],
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
                self.write_pointer = (self.write_pointer + 1) % DEPTH;
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

impl Default for MackStorage {
    fn default() -> MackStorage {
        MackStorage::new()
    }
}
