//! MAC Look-up Table
//!
//! This module contains the MAC Look-up Table defined in ANNEX C of the
//! [OSNMA ICD](https://www.gsc-europa.eu/sites/default/files/sites/all/files/Galileo_OSNMA_SIS_ICD_v1.1.pdf),
//! and the supporting code required to use it.

use crate::bitfields::Adkd;
use core::fmt;

const MSG: usize = 2;

// Maximum value of nt in the MAC Look-up Table
const MAX_NT: usize = 10;

// Number of entries in the MAC Look-up Table
const MAC_LT_ENTRIES: usize = 12;

/// Maximum number of FLX entries in a single MAC Look-up Table sequence.
///
/// This constant is needed to dimension the buffer used in MACSEQ verification.
pub const MAX_FLX_ENTRIES: usize = 4;

// Constants used for defining MAC Look-up Table entries more briefly
const F00S: MacLTSlot = MacLTSlot::Fixed {
    adkd: Adkd::InavCed,
    object: AuthObject::SelfAuth,
};
const F00E: MacLTSlot = MacLTSlot::Fixed {
    adkd: Adkd::InavCed,
    object: AuthObject::CrossAuth,
};
const F04S: MacLTSlot = MacLTSlot::Fixed {
    adkd: Adkd::InavTiming,
    object: AuthObject::SelfAuth,
};
const F12S: MacLTSlot = MacLTSlot::Fixed {
    adkd: Adkd::SlowMac,
    object: AuthObject::SelfAuth,
};
const F12E: MacLTSlot = MacLTSlot::Fixed {
    adkd: Adkd::SlowMac,
    object: AuthObject::CrossAuth,
};
const FLX: MacLTSlot = MacLTSlot::Flex;

struct MacLTEntry {
    id: u8,
    nt: u8,
    // The first entry in the sequence is omitted, since it is always 00S and is
    // not looked up, because it corresponds to tag0.
    //
    // Inexistent entries in the sequence are filled with FLX.
    //
    // Entries with Msg = 1 (currently none of these exist) use
    // the same values in the two arrays of `sequence`.
    sequence: [[MacLTSlot; MAX_NT - 1]; MSG],
}

// MAC Look-up Table
static MACLT: [MacLTEntry; MAC_LT_ENTRIES] = [
    MacLTEntry {
        id: 27,
        nt: 6,
        sequence: [
            [F00E, F00E, F00E, F12S, F00E, FLX, FLX, FLX, FLX],
            [F00E, F00E, F04S, F12S, F00E, FLX, FLX, FLX, FLX],
        ],
    },
    MacLTEntry {
        id: 28,
        nt: 10,
        sequence: [
            [F00E, F00E, F00E, F00S, F00E, F00E, F12S, F00E, F00E],
            [F00E, F00E, F00S, F00E, F00E, F04S, F12S, F00E, F00E],
        ],
    },
    MacLTEntry {
        id: 31,
        nt: 5,
        sequence: [
            [F00E, F00E, F12S, F00E, FLX, FLX, FLX, FLX, FLX],
            [F00E, F00E, F12S, F04S, FLX, FLX, FLX, FLX, FLX],
        ],
    },
    MacLTEntry {
        id: 33,
        nt: 6,
        sequence: [
            [F00E, F04S, F00E, F12S, F00E, FLX, FLX, FLX, FLX],
            [F00E, F00E, F12S, F00E, F12E, FLX, FLX, FLX, FLX],
        ],
    },
    MacLTEntry {
        id: 34,
        nt: 6,
        sequence: [
            [FLX, F04S, FLX, F12S, F00E, FLX, FLX, FLX, FLX],
            [FLX, F00E, F12S, F00E, F12E, FLX, FLX, FLX, FLX],
        ],
    },
    MacLTEntry {
        id: 35,
        nt: 6,
        sequence: [
            [FLX, F04S, FLX, F12S, FLX, FLX, FLX, FLX, FLX],
            [FLX, FLX, F12S, FLX, FLX, FLX, FLX, FLX, FLX],
        ],
    },
    MacLTEntry {
        id: 36,
        nt: 5,
        sequence: [
            [FLX, F04S, FLX, F12S, FLX, FLX, FLX, FLX, FLX],
            [FLX, F00E, F12S, F12E, FLX, FLX, FLX, FLX, FLX],
        ],
    },
    MacLTEntry {
        id: 37,
        nt: 5,
        sequence: [
            [F00E, F04S, F00E, F12S, FLX, FLX, FLX, FLX, FLX],
            [F00E, F00E, F12S, F12E, FLX, FLX, FLX, FLX, FLX],
        ],
    },
    MacLTEntry {
        id: 38,
        nt: 5,
        sequence: [
            [FLX, F04S, FLX, F12S, FLX, FLX, FLX, FLX, FLX],
            [FLX, FLX, F12S, FLX, FLX, FLX, FLX, FLX, FLX],
        ],
    },
    MacLTEntry {
        id: 39,
        nt: 4,
        sequence: [
            [FLX, F04S, FLX, FLX, FLX, FLX, FLX, FLX, FLX],
            [FLX, F00E, F12S, FLX, FLX, FLX, FLX, FLX, FLX],
        ],
    },
    MacLTEntry {
        id: 40,
        nt: 4,
        sequence: [
            [F00E, F04S, F12S, FLX, FLX, FLX, FLX, FLX, FLX],
            [F00E, F00E, F12E, FLX, FLX, FLX, FLX, FLX, FLX],
        ],
    },
    MacLTEntry {
        id: 41,
        nt: 4,
        sequence: [
            [FLX, F04S, FLX, FLX, FLX, FLX, FLX, FLX, FLX],
            [FLX, FLX, F12S, FLX, FLX, FLX, FLX, FLX, FLX],
        ],
    },
];

/// Looks up an entry in the MAC Look-up Table.
///
/// This function looks up and returns the entry of the MAC Look-up Table
/// corresponding to a `maclt` ID, message number `msg` (either zero or one) and
/// tag number `num_tag`. If the entry does not exist in the table, an error is
/// returned.
///
/// # Panics
///
/// This function panics if `msg` is not zero or one, or if `num_tag` is zero.
pub fn get_maclt_entry(maclt: u8, msg: usize, num_tag: usize) -> Result<MacLTSlot, MacLTError> {
    assert!((msg == 0) || (msg == 1));
    assert!(num_tag >= 1);
    let Some(entry) = MACLT.iter().find(|&x| x.id == maclt) else {
        return Err(MacLTError::InvalidMaclt);
    };
    if num_tag >= entry.nt.into() {
        return Err(MacLTError::InvalidTagNumber);
    }
    let entry = entry.sequence[msg][num_tag - 1];
    // Enforce that InavTiming must use SelfAuth as AuthObject
    if let MacLTSlot::Fixed { adkd, object } = entry {
        assert!(adkd != Adkd::InavTiming || object == AuthObject::SelfAuth);
    }
    Ok(entry)
}

/// Returns an iterator over the indices corresponding to FLX entries.
///
/// This function returns an iterator over the indices corresponding to FLX
/// entries for a particular `maclt` ID and message number `msg` (either zero or
/// one). If the ID does not exist in the table, an error is returned.
///
/// # Panics
///
/// This function panics if `msg` is not zero or one.
pub fn get_flx_indices(maclt: u8, msg: usize) -> Result<impl Iterator<Item = usize>, MacLTError> {
    assert!((msg == 0) || (msg == 1));
    let Some(entry) = MACLT.iter().find(|&x| x.id == maclt) else {
        return Err(MacLTError::InvalidMaclt);
    };
    Ok(entry.sequence[msg]
        .iter()
        .take(usize::from(entry.nt) - 1)
        .enumerate()
        .filter_map(|(j, &x)| if x == FLX { Some(j + 1) } else { None }))
}

/// MAC Look-up Table slot.
///
/// This enum represents a slot in the MAC Look-up Table.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum MacLTSlot {
    /// Fixed slot.
    ///
    /// A fixed slot, such as '00S', '04S', '12S', '00E', or '12E'. It is
    /// composed by an ADKD and an authentication object.
    Fixed {
        /// ADKD of the fixed slot.
        ///
        /// In the MAC Look-up Table it is represented by the numeric code of
        /// the ADKD ('00', '04', or '12').
        adkd: Adkd,
        /// Authentication object of the fixed slot.
        ///
        /// In the MAC Look-up Table it is represented by a character ('S' or
        /// 'E').
        object: AuthObject,
    },
    /// Flexible slot.
    ///
    /// Flexible slots are represented by 'FLX' in the MAC Look-up Table.
    Flex,
}

/// Authentication object.
///
/// This enum lists the possible objects that are authenticated by a MAC Look-up
/// Table entry.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum AuthObject {
    /// Self-authentication ('S' in the MAC Look-up Table entry).
    SelfAuth,
    /// Galileo Cross-authentication ('E' in the MAC Look-up Table entry).
    CrossAuth,
}

/// Errors produced during MAC Table look-up.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum MacLTError {
    /// The value of the MACLT does not appear as an ID in the MAC Look-up
    /// Table.
    InvalidMaclt,
    /// The tag number is greater than the number of tags 'nt' in the MAC
    /// Look-up Table entry.
    InvalidTagNumber,
}

impl fmt::Display for MacLTError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MacLTError::InvalidMaclt => "invalid MAC look-up table ID".fmt(f),
            MacLTError::InvalidTagNumber => "invalid tag number".fmt(f),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for MacLTError {}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn lookups() {
        assert_eq!(get_maclt_entry(34, 0, 1), Ok(FLX));
        assert_eq!(get_maclt_entry(34, 0, 2), Ok(F04S));
        assert_eq!(get_maclt_entry(34, 1, 5), Ok(F12E));
        assert_eq!(get_maclt_entry(26, 0, 1), Err(MacLTError::InvalidMaclt));
        assert_eq!(get_maclt_entry(34, 0, 6), Err(MacLTError::InvalidTagNumber));
    }

    #[test]
    #[should_panic]
    fn lookup_wrong_msg() {
        let _ = get_maclt_entry(34, 2, 1);
    }

    #[test]
    #[should_panic]
    fn lookup_wrong_tag_number() {
        let _ = get_maclt_entry(34, 0, 0);
    }

    /// Checks that the `MAX_FLX_ENTRIES` constant has the correct value.
    #[test]
    fn max_flx_entries() {
        let max = MACLT
            .iter()
            .map(|entry| {
                entry
                    .sequence
                    .iter()
                    .map(|s| {
                        s.iter()
                            .take(usize::from(entry.nt) - 1)
                            .filter(|&&x| x == FLX)
                            .count()
                    })
                    .max()
                    .unwrap()
            })
            .max()
            .unwrap();
        assert_eq!(max, MAX_FLX_ENTRIES);
    }

    #[test]
    fn flx_indices() {
        let indices = get_flx_indices(34, 0).unwrap().collect::<Vec<_>>();
        assert_eq!(&indices, &[1, 3]);
        let indices = get_flx_indices(34, 1).unwrap().collect::<Vec<_>>();
        assert_eq!(&indices, &[1]);
    }
}
