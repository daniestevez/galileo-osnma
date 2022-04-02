use crate::types::NUM_SVNS;
use core::fmt;
use core::num::NonZeroU8;

/// Galileo SVN.
///
/// The SVN is the Galileo satellite number, which is a number between 1 and
/// 36. This struct stores the SVN internally as a `NonZeroU8`, and guarantees
/// at construction that the value is always in range.
///
/// SVNs are typically written as Exx (E24, for instance). The `Display`
/// implementation of `Svn` does this.
///
/// # Examples
///
/// An `Svn` is typically constructed from an integer type using a `TryFrom`
/// implementation, which checks that the integer is in the correct range.
///
/// ```
/// use galileo_osnma::Svn;
///
/// let svn = Svn::try_from(24).unwrap();
/// assert_eq!(format!("{}", svn), "E24");
/// ```
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub struct Svn(NonZeroU8);

impl Svn {
    /// Iterate over all the SVNs.
    ///
    /// Returns an iterator that iterates over the SVNs from E01 to E36 in
    /// increasing order.
    pub fn iter() -> impl Iterator<Item = Svn> {
        (1..=NUM_SVNS)
            .into_iter()
            .map(|x| Svn::try_from(x).unwrap())
    }
}

macro_rules! impl_conv {
    ($t: ty) => {
        impl From<Svn> for $t {
            fn from(svn: Svn) -> $t {
                svn.0.get().try_into().unwrap()
            }
        }

        impl TryFrom<$t> for Svn {
            type Error = SvnError;
            fn try_from(value: $t) -> Result<Svn, SvnError> {
                let max = <$t>::try_from(NUM_SVNS).unwrap();
                if (1..=max).contains(&value) {
                    // This shouldn't panic, since we have checked the bounds
                    // already.
                    let val = NonZeroU8::new(u8::try_from(value).unwrap()).unwrap();
                    Ok(Svn(val))
                } else {
                    Err(SvnError::OutOfRange)
                }
            }
        }
    };
}

impl_conv!(u8);
impl_conv!(u16);
impl_conv!(u32);
impl_conv!(u64);
impl_conv!(u128);
impl_conv!(usize);
impl_conv!(i8);
impl_conv!(i16);
impl_conv!(i32);
impl_conv!(i64);
impl_conv!(i128);
impl_conv!(isize);

/// Formats an SVN as Exx.
///
/// Formats an `Svn` in the usual way as `"Exx"` (for instance, `"E24"`).
impl fmt::Display for Svn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "E{:02}", self.0)
    }
}

/// SVN construction error.
///
/// This represents the errors that can happen during the construction of and
/// [`Svn`].
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum SvnError {
    /// The value is outside the range 1-36.
    OutOfRange,
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn from_int() {
        let error = Err(SvnError::OutOfRange);

        for j in 1..=NUM_SVNS {
            assert!(Svn::try_from(j).is_ok());
        }
        assert_eq!(Svn::try_from(0), error);
        assert_eq!(Svn::try_from(37), error);
    }

    #[test]
    fn format() {
        assert_eq!(format!("{}", Svn::try_from(3).unwrap()), "E03");
        assert_eq!(format!("{}", Svn::try_from(24).unwrap()), "E24");
    }

    #[test]
    fn iterator() {
        let mut n = 0;
        for svn in Svn::iter() {
            n += 1;
            assert_eq!(usize::from(svn), n);
        }
        assert_eq!(n, 36);
    }
}
