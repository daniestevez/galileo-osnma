/// Galileo week number.
pub type Wn = u16;
/// Time of week.
///
/// This represents the time of week in seconds.
pub type Tow = u32;

const SECS_IN_WEEK: Tow = 24 * 3600 * 7;
const SECS_PER_SUBFRAME: Tow = 30;

/// GST (Galileo System Time)
///
/// The Galileo System Time, stored as a week number and a time of week.
///
/// # Examples
/// ```
/// use galileo_osnma::Gst;
///
/// let gst = Gst::new(1177, 175767);
/// assert_eq!(gst.wn(), 1177);
/// assert_eq!(gst.tow(), 175767);
/// ```
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct Gst {
    wn: Wn,
    tow: Tow,
}

impl Gst {
    /// Constructs a new GST from a week number and TOW.
    ///
    /// # Panics
    ///
    /// Panics if `tow` is greater or equal to 604800 (the number of
    /// seconds in a week).
    pub fn new(wn: Wn, tow: Tow) -> Self {
        assert!(tow < SECS_IN_WEEK);
        Gst { wn, tow }
    }

    /// Returns the week number of the GST.
    pub fn wn(&self) -> Wn {
        self.wn
    }

    /// Returns the time of week of the GST.
    pub fn tow(&self) -> Tow {
        self.tow
    }

    /// Adds `seconds` seconds to the GST.
    ///
    /// The GST corresponding to the sum is returned.
    ///
    /// # Examples
    ///
    /// ```
    /// use galileo_osnma::Gst;
    ///
    /// let gst = Gst::new(1177, 175767);
    /// let gst_next_page = gst.add_seconds(2);
    /// assert_eq!(gst_next_page.wn(), 1177);
    /// assert_eq!(gst_next_page.tow(), 175769);
    ///
    /// assert_eq!(gst_next_page.add_seconds(-2), gst);
    /// ```
    pub fn add_seconds(&self, seconds: i32) -> Self {
        let secs_in_week = SECS_IN_WEEK.try_into().unwrap();
        let weeks = seconds / secs_in_week;
        let seconds = seconds - weeks * secs_in_week;
        let mut tow = i32::try_from(self.tow).unwrap() + seconds;
        let mut wn = self.wn + u16::try_from(weeks).unwrap();
        if tow < 0 {
            wn -= 1;
            tow += secs_in_week;
        } else if tow >= secs_in_week {
            wn += 1;
            tow -= secs_in_week;
        };
        assert!((0..secs_in_week).contains(&tow));
        Gst {
            tow: tow.try_into().unwrap(),
            wn,
        }
    }

    /// Adds `subframes` 30-second subframes to the GST.
    ///
    /// The GST corresponding to the sum is returned.
    ///
    /// # Examples
    ///
    /// ```
    /// use galileo_osnma::Gst;
    ///
    /// let gst = Gst::new(1177, 175767);
    /// let gst2 = gst.add_subframes(3);
    /// assert_eq!(gst2.wn(), 1177);
    /// assert_eq!(gst2.tow(), 175857);
    ///
    /// assert_eq!(gst2.add_subframes(-3), gst);
    /// ```
    pub fn add_subframes(&self, subframes: i32) -> Self {
        self.add_seconds(subframes * i32::try_from(SECS_PER_SUBFRAME).unwrap())
    }

    /// Returns the GST at the start of the subframe that contains `self`.
    ///
    /// The GST returned has the same week number as `self` and its time
    /// of week is the largest multiple of 30 seconds that is smaller or
    /// equal than the time of week of `self`.
    ///
    /// # Examples
    ///
    /// ```
    /// use galileo_osnma::Gst;
    ///
    /// let gst = Gst::new(1177, 175767);
    /// let subframe = gst.gst_subframe();
    /// assert_eq!(subframe.wn(), 1177);
    /// assert_eq!(subframe.tow(), 175740);
    pub fn gst_subframe(&self) -> Self {
        Gst {
            wn: self.wn,
            tow: self.tow / SECS_PER_SUBFRAME * SECS_PER_SUBFRAME,
        }
    }

    /// Returns `true` if `self` corresponds to the start of a subframe.
    ///
    /// A GST corresponds to the start of a subframe if its time of week is a
    /// multiple of 30 seconds.
    ///
    /// # Examples
    /// ```
    /// use galileo_osnma::Gst;
    ///
    /// let gst = Gst::new(1177, 175767);
    /// let subframe = gst.gst_subframe();
    /// assert_eq!(gst.is_subframe(), false);
    /// assert_eq!(subframe.is_subframe(), true);
    pub fn is_subframe(&self) -> bool {
        self.tow % SECS_PER_SUBFRAME == 0
    }
}
