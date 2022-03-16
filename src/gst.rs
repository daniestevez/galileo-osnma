pub type Wn = u16;
pub type Tow = u32; // Time of week in seconds
pub type Towh = u8; // Time of week in hours

const SECS_IN_WEEK: Tow = 24 * 3600 * 7;
const SECS_PER_SUBFRAME: Tow = 30;

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct Gst {
    wn: Wn,
    tow: Tow,
}

impl Gst {
    pub fn new(wn: Wn, tow: Tow) -> Self {
        assert!(tow < SECS_IN_WEEK);
        Gst { wn, tow }
    }

    pub fn wn(&self) -> Wn {
        self.wn
    }

    pub fn tow(&self) -> Tow {
        self.tow
    }

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

    pub fn gst_subframe(&self) -> Self {
        Gst {
            wn: self.wn,
            tow: self.tow / SECS_PER_SUBFRAME * SECS_PER_SUBFRAME,
        }
    }

    pub fn is_subframe(&self) -> bool {
        self.tow % SECS_PER_SUBFRAME == 0
    }
}
