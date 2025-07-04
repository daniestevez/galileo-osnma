use galileo_osnma::{
    Osnma,
    storage::{FullStorage, SmallStorage},
};
use std::mem::size_of;

fn main() {
    dbg!(size_of::<Osnma<FullStorage>>());
    dbg!(size_of::<Osnma<SmallStorage>>());
}
