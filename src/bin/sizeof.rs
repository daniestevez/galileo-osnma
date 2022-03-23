use galileo_osnma::{types::FullStorage, types::NoSlowMacStorage, Osnma};
use std::mem::size_of;

fn main() {
    dbg!(size_of::<Osnma<FullStorage>>());
    dbg!(size_of::<Osnma<NoSlowMacStorage>>());
}
