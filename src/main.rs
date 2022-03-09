#[cfg(feature = "galmon")]
use galileo_osnma::bitfields::{DsmHeader, NmaHeader};
#[cfg(feature = "galmon")]
use galileo_osnma::galmon::navmon::nav_mon_message::GalileoInav;
#[cfg(feature = "galmon")]
use galileo_osnma::galmon::transport::ReadTransport;
#[cfg(feature = "galmon")]
use galileo_osnma::subframe::CollectSubframe;

#[cfg(feature = "galmon")]
fn main() -> std::io::Result<()> {
    #[cfg(feature = "env_logger")]
    env_logger::init();
    let mut read = ReadTransport::new(std::io::stdin());
    let mut subframe = CollectSubframe::new();
    loop {
        let packet = read.read_packet()?;
        if let Some(
            inav @ GalileoInav {
                reserved1: Some(osnma),
                ..
            },
        ) = &packet.gi
        {
            if let Some((hkroot, _mack)) = subframe.feed(
                osnma[..].try_into().unwrap(),
                inav.gnss_wn.try_into().unwrap(),
                inav.gnss_tow,
                inav.gnss_sv.try_into().unwrap(),
            ) {
                let nma_header = &hkroot[..1].try_into().unwrap();
                let nma_header = NmaHeader(nma_header);
                let dsm_header = &hkroot[1..2].try_into().unwrap();
                let dsm_header = DsmHeader(dsm_header);
                dbg!(nma_header, dsm_header);
            }
        }
    }
}

#[cfg(not(feature = "galmon"))]
fn main() {}
