#[cfg(all(feature = "galmon", feature = "pem"))]
use galileo_osnma::bitfields::{DsmHeader, DsmKroot, NmaHeader};
#[cfg(all(feature = "galmon", feature = "pem"))]
use galileo_osnma::dsm::CollectDsm;
#[cfg(all(feature = "galmon", feature = "pem"))]
use galileo_osnma::galmon::navmon::nav_mon_message::GalileoInav;
#[cfg(all(feature = "galmon", feature = "pem"))]
use galileo_osnma::galmon::transport::ReadTransport;
#[cfg(all(feature = "galmon", feature = "pem"))]
use galileo_osnma::subframe::CollectSubframe;

#[cfg(all(feature = "galmon", feature = "pem"))]
use p256::ecdsa::VerifyingKey;
#[cfg(all(feature = "galmon", feature = "pem"))]
use spki::DecodePublicKey;
#[cfg(all(feature = "galmon", feature = "pem"))]
use std::io::Read;

#[cfg(all(feature = "galmon", feature = "pem"))]
fn load_pubkey(path: &str) -> std::io::Result<VerifyingKey> {
    let mut file = std::fs::File::open(path)?;
    let mut pem = String::new();
    file.read_to_string(&mut pem)?;
    Ok(VerifyingKey::from_public_key_pem(&pem).expect("invalid pubkey"))
}

#[cfg(all(feature = "galmon", feature = "pem"))]
fn main() -> std::io::Result<()> {
    #[cfg(feature = "env_logger")]
    env_logger::init();

    let args: Vec<_> = std::env::args().collect();

    let pubkey = load_pubkey(&args[1])?;

    let mut read = ReadTransport::new(std::io::stdin());
    let mut subframe = CollectSubframe::new();
    let mut dsm = CollectDsm::new();
    loop {
        let packet = read.read_packet()?;
        if let Some(
            inav @ GalileoInav {
                reserved1: Some(osnma),
                ..
            },
        ) = &packet.gi
        {
            if osnma.iter().all(|&x| x == 0) {
                // no OSNMA data in this word
                continue;
            }
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
                let dsm_block = &hkroot[2..].try_into().unwrap();
                if let Some(dsm) = dsm.feed(dsm_header, dsm_block) {
                    let dsm_kroot = DsmKroot(dsm);
                    if !dsm_kroot.check_padding(nma_header) {
                        log::error!("wrong DSM-KROOT padding");
                    } else {
                        log::info!("correct DSM-KROOT padding");
                    }
                    if !dsm_kroot.check_signature(nma_header, &pubkey) {
                        log::error!("wrong DSM-KROOT ECDSA signature");
                    } else {
                        log::info!("correct DSM-KROOT ECDSA signature");
                    }
                }
            }
        }
    }
}

#[cfg(not(all(feature = "galmon", feature = "pem")))]
fn main() {}
